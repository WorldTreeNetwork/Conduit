//! E2EE key management handlers (E10 mrm.1–mrm.9, mrm.13).
//!
//! Implements:
//!   POST /_matrix/client/v3/keys/upload
//!   POST /_matrix/client/v3/keys/query
//!   POST /_matrix/client/v3/keys/claim
//!   POST /_matrix/client/v3/keys/changes
//!   PUT  /_matrix/client/v3/sendToDevice/:eventType/:txnId
//!   POST /_matrix/client/v3/keys/device_signing/upload
//!   POST /_matrix/client/v3/keys/signatures/upload
//!   GET/POST/PUT/DELETE /_matrix/client/v3/room_keys/version[/:version]
//!   GET/PUT/DELETE /_matrix/client/v3/room_keys/keys[/:roomId[/:sessionId]]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{Value, json};

use conduit::storage::Storage;

use super::{AuthState, AuthedUser, MatrixError};

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/keys/upload  (mrm.1)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct KeysUploadRequest {
    /// The device's identity keys, signed by its own Ed25519 key.
    #[serde(default)]
    pub device_keys: Option<Value>,
    /// one_time_keys: { "algorithm:key_id": string | KeyObject, ... }
    #[serde(default)]
    pub one_time_keys: HashMap<String, Value>,
    /// fallback_keys: at most one { "algorithm:key_id": string | KeyObject } per algorithm.
    #[serde(default)]
    pub fallback_keys: HashMap<String, Value>,
}

pub async fn keys_upload<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<KeysUploadRequest>,
) -> Response {
    use super::key_identity::{
        device_ed25519, validate_device_keys, validate_one_time_key, KeyError,
    };
    let storage = state.storage();
    let user_id = &authed.user_id;
    let device_id = &authed.device_id;

    // Validate everything before persisting anything (conduit-y99.14).
    let new_device_keys = match body.device_keys.as_ref().map(|keys| validate_device_keys(keys, user_id, device_id)) {
        None => None,
        Some(Ok(keys)) => Some(keys),
        Some(Err(error)) => return error.into_response(),
    };
    let stored = match storage.get_device_keys(user_id, device_id).await {
        Ok(stored) => stored,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let ed25519 = new_device_keys
        .as_ref()
        .or(stored.as_ref())
        .and_then(|keys| device_ed25519(keys, device_id));
    let mut one_time = Vec::new();
    for (kid, key_json) in &body.one_time_keys {
        match validate_one_time_key(kid, key_json, user_id, device_id, ed25519.as_deref()) {
            Ok(algorithm) => one_time.push((kid.clone(), algorithm, key_json.clone())),
            Err(error) => return error.into_response(),
        }
    }
    let mut fallback: HashMap<String, (String, Value)> = HashMap::new();
    for (kid, key_json) in &body.fallback_keys {
        let algorithm = match validate_one_time_key(kid, key_json, user_id, device_id, ed25519.as_deref()) {
            Ok(algorithm) => algorithm,
            Err(error) => return error.into_response(),
        };
        if fallback.insert(algorithm.clone(), (kid.clone(), key_json.clone())).is_some() {
            return KeyError::invalid_param(format!("at most one fallback key per algorithm ({algorithm})"))
                .into_response();
        }
    }

    if let Some(dk) = &new_device_keys {
        // An identical re-upload is not a device-list change.
        let changed = stored.as_ref() != Some(dk);
        if changed {
            if let Err(e) = storage.upsert_device_keys(user_id, device_id, dk).await {
                return MatrixError::unknown(e.to_string()).into_response();
            }
            let stream_id = match storage.record_device_list_change(user_id).await {
                Ok(id) => id,
                Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
            };
            broadcast_device_list_update(&state, user_id, device_id, stream_id, Some(dk.clone())).await;
        }
    }

    if !one_time.is_empty() {
        if let Err(e) = storage.insert_one_time_keys(user_id, device_id, one_time).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }
    for (algorithm, (kid, key_json)) in &fallback {
        if let Err(e) = storage
            .upsert_fallback_key(user_id, device_id, algorithm, kid, key_json)
            .await
        {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }

    // Return current OTK counts.
    let counts = match storage.one_time_key_counts(user_id, device_id).await {
        Ok(c) => c,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };

    let counts_json: serde_json::Map<String, Value> = counts
        .into_iter()
        .map(|(k, v)| (k, json!(v)))
        .collect();

    state.sync_notify().notify_waiters();
    (
        StatusCode::OK,
        Json(json!({ "one_time_key_counts": counts_json })),
    )
        .into_response()
}

/// Collect distinct remote server names that share a room with `user_id`
/// (conduit-6r1).
///
/// Walks all rooms, checks membership state, returns the set of remote server
/// parts seen for joined members. Excludes our own server.
///
/// **Perf follow-up (conduit-e0e):** this is O(rooms × members) per call and
/// runs on every device-key upload. Add a `(user_id → Set<remote_server>)`
/// cache invalidated on `m.room.member` changes, or push the propagation
/// into the membership-change pipeline.
pub(crate) async fn remote_servers_sharing_room_with(
    storage: &Arc<dyn Storage>,
    server_name: &str,
    user_id: &str,
) -> HashSet<String> {
    // Use the optimized storage method (O(user's rooms × members in those rooms))
    // instead of walking all rooms.
    match storage.get_remote_servers_for_user(user_id, server_name).await {
        Ok(servers) => servers.into_iter().collect(),
        Err(_) => HashSet::new(),
    }
}

/// Broadcast an `m.device_list_update` EDU to every remote server that shares
/// a room with `user_id` (conduit-6r1).
///
/// Best-effort and fire-and-forget — failures are logged. Triggered after
/// `keys_upload` and `device_signing_upload`.
pub(crate) async fn broadcast_device_list_update<S: AuthState>(
    state: &S,
    user_id: &str,
    device_id: &str,
    stream_id: i64,
    keys: Option<Value>,
) {
    let Some(queue) = state.federation_queue().cloned() else {
        return; // No federation wiring (tests / stub state) — silently skip.
    };
    let storage = state.storage().clone();
    let server_name = state.server_name().to_owned();
    let user_id = user_id.to_owned();
    let device_id = device_id.to_owned();

    tokio::spawn(async move {
        let servers =
            remote_servers_sharing_room_with(&storage, &server_name, &user_id).await;
        if servers.is_empty() {
            return;
        }
        let mut content = json!({
            "user_id": user_id,
            "device_id": device_id,
            "stream_id": stream_id,
            "prev_id": [],
        });
        if let Some(k) = keys {
            content["keys"] = k;
        }
        let edu = json!({
            "edu_type": "m.device_list_update",
            "content": content,
        });
        for dest in servers {
            queue.enqueue(&dest, vec![], vec![edu.clone()]).await;
        }
    });
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/keys/query  (mrm.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct KeysQueryRequest {
    /// { user_id: [device_id, ...] }  (empty list = all devices)
    #[serde(default)]
    pub device_keys: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
}

/// Merge stored cross-signing signatures into a key object.
fn merge_signatures<'a>(
    key: &mut Value,
    signatures: impl Iterator<Item = &'a (String, String, String, String)>,
) {
    for (signer, signer_key, _, signature) in signatures {
        if !key["signatures"].is_object() {
            key["signatures"] = json!({});
        }
        if !key["signatures"][signer].is_object() {
            key["signatures"][signer] = json!({});
        }
        key["signatures"][signer][signer_key] = json!(signature);
    }
}

pub async fn keys_query<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<KeysQueryRequest>,
) -> Response {
    use super::key_identity::{cross_signing_public, device_keys_are_authentic};
    let storage = state.storage();
    let requester = &authed.user_id;
    let mut result_device_keys: HashMap<String, Value> = HashMap::new();
    let mut result_master_keys: HashMap<String, Value> = HashMap::new();
    let mut result_self_signing: HashMap<String, Value> = HashMap::new();
    let mut result_user_signing: HashMap<String, Value> = HashMap::new();

    for (uid, device_filter) in &body.device_keys {
        let all_device_keys = match storage.get_device_keys_for_user(uid).await {
            Ok(m) => m,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        };
        let devices = match storage.list_devices_for_user(uid).await {
            Ok(devices) => devices,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        };
        let signatures = match storage.cross_signing_signatures_for(uid).await {
            Ok(signatures) => signatures,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        };

        // Only serve device keys that name this user/device and are
        // self-signed by the device's own Ed25519 key (conduit-y99.14).
        let mut user_keys = serde_json::Map::new();
        for (did, keys) in all_device_keys {
            if !device_filter.is_empty() && !device_filter.contains(&did) {
                continue;
            }
            if !device_keys_are_authentic(&keys, uid, &did) {
                tracing::warn!(user = %uid, device = %did, "withholding unauthenticated device keys");
                continue;
            }
            let mut keys = keys;
            // Device signatures come from the owner's self-signing key.
            merge_signatures(
                &mut keys,
                signatures.iter().filter(|(signer, _, target, _)| signer == uid && *target == did),
            );
            if let Some(name) = devices
                .iter()
                .find(|device| device.device_id == did)
                .and_then(|device| device.display_name.clone())
            {
                keys["unsigned"] = json!({"device_display_name": name});
            }
            user_keys.insert(did, keys);
        }
        if !user_keys.is_empty() {
            result_device_keys.insert(uid.clone(), Value::Object(user_keys));
        }

        let xsk = match storage.get_cross_signing_keys(uid).await {
            Ok(m) => m,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        };
        if let Some(mk) = xsk.get("master") {
            let mut master = mk.clone();
            if let Some(public) = cross_signing_public(mk) {
                // The owner's device signatures are public; a user-signing
                // signature is visible only to the user who made it.
                merge_signatures(
                    &mut master,
                    signatures.iter().filter(|(signer, _, target, _)| {
                        *target == public && (signer == uid || signer == requester)
                    }),
                );
            }
            result_master_keys.insert(uid.clone(), master);
        }
        if let Some(ss) = xsk.get("self_signing") {
            result_self_signing.insert(uid.clone(), ss.clone());
        }
        if uid == requester {
            if let Some(us) = xsk.get("user_signing") {
                result_user_signing.insert(uid.clone(), us.clone());
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "device_keys": result_device_keys,
            "master_keys": result_master_keys,
            "self_signing_keys": result_self_signing,
            "user_signing_keys": result_user_signing,
            "failures": {}
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/keys/claim  (mrm.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct KeysClaimRequest {
    /// { user_id: { device_id: algorithm } }
    pub one_time_keys: HashMap<String, HashMap<String, String>>,
    #[serde(default)]
    pub timeout: Option<u64>,
}

pub async fn keys_claim<S: AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Json(body): Json<KeysClaimRequest>,
) -> Response {
    let storage = state.storage();
    // result: { user_id: { device_id: { "algorithm:key_id": key_json } } }
    let mut claimed: HashMap<String, HashMap<String, Value>> = HashMap::new();

    for (uid, devices) in &body.one_time_keys {
        let mut user_claimed: HashMap<String, Value> = HashMap::new();
        for (did, algorithm) in devices {
            // Try OTK first; fall back to fallback key.
            let result = storage.claim_one_time_key(uid, did, algorithm).await;
            let key_entry = match result {
                Ok(Some((kid, kj))) => Some((kid, kj)),
                Ok(None) => {
                    // No OTK — try fallback.
                    match storage.claim_fallback_key(uid, did, algorithm).await {
                        Ok(r) => r,
                        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
                    }
                }
                Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
            };
            if let Some((kid, kj)) = key_entry {
                user_claimed.insert(did.clone(), json!({ kid: kj }));
            }
        }
        if !user_claimed.is_empty() {
            claimed.insert(uid.clone(), user_claimed);
        }
    }

    state.sync_notify().notify_waiters();
    (StatusCode::OK, Json(json!({ "one_time_keys": claimed }))).into_response()
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/keys/changes  (mrm.4)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct KeysChangesQuery {
    pub from: Option<String>,
    pub to: Option<String>,
}

pub async fn keys_changes<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(query): Query<KeysChangesQuery>,
) -> Response {
    use super::device_lists::{device_list_delta, JoinedRoomIndex};
    let storage = state.storage();

    let Some(from) = query.from.as_deref() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"errcode": "M_MISSING_PARAM", "error": "from is required"})),
        )
            .into_response();
    };
    let from = match super::sync::parse_since(from) {
        Ok(token) => token,
        Err(response) => return response,
    };
    // `to` is a hint (the client's latest next_batch); an absent or
    // unrecognised value means "now".
    let to = query.to.as_deref().and_then(|raw| super::sync::parse_since(raw).ok());
    let device_to = match to.as_ref() {
        Some(token) => token.device_pos,
        None => match storage.device_list_max_position().await {
            Ok(position) => position,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        },
    };
    let events_to = match to.as_ref() {
        Some(token) => token.events_pos,
        None => i64::MAX,
    };
    let key_updates = match storage.device_list_changes_between(from.device_pos, device_to).await {
        Ok(v) => v,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let window = match membership_window(storage.as_ref(), from.events_pos, events_to).await {
        Ok(window) => window,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let result = async {
        let index = JoinedRoomIndex::load(storage.as_ref(), &authed.user_id).await?;
        device_list_delta(storage.as_ref(), &authed.user_id, &index, &key_updates, &window).await
    }
    .await;
    match result {
        Ok((changed, left)) => {
            (StatusCode::OK, Json(json!({ "changed": changed, "left": left }))).into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

/// Membership and encryption state events with stream positions in
/// `(after, through]`, in stream order.
pub(crate) async fn membership_window(
    storage: &dyn Storage,
    after: i64,
    through: i64,
) -> conduit::Result<Vec<conduit::event::Event>> {
    let events: Vec<_> = storage
        .events_since(after, i64::MAX)
        .await?
        .into_iter()
        .filter(|event| matches!(event.event_type.as_str(), "m.room.member" | "m.room.encryption"))
        .collect();
    if through == i64::MAX {
        return Ok(events);
    }
    let ids: Vec<_> = events.iter().map(|event| event.event_id.clone()).collect();
    let positions = storage.event_stream_positions(&ids).await?;
    Ok(events
        .into_iter()
        .filter(|event| positions.get(&event.event_id).is_some_and(|position| *position <= through))
        .collect())
}

// ---------------------------------------------------------------------------
// PUT /_matrix/client/v3/sendToDevice/:eventType/:txnId  (mrm.6)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SendToDeviceBody {
    /// { user_id: { device_id: content } }
    pub messages: HashMap<String, HashMap<String, Value>>,
}

pub async fn send_to_device<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((event_type, txn_id)): Path<(String, String)>,
    request: axum::extract::Request,
) -> Response {
    use conduit::storage::{OutboundDelivery, ToDeviceDelivery, TransactionKey};
    let storage = state.storage();
    let key = TransactionKey::client(
        &authed.user_id,
        &authed.device_id,
        &["send_to_device", &event_type],
        &txn_id,
    );
    let mut replay = match crate::replay::Replay::start(storage.clone(), key.clone()).await {
        Ok(crate::replay::Start::Cached(response)) => {
            if let Some(queue) = state.federation_queue() {
                queue.start().await;
            }
            return response;
        }
        Ok(crate::replay::Start::Execute(replay)) => replay,
        Err(error) => return error,
    };
    let raw = match replay.body(request).await {
        Ok(body) => body,
        Err(error) => return error,
    };
    let body = match serde_json::from_value::<SendToDeviceBody>(raw) {
        Ok(body) => body,
        Err(error) => {
            return replay
                .finish(
                    StatusCode::BAD_REQUEST,
                    json!({"errcode": "M_BAD_JSON", "error": error.to_string()}),
                )
                .await
        }
    };
    // Every delivery may later cross federation, whose signed JSON must be
    // canonical. Reject unsupported values before recording any effects.
    if conduit::canonical_json::to_canonical_bytes(&body.messages).is_err() {
        return replay.finish(StatusCode::BAD_REQUEST, json!({"errcode": "M_BAD_JSON", "error": "to-device contents must be canonical JSON"})).await;
    }
    let mut local = Vec::new();
    let mut remote_by_server: HashMap<String, HashMap<String, HashMap<String, Value>>> =
        HashMap::new();
    for (target_user, devices) in body.messages {
        let Some((localpart, server)) = target_user.split_once(':') else {
            return replay
                .finish(
                    StatusCode::BAD_REQUEST,
                    json!({"errcode": "M_BAD_JSON", "error": "invalid target user ID"}),
                )
                .await;
        };
        if !localpart.starts_with('@') || localpart.len() < 2 || server.is_empty() {
            return replay
                .finish(
                    StatusCode::BAD_REQUEST,
                    json!({"errcode": "M_BAD_JSON", "error": "invalid target user ID"}),
                )
                .await;
        }
        if server == state.server_name() {
            for (device, content) in devices {
                local.push(ToDeviceDelivery {
                    target_user: target_user.clone(),
                    target_device: device,
                    sender: authed.user_id.clone(),
                    event_type: event_type.clone(),
                    content,
                });
            }
        } else {
            remote_by_server
                .entry(server.to_owned())
                .or_default()
                .insert(target_user, devices);
        }
    }
    if local.iter().any(|message| !message.content.is_object())
        || remote_by_server
            .values()
            .flat_map(|users| users.values())
            .flat_map(|devices| devices.values())
            .any(|content| !content.is_object())
    {
        return replay.finish(StatusCode::BAD_REQUEST, json!({"errcode": "M_BAD_JSON", "error": "to-device contents must be JSON objects"})).await;
    }
    if !remote_by_server.is_empty() && state.federation_queue().is_none() {
        return replay
            .finish(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"errcode": "M_UNKNOWN", "error": "federation delivery is unavailable"}),
            )
            .await;
    }
    let remote: Vec<_> = remote_by_server.into_iter().map(|(destination, messages)| {
        let id = uuid::Uuid::new_v4().simple().to_string();
        OutboundDelivery { destination, txn_id: id.clone(), payload: json!({
            "pdus": [], "edus": [{"edu_type": "m.direct_to_device", "content": {
                "sender": authed.user_id, "type": event_type, "message_id": id, "messages": messages
            }}]
        }) }
    }).collect();
    match storage.deliver_to_device_once(&key, &local, &remote).await {
        Ok(_) => {}
        Err(error) => return crate::replay::error(error),
    }
    if let Some(queue) = state.federation_queue() {
        for delivery in &remote {
            queue.wake(&delivery.destination).await;
        }
    }
    state.sync_notify().notify_waiters();
    replay.finish(StatusCode::OK, json!({})).await
}
/// Expand wildcard recipients before writing device-specific queue entries.
pub(crate) async fn enqueue_local_to_device(
    storage: &dyn Storage,
    target_user: &str,
    target_device: &str,
    sender: &str,
    event_type: &str,
    content: &Value,
) -> conduit::Result<()> {
    let devices = if target_device == "*" {
        storage
            .list_devices_for_user(target_user)
            .await?
            .into_iter()
            .map(|device| device.device_id)
            .collect()
    } else {
        vec![target_device.to_owned()]
    };
    for device_id in devices {
        storage
            .enqueue_to_device(target_user, &device_id, sender, event_type, content)
            .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/keys/device_signing/upload  (mrm.8)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeviceSigningUploadRequest {
    #[serde(default)]
    pub auth: Option<Value>,
    #[serde(default)]
    pub master_key: Option<Value>,
    #[serde(default)]
    pub self_signing_key: Option<Value>,
    #[serde(default)]
    pub user_signing_key: Option<Value>,
}

/// User-interactive authentication for replacing cross-signing keys.
/// Returns `None` when the request carries a valid `m.login.password` stage.
async fn require_password_uia<S: AuthState>(state: &S, user_id: &str, auth: Option<&Value>) -> Option<Response> {
    let challenge = |error: Option<&str>| {
        let mut body = json!({
            "flows": [{"stages": ["m.login.password"]}],
            "params": {},
            "session": auth.and_then(|auth| auth["session"].as_str()).map(str::to_owned)
                .unwrap_or_else(super::uia::new_session_id),
        });
        if let Some(error) = error {
            body["errcode"] = json!("M_FORBIDDEN");
            body["error"] = json!(error);
        }
        (StatusCode::UNAUTHORIZED, Json(body)).into_response()
    };
    let Some(auth) = auth.filter(|auth| auth["type"] == "m.login.password") else {
        return Some(challenge(None));
    };
    let identified = auth["identifier"]["user"]
        .as_str()
        .or_else(|| auth["user"].as_str())
        .map(|user| {
            if user.starts_with('@') {
                user.to_owned()
            } else {
                format!("@{user}:{}", state.server_name())
            }
        });
    if identified.as_deref().is_some_and(|user| user != user_id) {
        return Some(challenge(Some("identifier does not match the authenticated user")));
    }
    let Some(password) = auth["password"].as_str() else {
        return Some(challenge(Some("password is required")));
    };
    let hash = match state.storage().get_account(user_id).await {
        Ok(Some(account)) => account.password_hash,
        Ok(None) => None,
        Err(e) => return Some(MatrixError::unknown(e.to_string()).into_response()),
    };
    let Some(hash) = hash else {
        return Some(challenge(Some("account has no password")));
    };
    match super::verify_password(password.to_owned(), hash).await {
        Ok(true) => {
            if let Some(session) = auth["session"].as_str() {
                super::uia::mark_session_used(session);
            }
            None
        }
        Ok(false) => Some(challenge(Some("invalid password"))),
        Err(error) => Some(MatrixError::unknown(error).into_response()),
    }
}

pub async fn device_signing_upload<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<DeviceSigningUploadRequest>,
) -> Response {
    use super::key_identity::{cross_signing_public, validate_cross_signing_key, verify_signature, KeyError};
    let storage = state.storage();
    let user_id = &authed.user_id;

    let existing = match storage.get_cross_signing_keys(user_id).await {
        Ok(keys) => keys,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let provided: Vec<(&str, &str, &Value)> = [
        ("master", "master", body.master_key.as_ref()),
        ("self_signing", "self_signing", body.self_signing_key.as_ref()),
        ("user_signing", "user_signing", body.user_signing_key.as_ref()),
    ]
    .into_iter()
    .filter_map(|(slot, usage, key)| key.map(|key| (slot, usage, key)))
    .collect();
    let mut identities = Vec::new();
    for (_, usage, key) in &provided {
        match validate_cross_signing_key(key, user_id, usage) {
            Ok(identity) => identities.push(identity),
            Err(error) => return error.into_response(),
        }
    }
    // Self- and user-signing keys must be signed by the accompanying master
    // key, or else by the most recently uploaded one.
    let master_public = body
        .master_key
        .as_ref()
        .and_then(cross_signing_public)
        .or_else(|| existing.get("master").and_then(cross_signing_public));
    for (slot, _, key) in &provided {
        if *slot == "master" {
            continue;
        }
        let Some(master) = master_public.as_deref() else {
            return KeyError::invalid_signature(format!("{slot} key requires a master key to verify it")).into_response();
        };
        if !verify_signature(key, user_id, &format!("ed25519:{master}"), master) {
            return KeyError::invalid_signature(format!("{slot} key is not signed by the master key")).into_response();
        }
    }
    // Cross-signing key IDs share a namespace with device IDs in
    // /keys/signatures/upload, so a public key may not equal a device ID.
    let devices = match storage.list_devices_for_user(user_id).await {
        Ok(devices) => devices,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    if identities
        .iter()
        .any(|identity| devices.iter().any(|device| device.device_id == identity.public_key))
    {
        return KeyError::forbidden("Key ID in use").into_response();
    }

    // UIA is required unless no master key exists yet, or the request
    // re-uploads exactly the stored keys (an idempotent retry).
    let unchanged = provided
        .iter()
        .all(|(slot, _, key)| existing.get(*slot).is_some_and(|stored| stored == *key));
    if existing.contains_key("master") {
        let exact_retry = body.master_key.is_some() && unchanged;
        if !exact_retry {
            if let Some(response) = require_password_uia(&state, user_id, body.auth.as_ref()).await {
                return response;
            }
        }
    }
    if unchanged {
        return (StatusCode::OK, Json(json!({}))).into_response();
    }

    for (slot, _, key) in &provided {
        if let Err(e) = storage.upsert_cross_signing_key(user_id, slot, key).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }

    // Record device list change so peers see updated cross-signing keys.
    let stream_id = match storage.record_device_list_change(user_id).await {
        Ok(id) => id,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    // Federate an m.device_list_update EDU. Cross-signing key changes
    // surface as a device-less device_list_update (remotes re-query).
    broadcast_device_list_update(&state, user_id, "", stream_id, None).await;

    state.sync_notify().notify_waiters();
    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/keys/signatures/upload  (mrm.9)
// ---------------------------------------------------------------------------

/// Request body: `{ user_id: { key_id: signed JSON object } }`.
pub type SignaturesUploadRequest = HashMap<String, HashMap<String, Value>>;

pub async fn signatures_upload<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<SignaturesUploadRequest>,
) -> Response {
    use super::key_identity::{
        cross_signing_public, device_ed25519, device_keys_are_authentic, same_signed_content,
        verify_signature, KeyError,
    };
    let storage = state.storage();
    let me = &authed.user_id;
    let mine = match storage.get_cross_signing_keys(me).await {
        Ok(keys) => keys,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let my_self_signing = mine.get("self_signing").and_then(cross_signing_public);
    let my_user_signing = mine.get("user_signing").and_then(cross_signing_public);

    let mut failures: HashMap<String, HashMap<String, Value>> = HashMap::new();
    let mut changed_users = std::collections::BTreeSet::new();
    for (target_user, keys) in &body {
        for (target_key_id, signed) in keys {
            let mut fail = |error: KeyError| {
                failures
                    .entry(target_user.clone())
                    .or_default()
                    .insert(target_key_id.clone(), error.to_json());
            };
            let Some(new_signatures) = signed["signatures"][me.as_str()].as_object() else {
                fail(KeyError::invalid_signature("no signatures by the uploading user"));
                continue;
            };
            // Resolve the target key and which of my keys may sign it.
            let (target, signers): (Value, HashMap<String, String>) = if target_user == me {
                match storage.get_device_keys(me, target_key_id).await {
                    Ok(Some(device_keys)) => {
                        // My own device, signed by my self-signing key.
                        let signers = my_self_signing
                            .iter()
                            .map(|public| (format!("ed25519:{public}"), public.clone()))
                            .collect();
                        (device_keys, signers)
                    }
                    Ok(None) => match mine.get("master") {
                        Some(master) if cross_signing_public(master).as_deref() == Some(target_key_id.as_str()) => {
                            // My master key, signed by one of my devices.
                            let devices = match storage.get_device_keys_for_user(me).await {
                                Ok(devices) => devices,
                                Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
                            };
                            let signers = devices
                                .iter()
                                .filter(|(did, keys)| device_keys_are_authentic(keys, me, did))
                                .filter_map(|(did, keys)| {
                                    device_ed25519(keys, did).map(|public| (format!("ed25519:{did}"), public))
                                })
                                .collect();
                            (master.clone(), signers)
                        }
                        _ => {
                            fail(KeyError::not_found("unknown key"));
                            continue;
                        }
                    },
                    Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
                }
            } else {
                // Another user's master key, signed by my user-signing key.
                let theirs = match storage.get_cross_signing_keys(target_user).await {
                    Ok(keys) => keys,
                    Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
                };
                match theirs.get("master") {
                    Some(master) if cross_signing_public(master).as_deref() == Some(target_key_id.as_str()) => {
                        let signers = my_user_signing
                            .iter()
                            .map(|public| (format!("ed25519:{public}"), public.clone()))
                            .collect();
                        (master.clone(), signers)
                    }
                    _ => {
                        fail(KeyError::not_found("unknown master key"));
                        continue;
                    }
                }
            };
            if !same_signed_content(signed, &target) {
                fail(KeyError::invalid_signature("signed object does not match the stored key"));
                continue;
            }
            let mut stored_any = false;
            let mut rejected = None;
            for (signer_key_id, signature) in new_signatures {
                // Existing signatures on the object are carried, not re-added.
                if target["signatures"][me.as_str()][signer_key_id] == *signature {
                    continue;
                }
                let Some(public) = signers.get(signer_key_id) else {
                    rejected = Some(KeyError::invalid_signature(format!("{signer_key_id} may not sign this key")));
                    continue;
                };
                let Some(signature) = signature.as_str() else {
                    rejected = Some(KeyError::invalid_signature("signature must be a string"));
                    continue;
                };
                if !verify_signature(signed, me, signer_key_id, public) {
                    rejected = Some(KeyError::invalid_signature("Invalid signature"));
                    continue;
                }
                if let Err(e) = storage
                    .insert_cross_signing_signature(me, signer_key_id, target_user, target_key_id, signature)
                    .await
                {
                    return MatrixError::unknown(e.to_string()).into_response();
                }
                stored_any = true;
            }
            if let Some(error) = rejected {
                fail(error);
            }
            if stored_any {
                // Signatures on my own keys are public; a user-signing
                // signature is only visible to me.
                changed_users.insert(me.clone());
            }
        }
    }
    for user in changed_users {
        match storage.record_device_list_change(&user).await {
            Ok(stream_id) => broadcast_device_list_update(&state, &user, "", stream_id, None).await,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        }
    }
    state.sync_notify().notify_waiters();
    (StatusCode::OK, Json(json!({ "failures": failures }))).into_response()
}

// ---------------------------------------------------------------------------
// Room key backup (mrm.13)
// ---------------------------------------------------------------------------

// --- POST /_matrix/client/v3/room_keys/version ---

#[derive(Debug, Deserialize)]
pub struct RoomKeyVersionCreateRequest {
    pub algorithm: String,
    pub auth_data: Value,
}

pub async fn room_keys_version_create<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<RoomKeyVersionCreateRequest>,
) -> Response {
    let storage = state.storage();
    let user_id = &authed.user_id;

    // Verify auth_data signatures (conduit-aee). If a master cross-signing
    // key has been uploaded for the user, any signatures present in
    // auth_data must verify against it; otherwise we 400.
    if let Ok(xsk) = storage.get_cross_signing_keys(user_id).await {
        if let Some(master) = xsk.get("master") {
            if let Err(e) = verify_backup_auth_data(&body.auth_data, master) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "errcode": "M_INVALID_SIGNATURE",
                        "error": format!("backup auth_data signature invalid: {e}")
                    })),
                )
                    .into_response();
            }
        }
    }

    // Version = monotonic timestamp string.
    let version = chrono::Utc::now().timestamp_millis().to_string();

    match storage
        .create_room_keys_version(user_id, &version, &body.algorithm, &body.auth_data)
        .await
    {
        Ok(_etag) => (StatusCode::OK, Json(json!({ "version": version }))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

/// Verify the signatures on a room-keys backup `auth_data` against the user's
/// master cross-signing key (conduit-aee).
///
/// Returns:
/// - `Ok(())` if no signatures are present (nothing to verify), or if at least
///   one signature in `auth_data["signatures"]` verifies against a key in
///   `master_key_json["keys"]`.
/// - `Err(reason)` if signatures are present but none verify against the
///   master key.
pub(crate) fn verify_backup_auth_data(
    auth_data: &Value,
    master_key_json: &Value,
) -> Result<(), String> {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

    let Some(sigs) = auth_data
        .get("signatures")
        .and_then(|s| s.as_object())
        .filter(|m| !m.is_empty())
    else {
        return Ok(()); // No signatures to verify.
    };

    let mut stripped = auth_data.clone();
    if let Some(obj) = stripped.as_object_mut() {
        obj.remove("signatures");
        obj.remove("unsigned");
    }
    let bytes = conduit::canonical_json::to_canonical_bytes(&stripped)
        .map_err(|e| format!("canonicalize auth_data: {e}"))?;

    let master_keys = master_key_json
        .get("keys")
        .and_then(|k| k.as_object())
        .ok_or_else(|| "master cross-signing key missing 'keys' field".to_owned())?;

    let mut tried_any = false;
    for (_signing_user, sig_map) in sigs {
        let Some(sig_map) = sig_map.as_object() else {
            continue;
        };
        for (key_id, sig_val) in sig_map {
            let Some(sig_b64) = sig_val.as_str() else {
                continue;
            };
            let Some(pub_b64) = master_keys.get(key_id).and_then(|v| v.as_str()) else {
                continue; // Signature uses a different key than the master — skip.
            };
            tried_any = true;
            let pub_bytes = STANDARD_NO_PAD
                .decode(pub_b64)
                .map_err(|e| format!("public key base64: {e}"))?;
            let sig_bytes = STANDARD_NO_PAD
                .decode(sig_b64)
                .map_err(|e| format!("signature base64: {e}"))?;
            let pub_arr: [u8; 32] = pub_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "master public key is not 32 bytes".to_owned())?;
            let sig_arr: [u8; 64] = sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "signature is not 64 bytes".to_owned())?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pub_arr)
                .map_err(|e| format!("master key invalid: {e}"))?;
            let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
            if vk.verify_strict(&bytes, &sig).is_ok() {
                return Ok(());
            }
        }
    }

    if tried_any {
        Err("no signature verified against master key".to_owned())
    } else {
        // Signatures were present but used keys not in the master key. Per
        // spec, accept — these may be signed by other identity keys we don't
        // hold; the client will re-validate on restore.
        Ok(())
    }
}

// --- GET /_matrix/client/v3/room_keys/version ---

pub async fn room_keys_version_get_latest<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
) -> Response {
    let storage = state.storage();
    match storage.get_room_keys_version(&authed.user_id, None).await {
        Ok(Some(v)) => (StatusCode::OK, Json(room_key_version_json(v))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "errcode": "M_NOT_FOUND", "error": "No backup version found" })),
        )
            .into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// --- GET /_matrix/client/v3/room_keys/version/:version ---

pub async fn room_keys_version_get<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(version): Path<String>,
) -> Response {
    let storage = state.storage();
    match storage
        .get_room_keys_version(&authed.user_id, Some(&version))
        .await
    {
        Ok(Some(v)) => (StatusCode::OK, Json(room_key_version_json(v))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "errcode": "M_NOT_FOUND", "error": "Backup version not found" })),
        )
            .into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// --- PUT /_matrix/client/v3/room_keys/version/:version ---

#[derive(Debug, Deserialize)]
pub struct RoomKeyVersionUpdateRequest {
    pub auth_data: Value,
    // algorithm must match existing version; we ignore it for update.
    #[serde(default)]
    pub algorithm: Option<String>,
}

pub async fn room_keys_version_update<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(version): Path<String>,
    Json(body): Json<RoomKeyVersionUpdateRequest>,
) -> Response {
    let storage = state.storage();
    match storage
        .update_room_keys_version(&authed.user_id, &version, &body.auth_data)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// --- DELETE /_matrix/client/v3/room_keys/version/:version ---

pub async fn room_keys_version_delete<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(version): Path<String>,
) -> Response {
    let storage = state.storage();
    match storage
        .delete_room_keys_version(&authed.user_id, &version)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

fn room_key_version_json(v: conduit::storage::RoomKeyVersion) -> Value {
    json!({
        "version": v.version,
        "algorithm": v.algorithm,
        "auth_data": v.auth_data,
        "count": v.count,
        "etag": v.etag,
    })
}

// --- PUT /_matrix/client/v3/room_keys/keys (all rooms) ---

#[derive(Debug, Deserialize)]
pub struct RoomKeysQuery {
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct RoomKeysAllBody {
    /// { room_id: { sessions: { session_id: key_data } } }
    pub rooms: HashMap<String, RoomRoomKeys>,
}

#[derive(Debug, Deserialize)]
pub struct RoomRoomKeys {
    pub sessions: HashMap<String, Value>,
}

pub async fn room_keys_put_all<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(q): Query<RoomKeysQuery>,
    Json(body): Json<RoomKeysAllBody>,
) -> Response {
    let storage = state.storage();
    let user_id = &authed.user_id;
    for (room_id, room) in &body.rooms {
        for (session_id, key_data) in &room.sessions {
            if let Err(e) = storage
                .upsert_room_key(user_id, &q.version, room_id, session_id, key_data)
                .await
            {
                return MatrixError::unknown(e.to_string()).into_response();
            }
        }
    }
    room_keys_count_response(storage, user_id, &q.version).await
}

// --- GET /_matrix/client/v3/room_keys/keys ---

pub async fn room_keys_get_all<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(q): Query<RoomKeysQuery>,
) -> Response {
    let storage = state.storage();
    match storage
        .get_room_keys(&authed.user_id, &q.version, None, None)
        .await
    {
        Ok(rooms) => {
            let rooms_json: HashMap<String, Value> = rooms
                .into_iter()
                .map(|(rid, sessions)| (rid, json!({ "sessions": sessions })))
                .collect();
            (StatusCode::OK, Json(json!({ "rooms": rooms_json }))).into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// --- DELETE /_matrix/client/v3/room_keys/keys ---

pub async fn room_keys_delete_all<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(q): Query<RoomKeysQuery>,
) -> Response {
    let storage = state.storage();
    match storage
        .delete_room_keys(&authed.user_id, &q.version, None, None)
        .await
    {
        Ok(_) => room_keys_count_response(storage, &authed.user_id, &q.version).await,
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// --- PUT /_matrix/client/v3/room_keys/keys/:roomId ---

#[derive(Debug, Deserialize)]
pub struct RoomKeysSingleRoomBody {
    pub sessions: HashMap<String, Value>,
}

pub async fn room_keys_put_room<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Query(q): Query<RoomKeysQuery>,
    Json(body): Json<RoomKeysSingleRoomBody>,
) -> Response {
    let storage = state.storage();
    let user_id = &authed.user_id;
    for (session_id, key_data) in &body.sessions {
        if let Err(e) = storage
            .upsert_room_key(user_id, &q.version, &room_id, session_id, key_data)
            .await
        {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }
    room_keys_count_response(storage, user_id, &q.version).await
}

// --- GET /_matrix/client/v3/room_keys/keys/:roomId ---

pub async fn room_keys_get_room<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Query(q): Query<RoomKeysQuery>,
) -> Response {
    let storage = state.storage();
    match storage
        .get_room_keys(&authed.user_id, &q.version, Some(&room_id), None)
        .await
    {
        Ok(rooms) => {
            let sessions = rooms.get(&room_id).cloned().unwrap_or_default();
            (StatusCode::OK, Json(json!({ "sessions": sessions }))).into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// --- GET /_matrix/client/v3/room_keys/keys/:roomId/:sessionId ---

pub async fn room_keys_get_session<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<RoomKeysQuery>,
) -> Response {
    let storage = state.storage();
    match storage
        .get_room_keys(&authed.user_id, &q.version, Some(&room_id), Some(&session_id))
        .await
    {
        Ok(rooms) => {
            let sessions = rooms.get(&room_id).and_then(|s| s.get(&session_id)).cloned();
            match sessions {
                Some(kd) => (StatusCode::OK, Json(kd)).into_response(),
                None => (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "errcode": "M_NOT_FOUND", "error": "Session not found" })),
                )
                    .into_response(),
            }
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// --- PUT /_matrix/client/v3/room_keys/keys/:roomId/:sessionId ---

pub async fn room_keys_put_session<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<RoomKeysQuery>,
    Json(key_data): Json<Value>,
) -> Response {
    let storage = state.storage();
    let user_id = &authed.user_id;
    if let Err(e) = storage
        .upsert_room_key(user_id, &q.version, &room_id, &session_id, &key_data)
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    room_keys_count_response(storage, user_id, &q.version).await
}

// Helper: return { etag, count } response after a room key mutation.
async fn room_keys_count_response(
    storage: &std::sync::Arc<dyn conduit::storage::Storage>,
    user_id: &str,
    version: &str,
) -> Response {
    match storage.get_room_keys_version(user_id, Some(version)).await {
        Ok(Some(v)) => (
            StatusCode::OK,
            Json(json!({ "etag": v.etag, "count": v.count })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "errcode": "M_NOT_FOUND", "error": "Version not found" })),
        )
            .into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod fanout_tests {
    use super::*;
    use conduit::event::Event;
    use conduit::storage::MemoryStorage;

    #[tokio::test]
    async fn wildcard_delivery_preserves_each_device_queue() {
        let storage = conduit::storage::MemoryStorage::default();
        let user = "@bob:local.test";
        for device in ["ONE", "TWO"] {
            storage.upsert_device(user, device, None).await.unwrap();
        }
        let content = json!({"body": "verification"});
        super::enqueue_local_to_device(
            &storage,
            user,
            "*",
            "@alice:local.test",
            "m.test",
            &content,
        )
        .await
        .unwrap();
        let first = storage.drain_to_device(user, "ONE", 0, 100).await.unwrap();
        let second = storage.drain_to_device(user, "TWO", 0, 100).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].content, content);
        assert_eq!(second[0].content, content);
        storage
            .delete_to_device_before(user, "ONE", first[0].id)
            .await
            .unwrap();
        assert!(storage
            .drain_to_device(user, "ONE", 0, 100)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            storage
                .drain_to_device(user, "TWO", 0, 100)
                .await
                .unwrap()
                .len(),
            1
        );

        super::enqueue_local_to_device(
            &storage,
            user,
            "ONE",
            "@alice:local.test",
            "m.test",
            &content,
        )
        .await
        .unwrap();
        assert_eq!(
            storage
                .drain_to_device(user, "ONE", 0, 100)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            storage
                .drain_to_device(user, "TWO", 0, 100)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(storage
            .drain_to_device(user, "*", 0, 100)
            .await
            .unwrap()
            .is_empty());
    }

    fn member_event(room: &str, user: &str, membership: &str) -> Event {
        Event {
            event_id: format!("$mem-{room}-{user}"),
            room_id: room.to_owned(),
            sender: user.to_owned(),
            event_type: "m.room.member".to_owned(),
            content: json!({ "membership": membership }),
            state_key: Some(user.to_owned()),
            origin_server_ts: 0,
            auth_events: vec![],
            prev_events: vec![],
            hashes: json!({}),
            signatures: json!({}),
            depth: 1,
            unsigned: None,
        }
    }

    async fn seed_member(storage: &Arc<dyn Storage>, room: &str, user: &str, membership: &str) {
        let ev = member_event(room, user, membership);
        storage.put_event(&ev).await.unwrap();
        storage
            .set_state_entry(room, "m.room.member", user, &ev.event_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn remote_servers_collects_distinct_remotes() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::default());
        // Room 1: @alice:local + @bob:remote-a + @carol:remote-b (all joined)
        seed_member(&storage, "!r1:local", "@alice:local", "join").await;
        seed_member(&storage, "!r1:local", "@bob:remote-a", "join").await;
        seed_member(&storage, "!r1:local", "@carol:remote-b", "join").await;
        // Room 2: @alice:local + @bob:remote-a + @dave:remote-c (dave is invited, not joined)
        seed_member(&storage, "!r2:local", "@alice:local", "join").await;
        seed_member(&storage, "!r2:local", "@bob:remote-a", "join").await;
        seed_member(&storage, "!r2:local", "@dave:remote-c", "invite").await;
        // Room 3: alice is invited, not joined. eve:remote-d is joined.
        seed_member(&storage, "!r3:local", "@alice:local", "invite").await;
        seed_member(&storage, "!r3:local", "@eve:remote-d", "join").await;

        let s = remote_servers_sharing_room_with(&storage, "local", "@alice:local").await;
        assert!(s.contains("remote-a"));
        assert!(s.contains("remote-b"));
        // dave:remote-c is invited-only → still a remote member; included.
        // But our filter requires membership=join → so remote-c should NOT be included.
        assert!(!s.contains("remote-c"));
        // alice isn't joined in r3 → eve:remote-d not collected.
        assert!(!s.contains("remote-d"));
        // Our own server is excluded.
        assert!(!s.contains("local"));
        assert_eq!(s.len(), 2);
    }

    #[tokio::test]
    async fn sas_verification_to_device_round_trip() {
        // Confirms m.key.verification.start is carried by the to-device queue
        // (the same path is used for any opaque event_type) (conduit-c52).
        let storage = MemoryStorage::default();
        let content = json!({
            "method": "m.sas.v1",
            "transaction_id": "abc",
            "from_device": "DEV_A",
        });
        let id = storage
            .enqueue_to_device(
                "@bob:local",
                "DEV_B",
                "@alice:local",
                "m.key.verification.start",
                &content,
            )
            .await
            .unwrap();
        assert!(id > 0);
        let msgs = storage
            .drain_to_device("@bob:local", "DEV_B", 0, 10)
            .await
            .unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender, "@alice:local");
        assert_eq!(msgs[0].event_type, "m.key.verification.start");
        assert_eq!(msgs[0].content, content);
    }
}

#[cfg(test)]
mod backup_sig_tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn build_master(key_id: &str, vk: &ed25519_dalek::VerifyingKey) -> Value {
        let pub_b64 = STANDARD_NO_PAD.encode(vk.to_bytes());
        json!({
            "user_id": "@a:srv",
            "usage": ["master"],
            "keys": { key_id: pub_b64 },
        })
    }

    fn signed_auth_data(sk: &SigningKey, key_id: &str) -> Value {
        let mut auth_data = json!({
            "public_key": "AAAAAAAAAA",
            "extra": "data",
        });
        let bytes = conduit::canonical_json::to_canonical_bytes(&auth_data).unwrap();
        let sig = sk.sign(&bytes);
        let sig_b64 = STANDARD_NO_PAD.encode(sig.to_bytes());
        auth_data["signatures"] = json!({
            "@a:srv": { key_id: sig_b64 }
        });
        auth_data
    }

    #[test]
    fn verify_no_signatures_is_ok() {
        let auth_data = json!({"public_key": "abc"});
        let master = json!({"keys": {"ed25519:M": "AAAA"}});
        assert!(verify_backup_auth_data(&auth_data, &master).is_ok());
    }

    #[test]
    fn verify_valid_signature_against_master_is_ok() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let key_id = "ed25519:MASTER";
        let auth_data = signed_auth_data(&sk, key_id);
        let master = build_master(key_id, &vk);
        verify_backup_auth_data(&auth_data, &master).expect("valid sig must verify");
    }

    #[test]
    fn verify_corrupted_signature_rejects() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let key_id = "ed25519:MASTER";
        let mut auth_data = signed_auth_data(&sk, key_id);
        // Flip a byte in the signature.
        let sig_b64 = auth_data["signatures"]["@a:srv"][key_id]
            .as_str()
            .unwrap()
            .to_owned();
        let mut sig_bytes = STANDARD_NO_PAD.decode(&sig_b64).unwrap();
        sig_bytes[0] ^= 0xFF;
        let new_sig = STANDARD_NO_PAD.encode(&sig_bytes);
        auth_data["signatures"]["@a:srv"][key_id] = json!(new_sig);
        let master = build_master(key_id, &vk);
        assert!(verify_backup_auth_data(&auth_data, &master).is_err());
    }

    #[test]
    fn verify_signature_with_unknown_key_id_is_accepted() {
        // Spec note: signatures using keys we don't hold are tolerated; the
        // client will re-validate at restore time.
        let sk = SigningKey::generate(&mut OsRng);
        let auth_data = signed_auth_data(&sk, "ed25519:OTHER");
        // Master key uses a different key_id.
        let other = SigningKey::generate(&mut OsRng);
        let master = build_master("ed25519:MASTER", &other.verifying_key());
        assert!(verify_backup_auth_data(&auth_data, &master).is_ok());
    }
}

/// Extract device-list stream position from a combined sync token "s{events}_d{device}"
/// or a plain device-list token "d{device}".
pub fn parse_device_pos_from_token(token: &str) -> Option<i64> {
    // Combined token: "s123_d456" → extract 456
    if let Some(d_part) = token.split('_').find(|p| p.starts_with('d')) {
        return d_part.strip_prefix('d').and_then(|s| s.parse().ok());
    }
    // Plain: "d456"
    if let Some(s) = token.strip_prefix('d') {
        return s.parse().ok();
    }
    None
}
