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
    /// device_keys: the full DeviceKeys object (opaque blob, stored as-is).
    #[serde(default)]
    pub device_keys: Option<Value>,
    /// one_time_keys: { "algorithm:key_id": key_json, ... }
    #[serde(default)]
    pub one_time_keys: HashMap<String, Value>,
    /// fallback_keys: { "algorithm:key_id": key_json, ... }
    /// May also contain "algorithm": bool (the "unused_fallback_key_types" signal).
    #[serde(default)]
    pub fallback_keys: HashMap<String, Value>,
}

pub async fn keys_upload<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<KeysUploadRequest>,
) -> Response {
    let storage = state.storage();
    let user_id = &authed.user_id;
    let device_id = &authed.device_id;

    // Store device keys if provided.
    if let Some(dk) = &body.device_keys {
        if let Err(e) = storage.upsert_device_keys(user_id, device_id, dk).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
        // Record device list change so other users' /sync sees the update.
        let stream_id = storage.record_device_list_change(user_id).await.unwrap_or(0);
        // Federate an m.device_list_update EDU to remote servers sharing a
        // room with this user (conduit-6r1).
        broadcast_device_list_update(&state, user_id, device_id, stream_id, Some(dk.clone()))
            .await;
    }

    // Store one-time keys.
    if !body.one_time_keys.is_empty() {
        let mut parsed: Vec<(String, String, Value)> = Vec::new();
        for (kid, key_json) in &body.one_time_keys {
            // key_id format: "algorithm:key_id" e.g. "signed_curve25519:AAAABg"
            let algorithm = kid.split(':').next().unwrap_or(kid).to_owned();
            parsed.push((kid.clone(), algorithm, key_json.clone()));
        }
        if let Err(e) = storage.insert_one_time_keys(user_id, device_id, parsed).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }

    // Store fallback keys (values that are objects, not booleans).
    for (kid, key_json) in &body.fallback_keys {
        if key_json.is_object() {
            let algorithm = kid.split(':').next().unwrap_or(kid).to_owned();
            if let Err(e) = storage
                .upsert_fallback_key(user_id, device_id, &algorithm, kid, key_json)
                .await
            {
                return MatrixError::unknown(e.to_string()).into_response();
            }
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
    let mut servers: HashSet<String> = HashSet::new();
    let rooms = match storage.list_rooms(0, 10_000).await {
        Ok(r) => r,
        Err(_) => return servers,
    };
    for room_id in rooms {
        // Is `user_id` joined in this room?
        let in_room = match storage
            .get_state_entry(&room_id, "m.room.member", user_id)
            .await
        {
            Ok(Some(ev)) => ev
                .content
                .get("membership")
                .and_then(|v| v.as_str())
                .map(|m| m == "join")
                .unwrap_or(false),
            _ => false,
        };
        if !in_room {
            continue;
        }
        // Collect remote servers from other joined members.
        let state = match storage.get_current_state(&room_id).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        for ev in state {
            if ev.event_type != "m.room.member" {
                continue;
            }
            let membership = ev
                .content
                .get("membership")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if membership != "join" {
                continue;
            }
            let other = ev.state_key.as_deref().unwrap_or("");
            let srv = other.split(':').nth(1).unwrap_or("");
            if !srv.is_empty() && srv != server_name {
                servers.insert(srv.to_owned());
            }
        }
    }
    servers
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

pub async fn keys_query<S: AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Json(body): Json<KeysQueryRequest>,
) -> Response {
    let storage = state.storage();
    let mut result_device_keys: HashMap<String, Value> = HashMap::new();
    let mut result_master_keys: HashMap<String, Value> = HashMap::new();
    let mut result_self_signing: HashMap<String, Value> = HashMap::new();
    let mut result_user_signing: HashMap<String, Value> = HashMap::new();

    for (uid, device_filter) in &body.device_keys {
        // Fetch device identity keys.
        let all_device_keys = match storage.get_device_keys_for_user(uid).await {
            Ok(m) => m,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        };

        let user_keys: HashMap<String, Value> = if device_filter.is_empty() {
            all_device_keys
        } else {
            all_device_keys
                .into_iter()
                .filter(|(did, _)| device_filter.contains(did))
                .collect()
        };

        // Attach cross-signing signatures to device keys.
        // (Spec: server merges uploaded signatures into the device key objects.)
        // For simplicity we return device keys as-is; signatures endpoint (mrm.9)
        // stores them separately. A full implementation would merge here.
        // TODO: merge cross-signing signatures into returned device keys.

        if !user_keys.is_empty() {
            result_device_keys.insert(uid.clone(), json!(user_keys));
        }

        // Fetch cross-signing keys.
        let xsk = match storage.get_cross_signing_keys(uid).await {
            Ok(m) => m,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        };
        if let Some(mk) = xsk.get("master") {
            result_master_keys.insert(uid.clone(), mk.clone());
        }
        if let Some(ss) = xsk.get("self_signing") {
            result_self_signing.insert(uid.clone(), ss.clone());
        }
        if let Some(us) = xsk.get("user_signing") {
            result_user_signing.insert(uid.clone(), us.clone());
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
    _authed: AuthedUser,
    Query(query): Query<KeysChangesQuery>,
) -> Response {
    let storage = state.storage();

    // Parse device-list stream position from token.
    let since_pos: i64 = query
        .from
        .as_deref()
        .and_then(parse_device_pos_from_token)
        .unwrap_or(0);

    let changed = match storage.device_list_changes_since(since_pos).await {
        Ok(v) => v,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };

    (
        StatusCode::OK,
        Json(json!({ "changed": changed, "left": [] })),
    )
        .into_response()
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
    Json(body): Json<SendToDeviceBody>,
) -> Response {
    let storage = state.storage();
    let sender = &authed.user_id;

    // Bucket targets by server: local goes straight to the to-device queue;
    // remote dests are aggregated and dispatched through the federation
    // /sendToDevice endpoint (conduit-0t6).
    let mut remote_by_server: HashMap<String, HashMap<String, HashMap<String, Value>>> =
        HashMap::new();

    for (target_user, devices) in &body.messages {
        let target_server = target_user.split(':').nth(1).unwrap_or("");
        if target_server == state.server_name() {
            for (target_device, content) in devices {
                if let Err(e) = storage
                    .enqueue_to_device(target_user, target_device, sender, &event_type, content)
                    .await
                {
                    return MatrixError::unknown(e.to_string()).into_response();
                }
            }
        } else {
            let per_server = remote_by_server
                .entry(target_server.to_owned())
                .or_default();
            per_server
                .entry(target_user.clone())
                .or_default()
                .extend(devices.iter().map(|(d, c)| (d.clone(), c.clone())));
        }
    }

    if !remote_by_server.is_empty() {
        if let Some(client) = state.federation_client().cloned() {
            let event_type = event_type.clone();
            let txn_id = txn_id.clone();
            // Fire-and-forget per-server delivery. Federation errors are
            // logged but not surfaced — to-device is best-effort and the
            // remote may retry via /sync after device-list churn.
            // Follow-up: replace tokio::spawn with the durable PG-backed
            // outbound queue (conduit-5n3) so messages survive restart and
            // get retry-with-DLQ semantics.
            tokio::spawn(async move {
                for (dest, messages_for_server) in remote_by_server {
                    let messages_json = serde_json::to_value(&messages_for_server)
                        .unwrap_or_else(|_| json!({}));
                    if let Err(e) = client
                        .send_to_device(&dest, &txn_id, &event_type, messages_json)
                        .await
                    {
                        tracing::warn!(dest, error = %e, "federation /sendToDevice failed");
                    }
                }
            });
        } else {
            tracing::debug!(
                "remote sendToDevice requested but no federation client available"
            );
        }
    }

    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/keys/device_signing/upload  (mrm.8)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeviceSigningUploadRequest {
    #[serde(default)]
    pub master_key: Option<Value>,
    #[serde(default)]
    pub self_signing_key: Option<Value>,
    #[serde(default)]
    pub user_signing_key: Option<Value>,
}

pub async fn device_signing_upload<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<DeviceSigningUploadRequest>,
) -> Response {
    let storage = state.storage();
    let user_id = &authed.user_id;

    if let Some(mk) = &body.master_key {
        if let Err(e) = storage.upsert_cross_signing_key(user_id, "master", mk).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }
    if let Some(ss) = &body.self_signing_key {
        if let Err(e) = storage.upsert_cross_signing_key(user_id, "self_signing", ss).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }
    if let Some(us) = &body.user_signing_key {
        if let Err(e) = storage.upsert_cross_signing_key(user_id, "user_signing", us).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }

    // Record device list change so peers see updated cross-signing keys.
    let stream_id = storage.record_device_list_change(user_id).await.unwrap_or(0);
    // Federate an m.device_list_update EDU. Cross-signing key changes
    // surface as a device-less device_list_update (the EDU carries no
    // device_id-specific keys field — remotes re-query). (conduit-6r1)
    broadcast_device_list_update(&state, user_id, "", stream_id, None).await;

    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/keys/signatures/upload  (mrm.9)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SignaturesUploadRequest {
    /// { user_id: { key_id: { ...key with signatures } } }
    #[serde(default)]
    pub signatures: HashMap<String, HashMap<String, Value>>,
}

pub async fn signatures_upload<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<SignaturesUploadRequest>,
) -> Response {
    let storage = state.storage();
    let _signer_user = &authed.user_id;

    let mut failures: HashMap<String, Value> = HashMap::new();

    for (target_user, keys) in &body.signatures {
        for (target_key_id, key_obj) in keys {
            // Extract signatures from the key object.
            let sigs = match key_obj.get("signatures").and_then(|s| s.as_object()) {
                Some(s) => s.clone(),
                None => {
                    failures.insert(
                        format!("{target_user}/{target_key_id}"),
                        json!({ "errcode": "M_INVALID_SIGNATURE", "error": "no signatures field" }),
                    );
                    continue;
                }
            };

            for (signer_user_id, signer_keys) in &sigs {
                let signer_keys = match signer_keys.as_object() {
                    Some(s) => s.clone(),
                    None => continue,
                };
                for (signer_key_id, sig_val) in &signer_keys {
                    let sig = match sig_val.as_str() {
                        Some(s) => s.to_owned(),
                        None => continue,
                    };
                    if let Err(e) = storage
                        .insert_cross_signing_signature(
                            signer_user_id,
                            signer_key_id,
                            target_user,
                            target_key_id,
                            &sig,
                        )
                        .await
                    {
                        failures.insert(
                            format!("{target_user}/{target_key_id}"),
                            json!({ "errcode": "M_UNKNOWN", "error": e.to_string() }),
                        );
                    }
                }
            }
        }
    }

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
