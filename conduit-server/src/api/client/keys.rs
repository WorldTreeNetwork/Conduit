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

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{Value, json};

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
        let _ = storage.record_device_list_change(user_id).await;
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
    Path((event_type, _txn_id)): Path<(String, String)>,
    Json(body): Json<SendToDeviceBody>,
) -> Response {
    let storage = state.storage();
    let sender = &authed.user_id;

    for (target_user, devices) in &body.messages {
        let target_server = target_user.split(':').nth(1).unwrap_or("");
        if target_server == state.server_name() {
            // Local delivery.
            for (target_device, content) in devices {
                if let Err(e) = storage
                    .enqueue_to_device(target_user, target_device, sender, &event_type, content)
                    .await
                {
                    return MatrixError::unknown(e.to_string()).into_response();
                }
            }
        } else {
            // Remote delivery: enqueue via federation. Best-effort for now.
            // TODO: route through federation queue (mrm.10 outbound path).
            tracing::debug!(
                target_user = %target_user,
                "to-device for remote user — federation outbound not yet wired"
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
    let _ = storage.record_device_list_change(user_id).await;

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
