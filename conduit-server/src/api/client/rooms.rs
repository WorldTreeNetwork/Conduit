//! Room-related Client-Server API handlers.
//!
//! Implements:
//!   POST   /_matrix/client/v3/createRoom
//!   POST   /_matrix/client/v3/join/:roomIdOrAlias
//!   POST   /_matrix/client/v3/rooms/:roomId/leave
//!   POST   /_matrix/client/v3/rooms/:roomId/kick
//!   POST   /_matrix/client/v3/rooms/:roomId/ban
//!   POST   /_matrix/client/v3/rooms/:roomId/unban
//!   POST   /_matrix/client/v3/rooms/:roomId/invite
//!   PUT    /_matrix/client/v3/rooms/:roomId/send/:eventType/:txnId
//!   PUT    /_matrix/client/v3/rooms/:roomId/state/:eventType
//!   PUT    /_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey
//!   GET    /_matrix/client/v3/rooms/:roomId/state
//!   GET    /_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey
//!   GET    /_matrix/client/v3/rooms/:roomId/joined_members
//!   GET    /_matrix/client/v3/rooms/:roomId/messages

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use conduit::state_events::{Membership, parse_member};

use super::{AuthState, AuthedUser, MatrixError};
use super::event_pipeline::build_sign_and_persist;

// ---------------------------------------------------------------------------
// Room ID generation
// ---------------------------------------------------------------------------

/// Generate a new random room ID: `!{18 url-safe-base64 chars}:{server_name}`.
fn generate_room_id(server_name: &str) -> String {
    let mut bytes = [0u8; 14]; // 14 bytes → 18 base64 chars (ceil(14*8/6))
    rand::thread_rng().fill_bytes(&mut bytes);
    let random = URL_SAFE_NO_PAD.encode(bytes);
    // Trim to exactly 18 chars
    let random = &random[..18.min(random.len())];
    format!("!{random}:{server_name}")
}

// ---------------------------------------------------------------------------
// POST /createRoom
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct CreateRoomRequest {
    /// `"public"` or `"private"` (affects join_rules / history_visibility).
    pub visibility: Option<String>,
    /// Preset overrides visibility: `"public_chat"`, `"private_chat"`,
    /// `"trusted_private_chat"`.
    pub preset: Option<String>,
    pub name: Option<String>,
    pub topic: Option<String>,
    /// Extra state events to inject after the standard initial state.
    #[serde(default)]
    pub initial_state: Vec<InitialStateEvent>,
    /// User IDs to invite immediately after creation.
    #[serde(default)]
    pub invite: Vec<String>,
    pub room_alias_name: Option<String>,
    pub is_direct: Option<bool>,
    pub room_version: Option<String>,
    pub power_level_content_override: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct InitialStateEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub state_key: Option<String>,
    pub content: Value,
}

#[derive(Debug, Serialize)]
pub struct CreateRoomResponse {
    pub room_id: String,
}

pub async fn create_room<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<CreateRoomRequest>,
) -> Response {
    let sender = &authed.user_id;
    let server_name = state.server_name().to_owned();

    let room_id = generate_room_id(&server_name);
    let room_version = body.room_version.clone().unwrap_or_else(|| "11".to_owned());

    // Determine join_rule and history_visibility from preset / visibility.
    let (join_rule, history_visibility) = resolve_preset(&body);

    // -----------------------------------------------------------------------
    // 1. m.room.create
    // -----------------------------------------------------------------------
    let create_content = json!({
        "room_version": room_version,
        "creator": sender,
    });
    if let Err(e) = build_sign_and_persist(
        &state, sender, &room_id, "m.room.create", Some(""), create_content,
    ).await {
        return e.into_response();
    }

    // -----------------------------------------------------------------------
    // 2. m.room.member — creator joins
    // -----------------------------------------------------------------------
    let join_content = json!({ "membership": "join" });
    if let Err(e) = build_sign_and_persist(
        &state, sender, &room_id, "m.room.member", Some(sender.as_str()), join_content,
    ).await {
        return e.into_response();
    }

    // -----------------------------------------------------------------------
    // 3. m.room.power_levels
    // -----------------------------------------------------------------------
    let mut pl_users = serde_json::Map::new();
    pl_users.insert(sender.clone(), json!(100));

    let default_pl_content = json!({
        "ban": 50,
        "kick": 50,
        "redact": 50,
        "invite": 50,
        "events_default": 0,
        "state_default": 50,
        "users_default": 0,
        "users": pl_users,
        "events": {}
    });
    let pl_content = if let Some(override_pl) = body.power_level_content_override.clone() {
        // Merge override on top of defaults.
        let mut base = default_pl_content.clone();
        if let (Some(b), Some(o)) = (base.as_object_mut(), override_pl.as_object()) {
            for (k, v) in o {
                b.insert(k.clone(), v.clone());
            }
        }
        base
    } else {
        default_pl_content
    };

    if let Err(e) = build_sign_and_persist(
        &state, sender, &room_id, "m.room.power_levels", Some(""), pl_content,
    ).await {
        return e.into_response();
    }

    // -----------------------------------------------------------------------
    // 4. m.room.join_rules
    // -----------------------------------------------------------------------
    let jr_content = json!({ "join_rule": join_rule });
    if let Err(e) = build_sign_and_persist(
        &state, sender, &room_id, "m.room.join_rules", Some(""), jr_content,
    ).await {
        return e.into_response();
    }

    // -----------------------------------------------------------------------
    // 5. m.room.history_visibility
    // -----------------------------------------------------------------------
    let hv_content = json!({ "history_visibility": history_visibility });
    if let Err(e) = build_sign_and_persist(
        &state, sender, &room_id, "m.room.history_visibility", Some(""), hv_content,
    ).await {
        return e.into_response();
    }

    // -----------------------------------------------------------------------
    // 6. Optional name / topic
    // -----------------------------------------------------------------------
    if let Some(name) = &body.name {
        let content = json!({ "name": name });
        if let Err(e) = build_sign_and_persist(
            &state, sender, &room_id, "m.room.name", Some(""), content,
        ).await {
            return e.into_response();
        }
    }
    if let Some(topic) = &body.topic {
        let content = json!({ "topic": topic });
        if let Err(e) = build_sign_and_persist(
            &state, sender, &room_id, "m.room.topic", Some(""), content,
        ).await {
            return e.into_response();
        }
    }

    // -----------------------------------------------------------------------
    // 7. initial_state entries supplied by client
    // -----------------------------------------------------------------------
    for ev in &body.initial_state {
        let sk = ev.state_key.as_deref().unwrap_or("");
        if let Err(e) = build_sign_and_persist(
            &state, sender, &room_id, &ev.event_type, Some(sk), ev.content.clone(),
        ).await {
            return e.into_response();
        }
    }

    // -----------------------------------------------------------------------
    // 8. Invite users listed in `invite`
    // -----------------------------------------------------------------------
    for invitee in &body.invite {
        let is_direct = body.is_direct.unwrap_or(false);
        let invite_content = json!({
            "membership": "invite",
            "is_direct": is_direct
        });
        if let Err(e) = build_sign_and_persist(
            &state, sender, &room_id, "m.room.member", Some(invitee.as_str()),
            invite_content,
        ).await {
            return e.into_response();
        }
    }

    (StatusCode::OK, Json(CreateRoomResponse { room_id })).into_response()
}

/// Return `(join_rule, history_visibility)` based on preset/visibility.
fn resolve_preset(body: &CreateRoomRequest) -> (&'static str, &'static str) {
    match body.preset.as_deref() {
        Some("public_chat") => ("public", "shared"),
        Some("trusted_private_chat") => ("invite", "shared"),
        Some("private_chat") => ("invite", "invited"),
        _ => match body.visibility.as_deref() {
            Some("public") => ("public", "shared"),
            _ => ("invite", "invited"),
        },
    }
}

// ---------------------------------------------------------------------------
// POST /join/:roomIdOrAlias
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct JoinRequest {
    pub reason: Option<String>,
}

pub async fn join_room<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id_or_alias): Path<String>,
    Json(_body): Json<JoinRequest>,
) -> Response {
    let sender = &authed.user_id;
    // v0: local rooms only — treat the path param as a room_id directly.
    let room_id = room_id_or_alias;

    let join_content = json!({ "membership": "join" });
    match build_sign_and_persist(
        &state, sender, &room_id, "m.room.member", Some(sender.as_str()), join_content,
    ).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "room_id": room_id }))).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /rooms/:roomId/leave
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct LeaveRequest {
    pub reason: Option<String>,
}

pub async fn leave_room<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Json(_body): Json<LeaveRequest>,
) -> Response {
    let sender = &authed.user_id;
    let leave_content = json!({ "membership": "leave" });
    match build_sign_and_persist(
        &state, sender, &room_id, "m.room.member", Some(sender.as_str()), leave_content,
    ).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /rooms/:roomId/kick
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct KickRequest {
    pub user_id: String,
    pub reason: Option<String>,
}

pub async fn kick_user<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Json(body): Json<KickRequest>,
) -> Response {
    let sender = &authed.user_id;
    let mut content = json!({ "membership": "leave" });
    if let Some(reason) = &body.reason {
        content["reason"] = json!(reason);
    }
    match build_sign_and_persist(
        &state, sender, &room_id, "m.room.member", Some(body.user_id.as_str()), content,
    ).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /rooms/:roomId/ban
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct BanRequest {
    pub user_id: String,
    pub reason: Option<String>,
}

pub async fn ban_user<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Json(body): Json<BanRequest>,
) -> Response {
    let sender = &authed.user_id;
    let mut content = json!({ "membership": "ban" });
    if let Some(reason) = &body.reason {
        content["reason"] = json!(reason);
    }
    match build_sign_and_persist(
        &state, sender, &room_id, "m.room.member", Some(body.user_id.as_str()), content,
    ).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /rooms/:roomId/unban
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UnbanRequest {
    pub user_id: String,
    pub reason: Option<String>,
}

pub async fn unban_user<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Json(body): Json<UnbanRequest>,
) -> Response {
    let sender = &authed.user_id;
    // Unban = set membership back to leave.
    let content = json!({ "membership": "leave" });
    match build_sign_and_persist(
        &state, sender, &room_id, "m.room.member", Some(body.user_id.as_str()), content,
    ).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /rooms/:roomId/invite
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct InviteRequest {
    pub user_id: String,
    pub reason: Option<String>,
}

pub async fn invite_user<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Json(body): Json<InviteRequest>,
) -> Response {
    let sender = &authed.user_id;
    let content = json!({ "membership": "invite" });
    match build_sign_and_persist(
        &state, sender, &room_id, "m.room.member", Some(body.user_id.as_str()), content,
    ).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /rooms/:roomId/send/:eventType/:txnId
// ---------------------------------------------------------------------------

pub async fn send_message_event<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_type, txn_id)): Path<(String, String, String)>,
    Json(content): Json<Value>,
) -> Response {
    let sender = &authed.user_id;
    let device_id = &authed.device_id;

    // Idempotency: check the txn cache.
    let cache_key = (sender.clone(), device_id.clone(), txn_id.clone());
    {
        let cache = state.txn_cache().read().await;
        if let Some(cached_event_id) = cache.get(&cache_key) {
            return (StatusCode::OK, Json(json!({ "event_id": cached_event_id }))).into_response();
        }
    }

    match build_sign_and_persist(
        &state, sender, &room_id, &event_type,
        None, // message events have no state_key
        content,
    ).await {
        Ok(event_id) => {
            // Store in txn cache.
            let mut cache = state.txn_cache().write().await;
            cache.insert(cache_key, event_id.clone());
            (StatusCode::OK, Json(json!({ "event_id": event_id }))).into_response()
        }
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /rooms/:roomId/state/:eventType  (empty state_key)
// PUT /rooms/:roomId/state/:eventType/:stateKey
// ---------------------------------------------------------------------------

pub async fn send_state_event<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_type)): Path<(String, String)>,
    Json(content): Json<Value>,
) -> Response {
    send_state_event_inner(&state, &authed.user_id, &room_id, &event_type, "", content).await
}

pub async fn send_state_event_with_key<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_type, state_key)): Path<(String, String, String)>,
    Json(content): Json<Value>,
) -> Response {
    send_state_event_inner(&state, &authed.user_id, &room_id, &event_type, &state_key, content).await
}

async fn send_state_event_inner<S: AuthState>(
    state: &S,
    sender: &str,
    room_id: &str,
    event_type: &str,
    state_key: &str,
    content: Value,
) -> Response {
    match build_sign_and_persist(state, sender, room_id, event_type, Some(state_key), content).await {
        Ok(event_id) => (StatusCode::OK, Json(json!({ "event_id": event_id }))).into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /rooms/:roomId/state
// ---------------------------------------------------------------------------

pub async fn get_room_state<S: AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path(room_id): Path<String>,
) -> Response {
    match state.storage().get_current_state(&room_id).await {
        Ok(events) => {
            let values: Vec<Value> = events.into_iter().map(|e| serde_json::to_value(e).unwrap_or(Value::Null)).collect();
            (StatusCode::OK, Json(values)).into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /rooms/:roomId/state/:eventType           (empty state_key)
// GET /rooms/:roomId/state/:eventType/:stateKey
// ---------------------------------------------------------------------------

/// GET the content of a state event with an empty state_key.
pub async fn get_state_event_no_key<S: AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path((room_id, event_type)): Path<(String, String)>,
) -> Response {
    get_state_event_inner(state, room_id, event_type, String::new()).await
}

/// GET the content of a state event with an explicit state_key.
pub async fn get_state_event<S: AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path((room_id, event_type, state_key)): Path<(String, String, String)>,
) -> Response {
    get_state_event_inner(state, room_id, event_type, state_key).await
}

async fn get_state_event_inner<S: AuthState>(
    state: S,
    room_id: String,
    event_type: String,
    state_key: String,
) -> Response {
    match state.storage().get_state_entry(&room_id, &event_type, &state_key).await {
        Ok(Some(ev)) => (StatusCode::OK, Json(ev.content)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "errcode": "M_NOT_FOUND", "error": "State event not found" })),
        ).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /rooms/:roomId/joined_members
// ---------------------------------------------------------------------------

pub async fn joined_members<S: AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path(room_id): Path<String>,
) -> Response {
    let storage = state.storage();
    let state_events = match storage.get_current_state(&room_id).await {
        Ok(evs) => evs,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };

    let mut joined: HashMap<String, Value> = HashMap::new();
    for ev in &state_events {
        if ev.event_type == "m.room.member" {
            let user_id = match &ev.state_key {
                Some(sk) => sk.clone(),
                None => continue,
            };
            if let Ok(mc) = parse_member(&ev.content) {
                if mc.membership == Membership::Join {
                    let mut member_info = serde_json::Map::new();
                    if let Some(dn) = mc.displayname {
                        member_info.insert("display_name".to_owned(), json!(dn));
                    } else {
                        member_info.insert("display_name".to_owned(), Value::Null);
                    }
                    if let Some(av) = mc.avatar_url {
                        member_info.insert("avatar_url".to_owned(), json!(av));
                    } else {
                        member_info.insert("avatar_url".to_owned(), Value::Null);
                    }
                    joined.insert(user_id, Value::Object(member_info));
                }
            }
        }
    }

    (StatusCode::OK, Json(json!({ "joined": joined }))).into_response()
}

// ---------------------------------------------------------------------------
// GET /rooms/:roomId/messages
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct MessagesQuery {
    /// Pagination direction: `"b"` (backwards) or `"f"` (forwards).
    pub dir: Option<String>,
    /// Start token (stream_position as string).
    pub from: Option<String>,
    /// Maximum number of events to return (default 10).
    pub limit: Option<i64>,
}

pub async fn get_messages<S: AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path(room_id): Path<String>,
    Query(query): Query<MessagesQuery>,
) -> Response {
    let storage = state.storage();
    let dir = query.dir.as_deref().unwrap_or("b");
    let dir_char = if dir == "f" { 'f' } else { 'b' };
    let limit = query.limit.unwrap_or(10).max(1).min(100);

    // Determine start position.
    let from: i64 = if let Some(token) = &query.from {
        token.parse::<i64>().unwrap_or(0)
    } else {
        match dir_char {
            'b' => {
                // Start from the most recent event.
                match storage.room_latest_stream_position(&room_id).await {
                    Ok(Some(pos)) => pos,
                    Ok(None) => {
                        return (StatusCode::OK, Json(json!({ "chunk": [], "start": "0", "end": "0" }))).into_response();
                    }
                    Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
                }
            }
            _ => 0,
        }
    };

    match storage.room_events_paginated(&room_id, dir_char, from, limit).await {
        Ok((events, next_pos)) => {
            let chunk: Vec<Value> = events
                .into_iter()
                .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
                .collect();
            let end_token = next_pos.map(|p| p.to_string()).unwrap_or_default();
            (
                StatusCode::OK,
                Json(json!({
                    "chunk": chunk,
                    "start": from.to_string(),
                    "end": end_token
                })),
            ).into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}
