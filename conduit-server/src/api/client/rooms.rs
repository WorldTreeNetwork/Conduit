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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use conduit::room::{CreateRoomInitialState, CreateRoomParams, Room};
use conduit::state_events::{Membership, parse_member};

use super::{AuthState, AuthedUser, MatrixError};
use super::event_pipeline::RoomEventSenderWrapper;

// ---------------------------------------------------------------------------
// Room ID generation
// ---------------------------------------------------------------------------

/// Generate a new random room ID: `!{18 url-safe base64 chars}:{server_name}`.
pub fn generate_room_id(server_name: &str) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rand::RngCore;
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

    // Build create-room parameters.
    let params = CreateRoomParams {
        name: body.name.as_deref(),
        topic: body.topic.as_deref(),
        initial_state: body.initial_state.into_iter().map(|ev| CreateRoomInitialState {
            event_type: ev.event_type,
            state_key: ev.state_key,
            content: ev.content,
        }).collect(),
        power_level_content_override: body.power_level_content_override.clone(),
    };

    // Delegate room creation to the Room struct.
    if let Err(e) = Room::create(
        sender, &room_id, &room_version, join_rule, history_visibility, &params,
        &RoomEventSenderWrapper(&state),
    ).await {
        return MatrixError::unknown(e.to_string()).into_response();
    }

    // Invite users listed in `invite`.
    for invitee in &body.invite {
        let room = Room::new(&room_id);
        let is_direct = body.is_direct.unwrap_or(false);
        if let Err(e) = room.invite(sender, invitee, is_direct, &RoomEventSenderWrapper(&state)).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }

    // Bind alias if `room_alias_name` was supplied.
    if let Some(alias_name) = body.room_alias_name.as_deref() {
        let alias = format!("#{alias_name}:{}", state.server_name());
        if let Err(e) = state
            .storage()
            .upsert_alias(&alias, &room_id, sender)
            .await
        {
            // Alias collision is non-fatal per spec — log and continue.
            tracing::warn!(
                room_id,
                alias,
                error = %e,
                "createRoom: room_alias_name binding failed"
            );
        }
    }

    (StatusCode::OK, Json(CreateRoomResponse { room_id })).into_response()
}

/// Return `(join_rule, history_visibility)` based on preset/visibility.
/// Delegated to `conduit::room::resolve_preset`.
fn resolve_preset(body: &CreateRoomRequest) -> (&'static str, &'static str) {
    conduit::room::resolve_preset(body.preset.as_deref(), body.visibility.as_deref())
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

    // Resolve aliases starting with '#' against the local directory.
    let room_id = if room_id_or_alias.starts_with('#') {
        match state.storage().get_room_for_alias(&room_id_or_alias).await {
            Ok(Some(rid)) => rid,
            Ok(None) => {
                return (StatusCode::NOT_FOUND, Json(json!({
                    "errcode": "M_NOT_FOUND",
                    "error": "Room alias not found",
                }))).into_response();
            }
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        }
    } else {
        room_id_or_alias
    };

    let room = Room::new(&room_id);
    match room.join(sender, &RoomEventSenderWrapper(&state)).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "room_id": room_id }))).into_response(),
        Err(e) => MatrixError::from_conduit(e).into_response(),
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
    Json(body): Json<LeaveRequest>,
) -> Response {
    let sender = &authed.user_id;
    let room = Room::new(&room_id);
    match room.leave(sender, body.reason.as_deref(), &RoomEventSenderWrapper(&state)).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::from_conduit(e).into_response(),
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
    let room = Room::new(&room_id);
    match room.kick(sender, &body.user_id, body.reason.as_deref(), &RoomEventSenderWrapper(&state)).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::from_conduit(e).into_response(),
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
    let room = Room::new(&room_id);
    match room.ban(sender, &body.user_id, body.reason.as_deref(), &RoomEventSenderWrapper(&state)).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::from_conduit(e).into_response(),
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
    let room = Room::new(&room_id);
    match room.unban(sender, &body.user_id, &RoomEventSenderWrapper(&state)).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::from_conduit(e).into_response(),
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
    let room = Room::new(&room_id);
    match room.invite(sender, &body.user_id, false, &RoomEventSenderWrapper(&state)).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::from_conduit(e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /rooms/:roomId/send/:eventType/:txnId
// ---------------------------------------------------------------------------

pub async fn send_message_event<S: AuthState + conduit::room::RoomEventSender>(
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

    let room = Room::new(&room_id);
    match room.send_event(sender, &event_type, content, &RoomEventSenderWrapper(&state)).await {
        Ok(event_id) => {
            // Store in txn cache.
            let mut cache = state.txn_cache().write().await;
            cache.insert(cache_key, event_id.clone());
            (StatusCode::OK, Json(json!({ "event_id": event_id }))).into_response()
        }
        Err(e) => MatrixError::from_conduit(e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /rooms/:roomId/state/:eventType  (empty state_key)
// PUT /rooms/:roomId/state/:eventType/:stateKey
// ---------------------------------------------------------------------------

pub async fn send_state_event<S: AuthState + conduit::room::RoomEventSender>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_type)): Path<(String, String)>,
    Json(content): Json<Value>,
) -> Response {
    send_state_event_inner(&state, &authed.user_id, &room_id, &event_type, "", content).await
}

pub async fn send_state_event_with_key<S: AuthState + conduit::room::RoomEventSender>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_type, state_key)): Path<(String, String, String)>,
    Json(content): Json<Value>,
) -> Response {
    send_state_event_inner(&state, &authed.user_id, &room_id, &event_type, &state_key, content).await
}

async fn send_state_event_inner<S: AuthState + conduit::room::RoomEventSender>(
    state: &S,
    sender: &str,
    room_id: &str,
    event_type: &str,
    state_key: &str,
    content: Value,
) -> Response {
    let room = Room::new(room_id);
    match room.send_state_event(sender, event_type, state_key, content, &RoomEventSenderWrapper(state)).await {
        Ok(event_id) => (StatusCode::OK, Json(json!({ "event_id": event_id }))).into_response(),
        Err(e) => MatrixError::from_conduit(e).into_response(),
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
    let room = Room::new(&room_id);
    match room.current_state_vec(state.storage().as_ref()).await {
        Ok(events) => {
            let values: Vec<Value> = events.into_iter().map(|e| serde_json::to_value(e).unwrap_or(Value::Null)).collect();
            (StatusCode::OK, Json(values)).into_response()
        }
        Err(e) => MatrixError::from_conduit(e).into_response(),
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
    let room = Room::new(&room_id);
    match room.get_state_entry(&event_type, &state_key, state.storage().as_ref()).await {
        Ok(Some(ev)) => (StatusCode::OK, Json(ev.content)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "errcode": "M_NOT_FOUND", "error": "State event not found" })),
        ).into_response(),
        Err(e) => MatrixError::from_conduit(e).into_response(),
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
    let room = Room::new(&room_id);
    let state_events = match room.current_state_vec(state.storage().as_ref()).await {
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
        Err(e) => MatrixError::from_conduit(e).into_response(),
    }
}
