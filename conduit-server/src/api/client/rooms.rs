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

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use conduit::filter::RoomEventFilter;
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
    /// Third-party invites (`Invite3pid` objects) issued after creation.
    #[serde(default)]
    pub invite_3pid: Vec<Value>,
    pub room_alias_name: Option<String>,
    pub is_direct: Option<bool>,
    pub room_version: Option<String>,
    pub power_level_content_override: Option<Value>,
    /// Extra keys for the `m.room.create` content (e.g. `type: m.space`).
    pub creation_content: Option<Value>,
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

    let room_version = body.room_version.clone().unwrap_or_else(|| conduit::ROOM_VERSION.to_owned());
    let room_id = if conduit::room_version::parse(&room_version).is_some_and(|version| version >= 12) {
        String::new()
    } else {
        generate_room_id(&server_name)
    };

    // Preset state: join rule, history visibility, guest access.
    let preset = resolve_preset(&body);

    // The requested alias must be free before anything is created
    // (`400 M_ROOM_IN_USE`), per the createRoom spec.
    let alias = match body.room_alias_name.as_deref() {
        None => None,
        Some(name) if name.is_empty() || name.contains(':') || name.chars().any(char::is_whitespace) => {
            return (StatusCode::BAD_REQUEST, Json(json!({
                "errcode": "M_INVALID_PARAM",
                "error": "room_alias_name must be a non-empty localpart",
            }))).into_response();
        }
        Some(name) => {
            let alias = format!("#{name}:{server_name}");
            if let Some(refusal) = super::appservice_auth::alias_exclusivity_error(&state, &authed, &alias) {
                return refusal;
            }
            match state.storage().get_room_for_alias(&alias).await {
                Ok(None) => Some(alias),
                Ok(Some(_)) => {
                    return (StatusCode::BAD_REQUEST, Json(json!({
                        "errcode": "M_ROOM_IN_USE",
                        "error": "Room alias already taken",
                    }))).into_response();
                }
                Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
            }
        }
    };
    let publish = body.visibility.as_deref() == Some("public");

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
        creation_content: body.creation_content.clone(),
        guest_access: Some(preset.guest_access.to_owned()),
        canonical_alias: alias.clone(),
        invite: body.invite.clone(),
        trusted_private_chat: preset.trusted_private_chat,
    };

    // Delegate room creation to the Room struct.
    let room_id = match Room::create(
        sender, &room_id, &room_version, preset.join_rule, preset.history_visibility, &params,
        &RoomEventSenderWrapper(&state),
    ).await {
        Ok(room) => room.room_id,
        Err(e) => return MatrixError::from_conduit(e).into_response(),
    };

    // Invite blocking (v1.18): refuse before anything is created.
    for invitee in &body.invite {
        if let Err(blocked) = super::room_membership::check_invite_allowed(&state, invitee).await {
            return blocked;
        }
    }

    // Invite users listed in `invite`.
    for invitee in &body.invite {
        let room = Room::new(&room_id);
        let is_direct = body.is_direct.unwrap_or(false);
        if let Err(e) = room.invite(sender, invitee, is_direct, &RoomEventSenderWrapper(&state)).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }

    // `invite_3pid`: third-party invites through the identity server
    // (conduit-y99.36), after the alias so store-invite can name it.
    for invite in &body.invite_3pid {
        if let Err(r) = super::third_party::invite_by_3pid(&state, sender, &room_id, invite).await {
            return r;
        }
    }

    // `visibility: public` publishes the room in the room directory.
    if publish {
        if let Err(e) = state.storage().set_room_published(&room_id, true).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }

    (StatusCode::OK, Json(CreateRoomResponse { room_id })).into_response()
}

/// Preset state from the createRoom body.
fn resolve_preset(body: &CreateRoomRequest) -> conduit::room::RoomPreset {
    conduit::room::resolve_preset(body.preset.as_deref(), body.visibility.as_deref())
}

// ---------------------------------------------------------------------------
// POST /join/:roomIdOrAlias
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct JoinRequest {
    pub reason: Option<String>,
    /// Identity-server signature of a pending `m.room.third_party_invite`.
    /// Kept as raw JSON so the signed bytes stay intact.
    #[serde(default)]
    pub third_party_signed: Option<Value>,
}

pub async fn join_room<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id_or_alias): Path<String>,
    Json(body): Json<JoinRequest>,
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

    // Key validity is not an auth-rule check: other servers must still accept
    // the membership. Only the resident server, and only when this join is
    // authorised by `third_party_signed`, fetches `key_validity_url`.
    if let Some(signed) = body.third_party_signed.as_ref() {
        if let Err(response) = super::third_party::accept_third_party_join(&state, sender, &room_id, signed).await {
            return response;
        }
    }

    let room = Room::new(&room_id);
    match room.join_with_reason(sender, body.reason.as_deref(), &RoomEventSenderWrapper(&state)).await {
        Ok(_) => {
            if let Ok(Some(create)) = state.storage().get_state_entry(&room_id, "m.room.create", "").await {
                if let Some(old_room) = create.content.get("predecessor").and_then(|p| p.get("room_id")).and_then(Value::as_str) {
                    super::room_content::upgrade::copy_personal_settings(
                        state.storage().as_ref(),
                        sender,
                        old_room,
                        &room_id,
                    )
                    .await;
                }
            }
            if let Some(queue) = state.federation_queue() {
                super::keys::publish_device_lists_after_join(
                    state.storage(),
                    queue,
                    state.server_name(),
                    &room_id,
                    sender,
                )
                .await;
            }
            (StatusCode::OK, Json(json!({ "room_id": room_id }))).into_response()
        }
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
    match room.unban_with_reason(sender, &body.user_id, body.reason.as_deref(), &RoomEventSenderWrapper(&state)).await {
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
    Json(raw): Json<Value>,
) -> Response {
    let sender = &authed.user_id;
    // Third-party form: id_server / id_access_token / medium / address.
    if super::third_party::is_3pid_invite(&raw) {
        return match super::third_party::invite_by_3pid(&state, sender, &room_id, &raw).await {
            Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
            Err(r) => r,
        };
    }
    let body: InviteRequest = match serde_json::from_value(raw) {
        Ok(b) => b,
        Err(e) => return MatrixError::bad_json(e.to_string()).into_response(),
    };
    if let Err(blocked) = super::room_membership::check_invite_allowed(&state, &body.user_id).await {
        return blocked;
    }
    // A server denied by m.room.server_acl cannot be invited into the room.
    // The check is local so it fails before any outbound federation.
    if let Some(server_name) = conduit::signing::server_of_user_id(&body.user_id) {
        match conduit::server_acl::server_allowed_by_room(state.storage().as_ref(), &room_id, server_name).await {
            Ok(false) => {
                return MatrixError::forbidden("Server is denied access to this room by the server ACL").into_response();
            }
            Ok(true) => {}
            Err(error) => return MatrixError::from_conduit(error).into_response(),
        }
    }
    let room = Room::new(&room_id);
    match room.invite_with_reason(sender, &body.user_id, false, body.reason.as_deref(), &RoomEventSenderWrapper(&state)).await {
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
    request: axum::extract::Request,
) -> Response {
    let key = conduit::storage::TransactionKey::client(
        &authed.user_id,
        &authed.device_id,
        &["room_send", &room_id, &event_type],
        &txn_id,
    );
    let mut replay = match crate::replay::Replay::start(state.storage().clone(), key.clone()).await
    {
        Ok(crate::replay::Start::Cached(response)) => return response,
        Ok(crate::replay::Start::Execute(replay)) => replay,
        Err(error) => return error,
    };
    let content = match replay.body(request).await {
        Ok(body) => body,
        Err(error) => return error,
    };
    if !content.is_object() || conduit::canonical_json::to_canonical_bytes(&content).is_err() {
        return replay.finish(StatusCode::BAD_REQUEST, json!({"errcode": "M_BAD_JSON", "error": "event content must be a canonical JSON object"})).await;
    }
    // Redactions sent through /send obey the /redact permission rules.
    if event_type == "m.room.redaction" {
        let Some(target) = content.get("redacts").and_then(Value::as_str) else {
            return replay.finish(StatusCode::BAD_REQUEST, json!({"errcode": "M_BAD_JSON", "error": "m.room.redaction requires content.redacts"})).await;
        };
        if let Err((code, body)) = super::room_content::redact::authorize_redaction(&state, &authed.user_id, &room_id, target).await {
            return replay.finish(code, body).await;
        }
    }
    if let Err((code, body)) = super::room_content::relations::validate_outgoing(&state, &authed.user_id, &room_id, &event_type, &content).await {
        // Replay derives a stored reply's status from its errcode, which
        // would turn the spec's 400 M_UNKNOWN into a 500; that rejection is
        // deterministic, so it is answered without freezing the transaction.
        if body["errcode"] == "M_UNKNOWN" {
            return (code, Json(body)).into_response();
        }
        return replay.finish(code, body).await;
    }
    // Spec: homeservers SHOULD reject m.room.message without msgtype and body.
    if event_type == "m.room.message" {
        let msgtype = content.get("msgtype").and_then(Value::as_str).filter(|value| !value.is_empty());
        let body = content.get("body").and_then(Value::as_str);
        if msgtype.is_none() || body.is_none() {
            return replay
                .finish(
                    StatusCode::BAD_REQUEST,
                    json!({"errcode": "M_BAD_JSON", "error": "m.room.message requires msgtype and body"}),
                )
                .await;
        }
    }
    match super::event_pipeline::build_sign_and_persist_transaction(
        &state,
        &authed.user_id,
        &room_id,
        &event_type,
        content,
        &key,
    )
    .await
    {
        Ok(event_id) => {
            replay
                .finish(StatusCode::OK, json!({"event_id": event_id}))
                .await
        }
        Err((code, error)) => {
            let body = serde_json::to_value(error.0).expect("Matrix error serializes");
            // Transaction replay rewrites status from errcode, which would
            // turn a policy server's 400 M_FORBIDDEN into 403. The policy
            // server's status is the one the client is supposed to see.
            if code != crate::replay::status(&body) {
                return (code, Json(body)).into_response();
            }
            replay.finish(code, body).await
        }
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
    // add-pdu-wire: U+0000 cannot live in the TEXT key columns, and a U+FFFD
    // stand-in could merge two state keys; refuse before building the event.
    if event_type.contains('\0') || state_key.contains('\0') {
        return MatrixError::invalid_param("event type and state key must not contain U+0000").into_response();
    }
    if event_type == "m.room.member" && content.get("membership").and_then(Value::as_str) == Some("invite") {
        if let Err(blocked) = super::room_membership::check_invite_allowed(state, state_key).await {
            return blocked;
        }
    }
    if let Some(rejected) = reject_bad_canonical_alias(state, room_id, event_type, &content).await {
        return rejected;
    }
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
    authed: AuthedUser,
    Path(room_id): Path<String>,
) -> Response {
    if let Err(e) =
        conduit::auth::require_read_access(state.storage().as_ref(), &room_id, &authed.user_id).await
    {
        return MatrixError::from_conduit(e).into_response();
    }

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
    authed: AuthedUser,
    Path((room_id, event_type)): Path<(String, String)>,
) -> Response {
    get_state_event_inner(state, &authed.user_id, room_id, event_type, String::new()).await
}

/// GET the content of a state event with an explicit state_key.
pub async fn get_state_event<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_type, state_key)): Path<(String, String, String)>,
) -> Response {
    get_state_event_inner(state, &authed.user_id, room_id, event_type, state_key).await
}

async fn get_state_event_inner<S: AuthState>(
    state: S,
    user_id: &str,
    room_id: String,
    event_type: String,
    state_key: String,
) -> Response {
    if let Err(e) =
        conduit::auth::require_read_access(state.storage().as_ref(), &room_id, user_id).await
    {
        return MatrixError::from_conduit(e).into_response();
    }

    let room = Room::new(&room_id);
    match room.get_state_entry(&event_type, &state_key, state.storage().as_ref()).await {
        Ok(Some(ev)) => (StatusCode::OK, Json(ev.pdu.content)).into_response(),
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
    authed: AuthedUser,
    Path(room_id): Path<String>,
) -> Response {
    if let Err(e) =
        conduit::auth::require_read_access(state.storage().as_ref(), &room_id, &authed.user_id).await
    {
        return MatrixError::from_conduit(e).into_response();
    }

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
    /// Exclusive stop token in the direction of pagination.
    pub to: Option<String>,
    /// Maximum number of events to return (default 10).
    pub limit: Option<i64>,
    /// JSON [`RoomEventFilter`]. Events that do not match are skipped, and
    /// the server keeps paging until `limit` matches or the timeline ends.
    pub filter: Option<String>,
}

fn parse_stream_token(token: &str) -> Option<i64> {
    token
        .strip_prefix('s')
        .unwrap_or(token)
        .split('_')
        .next()
        .unwrap_or("")
        .parse::<i64>()
        .ok()
        .filter(|position| *position >= 0)
}

/// `#localpart:server` with a non-empty localpart and server name.
fn valid_room_alias(alias: &str) -> bool {
    let Some(rest) = alias.strip_prefix('#') else {
        return false;
    };
    let Some((local, server)) = rest.split_once(':') else {
        return false;
    };
    !local.is_empty()
        && !server.is_empty()
        && !local.contains(':')
        && !local.chars().any(char::is_whitespace)
        && !server.chars().any(char::is_whitespace)
}

/// Spec: every alias in `m.room.canonical_alias` must be syntactically valid
/// (`400 M_INVALID_PARAM`) and must already point at this room
/// (`400 M_BAD_ALIAS`). An event with no aliases (clearing the state) is fine.
async fn reject_bad_canonical_alias<S: AuthState>(
    state: &S,
    room_id: &str,
    event_type: &str,
    content: &Value,
) -> Option<Response> {
    if event_type != "m.room.canonical_alias" {
        return None;
    }
    let mut aliases = Vec::new();
    match content.get("alias") {
        None | Some(Value::Null) => {}
        Some(Value::String(alias)) => aliases.push(alias.clone()),
        Some(_) => {
            return Some(MatrixError::invalid_param("alias must be a string").into_response());
        }
    }
    match content.get("alt_aliases") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for item in items {
                match item.as_str() {
                    Some(alias) => aliases.push(alias.to_owned()),
                    None => {
                        return Some(
                            MatrixError::invalid_param("alt_aliases entries must be strings").into_response(),
                        );
                    }
                }
            }
        }
        Some(_) => {
            return Some(MatrixError::invalid_param("alt_aliases must be an array").into_response());
        }
    }
    let storage = state.storage();
    for alias in aliases {
        if !valid_room_alias(&alias) {
            return Some(MatrixError::invalid_param(format!("invalid alias: {alias}")).into_response());
        }
        match storage.get_room_for_alias(&alias).await {
            Ok(Some(target)) if target == room_id => {}
            Ok(_) => {
                return Some(
                    MatrixError::bad_alias(format!("The alias '{alias}' does not point to this room.")).into_response(),
                );
            }
            Err(error) => return Some(MatrixError::unknown(error.to_string()).into_response()),
        }
    }
    None
}

pub async fn get_messages<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Query(query): Query<MessagesQuery>,
) -> Response {
    let storage = state.storage();

    if let Err(e) =
        conduit::auth::require_read_access(storage.as_ref(), &room_id, &authed.user_id).await
    {
        return MatrixError::from_conduit(e).into_response();
    }
    let dir = query.dir.as_deref().unwrap_or("b");
    let dir_char = if dir == "f" { 'f' } else { 'b' };
    let limit = query.limit.unwrap_or(10).max(1).min(100);
    let room_filter: Option<RoomEventFilter> = match query.filter.as_deref() {
        None => None,
        Some(raw) => match serde_json::from_str(raw) {
            Ok(filter) => Some(filter),
            Err(error) => {
                return MatrixError::bad_json(format!("invalid filter: {error}")).into_response();
            }
        },
    };
    let to = match query.to.as_deref() {
        None => None,
        Some(token) => match parse_stream_token(token) {
            Some(position) => Some(position),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"errcode": "M_INVALID_PARAM", "error": "invalid pagination token"})),
                )
                    .into_response();
            }
        },
    };

    // Determine start position.
    let from: i64 = if let Some(token) = &query.from {
        match parse_stream_token(token) {
            Some(position) => position,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"errcode": "M_INVALID_PARAM", "error": "invalid pagination token"})),
                )
                    .into_response();
            }
        }
    } else {
        match dir_char {
            'b' => {
                // Start from the most recent event.
                match storage.room_latest_stream_position(&room_id).await {
                    Ok(Some(pos)) => pos,
                    Ok(None) => {
                        // No events: no further pages, so `end` is omitted.
                        return (StatusCode::OK, Json(json!({ "chunk": [], "start": "0" }))).into_response();
                    }
                    Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
                }
            }
            _ => 0,
        }
    };

    // A RoomEventFilter or a `to` token must not shorten the page: keep
    // reading until `limit` visible matches, the exclusive `to` bound, or
    // the end of the timeline.
    let selective = room_filter.is_some() || to.is_some();
    let page = if selective {
        let mut cursor = from;
        let mut kept = Vec::new();
        let mut last_included: Option<i64> = None;
        let mut exhausted = false;
        let mut hit_to = false;
        while (kept.len() as i64) < limit && !hit_to {
            let batch = (limit - kept.len() as i64).max(20);
            let (events, next) = match storage.room_events_paginated(&room_id, dir_char, cursor, batch).await {
                Ok(page) => page,
                Err(e) => return MatrixError::from_conduit(e).into_response(),
            };
            if events.is_empty() {
                exhausted = true;
                break;
            }
            let ids: Vec<String> = events.iter().map(|event| event.event_id.clone()).collect();
            let positions = match storage.event_stream_positions(&ids).await {
                Ok(positions) => positions,
                Err(e) => return MatrixError::from_conduit(e).into_response(),
            };
            let visible = match conduit::auth::filter_visible_for_user(
                storage.as_ref(),
                &room_id,
                &authed.user_id,
                events.clone(),
            )
            .await
            {
                Ok(events) => events,
                Err(e) => return MatrixError::from_conduit(e).into_response(),
            };
            let visible_ids: HashSet<String> = visible.into_iter().map(|event| event.event_id).collect();
            for event in events {
                if (kept.len() as i64) >= limit {
                    break;
                }
                if let Some(position) = positions.get(&event.event_id) {
                    let past = match (dir_char, to) {
                        ('b', Some(bound)) => *position <= bound,
                        ('f', Some(bound)) => *position >= bound,
                        _ => false,
                    };
                    if past {
                        hit_to = true;
                        break;
                    }
                    if visible_ids.contains(&event.event_id)
                        && room_filter.as_ref().is_none_or(|filter| {
                            filter.matches(&room_id, &serde_json::to_value(&event).unwrap_or(Value::Null))
                        })
                    {
                        last_included = Some(*position);
                        kept.push(event);
                    }
                }
            }
            match next {
                Some(next) if !hit_to && (kept.len() as i64) < limit => cursor = next,
                Some(_) => break,
                None => {
                    exhausted = true;
                    break;
                }
            }
        }
        let next_pos = if exhausted || hit_to {
            None
        } else {
            last_included.map(|position| if dir_char == 'b' { position - 1 } else { position + 1 })
        };
        (kept, next_pos)
    } else {
        match storage.room_events_paginated(&room_id, dir_char, from, limit).await {
            Ok((events, next_pos)) => {
                let events = match conduit::auth::filter_visible_for_user(
                    storage.as_ref(),
                    &room_id,
                    &authed.user_id,
                    events,
                )
                .await
                {
                    Ok(events) => events,
                    Err(e) => return MatrixError::from_conduit(e).into_response(),
                };
                (events, next_pos)
            }
            Err(e) => return MatrixError::from_conduit(e).into_response(),
        }
    };

    let (events, next_pos) = page;
    // Ignored senders, redactions and bundled aggregations
    // (conduit-y99.19).
    let viewer = match super::room_content::serve::Viewer::load(storage.as_ref(), &authed.user_id).await {
        Ok(viewer) => viewer,
        Err(e) => return MatrixError::from_conduit(e).into_response(),
    };
    let mut chunk: Vec<Value> = viewer
        .without_ignored(events)
        .into_iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();
    if let Err(e) = viewer.decorate_values(&mut chunk, true).await {
        return MatrixError::from_conduit(e).into_response();
    }
    let own: Vec<String> = chunk
        .iter()
        .filter(|event| event["sender"] == authed.user_id)
        .filter_map(|event| event["event_id"].as_str().map(str::to_owned))
        .collect();
    if !own.is_empty() {
        match storage.client_transaction_ids(&authed.user_id, &authed.device_id, &own).await {
            Ok(transactions) => {
                for event in &mut chunk {
                    let Some(txn) = event["event_id"].as_str().and_then(|id| transactions.get(id)) else {
                        continue;
                    };
                    if !event["unsigned"].is_object() {
                        event["unsigned"] = json!({});
                    }
                    event["unsigned"]["transaction_id"] = json!(txn);
                }
            }
            Err(error) => return MatrixError::from_conduit(error).into_response(),
        }
    }
    // `end` is omitted when there are no more events in this
    // direction (spec: "If no further events are available ... the
    // end property is omitted").
    let mut body = json!({"chunk": chunk, "start": from.to_string()});
    if let Some(next) = next_pos {
        body["end"] = json!(next.to_string());
    }
    (StatusCode::OK, Json(body)).into_response()
}
