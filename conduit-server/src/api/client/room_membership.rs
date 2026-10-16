//! Room membership gaps (conduit-y99.29, Matrix v1.19):
//!
//!   POST /_matrix/client/v3/rooms/:roomId/join
//!   GET  /_matrix/client/v1/room_summary/:roomIdOrAlias   (v1.15)
//!   GET  /_matrix/client/v1/mutual_rooms                  (v1.19)
//!
//! plus the invite permission module (v1.18): a local user whose
//! `m.invite_permission_config` account data has `default_action: block`
//! cannot be invited (`403 M_INVITE_BLOCKED`) and their pending invites are
//! hidden from `/sync`.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};

use conduit::auth::{effective_user_level, StateMap};
use conduit::event::Event;
use conduit::signing::server_of_user_id;
use conduit::state_events::parse_power_levels;
use conduit::storage::Storage;

use super::rooms::{join_room, JoinRequest};
use super::session::MaybeAuthed;
use super::{AuthState, AuthedUser, MatrixError};

pub fn router<S: AuthState>() -> Router<S> {
    Router::new()
        .route("/_matrix/client/v3/rooms/:roomId/join", post(join_by_room_id::<S>))
        .route("/_matrix/client/v1/room_summary/:roomIdOrAlias", get(room_summary::<S>))
        .route("/_matrix/client/v1/mutual_rooms", get(mutual_rooms::<S>))
}

fn error(status: StatusCode, errcode: &str, message: impl Into<String>) -> Response {
    (status, Json(json!({ "errcode": errcode, "error": message.into() }))).into_response()
}

// ---------------------------------------------------------------------------
// Invite permission
// ---------------------------------------------------------------------------

/// Account data type holding a user's invite permission configuration.
pub const INVITE_PERMISSION_CONFIG: &str = "m.invite_permission_config";

/// Whether `user_id` has asked to block every invite. Missing, invalid or
/// unknown `default_action` values mean invites are received as normal.
pub async fn blocks_invites(storage: &dyn Storage, user_id: &str) -> bool {
    matches!(
        storage.get_account_data(user_id, None, INVITE_PERMISSION_CONFIG).await,
        Ok(Some(config)) if config.get("default_action").and_then(Value::as_str) == Some("block")
    )
}

/// `403 M_INVITE_BLOCKED` when `target` is a local user blocking invites.
/// Remote targets are judged by their own homeserver.
pub async fn check_invite_allowed<S: AuthState>(state: &S, target: &str) -> Result<(), Response> {
    let local = target
        .rsplit_once(':')
        .is_some_and(|(_, server)| server == state.server_name());
    if local && blocks_invites(state.storage().as_ref(), target).await {
        return Err(error(
            StatusCode::FORBIDDEN,
            "M_INVITE_BLOCKED",
            format!("{target} is not accepting invites"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Restricted / knock_restricted joins
// ---------------------------------------------------------------------------

/// What the server authoring a join should do with allow conditions.
///
/// Event auth never looks up the other room. It checks
/// `join_authorised_via_users_server`. This decision is that lookup.
#[derive(Debug, PartialEq, Eq)]
pub enum RestrictedDecision {
    /// Not a restricted join, or the user is already invited or joined.
    Open,
    /// Stamp this local joined user, who can invite, onto the join.
    Authorise(String),
    /// No allow condition could be checked (the rooms are unknown here).
    UnableToAuthorise,
    /// The conditions were checked and the user does not satisfy them.
    Forbidden,
    /// A condition matched, but no local joined user can issue invites.
    UnableToGrant,
}

/// Decide a restricted join for `user_id` into `room_id`.
///
/// An invite or an existing join is [`RestrictedDecision::Open`]: the
/// restrictions do not apply. Otherwise each `m.room_membership` condition
/// is checked against that room's real member event. Unknown condition
/// types are skipped. A satisfied condition needs a local joined user with
/// invite power; the room creator is preferred.
pub async fn decide_restricted_join(
    storage: &dyn Storage,
    server_name: &str,
    user_id: &str,
    room_id: &str,
) -> Result<RestrictedDecision, conduit::Error> {
    if let Some(event) = storage.get_state_entry(room_id, "m.room.member", user_id).await? {
        let membership = event.content.get("membership").and_then(Value::as_str);
        if matches!(membership, Some("invite" | "join")) {
            return Ok(RestrictedDecision::Open);
        }
    }
    let Some(rules) = storage.get_state_entry(room_id, "m.room.join_rules", "").await? else {
        return Ok(RestrictedDecision::Open);
    };
    let rule = rules.content.get("join_rule").and_then(Value::as_str).unwrap_or("invite");
    if rule != "restricted" && rule != "knock_restricted" {
        return Ok(RestrictedDecision::Open);
    }
    let create = storage.get_state_entry(room_id, "m.room.create", "").await?;
    let version = create
        .as_ref()
        .map(|event| conduit::room_version::version_of_content(&event.content))
        .unwrap_or(11);
    let supported = if rule == "knock_restricted" { version >= 10 } else { version >= 8 };
    if !supported {
        return Ok(RestrictedDecision::Forbidden);
    }

    let allow = rules
        .content
        .get("allow")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut satisfied = false;
    let mut unknown = 0u32;
    let mut known_failed = 0u32;
    let mut well_formed = 0u32;
    for condition in &allow {
        if condition.get("type").and_then(Value::as_str) != Some("m.room_membership") {
            continue;
        }
        let Some(allowed_room) = condition.get("room_id").and_then(Value::as_str) else {
            continue;
        };
        well_formed += 1;
        let member = storage.get_state_entry(allowed_room, "m.room.member", user_id).await?;
        let joined = member
            .as_ref()
            .and_then(|event| event.content.get("membership"))
            .and_then(Value::as_str)
            == Some("join");
        if joined {
            satisfied = true;
            break;
        }
        let known = storage
            .get_state_entry(allowed_room, "m.room.create", "")
            .await?
            .is_some();
        if known {
            known_failed += 1;
        } else {
            unknown += 1;
        }
    }
    if !satisfied {
        if well_formed > 0 && known_failed == 0 && unknown > 0 {
            return Ok(RestrictedDecision::UnableToAuthorise);
        }
        return Ok(RestrictedDecision::Forbidden);
    }
    Ok(match pick_authoriser(storage, server_name, room_id).await? {
        Some(user) => RestrictedDecision::Authorise(user),
        None => RestrictedDecision::UnableToGrant,
    })
}

/// A local user who is joined and whose power is at least the invite level.
/// The create sender wins when they qualify; otherwise the lowest user id.
async fn pick_authoriser(
    storage: &dyn Storage,
    server_name: &str,
    room_id: &str,
) -> Result<Option<String>, conduit::Error> {
    let current = storage.get_current_state(room_id).await?;
    let mut map: StateMap<Event> = HashMap::new();
    for event in &current {
        if event.state_key.is_some()
            && (event.event_type == "m.room.create" || event.event_type == "m.room.power_levels")
        {
            map.insert((event.event_type.clone(), event.state_key.clone().unwrap_or_default()), event.clone());
        }
    }
    let invite = map
        .get(&("m.room.power_levels".to_owned(), String::new()))
        .and_then(|event| parse_power_levels(&event.content).ok())
        .map(|levels| levels.invite)
        .unwrap_or(50);
    let creator = map
        .get(&("m.room.create".to_owned(), String::new()))
        .map(|event| event.sender.clone());
    let mut able = Vec::new();
    for event in &current {
        if event.event_type != "m.room.member" {
            continue;
        }
        if event.content.get("membership").and_then(Value::as_str) != Some("join") {
            continue;
        }
        let Some(user) = event.state_key.clone() else {
            continue;
        };
        if server_of_user_id(&user) != Some(server_name) {
            continue;
        }
        map.insert(("m.room.member".to_owned(), user.clone()), event.clone());
        if effective_user_level(&user, &map) >= invite {
            able.push(user);
        }
    }
    if let Some(creator) = creator {
        if able.iter().any(|user| user == &creator) {
            return Ok(Some(creator));
        }
    }
    able.sort();
    Ok(able.into_iter().next())
}

// ---------------------------------------------------------------------------
// POST /rooms/:roomId/join
// ---------------------------------------------------------------------------

/// Same semantics as `/join/{roomIdOrAlias}` but only accepts a room ID.
pub async fn join_by_room_id<S: AuthState>(
    state: State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    raw: RawQuery,
    body: Json<JoinRequest>,
) -> Response {
    if !room_id.starts_with('!') {
        return error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "rooms/{roomId}/join takes a room ID; use /join/{roomIdOrAlias} for aliases",
        );
    }
    join_room(state, authed, Path(room_id), raw, body).await
}

// ---------------------------------------------------------------------------
// GET /room_summary/:roomIdOrAlias
// ---------------------------------------------------------------------------

fn state_content<'a>(state: &'a HashMap<(String, String), Event>, kind: &str, key: &str) -> Option<&'a Value> {
    state.get(&(kind.to_owned(), key.to_owned())).map(|e| &e.content)
}

fn plain_topic(content: &Value) -> Option<String> {
    if let Some(entries) = content.get("m.topic").and_then(|t| t.get("m.text")).and_then(Value::as_array) {
        if let Some(body) = entries.iter().find_map(|entry| {
            let mime = entry.get("mimetype").and_then(Value::as_str).unwrap_or("text/plain");
            (mime == "text/plain").then(|| entry.get("body").and_then(Value::as_str)).flatten()
        }) {
            return Some(body.to_owned());
        }
    }
    content.get("topic").and_then(Value::as_str).map(str::to_owned)
}

/// Repeated `via` query parameters. One value and many values are both
/// legal; axum's `Query<Vec<_>>` rejects a single value.
fn via_servers(query: Option<&str>) -> Vec<String> {
    let Some(query) = query else {
        return Vec::new();
    };
    url::form_urlencoded::parse(query.as_bytes())
        .filter(|(key, value)| key == "via" && !value.is_empty())
        .map(|(_, value)| value.into_owned())
        .collect()
}

/// `GET /_matrix/client/v1/room_summary/{roomIdOrAlias}`. Authentication is
/// optional: anonymous callers only see rooms that are publicly joinable,
/// knockable or world-readable. Rooms the caller may not see are `404`,
/// so the endpoint does not reveal their existence. A room this server
/// cannot summarise is requested from each `via` server.
pub async fn room_summary<S: AuthState>(
    State(state): State<S>,
    MaybeAuthed(authed): MaybeAuthed,
    Path(room_id_or_alias): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let storage = state.storage();
    let not_found = || MatrixError::new_not_found("Room not found.").into_response();
    let via = via_servers(raw_query.as_deref());
    let room_id = if room_id_or_alias.starts_with('#') {
        match storage.get_room_for_alias(&room_id_or_alias).await {
            Ok(Some(room_id)) => room_id,
            Ok(None) => return remote_room_summary(&state, &room_id_or_alias, &via, authed.as_ref()).await,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        }
    } else {
        room_id_or_alias
    };
    let events = match storage.get_current_state(&room_id).await {
        Ok(events) => events,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let current: HashMap<(String, String), Event> = events
        .into_iter()
        .filter_map(|e| Some(((e.event_type.clone(), e.state_key.clone()?), e)))
        .collect();
    let Some(create) = state_content(&current, "m.room.create", "") else {
        return remote_room_summary(&state, &room_id, &via, authed.as_ref()).await;
    };
    let join_rules = state_content(&current, "m.room.join_rules", "");
    let join_rule = join_rules
        .and_then(|c| c.get("join_rule"))
        .and_then(Value::as_str)
        .unwrap_or("invite")
        .to_owned();
    let world_readable = state_content(&current, "m.room.history_visibility", "")
        .and_then(|c| c.get("history_visibility"))
        .and_then(Value::as_str)
        == Some("world_readable");
    let allowed_room_ids: Vec<String> = if join_rule == "restricted" || join_rule == "knock_restricted" {
        join_rules
            .and_then(|c| c.get("allow"))
            .and_then(Value::as_array)
            .map(|allow| {
                allow
                    .iter()
                    .filter(|a| a.get("type").and_then(Value::as_str) == Some("m.room_membership"))
                    .filter_map(|a| a.get("room_id").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let membership = authed.as_ref().map(|user| {
        state_content(&current, "m.room.member", &user.user_id)
            .and_then(|c| c.get("membership"))
            .and_then(Value::as_str)
            .unwrap_or("leave")
            .to_owned()
    });

    let public = matches!(join_rule.as_str(), "public" | "knock" | "knock_restricted");
    let mut visible = public || world_readable;
    if !visible {
        if let Some(user) = authed.as_ref() {
            visible = matches!(membership.as_deref(), Some("join" | "invite" | "knock"));
            if !visible && !allowed_room_ids.is_empty() {
                match storage.joined_rooms(&user.user_id).await {
                    Ok(joined) => visible = allowed_room_ids.iter().any(|r| joined.contains(r)),
                    Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
                }
            }
        }
    }
    if !visible {
        return not_found();
    }

    let num_joined_members = current
        .iter()
        .filter(|((kind, _), e)| kind == "m.room.member" && e.content.get("membership").and_then(Value::as_str) == Some("join"))
        .count();
    let mut summary = serde_json::Map::new();
    summary.insert("room_id".into(), json!(room_id));
    summary.insert("num_joined_members".into(), json!(num_joined_members));
    summary.insert("world_readable".into(), json!(world_readable));
    summary.insert(
        "guest_can_join".into(),
        json!(state_content(&current, "m.room.guest_access", "")
            .and_then(|c| c.get("guest_access"))
            .and_then(Value::as_str)
            == Some("can_join")),
    );
    summary.insert("join_rule".into(), json!(join_rule));
    summary.insert(
        "room_version".into(),
        json!(create.get("room_version").and_then(Value::as_str).unwrap_or("1")),
    );
    if let Some(kind) = create.get("type").and_then(Value::as_str) {
        summary.insert("room_type".into(), json!(kind));
    }
    if let Some(name) = state_content(&current, "m.room.name", "").and_then(|c| c.get("name")).and_then(Value::as_str) {
        if !name.is_empty() {
            summary.insert("name".into(), json!(name));
        }
    }
    if let Some(topic) = state_content(&current, "m.room.topic", "").and_then(plain_topic) {
        summary.insert("topic".into(), json!(topic));
    }
    if let Some(url) = state_content(&current, "m.room.avatar", "").and_then(|c| c.get("url")).and_then(Value::as_str) {
        summary.insert("avatar_url".into(), json!(url));
    }
    if let Some(alias) = state_content(&current, "m.room.canonical_alias", "").and_then(|c| c.get("alias")).and_then(Value::as_str) {
        summary.insert("canonical_alias".into(), json!(alias));
    }
    if let Some(algorithm) = state_content(&current, "m.room.encryption", "").and_then(|c| c.get("algorithm")).and_then(Value::as_str) {
        summary.insert("encryption".into(), json!(algorithm));
    }
    if !allowed_room_ids.is_empty() {
        summary.insert("allowed_room_ids".into(), json!(allowed_room_ids));
    }
    if let Some(membership) = membership {
        summary.insert("membership".into(), json!(membership));
    }
    (StatusCode::OK, Json(Value::Object(summary))).into_response()
}

fn federation_enabled() -> bool {
    std::env::var("CONDUIT_FEDERATION").ok().as_deref() != Some("0")
}

fn push_unique(dests: &mut Vec<String>, name: &str, local: &str) {
    if name.is_empty() || name == local || dests.iter().any(|existing| existing == name) {
        return;
    }
    dests.push(name.to_owned());
}

/// Copy the federation hierarchy `room` object into a client RoomSummary.
/// `children_state` stays on the federation object. A summary that omits a
/// required field, or names a different room, is not usable.
fn client_summary_from_hierarchy(room: &serde_json::Map<String, Value>, expected_room_id: &str) -> Option<serde_json::Map<String, Value>> {
    let room_id = room.get("room_id")?.as_str()?;
    if room_id != expected_room_id {
        return None;
    }
    let guest_can_join = room.get("guest_can_join")?.as_bool()?;
    let world_readable = room.get("world_readable")?.as_bool()?;
    let num_joined_members = room.get("num_joined_members")?.as_i64().filter(|count| *count >= 0)?;
    let mut summary = serde_json::Map::new();
    summary.insert("room_id".into(), json!(room_id));
    summary.insert("num_joined_members".into(), json!(num_joined_members));
    summary.insert("world_readable".into(), json!(world_readable));
    summary.insert("guest_can_join".into(), json!(guest_can_join));
    if let Some(rule) = room.get("join_rule").and_then(Value::as_str).filter(|rule| !rule.is_empty()) {
        summary.insert("join_rule".into(), json!(rule));
    }
    for key in ["avatar_url", "canonical_alias", "encryption", "name", "topic", "room_type", "room_version"] {
        if let Some(value) = room.get(key).and_then(Value::as_str).filter(|value| !value.is_empty()) {
            summary.insert(key.to_owned(), json!(value));
        }
    }
    if let Some(ids) = room.get("allowed_room_ids").and_then(Value::as_array) {
        let ids: Vec<&str> = ids.iter().filter_map(Value::as_str).filter(|id| !id.is_empty()).collect();
        if !ids.is_empty() {
            summary.insert("allowed_room_ids".into(), json!(ids));
        }
    }
    Some(summary)
}

fn summary_is_visible(summary: &serde_json::Map<String, Value>, joined: &[String]) -> bool {
    let join_rule = summary.get("join_rule").and_then(Value::as_str).unwrap_or("public");
    let world_readable = summary.get("world_readable").and_then(Value::as_bool).unwrap_or(false);
    if matches!(join_rule, "public" | "knock" | "knock_restricted") || world_readable {
        return true;
    }
    if matches!(
        summary.get("membership").and_then(Value::as_str),
        Some("join" | "invite" | "knock")
    ) {
        return true;
    }
    if join_rule == "restricted" {
        return summary
            .get("allowed_room_ids")
            .and_then(Value::as_array)
            .is_some_and(|ids| ids.iter().any(|id| id.as_str().is_some_and(|id| joined.iter().any(|room| room == id))));
    }
    false
}

/// Ask `via` for a summary this server cannot build. An alias is resolved
/// with `/query/directory` first. The summary itself comes from the `room`
/// object of `GET /hierarchy/{roomId}`. A summary the caller may not see is
/// `404`, the same as a local room.
async fn remote_room_summary<S: AuthState>(
    state: &S,
    room_id_or_alias: &str,
    via: &[String],
    authed: Option<&AuthedUser>,
) -> Response {
    let not_found = || MatrixError::new_not_found("Room not found.").into_response();
    if via.is_empty() || !federation_enabled() {
        return not_found();
    }
    let Some(client) = state.federation_client() else {
        return not_found();
    };
    let local = state.server_name();
    let vias: Vec<&str> = via.iter().map(String::as_str).filter(|name| !name.is_empty() && *name != local).collect();
    if vias.is_empty() {
        return not_found();
    }

    let (room_id, dests) = if let Some(alias) = room_id_or_alias.strip_prefix('#') {
        if alias.is_empty() {
            return not_found();
        }
        let mut resolved = None;
        let mut dests = Vec::new();
        for via_server in &vias {
            match client.query_directory(via_server, room_id_or_alias).await {
                Ok(directory) if directory.room_id.starts_with('!') => {
                    if directory.servers.is_empty() {
                        push_unique(&mut dests, via_server, local);
                    } else {
                        for server in &directory.servers {
                            push_unique(&mut dests, server, local);
                        }
                    }
                    for via_server in &vias {
                        push_unique(&mut dests, via_server, local);
                    }
                    resolved = Some(directory.room_id);
                    break;
                }
                _ => {}
            }
        }
        let Some(room_id) = resolved else {
            return not_found();
        };
        (room_id, dests)
    } else if room_id_or_alias.starts_with('!') {
        let mut dests = Vec::new();
        for via_server in &vias {
            push_unique(&mut dests, via_server, local);
        }
        (room_id_or_alias.to_owned(), dests)
    } else {
        return not_found();
    };

    for dest in &dests {
        let value = match client.room_hierarchy(dest, &room_id, false).await {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(room) = value.get("room").and_then(Value::as_object) else {
            continue;
        };
        let Some(summary) = client_summary_from_hierarchy(room, &room_id) else {
            continue;
        };
        let joined = match authed {
            Some(user) => match state.storage().joined_rooms(&user.user_id).await {
                Ok(joined) => joined,
                Err(error) => return MatrixError::unknown(error.to_string()).into_response(),
            },
            None => Vec::new(),
        };
        if !summary_is_visible(&summary, &joined) {
            return not_found();
        }
        return (StatusCode::OK, Json(Value::Object(summary))).into_response();
    }
    not_found()
}

// ---------------------------------------------------------------------------
// GET /mutual_rooms
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct MutualRoomsQuery {
    pub user_id: Option<String>,
    pub from: Option<String>,
}

/// Batch tokens stay valid for an hour (spec: at least 10 minutes).
const BATCH_TOKEN_TTL_MS: i64 = 60 * 60 * 1000;

fn batch_size() -> usize {
    std::env::var("CONDUIT_MUTUAL_ROOMS_BATCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(100)
}

fn encode_batch(user_id: &str, after: &str, expires: i64) -> String {
    URL_SAFE_NO_PAD.encode(json!({"u": user_id, "a": after, "e": expires}).to_string())
}

/// The room ID to continue after, if `token` is valid for `user_id`.
fn decode_batch(token: &str, user_id: &str, now: i64) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    if value.get("u")?.as_str()? != user_id || value.get("e")?.as_i64()? < now {
        return None;
    }
    value.get("a")?.as_str().map(str::to_owned)
}

fn valid_user_id(user_id: &str) -> bool {
    user_id.starts_with('@')
        && user_id.len() <= 255
        && user_id[1..].split_once(':').is_some_and(|(local, server)| !local.is_empty() && !server.is_empty())
}

pub async fn mutual_rooms<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(query): Query<MutualRoomsQuery>,
) -> Response {
    let Some(other) = query.user_id else {
        return error(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", "user_id is required");
    };
    if !valid_user_id(&other) {
        return error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "The user ID provided was invalid");
    }
    if other == authed.user_id {
        return error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "user_id must not be your own user ID");
    }
    let now = chrono::Utc::now().timestamp_millis();
    let after = match query.from.as_deref() {
        None => None,
        Some(token) => match decode_batch(token, &other, now) {
            Some(after) => Some(after),
            None => {
                return error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "The from token is invalid or expired")
            }
        },
    };
    let storage = state.storage();
    let (mine, theirs) = match (storage.joined_rooms(&authed.user_id).await, storage.joined_rooms(&other).await) {
        (Ok(mine), Ok(theirs)) => (mine, theirs),
        (Err(e), _) | (_, Err(e)) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let mut shared: Vec<String> = mine.into_iter().filter(|room| theirs.contains(room)).collect();
    shared.sort();
    shared.dedup();
    let count = shared.len();
    let remaining: Vec<String> = shared
        .into_iter()
        .filter(|room| after.as_ref().is_none_or(|a| room > a))
        .collect();
    let size = batch_size();
    let mut response = json!({ "count": count });
    if remaining.len() > size {
        let page = &remaining[..size];
        response["next_batch"] = json!(encode_batch(&other, &page[size - 1], now + BATCH_TOKEN_TTL_MS));
        response["joined"] = json!(page);
    } else {
        response["joined"] = json!(remaining);
    }
    (StatusCode::OK, Json(response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_tokens_bind_user_and_expire() {
        let token = encode_batch("@bob:hs", "!b:hs", 1_000);
        assert_eq!(decode_batch(&token, "@bob:hs", 999).as_deref(), Some("!b:hs"));
        assert_eq!(decode_batch(&token, "@carol:hs", 999), None);
        assert_eq!(decode_batch(&token, "@bob:hs", 1_001), None);
        assert_eq!(decode_batch("not-a-token", "@bob:hs", 0), None);
    }

    #[test]
    fn plain_topic_prefers_text_plain_m_topic() {
        let content = json!({
            "topic": "fallback",
            "m.topic": {"m.text": [
                {"mimetype": "text/html", "body": "<b>rich</b>"},
                {"body": "plain"}
            ]}
        });
        assert_eq!(plain_topic(&content).as_deref(), Some("plain"));
        assert_eq!(plain_topic(&json!({"topic": "only"})).as_deref(), Some("only"));
        assert_eq!(plain_topic(&json!({})), None);
    }

    #[test]
    fn user_id_validation() {
        assert!(valid_user_id("@a:b"));
        assert!(!valid_user_id("a:b"));
        assert!(!valid_user_id("@:b"));
        assert!(!valid_user_id("@a"));
    }
}
