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
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};

use conduit::event::Event;
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
// POST /rooms/:roomId/join
// ---------------------------------------------------------------------------

/// Same semantics as `/join/{roomIdOrAlias}` but only accepts a room ID.
pub async fn join_by_room_id<S: AuthState>(
    state: State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    body: Json<JoinRequest>,
) -> Response {
    if !room_id.starts_with('!') {
        return error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "rooms/{roomId}/join takes a room ID; use /join/{roomIdOrAlias} for aliases",
        );
    }
    join_room(state, authed, Path(room_id), body).await
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

/// `GET /_matrix/client/v1/room_summary/{roomIdOrAlias}`. Authentication is
/// optional: anonymous callers only see rooms that are publicly joinable,
/// knockable or world-readable. Rooms the caller may not see are `404`,
/// so the endpoint does not reveal their existence.
pub async fn room_summary<S: AuthState>(
    State(state): State<S>,
    MaybeAuthed(authed): MaybeAuthed,
    Path(room_id_or_alias): Path<String>,
) -> Response {
    let storage = state.storage();
    let not_found = || MatrixError::new_not_found("Room not found.").into_response();
    let room_id = if room_id_or_alias.starts_with('#') {
        match storage.get_room_for_alias(&room_id_or_alias).await {
            Ok(Some(room_id)) => room_id,
            Ok(None) => return not_found(),
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
        return not_found();
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
