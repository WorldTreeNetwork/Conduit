//! Server notices (Matrix v1.19 §Server Notices; conduit-y99.41).
//!
//! Each user gets exactly one notices room, created on the first notice
//! by a server-owned system account and tagged `m.server_notice` in the
//! user's room account data.  The user is invited, never auto-joined.
//! Notices are `m.room.message` events with `msgtype: m.server_notice`.
//! Rejecting the invite answers `403 M_CANNOT_LEAVE_SERVER_NOTICE_ROOM`;
//! leaving after joining is allowed (spec: servers should not prevent it).
//! A user who left is re-invited to the same room on the next notice.
//!
//! Operators send notices with
//! `POST /_matrix/conduit/admin/v1/server_notices`
//! `{"user_id": "@u:hs", "content": {"body": "...", ...}}` (admin only).
//! The system account's localpart is `CONDUIT_SERVER_NOTICES_LOCALPART`
//! (default `server-notices`).

use axum::{
    extract::State,
    http::{request::Parts, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use conduit::room::{CreateRoomParams, Room};

use super::event_pipeline::{build_sign_and_persist, RoomEventSenderWrapper};
use super::{AuthState, MatrixError};
use crate::api::admin::AdminAuthed;

/// The room tag clients use to find the notices room.
pub const SERVER_NOTICE_TAG: &str = "m.server_notice";

pub fn router<S: AuthState>() -> Router<S> {
    Router::new().route("/_matrix/conduit/admin/v1/server_notices", post(send::<S>))
}

/// The system account that owns notices rooms.
pub fn system_user_id(server_name: &str) -> String {
    let localpart = std::env::var("CONDUIT_SERVER_NOTICES_LOCALPART")
        .ok()
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "server-notices".to_owned());
    format!("@{localpart}:{server_name}")
}

fn cannot_leave() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "errcode": "M_CANNOT_LEAVE_SERVER_NOTICE_ROOM",
            "error": "You cannot reject the invite to the server notices room",
        })),
    )
        .into_response()
}

/// The room a `POST /rooms/{roomId}/leave` targets.
fn leave_target(method: &Method, path: &str) -> Option<String> {
    if method != Method::POST {
        return None;
    }
    let rest = path
        .strip_prefix("/_matrix/client/v3/rooms/")
        .or_else(|| path.strip_prefix("/_matrix/client/r0/rooms/"))?;
    let room = rest.strip_suffix("/leave")?;
    if room.contains('/') {
        return None;
    }
    url::form_urlencoded::parse(format!("r={}", room.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
}

/// Refuse to let a user reject their notices-room invite.
pub async fn leave_gate<S: AuthState>(state: &S, parts: &Parts, user_id: &str) -> Result<(), Response> {
    let Some(room_id) = leave_target(&parts.method, parts.uri.path()) else {
        return Ok(());
    };
    let unknown = |e: conduit::Error| MatrixError::unknown(e.to_string()).into_response();
    let notices = state.storage().server_notice_room(user_id).await.map_err(unknown)?;
    if notices.as_deref() != Some(room_id.as_str()) {
        return Ok(());
    }
    let membership = state
        .storage()
        .get_state_entry(&room_id, "m.room.member", user_id)
        .await
        .map_err(unknown)?
        .and_then(|e| e.content.get("membership").and_then(Value::as_str).map(str::to_owned));
    if membership.as_deref() == Some("invite") {
        return Err(cannot_leave());
    }
    Ok(())
}

async fn ensure_system_account<S: AuthState>(state: &S, system: &str) -> Result<(), String> {
    let storage = state.storage();
    if storage.get_account(system).await.map_err(|e| e.to_string())?.is_none() {
        storage.create_account(system, None).await.map_err(|e| e.to_string())?;
        storage
            .set_displayname(system, Some("Server Notices"))
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Tag the room `m.server_notice` for the user, keeping other tags.
async fn tag_room<S: AuthState>(state: &S, user_id: &str, room_id: &str) -> Result<(), String> {
    let storage = state.storage();
    let mut tags = storage
        .get_account_data(user_id, Some(room_id), "m.tag")
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| json!({"tags": {}}));
    if !tags.get("tags").is_some_and(Value::is_object) {
        tags = json!({"tags": {}});
    }
    if tags["tags"].get(SERVER_NOTICE_TAG).is_some() {
        return Ok(());
    }
    tags["tags"][SERVER_NOTICE_TAG] = json!({});
    storage
        .set_account_data(user_id, Some(room_id), "m.tag", &tags)
        .await
        .map_err(|e| e.to_string())?;
    state.sync_notify().notify_waiters();
    Ok(())
}

/// Send a server notice to a local user, creating and inviting them to
/// their notices room as needed.  Returns the notice's event ID.
pub async fn send_notice<S: AuthState>(state: &S, user_id: &str, content: Value) -> Result<String, Response> {
    let fail = |e: String| MatrixError::unknown(e).into_response();
    let system = system_user_id(state.server_name());
    ensure_system_account(state, &system).await.map_err(fail)?;
    let storage = state.storage();
    let sender = RoomEventSenderWrapper(state);

    let room_id = match storage.server_notice_room(user_id).await.map_err(|e| fail(e.to_string()))? {
        Some(r) => r,
        None => {
            let room_id = super::rooms::generate_room_id(state.server_name());
            let params = CreateRoomParams {
                name: Some("Server Notices"),
                topic: Some("Official messages from the server administrators"),
                // Only the server speaks here; the user may still read,
                // leave after joining, and redact nothing but their own.
                power_level_content_override: Some(json!({"events_default": 50, "invite": 100})),
                ..Default::default()
            };
            Room::create(&system, &room_id, "11", "invite", "shared", &params, &sender)
                .await
                .map_err(MatrixError::from_conduit)
                .map_err(IntoResponse::into_response)?;
            storage
                .set_server_notice_room(user_id, &room_id)
                .await
                .map_err(|e| fail(e.to_string()))?;
            room_id
        }
    };

    // Invite (never auto-join) unless already invited or joined.
    let membership = storage
        .get_state_entry(&room_id, "m.room.member", user_id)
        .await
        .map_err(|e| fail(e.to_string()))?
        .and_then(|e| e.content.get("membership").and_then(Value::as_str).map(str::to_owned));
    if !matches!(membership.as_deref(), Some("invite" | "join")) {
        Room::new(&room_id)
            .invite(&system, user_id, false, &sender)
            .await
            .map_err(MatrixError::from_conduit)
            .map_err(IntoResponse::into_response)?;
    }
    tag_room(state, user_id, &room_id).await.map_err(fail)?;

    let mut content = match content {
        Value::Object(o) => Value::Object(o),
        _ => json!({}),
    };
    content["msgtype"] = json!("m.server_notice");
    if content.get("body").and_then(Value::as_str).is_none() {
        content["body"] = json!("");
    }
    build_sign_and_persist(state, &system, &room_id, "m.room.message", None, content)
        .await
        .map_err(IntoResponse::into_response)
}

#[derive(Debug, Deserialize)]
pub struct SendNoticeRequest {
    pub user_id: String,
    pub content: Value,
}

/// `POST /_matrix/conduit/admin/v1/server_notices` (admin only).
pub async fn send<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Json(body): Json<SendNoticeRequest>,
) -> Response {
    let local = body
        .user_id
        .rsplit_once(':')
        .is_some_and(|(_, server)| server == state.server_name());
    if !local {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"errcode": "M_INVALID_PARAM", "error": "Server notices go to local users only"})),
        )
            .into_response();
    }
    match state.storage().get_account(&body.user_id).await {
        Ok(Some(a)) if a.deactivated_at.is_none() => {}
        Ok(_) => return MatrixError::new_not_found("User not found").into_response(),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }
    if !body.content.is_object() {
        return MatrixError::bad_json("content must be an object").into_response();
    }
    match send_notice(&state, &body.user_id, body.content.clone()).await {
        Ok(event_id) => {
            let _ = state
                .storage()
                .append_audit_log(&admin.user_id, "server_notice", Some(&body.user_id), &json!({"event_id": event_id}))
                .await;
            (StatusCode::OK, Json(json!({"event_id": event_id}))).into_response()
        }
        Err(r) => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leave_targets_are_decoded() {
        assert_eq!(
            leave_target(&Method::POST, "/_matrix/client/v3/rooms/%21r%3Ahs/leave").as_deref(),
            Some("!r:hs")
        );
        assert_eq!(leave_target(&Method::POST, "/_matrix/client/v3/rooms/!r:hs/leave").as_deref(), Some("!r:hs"));
        assert!(leave_target(&Method::GET, "/_matrix/client/v3/rooms/!r:hs/leave").is_none());
        assert!(leave_target(&Method::POST, "/_matrix/client/v3/rooms/!r:hs/forget").is_none());
    }

    #[test]
    fn system_user_is_local() {
        assert!(system_user_id("hs.test").ends_with(":hs.test"));
    }
}
