//! Receipt handler (1mo.6, conduit-y99.15).
//!
//! POST /_matrix/client/v3/rooms/:roomId/receipt/:receiptType/:eventId
//!
//! Receipt types `m.read` and `m.read.private`, each unthreaded or scoped to
//! a thread (`thread_id`: `main` or a thread root event ID). Scopes coexist:
//! one receipt per `(user, type, thread)`. `m.fully_read` is the read-marker
//! alias owned by the read-markers handler.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::{json, Value};

use super::{AuthState, AuthedUser, MatrixError};

fn invalid_param(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"errcode": "M_INVALID_PARAM", "error": message.into()})),
    )
        .into_response()
}

/// Maximum relation hops followed when deciding which thread an event is in
/// (the spec recommends three).
const THREAD_HOPS: usize = 3;

/// A version-12 create PDU omits `room_id`; the room id is that event id
/// with the `$` sigil replaced by `!`. Every other event carries `room_id`.
fn event_belongs_to_room(event: &conduit::event::Event, room_id: &str) -> bool {
    if event.room_id == room_id {
        return true;
    }
    event.room_id.is_empty() && conduit::room_version::room_id_from_event_id(&event.event_id) == room_id
}

/// The thread an event belongs to: `None` for the main timeline, or the
/// thread root's event ID.
pub(crate) async fn thread_of(
    storage: &dyn conduit::storage::Storage,
    event: &conduit::event::Event,
) -> conduit::Result<Option<String>> {
    let mut current = event.clone();
    for _ in 0..THREAD_HOPS {
        let relation = &current.content["m.relates_to"];
        let Some(parent) = relation["event_id"].as_str() else {
            return Ok(None);
        };
        if relation["rel_type"] == "m.thread" {
            return Ok(Some(parent.to_owned()));
        }
        match storage.get_event(parent).await? {
            Some(parent) if parent.room_id == event.room_id => current = parent,
            _ => return Ok(None),
        }
    }
    Ok(None)
}

pub async fn post_receipt<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, receipt_type, event_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Response {
    // The body is optional; when present it must be a JSON object.
    let body: Value = if body.iter().all(u8::is_ascii_whitespace) {
        json!({})
    } else {
        match serde_json::from_slice::<Value>(&body) {
            Ok(value) if value.is_object() => value,
            Ok(_) => return MatrixError::bad_json("receipt body must be a JSON object").into_response(),
            Err(error) => return MatrixError::bad_json(error.to_string()).into_response(),
        }
    };
    let thread_id = match body.get("thread_id") {
        None => None,
        Some(Value::String(thread)) if !thread.is_empty() => Some(thread.clone()),
        Some(_) => return invalid_param("thread_id field must be a non-empty string"),
    };

    match receipt_type.as_str() {
        "m.read" | "m.read.private" => {}
        "m.fully_read" => {
            return invalid_param("m.fully_read is set through /read_markers")
        }
        other => return invalid_param(format!("unsupported receipt type: {other}")),
    }

    let storage = state.storage();
    // Only current members may acknowledge events in a room.
    let joined = match storage
        .get_state_entry(&room_id, "m.room.member", &authed.user_id)
        .await
    {
        Ok(member) => member.is_some_and(|event| event.content["membership"] == "join"),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    if !joined {
        return MatrixError::forbidden("you are not joined to this room").into_response();
    }
    let event = match storage.get_event(&event_id).await {
        Ok(Some(event)) if event_belongs_to_room(&event, &room_id) => event,
        Ok(_) => return MatrixError::new_not_found("event not found in this room").into_response(),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };

    // A threaded receipt must name the thread the event is in. A thread
    // root is in the main timeline, and may also anchor its own thread.
    if let Some(thread) = &thread_id {
        let actual = match thread_of(storage.as_ref(), &event).await {
            Ok(actual) => actual,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        };
        let related = if thread == "main" {
            actual.is_none()
        } else {
            actual.as_deref() == Some(thread.as_str()) || (actual.is_none() && event.event_id == *thread)
        };
        if !related {
            return invalid_param("the event is not related to the thread_id");
        }
    }

    let ts = Utc::now().timestamp_millis();
    if let Err(e) = storage
        .set_threaded_receipt(&room_id, &authed.user_id, &receipt_type, thread_id.as_deref(), &event_id, ts)
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }

    // Public read receipts are deltas for the other servers in the room.
    // `m.read.private` stays on this homeserver.
    if let Some(queue) = state.federation_queue() {
        fanout_receipt(
            storage,
            queue,
            state.server_name(),
            &room_id,
            &authed.user_id,
            &receipt_type,
            thread_id.as_deref(),
            &event_id,
            ts,
        )
        .await;
    }

    state.sync_notify().notify_waiters();
    (StatusCode::OK, Json(json!({}))).into_response()
}

/// Apply an inbound `m.receipt` EDU. Only listed `m.read` entries change;
/// anything not in the EDU, including private receipts, is left alone. A
/// room the ACL denies is skipped. The user must belong to `origin` and be
/// joined.
pub(crate) async fn apply_inbound_receipt(
    storage: &dyn conduit::storage::Storage,
    origin: &str,
    edu: &Value,
) -> conduit::Result<()> {
    let Some(content) = edu.get("content").and_then(Value::as_object) else {
        return Ok(());
    };
    for (room_id, room_receipts) in content {
        if !conduit::server_acl::server_allowed_by_room(storage, room_id, origin).await? {
            continue;
        }
        let Some(room_receipts) = room_receipts.as_object() else { continue };
        for (receipt_type, users) in room_receipts {
            if receipt_type != "m.read" {
                continue;
            }
            let Some(users) = users.as_object() else { continue };
            for (user_id, body) in users {
                if conduit::signing::server_of_user_id(user_id) != Some(origin) {
                    continue;
                }
                let joined = storage
                    .get_state_entry(room_id, "m.room.member", user_id)
                    .await?
                    .is_some_and(|event| event.content.get("membership").and_then(Value::as_str) == Some("join"));
                if !joined {
                    continue;
                }
                let Some(event_id) = body
                    .get("event_ids")
                    .and_then(Value::as_array)
                    .and_then(|ids| ids.iter().find_map(Value::as_str))
                else {
                    continue;
                };
                let data = body.get("data");
                let thread_id = match data.and_then(|data| data.get("thread_id")) {
                    None | Some(Value::Null) => None,
                    Some(Value::String(thread)) if !thread.is_empty() => Some(thread.as_str()),
                    Some(_) => continue,
                };
                let ts = data
                    .and_then(|data| data.get("ts"))
                    .and_then(Value::as_i64)
                    .unwrap_or_else(|| Utc::now().timestamp_millis());
                storage
                    .set_threaded_receipt(room_id, user_id, "m.read", thread_id, event_id, ts)
                    .await?;
            }
        }
    }
    Ok(())
}

/// Send one public read-receipt delta to every other server with a joined member.
pub(crate) async fn fanout_receipt(
    storage: &std::sync::Arc<dyn conduit::storage::Storage>,
    queue: &crate::federation::Queue,
    server_name: &str,
    room_id: &str,
    user_id: &str,
    receipt_type: &str,
    thread_id: Option<&str>,
    event_id: &str,
    ts: i64,
) {
    if receipt_type != "m.read" {
        return;
    }
    let servers = match storage.joined_remote_servers(room_id, server_name).await {
        Ok(servers) => servers,
        Err(error) => {
            tracing::warn!(%error, "receipt federation fanout skipped");
            return;
        }
    };
    if servers.is_empty() {
        return;
    }
    let mut data = json!({ "ts": ts });
    if let Some(thread) = thread_id {
        data["thread_id"] = json!(thread);
    }
    let edu = json!({
        "edu_type": "m.receipt",
        "content": {
            room_id: {
                "m.read": {
                    user_id: {
                        "event_ids": [event_id],
                        "data": data,
                    }
                }
            }
        }
    });
    for dest in servers {
        queue.enqueue(&dest, vec![], vec![edu.clone()]).await;
    }
}
