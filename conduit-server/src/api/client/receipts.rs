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
        Ok(Some(event)) if event.room_id == room_id => event,
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

    state.sync_notify().notify_waiters();
    (StatusCode::OK, Json(json!({}))).into_response()
}
