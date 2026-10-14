//! Deprecated-but-present client endpoints (Matrix v1.19; conduit-y99.42).
//!
//! GET /_matrix/client/v3/events                  legacy event stream
//! GET /_matrix/client/v3/events?room_id=         room previews (peeking)
//! GET /_matrix/client/v3/events/{eventId}        one event by ID
//! GET /_matrix/client/v3/initialSync             legacy full sync
//! GET /_matrix/client/v3/rooms/{roomId}/initialSync   one room (peeking)
//!
//! Stream tokens are `s{position}` over the global event stream, the same
//! form `/messages` accepts.  Every event is filtered by history
//! visibility at that event (`filter_visible_for_user`), so a peeker sees
//! only events whose room was `world_readable` for them, and ignored
//! senders and redactions are applied as on every other read path.

use std::collections::HashMap;
use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};

use conduit::event::Event;

use super::room_content::serve::Viewer;
use super::room_content::{
    invalid_param, not_found, parse_position, position_token, state_at, storage_error,
    visible_events, RoomAccess,
};
use super::{AuthState, AuthedUser, MatrixError};

/// Longest a legacy `/events` request may block.
const MAX_TIMEOUT_MS: u64 = 30_000;
/// Events scanned per `/events` request.
const SCAN_LIMIT: i64 = 500;

pub fn router<S: AuthState>() -> Router<S> {
    Router::new()
        .route("/_matrix/client/v3/events", get(events::<S>))
        .route("/_matrix/client/v3/events/:eventId", get(event_by_id::<S>))
        .route("/_matrix/client/v3/initialSync", get(initial_sync::<S>))
        .route("/_matrix/client/v3/rooms/:roomId/initialSync", get(room_initial_sync::<S>))
}

async fn serve(storage: &dyn conduit::storage::Storage, user_id: &str, events: Vec<Event>) -> Result<Vec<Value>, Response> {
    let viewer = Viewer::load(storage, user_id).await.map_err(storage_error)?;
    let events = viewer.without_ignored(events);
    let mut values: Vec<Value> = events
        .into_iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();
    viewer.decorate_values(&mut values, true).await.map_err(storage_error)?;
    Ok(values)
}

// ---------------------------------------------------------------------------
// GET /events
// ---------------------------------------------------------------------------

/// Events after `from` the user may see: in rooms they are (or were)
/// in, or in `peek_room` only when peeking.  Returns the served chunk and
/// the position scanned up to.
async fn stream_after<S: AuthState>(
    state: &S,
    user_id: &str,
    from: i64,
    peek_room: Option<&str>,
) -> Result<(Vec<Value>, i64), Response> {
    let storage = state.storage().as_ref();
    let batch = storage.events_since(from, SCAN_LIMIT).await.map_err(storage_error)?;
    if batch.is_empty() {
        return Ok((Vec::new(), from));
    }
    let ids: Vec<String> = batch.iter().map(|e| e.event_id.clone()).collect();
    let positions = storage.event_stream_positions(&ids).await.map_err(storage_error)?;
    let end = positions.values().copied().max().unwrap_or(from).max(from);

    let mut by_room: Vec<(String, Vec<Event>)> = Vec::new();
    for event in batch {
        if peek_room.is_some_and(|r| r != event.room_id) {
            continue;
        }
        match by_room.iter_mut().find(|(r, _)| *r == event.room_id) {
            Some((_, list)) => list.push(event),
            None => by_room.push((event.room_id.clone(), vec![event])),
        }
    }
    let mut visible = Vec::new();
    for (room_id, events) in by_room {
        let access = RoomAccess::load(storage, &room_id, user_id).await.map_err(storage_error)?;
        if peek_room.is_none() && access.membership.is_none() {
            // The plain stream covers rooms the user has a membership in;
            // other world-readable rooms are only streamed when peeked.
            continue;
        }
        visible.extend(
            visible_events(storage, &access, &room_id, user_id, events)
                .await
                .map_err(storage_error)?,
        );
    }
    visible.sort_by_key(|e| positions.get(&e.event_id).copied().unwrap_or(0));
    Ok((serve(storage, user_id, visible).await?, end))
}

pub async fn events<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let storage = state.storage();
    let peek_room = query.get("room_id").cloned();
    if let Some(room_id) = &peek_room {
        // Peeking: allowed for members and for world-readable rooms.
        let access = match RoomAccess::load(storage.as_ref(), room_id, &authed.user_id).await {
            Ok(a) => a,
            Err(e) => return storage_error(e),
        };
        if !access.may_read_history() {
            return MatrixError::forbidden("You may not peek into this room").into_response();
        }
    }
    let from = match query.get("from") {
        Some(token) => match parse_position(token) {
            Some(p) => p,
            None => return invalid_param("Bad pagination from parameter"),
        },
        None => match storage.global_max_stream_position().await {
            Ok(p) => p,
            Err(e) => return storage_error(e),
        },
    };
    let timeout_ms = match query.get("timeout") {
        None => 0,
        Some(raw) => match raw.parse::<u64>() {
            Ok(t) => t.min(MAX_TIMEOUT_MS),
            Err(_) => return invalid_param("timeout must be a non-negative integer"),
        },
    };

    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut wake = state.events_tx().subscribe();
    let mut cursor = from;
    loop {
        let (chunk, end) = match stream_after(&state, &authed.user_id, cursor, peek_room.as_deref()).await {
            Ok(r) => r,
            Err(r) => return r,
        };
        cursor = end;
        if !chunk.is_empty() || tokio::time::Instant::now() >= deadline {
            return (
                StatusCode::OK,
                Json(json!({
                    "start": position_token(from),
                    "end": position_token(cursor),
                    "chunk": chunk,
                })),
            )
                .into_response();
        }
        if tokio::time::timeout_at(deadline, wake.recv()).await.is_err() {
            continue; // deadline: one last scan, then answer
        }
    }
}

// ---------------------------------------------------------------------------
// GET /events/{eventId}
// ---------------------------------------------------------------------------

pub async fn event_by_id<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(event_id): Path<String>,
) -> Response {
    let storage = state.storage().as_ref();
    let event = match storage.get_event(&event_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return not_found("Event not found."),
        Err(e) => return storage_error(e),
    };
    let access = match RoomAccess::load(storage, &event.room_id, &authed.user_id).await {
        Ok(a) => a,
        Err(e) => return storage_error(e),
    };
    let room_id = event.room_id.clone();
    let visible = match visible_events(storage, &access, &room_id, &authed.user_id, vec![event]).await {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    if visible.is_empty() {
        // Spec: 404 also when the user may not read the event.
        return not_found("Event not found.");
    }
    match serve(storage, &authed.user_id, visible).await {
        Ok(mut values) => (StatusCode::OK, Json(values.remove(0))).into_response(),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------------------
// initialSync
// ---------------------------------------------------------------------------

/// One `RoomInfo`: membership, recent messages, state, visibility and
/// room account data, as of the user's departure when they left.
async fn room_info<S: AuthState>(
    state: &S,
    user_id: &str,
    room_id: &str,
    access: &RoomAccess,
    limit: usize,
) -> Result<Value, Response> {
    let storage = state.storage().as_ref();
    let mut info = json!({ "room_id": room_id });
    if let Some(m) = &access.membership {
        info["membership"] = json!(m);
    }
    if access.membership.as_deref() == Some("invite") {
        if let Some(member) = &access.member {
            info["invite"] = serde_json::to_value(member).unwrap_or(Value::Null);
        }
        return Ok(info);
    }
    let horizon = access.state_horizon();
    let rows = storage.room_events_with_positions(room_id).await.map_err(storage_error)?;
    let rows: Vec<(i64, Event)> = rows
        .into_iter()
        .filter(|(pos, _)| horizon.is_none_or(|h| *pos <= h))
        .collect();
    let positions: HashMap<String, i64> = rows.iter().map(|(p, e)| (e.event_id.clone(), *p)).collect();
    let events: Vec<Event> = rows.into_iter().map(|(_, e)| e).collect();
    let mut visible = visible_events(storage, access, room_id, user_id, events)
        .await
        .map_err(storage_error)?;
    let skip = visible.len().saturating_sub(limit);
    let recent: Vec<Event> = visible.drain(skip..).collect();
    let first = recent.first().and_then(|e| positions.get(&e.event_id)).copied();
    let last = recent.last().and_then(|e| positions.get(&e.event_id)).copied();
    let chunk = serve(storage, user_id, recent).await?;
    let mut messages = json!({
        "chunk": chunk,
        "end": position_token(last.map(|p| p + 1).unwrap_or(0)),
    });
    if let Some(first) = first.filter(|p| *p > 0) {
        messages["start"] = json!(position_token(first - 1));
    }
    info["messages"] = messages;
    let room_state = state_at(storage, room_id, horizon).await.map_err(storage_error)?;
    info["state"] = json!(room_state);
    let published = storage.is_room_published(room_id).await.map_err(storage_error)?;
    info["visibility"] = json!(if published { "public" } else { "private" });
    if access.membership.is_some() {
        let mut account_data = Vec::new();
        for event_type in ["m.tag", "m.fully_read"] {
            if let Some(content) = storage
                .get_account_data(user_id, Some(room_id), event_type)
                .await
                .map_err(storage_error)?
            {
                account_data.push(json!({"type": event_type, "content": content}));
            }
        }
        info["account_data"] = json!(account_data);
    }
    Ok(info)
}

fn limit_of(query: &HashMap<String, String>) -> Option<usize> {
    match query.get("limit") {
        None => Some(10),
        Some(raw) => match raw.parse::<i64>() {
            Ok(n) if n >= 0 => Some((n as usize).min(100)),
            _ => None,
        },
    }
}

pub async fn initial_sync<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(limit) = limit_of(&query) else {
        return invalid_param("limit must be a non-negative integer");
    };
    let archived = query.get("archived").is_some_and(|v| v == "true");
    let storage = state.storage().as_ref();
    let end = match storage.global_max_stream_position().await {
        Ok(p) => p,
        Err(e) => return storage_error(e),
    };
    let memberships = match storage.current_memberships(&authed.user_id).await {
        Ok(m) => m,
        Err(e) => return storage_error(e),
    };
    let mut rooms = Vec::new();
    for member in memberships {
        let room_id = member.room_id.clone();
        let access = match RoomAccess::load(storage, &room_id, &authed.user_id).await {
            Ok(a) => a,
            Err(e) => return storage_error(e),
        };
        let wanted = match access.membership.as_deref() {
            Some("join" | "invite") => true,
            Some("leave" | "ban") => archived && !access.forgotten,
            _ => false,
        };
        if !wanted {
            continue;
        }
        match room_info(&state, &authed.user_id, &room_id, &access, limit).await {
            Ok(info) => rooms.push(info),
            Err(r) => return r,
        }
    }
    let presence: Vec<Value> = state
        .presence_store()
        .all_entries()
        .await
        .into_iter()
        .filter(|(user, _)| *user == authed.user_id)
        .map(|(user, entry)| {
            json!({"type": "m.presence", "sender": user, "content": {
                "presence": entry.effective_presence(),
                "last_active_ago": entry.last_changed_at.elapsed().as_millis() as u64,
            }})
        })
        .collect();
    let mut account_data = Vec::new();
    for event_type in ["m.push_rules", "m.direct", "m.ignored_user_list"] {
        if let Ok(Some(content)) = storage.get_account_data(&authed.user_id, None, event_type).await {
            account_data.push(json!({"type": event_type, "content": content}));
        }
    }
    (
        StatusCode::OK,
        Json(json!({
            "end": position_token(end),
            "rooms": rooms,
            "presence": presence,
            "account_data": account_data,
        })),
    )
        .into_response()
}

pub async fn room_initial_sync<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(limit) = limit_of(&query) else {
        return invalid_param("limit must be a non-negative integer");
    };
    let storage = state.storage().as_ref();
    let access = match RoomAccess::load(storage, &room_id, &authed.user_id).await {
        Ok(a) => a,
        Err(e) => return storage_error(e),
    };
    // Members, past members (unless forgotten) and peekers of
    // world-readable rooms; anyone else is 403 (spec).
    if !access.may_read_history() {
        return MatrixError::forbidden("You aren't a member of the room and weren't previously a member of the room.")
            .into_response();
    }
    match room_info(&state, &authed.user_id, &room_id, &access, limit).await {
        Ok(info) => (StatusCode::OK, Json(info)).into_response(),
        Err(r) => r,
    }
}
