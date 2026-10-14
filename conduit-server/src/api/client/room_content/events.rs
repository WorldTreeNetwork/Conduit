//! Single events, members, context, joined rooms, forget, read markers,
//! tags and timestamp lookup (conduit-y99.19).

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::{json, Value};

use conduit::event::Event;
use conduit::filter::RoomEventFilter;

use super::serve::Viewer;
use super::{
    error, invalid_param, not_found, parse_position, position_token, state_at,
    storage_error, visible_events, RoomAccess,
};
use crate::api::client::{AuthState, AuthedUser, MatrixError};

/// Fetch `event_id` from `room_id` if the user may see it.
pub(crate) async fn visible_event(
    storage: &dyn conduit::storage::Storage,
    access: &RoomAccess,
    room_id: &str,
    user_id: &str,
    event_id: &str,
) -> Result<Option<Event>, Response> {
    let Some(event) = storage.get_event(event_id).await.map_err(storage_error)? else {
        return Ok(None);
    };
    if event.room_id != room_id {
        return Ok(None);
    }
    Ok(visible_events(storage, access, room_id, user_id, vec![event])
        .await
        .map_err(storage_error)?
        .pop())
}

// ---------------------------------------------------------------------------
// GET /rooms/:roomId/event/:eventId
// ---------------------------------------------------------------------------

pub async fn get_event<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_id)): Path<(String, String)>,
) -> Response {
    let storage = state.storage().as_ref();
    let access = match RoomAccess::load(storage, &room_id, &authed.user_id).await {
        Ok(access) => access,
        Err(e) => return storage_error(e),
    };
    // Spec: 404 both when the event is unknown and when the user may not
    // see it, so the response does not leak existence.
    let event = match visible_event(storage, &access, &room_id, &authed.user_id, &event_id).await {
        Ok(Some(event)) => event,
        Ok(None) => return not_found("Event not found."),
        Err(response) => return response,
    };
    let viewer = match Viewer::load(storage, &authed.user_id).await {
        Ok(viewer) => viewer,
        Err(e) => return storage_error(e),
    };
    match viewer.serve_one(&event, true).await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(e) => storage_error(e),
    }
}

// ---------------------------------------------------------------------------
// GET /rooms/:roomId/members
// ---------------------------------------------------------------------------

const MEMBERSHIPS: [&str; 5] = ["join", "invite", "knock", "leave", "ban"];

pub async fn get_members<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let storage = state.storage().as_ref();
    for name in ["membership", "not_membership"] {
        if let Some(value) = query.get(name) {
            if !MEMBERSHIPS.contains(&value.as_str()) {
                return invalid_param(format!("{name} must be one of {MEMBERSHIPS:?}"));
            }
        }
    }
    let access = match RoomAccess::load(storage, &room_id, &authed.user_id).await {
        Ok(access) => access,
        Err(e) => return storage_error(e),
    };
    // Joined (or peeking a world-readable room): current members. Left:
    // the members as of the departure. Anyone else: 403.
    let horizon = if access.is_joined() || access.world_readable {
        None
    } else if access.departed() {
        access.member_position
    } else {
        return MatrixError::forbidden(format!(
            "{} is not and was not a member of {room_id}",
            authed.user_id
        ))
        .into_response();
    };
    let at = match query.get("at") {
        None => horizon,
        Some(token) => match parse_position(token) {
            // A token never reveals state past the user's horizon.
            Some(position) => Some(horizon.map_or(position, |limit| position.min(limit))),
            None => return invalid_param("invalid at token"),
        },
    };
    let events = match state_at(storage, &room_id, at).await {
        Ok(events) => events,
        Err(e) => return storage_error(e),
    };
    let mut members: Vec<Event> = events
        .into_iter()
        .filter(|event| event.event_type == "m.room.member")
        .filter(|event| {
            let membership = event.content.get("membership").and_then(Value::as_str).unwrap_or("");
            conduit::room_content::membership_selected(
                membership,
                query.get("membership").map(String::as_str),
                query.get("not_membership").map(String::as_str),
            )
        })
        .collect();
    members.sort_by(|a, b| a.state_key.cmp(&b.state_key));
    let viewer = Viewer { storage, user_id: &authed.user_id, ignored: HashSet::new() };
    match viewer.serve(&members, false).await {
        Ok(chunk) => (StatusCode::OK, Json(json!({"chunk": chunk}))).into_response(),
        Err(e) => storage_error(e),
    }
}

// ---------------------------------------------------------------------------
// GET /rooms/:roomId/context/:eventId
// ---------------------------------------------------------------------------

/// Collect up to `want` visible events on one side of `start`, paging the
/// room timeline so filtering never shortens the window artificially.
/// Returns the events (nearest first) and the position of the last one
/// examined, from which pagination continues.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn collect_window(
    storage: &dyn conduit::storage::Storage,
    access: &RoomAccess,
    viewer: &Viewer<'_>,
    room_id: &str,
    dir: char,
    start: i64,
    want: usize,
    filter: Option<&RoomEventFilter>,
) -> Result<(Vec<Event>, Option<i64>), Response> {
    let mut out = Vec::new();
    let mut cursor = start;
    let mut last_examined = None;
    while out.len() < want && cursor >= 0 {
        let batch = (want - out.len()).max(10) as i64 * 2;
        let (events, next) = storage
            .room_events_paginated(room_id, dir, cursor, batch)
            .await
            .map_err(storage_error)?;
        if events.is_empty() {
            break;
        }
        let ids: Vec<String> = events.iter().map(|event| event.event_id.clone()).collect();
        let positions = storage.event_stream_positions(&ids).await.map_err(storage_error)?;
        let visible = visible_events(storage, access, room_id, viewer.user_id, events.clone())
            .await
            .map_err(storage_error)?;
        let visible: HashSet<String> = visible.into_iter().map(|event| event.event_id).collect();
        for event in events {
            if out.len() >= want {
                break;
            }
            last_examined = positions.get(&event.event_id).copied();
            let shown = visible.contains(&event.event_id)
                && !viewer.hides(&event)
                && filter.is_none_or(|filter| {
                    filter.matches(room_id, &serde_json::to_value(&event).unwrap_or(Value::Null))
                });
            if shown {
                out.push(event);
            }
        }
        match next {
            Some(next) => cursor = next,
            None => break,
        }
    }
    Ok((out, last_examined))
}

pub async fn get_context<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_id)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let storage = state.storage().as_ref();
    let limit = match query.get("limit") {
        None => 10,
        Some(raw) => match raw.parse::<i64>() {
            Ok(limit) if limit >= 0 => (limit as usize).min(100),
            _ => return invalid_param("limit must be a non-negative integer"),
        },
    };
    let filter: Option<RoomEventFilter> = match query.get("filter") {
        None => None,
        Some(raw) => match serde_json::from_str(raw) {
            Ok(filter) => Some(filter),
            Err(e) => return MatrixError::bad_json(format!("invalid filter: {e}")).into_response(),
        },
    };
    let access = match RoomAccess::load(storage, &room_id, &authed.user_id).await {
        Ok(access) => access,
        Err(e) => return storage_error(e),
    };
    let event = match visible_event(storage, &access, &room_id, &authed.user_id, &event_id).await {
        Ok(Some(event)) => event,
        Ok(None) => return not_found("Event not found."),
        Err(response) => return response,
    };
    let viewer = match Viewer::load(storage, &authed.user_id).await {
        Ok(viewer) => viewer,
        Err(e) => return storage_error(e),
    };
    let position = match storage.event_stream_positions(std::slice::from_ref(&event.event_id)).await {
        Ok(positions) => match positions.get(&event.event_id) {
            Some(position) => *position,
            None => return not_found("Event not found."),
        },
        Err(e) => return storage_error(e),
    };
    let want_before = limit / 2;
    let want_after = limit - want_before;
    let (before, before_edge) = match collect_window(
        storage, &access, &viewer, &room_id, 'b', position - 1, want_before, filter.as_ref(),
    )
    .await
    {
        Ok(window) => window,
        Err(response) => return response,
    };
    let (after, after_edge) = match collect_window(
        storage, &access, &viewer, &room_id, 'f', position + 1, want_after, filter.as_ref(),
    )
    .await
    {
        Ok(window) => window,
        Err(response) => return response,
    };
    // Tokens are /messages cursors (inclusive): start continues backwards
    // just before the earliest event examined; end continues forwards just
    // after the latest one.
    let start = before_edge.unwrap_or(position) - 1;
    let end = after_edge.unwrap_or(position) + 1;
    let latest = match after.last() {
        Some(last) => match storage.event_stream_positions(std::slice::from_ref(&last.event_id)).await {
            Ok(positions) => positions.get(&last.event_id).copied().unwrap_or(position),
            Err(e) => return storage_error(e),
        },
        None => position,
    };

    // State at the last event returned, filtered like the timeline and
    // lazily loaded when asked.
    let mut state_events = match state_at(storage, &room_id, Some(latest)).await {
        Ok(events) => events,
        Err(e) => return storage_error(e),
    };
    if let Some(filter) = &filter {
        let senders: HashSet<&str> = before
            .iter()
            .chain(after.iter())
            .chain(std::iter::once(&event))
            .map(|event| event.sender.as_str())
            .collect();
        state_events.retain(|state_event| {
            filter.matches(&room_id, &serde_json::to_value(state_event).unwrap_or(Value::Null))
                && (!filter.lazy_load_members
                    || state_event.event_type != "m.room.member"
                    || state_event.state_key.as_deref().is_some_and(|member| senders.contains(member)))
        });
    }
    let (Ok(event_value), Ok(before), Ok(after), Ok(state_values)) = (
        viewer.serve_one(&event, true).await,
        viewer.serve(&before, true).await,
        viewer.serve(&after, true).await,
        viewer.serve(&state_events, false).await,
    ) else {
        return MatrixError::unknown("failed to serve context").into_response();
    };
    (
        StatusCode::OK,
        Json(json!({
            "event": event_value,
            "events_before": before,
            "events_after": after,
            "state": state_values,
            "start": position_token(start),
            "end": position_token(end),
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /joined_rooms
// ---------------------------------------------------------------------------

pub async fn joined_rooms<S: AuthState>(State(state): State<S>, authed: AuthedUser) -> Response {
    match state.storage().joined_rooms(&authed.user_id).await {
        Ok(mut rooms) => {
            rooms.sort();
            (StatusCode::OK, Json(json!({"joined_rooms": rooms}))).into_response()
        }
        Err(e) => storage_error(e),
    }
}

// ---------------------------------------------------------------------------
// POST /rooms/:roomId/forget
// ---------------------------------------------------------------------------

pub async fn forget_room<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
) -> Response {
    let storage = state.storage().as_ref();
    let access = match RoomAccess::load(storage, &room_id, &authed.user_id).await {
        Ok(access) => access,
        Err(e) => return storage_error(e),
    };
    match (access.membership.as_deref(), &access.member) {
        (Some("leave" | "ban"), Some(member)) => {
            if let Err(e) = storage.forget_room(&authed.user_id, &room_id, &member.event_id).await {
                return storage_error(e);
            }
            state.sync_notify().notify_waiters();
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        // Nothing to forget: never a member (or the room is unknown).
        (None, _) => (StatusCode::OK, Json(json!({}))).into_response(),
        _ => error(
            StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            "The user has not left the room",
        ),
    }
}

// ---------------------------------------------------------------------------
// POST /rooms/:roomId/read_markers
// ---------------------------------------------------------------------------

pub async fn read_markers<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let storage = state.storage().as_ref();
    let Some(body) = body.as_object() else {
        return MatrixError::bad_json("request body must be an object").into_response();
    };
    let access = match RoomAccess::load(storage, &room_id, &authed.user_id).await {
        Ok(access) => access,
        Err(e) => return storage_error(e),
    };
    if !access.is_joined() {
        return MatrixError::forbidden(format!("{} is not joined to {room_id}", authed.user_id))
            .into_response();
    }
    let mut markers = Vec::new();
    for key in ["m.fully_read", "m.read", "m.read.private"] {
        match body.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::String(event_id)) => markers.push((key, event_id.clone())),
            Some(_) => return MatrixError::bad_json(format!("{key} must be an event ID")).into_response(),
        }
    }
    // Every marker must name an event of this room the user can see.
    for (_, event_id) in &markers {
        match visible_event(storage, &access, &room_id, &authed.user_id, event_id).await {
            Ok(Some(_)) => {}
            Ok(None) => return not_found(&format!("event {event_id} not found in room")),
            Err(response) => return response,
        }
    }
    let ts = Utc::now().timestamp_millis();
    for (key, event_id) in markers {
        let result = if key == "m.fully_read" {
            storage
                .set_account_data(&authed.user_id, Some(&room_id), "m.fully_read", &json!({"event_id": event_id}))
                .await
        } else {
            storage.set_receipt(&room_id, &authed.user_id, key, &event_id, ts).await
        };
        if let Err(e) = result {
            return storage_error(e);
        }
    }
    state.sync_notify().notify_waiters();
    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// Room tags: GET/PUT/DELETE /user/:userId/rooms/:roomId/tags[/:tag]
// ---------------------------------------------------------------------------

async fn load_tags(
    storage: &dyn conduit::storage::Storage,
    user_id: &str,
    room_id: &str,
) -> conduit::Result<serde_json::Map<String, Value>> {
    Ok(storage
        .get_account_data(user_id, Some(room_id), "m.tag")
        .await?
        .and_then(|content| content.get("tags").and_then(Value::as_object).cloned())
        .unwrap_or_default())
}

fn own_tags(authed: &AuthedUser, user_id: &str) -> Option<Response> {
    (authed.user_id != user_id)
        .then(|| MatrixError::forbidden("cannot access another user's tags").into_response())
}

pub async fn get_tags<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((user_id, room_id)): Path<(String, String)>,
) -> Response {
    if let Some(response) = own_tags(&authed, &user_id) {
        return response;
    }
    match load_tags(state.storage().as_ref(), &user_id, &room_id).await {
        Ok(tags) => (StatusCode::OK, Json(json!({"tags": tags}))).into_response(),
        Err(e) => storage_error(e),
    }
}

pub async fn put_tag<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Response {
    if let Some(response) = own_tags(&authed, &user_id) {
        return response;
    }
    if !body.is_object() {
        return MatrixError::bad_json("tag content must be an object").into_response();
    }
    if body.get("order").is_some_and(|order| !order.is_number()) {
        return MatrixError::bad_json("order must be a number").into_response();
    }
    if tag.len() > 255 {
        return invalid_param("tag names are at most 255 bytes");
    }
    let storage = state.storage().as_ref();
    let mut tags = match load_tags(storage, &user_id, &room_id).await {
        Ok(tags) => tags,
        Err(e) => return storage_error(e),
    };
    tags.insert(tag, body);
    if let Err(e) = storage
        .set_account_data(&user_id, Some(&room_id), "m.tag", &json!({"tags": tags}))
        .await
    {
        return storage_error(e);
    }
    state.sync_notify().notify_waiters();
    (StatusCode::OK, Json(json!({}))).into_response()
}

pub async fn delete_tag<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
) -> Response {
    if let Some(response) = own_tags(&authed, &user_id) {
        return response;
    }
    let storage = state.storage().as_ref();
    let mut tags = match load_tags(storage, &user_id, &room_id).await {
        Ok(tags) => tags,
        Err(e) => return storage_error(e),
    };
    // Deleting an absent tag succeeds (idempotent), without a sync change.
    if tags.remove(&tag).is_some() {
        if let Err(e) = storage
            .set_account_data(&user_id, Some(&room_id), "m.tag", &json!({"tags": tags}))
            .await
        {
            return storage_error(e);
        }
        state.sync_notify().notify_waiters();
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// GET /_matrix/client/v1/rooms/:roomId/timestamp_to_event
// ---------------------------------------------------------------------------

pub async fn timestamp_to_event<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let storage = state.storage().as_ref();
    let Some(ts) = query.get("ts").and_then(|raw| raw.parse::<i64>().ok()) else {
        return invalid_param("ts is required and must be an integer");
    };
    let forward = match query.get("dir").map(String::as_str) {
        Some("f") => true,
        Some("b") => false,
        _ => return invalid_param("dir is required and must be f or b"),
    };
    let access = match RoomAccess::load(storage, &room_id, &authed.user_id).await {
        Ok(access) => access,
        Err(e) => return storage_error(e),
    };
    if !access.may_read_history() {
        return MatrixError::forbidden(format!("{} cannot read {room_id}", authed.user_id))
            .into_response();
    }
    // Scan outward in batches, returning the nearest event the user can see.
    const BATCH: i64 = 50;
    let mut bound = ts;
    let mut seen: HashSet<String> = HashSet::new();
    loop {
        let candidates = match storage.events_near_timestamp(&room_id, bound, forward, BATCH).await {
            Ok(events) => events,
            Err(e) => return storage_error(e),
        };
        let fresh: Vec<Event> = candidates
            .iter()
            .filter(|event| !seen.contains(&event.event_id))
            .cloned()
            .collect();
        if fresh.is_empty() {
            return not_found("Unable to find event from the given timestamp");
        }
        seen.extend(fresh.iter().map(|event| event.event_id.clone()));
        let visible = match visible_events(storage, &access, &room_id, &authed.user_id, fresh.clone()).await {
            Ok(events) => events,
            Err(e) => return storage_error(e),
        };
        let visible: HashSet<&str> = visible.iter().map(|event| event.event_id.as_str()).collect();
        if let Some(found) = fresh.iter().find(|event| visible.contains(event.event_id.as_str())) {
            return (
                StatusCode::OK,
                Json(json!({"event_id": found.event_id, "origin_server_ts": found.origin_server_ts})),
            )
                .into_response();
        }
        // Continue from the farthest timestamp examined (ties included; the
        // `seen` set skips repeats).
        bound = fresh.last().map(|event| event.origin_server_ts as i64).unwrap_or(bound);
        if (candidates.len() as i64) < BATCH {
            return not_found("Unable to find event from the given timestamp");
        }
    }
}

