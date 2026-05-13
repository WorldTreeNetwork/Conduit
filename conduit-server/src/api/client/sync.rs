//! `GET /_matrix/client/v3/sync` handler.
//!
//! Implements:
//!   - il0.14: full sync (no `since`)
//!   - il0.15: incremental sync + long-poll (`since` + `timeout`)
//!   - il0.16: best-effort filter support (`room.timeline.limit`, `.types`, `.rooms`)
//!   - il0.17: stream-position token format `"s<position>"`

use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::Duration;

use conduit::state_events::{Membership, parse_member};

use super::{AuthState, AuthedUser, MatrixError};

// ---------------------------------------------------------------------------
// Token helpers (il0.17)
// ---------------------------------------------------------------------------

/// Parse a sync `since` token of the form `"s<i64>"`.
/// Returns `None` for an absent token (initial sync).
/// Returns `Err` with a 400 response for a malformed token.
fn parse_since(raw: &str) -> Result<i64, Response> {
    let digits = raw.strip_prefix('s').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errcode": "M_INVALID_PARAM",
                "error": "invalid since token: must start with 's'"
            })),
        )
            .into_response()
    })?;
    digits.parse::<i64>().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errcode": "M_INVALID_PARAM",
                "error": "invalid since token: non-numeric position"
            })),
        )
            .into_response()
    })
}

fn encode_token(pos: i64) -> String {
    format!("s{pos}")
}

// ---------------------------------------------------------------------------
// Filter parsing (il0.16 — best-effort)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct SyncFilter {
    /// Max number of timeline events per room. Default 10.
    timeline_limit: i64,
    /// If non-empty, only include these event types in timeline.
    timeline_types: Vec<String>,
    /// If non-empty, only include these room IDs.
    rooms: Vec<String>,
}

fn parse_filter(raw: &str) -> SyncFilter {
    let mut f = SyncFilter { timeline_limit: 10, ..Default::default() };
    // If it parses as JSON use it; otherwise treat as an opaque filter ID
    // (stored filters not yet implemented — return defaults).
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        return f;
    };
    if let Some(limit) = v.pointer("/room/timeline/limit").and_then(Value::as_i64) {
        f.timeline_limit = limit.max(1).min(500);
    }
    if let Some(types) = v.pointer("/room/timeline/types").and_then(Value::as_array) {
        f.timeline_types = types
            .iter()
            .filter_map(|t| t.as_str().map(str::to_owned))
            .collect();
    }
    if let Some(rooms) = v.pointer("/room/rooms").and_then(Value::as_array) {
        f.rooms = rooms
            .iter()
            .filter_map(|r| r.as_str().map(str::to_owned))
            .collect();
    }
    f
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SyncQuery {
    pub since: Option<String>,
    /// Long-poll timeout in milliseconds. 0 = no wait (default).
    pub timeout: Option<u64>,
    pub filter: Option<String>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TimelineBlock {
    events: Vec<Value>,
    limited: bool,
    prev_batch: String,
}

#[derive(Serialize)]
struct StateBlock {
    events: Vec<Value>,
}

#[derive(Serialize)]
struct EphemeralBlock {
    events: Vec<Value>,
}

#[derive(Serialize)]
struct AccountDataBlock {
    events: Vec<Value>,
}

#[derive(Serialize)]
struct UnreadNotifications {
    highlight_count: u64,
    notification_count: u64,
}

#[derive(Serialize)]
struct JoinedRoomBlock {
    timeline: TimelineBlock,
    state: StateBlock,
    account_data: AccountDataBlock,
    ephemeral: EphemeralBlock,
    unread_notifications: UnreadNotifications,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub async fn sync<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(query): Query<SyncQuery>,
) -> Response {
    let user_id = &authed.user_id;
    let storage = state.storage();

    // Parse filter (best-effort).
    let filter = query
        .filter
        .as_deref()
        .map(parse_filter)
        .unwrap_or_else(|| SyncFilter { timeline_limit: 10, ..Default::default() });

    // Parse `since` token.
    let since_pos: Option<i64> = match &query.since {
        None => None,
        Some(raw) => match parse_since(raw) {
            Ok(pos) => Some(pos),
            Err(resp) => return resp,
        },
    };

    // Clamp timeout: 0–30000 ms.
    let timeout_ms = query.timeout.unwrap_or(0).min(30_000);

    // -------------------------------------------------------------------
    // Long-poll: if incremental and no new events, wait up to `timeout`.
    // -------------------------------------------------------------------
    let since = since_pos.unwrap_or(0);

    if since_pos.is_some() && timeout_ms > 0 {
        // Subscribe before checking for events to avoid a race.
        let mut rx = state.events_tx().subscribe();

        // Check if there are already new events.
        let has_new = match storage.events_since(since, 1).await {
            Ok(evs) => !evs.is_empty(),
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        };

        if !has_new {
            // Block until an event arrives or timeout fires.
            let sleep = tokio::time::sleep(Duration::from_millis(timeout_ms));
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    biased;
                    result = rx.recv() => {
                        match result {
                            Ok(new_pos) if new_pos > since => break,
                            Ok(_) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => break,
                            Err(_) => break,
                        }
                    }
                    _ = &mut sleep => break,
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Build response
    // -------------------------------------------------------------------
    build_sync_response(&state, user_id, since_pos, &filter).await
}

async fn build_sync_response<S: AuthState>(
    state: &S,
    user_id: &str,
    since_pos: Option<i64>,
    filter: &SyncFilter,
) -> Response {
    let storage = state.storage();

    // Find the rooms where the user is currently joined.
    // Strategy: scan events_since(0) is expensive; instead we need to find
    // all rooms the user has a m.room.member state event with membership=join.
    // We do this by fetching events_since to find rooms the user interacts with,
    // but for correctness we use a different approach:
    // Get all events globally since 0 and filter by membership state.
    //
    // For initial sync: get all events, find rooms where user is joined.
    // For incremental: get events since `since`.
    let since = since_pos.unwrap_or(0);

    // Collect all new events since `since` (large limit for correctness; v0).
    let new_events = match storage.events_since(since, 10_000).await {
        Ok(evs) => evs,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };

    // Determine which rooms to include: rooms where user is currently joined.
    // We check current state for every room that has any new event.
    let new_event_room_ids: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        new_events.iter().for_each(|e| { seen.insert(e.room_id.clone()); });
        seen.into_iter().collect()
    };

    // For initial sync, we also need rooms with no new events but where user
    // was already joined. We find those by scanning all events (since=0).
    // For incremental sync we only include rooms with new activity.
    let all_rooms_to_check: Vec<String> = if since_pos.is_none() {
        // Initial: check all rooms with any events.
        match storage.events_since(0, 100_000).await {
            Ok(evs) => {
                let mut seen = std::collections::HashSet::new();
                evs.iter().for_each(|e| { seen.insert(e.room_id.clone()); });
                seen.into_iter().collect()
            }
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        }
    } else {
        new_event_room_ids.clone()
    };

    // Apply room filter.
    let rooms_to_check: Vec<String> = if filter.rooms.is_empty() {
        all_rooms_to_check
    } else {
        all_rooms_to_check
            .into_iter()
            .filter(|r| filter.rooms.contains(r))
            .collect()
    };

    // For each room, check if user is currently joined.
    let mut joined_rooms: HashMap<String, JoinedRoomBlock> = HashMap::new();

    for room_id in &rooms_to_check {
        // Check current membership.
        let member_ev = match storage
            .get_state_entry(room_id, "m.room.member", user_id)
            .await
        {
            Ok(ev) => ev,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        };

        let is_joined = member_ev
            .as_ref()
            .and_then(|ev| parse_member(&ev.content).ok())
            .map(|mc| mc.membership == Membership::Join)
            .unwrap_or(false);

        if !is_joined {
            continue;
        }

        let block = if since_pos.is_none() {
            // Initial sync: state = current state, timeline = recent events.
            match build_initial_room_block(state, room_id, filter).await {
                Ok(b) => b,
                Err(resp) => return resp,
            }
        } else {
            // Incremental: state = empty, timeline = new events since `since`.
            build_incremental_room_block(
                room_id,
                &new_events,
                since,
                filter,
            )
        };

        joined_rooms.insert(room_id.clone(), block);
    }

    // Compute next_batch.
    let next_pos = match storage.global_max_stream_position().await {
        Ok(p) => p,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let next_batch = encode_token(next_pos);

    let rooms_obj = json!({
        "join": joined_rooms,
        "invite": {},
        "leave":  {},
        "knock":  {}
    });

    (
        StatusCode::OK,
        Json(json!({
            "next_batch": next_batch,
            "rooms": rooms_obj,
            "presence":     { "events": [] },
            "account_data": { "events": [] },
            "to_device":    { "events": [] },
            "device_lists": { "changed": [], "left": [] },
            "device_one_time_keys_count": {}
        })),
    )
        .into_response()
}

/// Build a room block for initial sync.
async fn build_initial_room_block<S: AuthState>(
    state: &S,
    room_id: &str,
    filter: &SyncFilter,
) -> Result<JoinedRoomBlock, Response> {
    let storage = state.storage();

    // Current state events (all of them — for initial sync).
    let state_events = storage.get_current_state(room_id).await.map_err(|e| {
        MatrixError::unknown(e.to_string()).into_response()
    })?;

    // Recent timeline events (newest N, backwards).
    let latest_pos = storage
        .room_latest_stream_position(room_id)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?
        .unwrap_or(0);

    let (raw_timeline, _next) = storage
        .room_events_paginated(room_id, 'b', latest_pos, filter.timeline_limit)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?;

    // Reverse to chronological order.
    let mut timeline_events = raw_timeline;
    timeline_events.reverse();

    // Apply type filter.
    let timeline_events = apply_type_filter(timeline_events, filter);

    let prev_batch_pos = timeline_events
        .first()
        .map(|e| e.depth)
        .unwrap_or(0);

    let timeline_values: Vec<Value> = timeline_events
        .iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();

    let state_values: Vec<Value> = state_events
        .iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();

    Ok(JoinedRoomBlock {
        timeline: TimelineBlock {
            events: timeline_values,
            limited: false,
            prev_batch: encode_token(prev_batch_pos),
        },
        state: StateBlock { events: state_values },
        account_data: AccountDataBlock { events: vec![] },
        ephemeral: EphemeralBlock { events: vec![] },
        unread_notifications: UnreadNotifications {
            highlight_count: 0,
            notification_count: 0,
        },
    })
}

/// Build a room block for incremental sync from pre-fetched new events.
fn build_incremental_room_block(
    room_id: &str,
    new_events: &[conduit::event::Event],
    since: i64,
    filter: &SyncFilter,
) -> JoinedRoomBlock {
    let mut room_events: Vec<conduit::event::Event> = new_events
        .iter()
        .filter(|e| e.room_id == room_id)
        .cloned()
        .collect();

    // Apply type filter.
    room_events = apply_type_filter(room_events, filter);

    // Cap to timeline_limit (take most-recent).
    let limited = room_events.len() > filter.timeline_limit as usize;
    if limited {
        let start = room_events.len() - filter.timeline_limit as usize;
        room_events = room_events[start..].to_vec();
    }

    let prev_batch = encode_token(since);

    let timeline_values: Vec<Value> = room_events
        .iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();

    JoinedRoomBlock {
        timeline: TimelineBlock {
            events: timeline_values,
            limited,
            prev_batch,
        },
        state: StateBlock { events: vec![] },
        account_data: AccountDataBlock { events: vec![] },
        ephemeral: EphemeralBlock { events: vec![] },
        unread_notifications: UnreadNotifications {
            highlight_count: 0,
            notification_count: 0,
        },
    }
}

fn apply_type_filter(
    events: Vec<conduit::event::Event>,
    filter: &SyncFilter,
) -> Vec<conduit::event::Event> {
    if filter.timeline_types.is_empty() {
        events
    } else {
        events
            .into_iter()
            .filter(|e| filter.timeline_types.contains(&e.event_type))
            .collect()
    }
}
