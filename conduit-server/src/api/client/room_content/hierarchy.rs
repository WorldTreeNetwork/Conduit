//! GET /_matrix/client/v1/rooms/:roomId/hierarchy (conduit-y99.19).
//!
//! Depth-first walk over valid `m.space.child` state (non-empty `via`),
//! children ordered per the spec (`order`, then `origin_server_ts`, then
//! room ID). A room is listed when the requesting user is joined or
//! invited, may join it (public, or restricted with a satisfied
//! condition), may knock, or it is world-readable. Only rooms known to
//! this server are described: filling unknown children over federation is
//! tracked separately (see docs/features/client-server-api.md).

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use conduit::auth::StateMap;
use conduit::event::Event;
use conduit::room_content::{is_valid_space_child, space_child_ordering};
use conduit::storage::Storage;

use super::{invalid_param, limit_param, storage_error};
use crate::api::client::{AuthState, AuthedUser, MatrixError};

const DEFAULT_MAX_DEPTH: usize = 10;

fn get<'a>(state: &'a StateMap<Event>, kind: &str) -> Option<&'a Event> {
    state.get(&(kind.to_owned(), String::new()))
}

fn content_str<'a>(state: &'a StateMap<Event>, kind: &str, field: &str) -> Option<&'a str> {
    get(state, kind).and_then(|event| event.content.get(field)).and_then(Value::as_str)
}

/// Rooms of a restricted join rule's `m.room_membership` conditions.
fn allowed_room_ids(state: &StateMap<Event>) -> Vec<String> {
    get(state, "m.room.join_rules")
        .and_then(|event| event.content.get("allow"))
        .and_then(Value::as_array)
        .map(|allow| {
            allow
                .iter()
                .filter(|rule| rule["type"] == "m.room_membership")
                .filter_map(|rule| rule["room_id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// May the user see this room in a hierarchy (spec list for `rooms`)?
async fn accessible(
    storage: &dyn Storage,
    state: &StateMap<Event>,
    user_id: &str,
) -> conduit::Result<bool> {
    let membership = state
        .get(&("m.room.member".to_owned(), user_id.to_owned()))
        .and_then(|event| event.content["membership"].as_str());
    if matches!(membership, Some("join" | "invite")) {
        return Ok(true);
    }
    if membership == Some("ban") {
        return Ok(false);
    }
    if content_str(state, "m.room.history_visibility", "history_visibility") == Some("world_readable") {
        return Ok(true);
    }
    match content_str(state, "m.room.join_rules", "join_rule") {
        Some("public" | "knock" | "knock_restricted") => Ok(true),
        Some("restricted") => {
            for room in allowed_room_ids(state) {
                let member = storage.get_state_entry(&room, "m.room.member", user_id).await?;
                if member.is_some_and(|event| event.content["membership"] == "join") {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// Valid children of a space, ordered, honouring `suggested_only`.
pub(crate) fn ordered_children(state: &StateMap<Event>, suggested_only: bool) -> Vec<Event> {
    let mut children: Vec<Event> = state
        .values()
        .filter(|event| is_valid_space_child(event))
        .filter(|event| !suggested_only || event.content["suggested"] == true)
        .cloned()
        .collect();
    children.sort_by(space_child_ordering);
    children
}

pub(crate) fn summary(room_id: &str, state: &StateMap<Event>, children: &[Event]) -> Value {
    let joined = state
        .iter()
        .filter(|((kind, _), event)| kind == "m.room.member" && event.content["membership"] == "join")
        .count();
    let create = get(state, "m.room.create");
    let mut room = json!({
        "room_id": room_id,
        "num_joined_members": joined,
        "world_readable": content_str(state, "m.room.history_visibility", "history_visibility") == Some("world_readable"),
        "guest_can_join": content_str(state, "m.room.guest_access", "guest_access") == Some("can_join"),
        "join_rule": content_str(state, "m.room.join_rules", "join_rule").unwrap_or("invite"),
        "room_version": create.and_then(|event| event.content["room_version"].as_str()).unwrap_or("1"),
        "children_state": children.iter().map(|child| json!({
            "type": child.event_type,
            "state_key": child.state_key,
            "content": child.content,
            "sender": child.sender,
            "origin_server_ts": child.origin_server_ts,
        })).collect::<Vec<_>>(),
    });
    for (key, kind, field) in [
        ("name", "m.room.name", "name"),
        ("topic", "m.room.topic", "topic"),
        ("avatar_url", "m.room.avatar", "url"),
        ("canonical_alias", "m.room.canonical_alias", "alias"),
        ("encryption", "m.room.encryption", "algorithm"),
    ] {
        if let Some(value) = content_str(state, kind, field).filter(|value| !value.is_empty()) {
            room[key] = json!(value);
        }
    }
    if let Some(room_type) = create.and_then(|event| event.content.get("type")).filter(|v| v.is_string()) {
        room["room_type"] = room_type.clone();
    }
    let allowed = allowed_room_ids(state);
    if !allowed.is_empty() {
        room["allowed_room_ids"] = json!(allowed);
    }
    room
}

pub async fn hierarchy<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let storage = state.storage().as_ref();
    let suggested_only = match query.get("suggested_only").map(String::as_str) {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return invalid_param("suggested_only must be true or false"),
    };
    let limit = match limit_param(&query, "limit", 50, 100) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let max_depth = match query.get("max_depth") {
        None => DEFAULT_MAX_DEPTH,
        Some(raw) => match raw.parse::<i64>() {
            Ok(depth) if depth >= 0 => (depth as usize).min(DEFAULT_MAX_DEPTH),
            _ => return invalid_param("max_depth must be a non-negative integer"),
        },
    };
    // Tokens pin the walk parameters: `h{offset}_{suggested}_{depth}`.
    let offset = match query.get("from") {
        None => 0,
        Some(token) => {
            let parts: Vec<&str> = token.strip_prefix('h').unwrap_or("").split('_').collect();
            match parts.as_slice() {
                [offset, suggested, depth]
                    if *suggested == (suggested_only as u8).to_string() && *depth == max_depth.to_string() =>
                {
                    match offset.parse::<usize>() {
                        Ok(offset) => offset,
                        Err(_) => return invalid_param("invalid from token"),
                    }
                }
                [_, _, _] => return invalid_param("suggested_only and max_depth cannot change during pagination"),
                _ => return invalid_param("invalid from token"),
            }
        }
    };

    let root_state = match conduit::auth::current_state_map(storage, &room_id).await {
        Ok(root_state) => root_state,
        Err(e) => return storage_error(e),
    };
    let root_ok = match accessible(storage, &root_state, &authed.user_id).await {
        Ok(ok) => ok && get(&root_state, "m.room.create").is_some(),
        Err(e) => return storage_error(e),
    };
    if !root_ok {
        return MatrixError::forbidden("You cannot view or peek on this room").into_response();
    }

    // Depth-first, children in spec order; loops are cut by `visited`.
    let mut rooms = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut stack: Vec<(String, usize, Option<StateMap<Event>>)> = vec![(room_id.clone(), 0, Some(root_state))];
    while let Some((room, depth, known_state)) = stack.pop() {
        if !visited.insert(room.clone()) {
            continue;
        }
        let room_state = match known_state {
            Some(room_state) => room_state,
            None => match conduit::auth::current_state_map(storage, &room).await {
                Ok(room_state) => room_state,
                Err(e) => return storage_error(e),
            },
        };
        if get(&room_state, "m.room.create").is_none() {
            continue; // unknown locally; federation fill-in is not implemented
        }
        match accessible(storage, &room_state, &authed.user_id).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => return storage_error(e),
        }
        let room_children = ordered_children(&room_state, suggested_only);
        rooms.push(summary(&room, &room_state, &room_children));
        if depth < max_depth {
            for child in room_children.iter().rev() {
                if let Some(child_id) = &child.state_key {
                    if !visited.contains(child_id) {
                        stack.push((child_id.clone(), depth + 1, None));
                    }
                }
            }
        }
    }
    let total = rooms.len();
    let page: Vec<Value> = rooms.into_iter().skip(offset).take(limit).collect();
    let mut body = json!({"rooms": page});
    if offset + limit < total {
        body["next_batch"] = json!(format!("h{}_{}_{}", offset + limit, suggested_only as u8, max_depth));
    }
    (StatusCode::OK, Json(body)).into_response()
}
