//! GET /_matrix/client/v1/rooms/:roomId/hierarchy (conduit-y99.19).
//!
//! Depth-first walk over valid `m.space.child` state (non-empty `via`),
//! children ordered per the spec (`order`, then `origin_server_ts`, then
//! room ID). A room is listed when the requesting user is joined or
//! invited, may join it (public, or restricted with a satisfied
//! condition), may knock, or it is world-readable. A child this server
//! does not know is requested from the servers in its `via` list. Rooms
//! this server already knows keep their local summary.

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use conduit::auth::StateMap;
use conduit::event::{Event, Pdu};
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
    // `remote_rooms` holds summaries learned from federation during this
    // walk. Local state is consulted first and wins.
    let mut rooms = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut remote_rooms: HashMap<String, Value> = HashMap::new();
    let mut inaccessible: HashSet<String> = HashSet::new();
    let mut stack: Vec<(String, usize, Option<StateMap<Event>>, Vec<String>)> =
        vec![(room_id.clone(), 0, Some(root_state), Vec::new())];
    while let Some((room, depth, known_state, via)) = stack.pop() {
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
        if get(&room_state, "m.room.create").is_some() {
            match accessible(storage, &room_state, &authed.user_id).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => return storage_error(e),
            }
            let room_children = ordered_children(&room_state, suggested_only);
            rooms.push(summary(&room, &room_state, &room_children));
            if depth < max_depth {
                push_children(&mut stack, &mut visited, &room_children, depth);
            }
            continue;
        }
        if inaccessible.contains(&room) {
            continue;
        }
        if !remote_rooms.contains_key(&room) {
            fetch_remote_hierarchy(&state, &room, &via, suggested_only, &mut remote_rooms, &mut inaccessible).await;
        }
        if inaccessible.contains(&room) {
            continue;
        }
        let Some(remote) = remote_rooms.get(&room).cloned() else {
            continue;
        };
        let room_children = ordered_stripped_children(&remote, suggested_only);
        match remote_user_may_see(storage, &room, &remote, &authed.user_id).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => return storage_error(e),
        }
        let Some(described) = client_room_from_remote(&remote, &room_children) else {
            continue;
        };
        rooms.push(described);
        if depth < max_depth {
            push_children(&mut stack, &mut visited, &room_children, depth);
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

fn federation_enabled() -> bool {
    std::env::var("CONDUIT_FEDERATION").ok().as_deref() != Some("0")
}

fn via_of(event: &Event) -> Vec<String> {
    event
        .content
        .get("via")
        .and_then(Value::as_array)
        .map(|via| via.iter().filter_map(Value::as_str).filter(|server| !server.is_empty()).map(str::to_owned).collect())
        .unwrap_or_default()
}

fn push_children(
    stack: &mut Vec<(String, usize, Option<StateMap<Event>>, Vec<String>)>,
    visited: &HashSet<String>,
    children: &[Event],
    depth: usize,
) {
    for child in children.iter().rev() {
        let Some(child_id) = &child.state_key else { continue };
        if visited.contains(child_id) {
            continue;
        }
        stack.push((child_id.clone(), depth + 1, None, via_of(child)));
    }
}

fn stripped_child(value: &Value) -> Option<Event> {
    if value.get("type").and_then(Value::as_str) != Some("m.space.child") {
        return None;
    }
    let state_key = value.get("state_key")?.as_str()?.to_owned();
    let content = value.get("content")?.clone();
    let sender = value.get("sender").and_then(Value::as_str).unwrap_or("").to_owned();
    let origin_server_ts = value
        .get("origin_server_ts")
        .and_then(Value::as_u64)
        .or_else(|| value.get("origin_server_ts").and_then(Value::as_i64).and_then(|ts| u64::try_from(ts).ok()))
        .unwrap_or(0);
    Some(Event::new(
        format!("$space-child:{state_key}"),
        Pdu::new("", sender, "m.space.child", Some(state_key), content, origin_server_ts, Vec::new(), Vec::new(), 1),
    ))
}

fn ordered_stripped_children(room: &Value, suggested_only: bool) -> Vec<Event> {
    let Some(children) = room.get("children_state").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut children: Vec<Event> = children
        .iter()
        .filter_map(stripped_child)
        .filter(is_valid_space_child)
        .filter(|event| !suggested_only || event.content["suggested"] == true)
        .collect();
    children.sort_by(space_child_ordering);
    children
}

fn remote_summary_usable(room: &Value) -> bool {
    room.get("room_id").and_then(Value::as_str).is_some_and(|id| id.starts_with('!'))
        && room.get("guest_can_join").and_then(Value::as_bool).is_some()
        && room.get("world_readable").and_then(Value::as_bool).is_some()
        && room.get("num_joined_members").and_then(Value::as_i64).is_some_and(|count| count >= 0)
}

fn children_state_json(children: &[Event]) -> Value {
    json!(children
        .iter()
        .map(|child| json!({
            "type": child.event_type,
            "state_key": child.state_key,
            "content": child.content,
            "sender": child.sender,
            "origin_server_ts": child.origin_server_ts,
        }))
        .collect::<Vec<_>>())
}

/// Federation hierarchy `room` object, with `children_state` reduced to the
/// valid children this response will walk.
fn client_room_from_remote(room: &Value, children: &[Event]) -> Option<Value> {
    if !remote_summary_usable(room) {
        return None;
    }
    let mut described = json!({
        "room_id": room.get("room_id")?,
        "num_joined_members": room.get("num_joined_members")?,
        "world_readable": room.get("world_readable")?,
        "guest_can_join": room.get("guest_can_join")?,
        "join_rule": room.get("join_rule").and_then(Value::as_str).filter(|rule| !rule.is_empty()).unwrap_or("public"),
        "children_state": children_state_json(children),
    });
    for key in ["avatar_url", "canonical_alias", "encryption", "name", "topic", "room_type", "room_version"] {
        if let Some(value) = room.get(key).and_then(Value::as_str).filter(|value| !value.is_empty()) {
            described[key] = json!(value);
        }
    }
    if let Some(ids) = room.get("allowed_room_ids").and_then(Value::as_array) {
        let ids: Vec<&str> = ids.iter().filter_map(Value::as_str).filter(|id| !id.is_empty()).collect();
        if !ids.is_empty() {
            described["allowed_room_ids"] = json!(ids);
        }
    }
    Some(described)
}

async fn remote_user_may_see(storage: &dyn Storage, room_id: &str, summary: &Value, user_id: &str) -> conduit::Result<bool> {
    if let Some(member) = storage.get_state_entry(room_id, "m.room.member", user_id).await? {
        match member.content.get("membership").and_then(Value::as_str) {
            Some("ban") => return Ok(false),
            Some("join" | "invite") => return Ok(true),
            _ => {}
        }
    }
    let world_readable = summary.get("world_readable").and_then(Value::as_bool).unwrap_or(false);
    let join_rule = summary.get("join_rule").and_then(Value::as_str).unwrap_or("public");
    if world_readable || matches!(join_rule, "public" | "knock" | "knock_restricted") {
        return Ok(true);
    }
    if join_rule == "restricted" {
        if let Some(allowed) = summary.get("allowed_room_ids").and_then(Value::as_array) {
            for allowed_room in allowed.iter().filter_map(Value::as_str) {
                let member = storage.get_state_entry(allowed_room, "m.room.member", user_id).await?;
                if member.is_some_and(|event| event.content["membership"] == "join") {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// `GET /_matrix/federation/v1/hierarchy/{roomId}` on each `via` server.
/// The first usable response fills `remote_rooms`. Rooms named in
/// `inaccessible_children` are not stored and are not requested again.
async fn fetch_remote_hierarchy<S: AuthState>(
    state: &S,
    room_id: &str,
    via: &[String],
    suggested_only: bool,
    remote_rooms: &mut HashMap<String, Value>,
    inaccessible: &mut HashSet<String>,
) {
    if !federation_enabled() {
        return;
    }
    let Some(client) = state.federation_client() else {
        return;
    };
    let local = state.server_name();
    for dest in via {
        if dest.is_empty() || dest == local {
            continue;
        }
        let value = match client.room_hierarchy(dest, room_id, suggested_only).await {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(room) = value.get("room").cloned() else {
            continue;
        };
        if room.get("room_id").and_then(Value::as_str) != Some(room_id) || !remote_summary_usable(&room) {
            continue;
        }
        remote_rooms.entry(room_id.to_owned()).or_insert(room);
        if let Some(children) = value.get("children").and_then(Value::as_array) {
            for child in children {
                let Some(child_id) = child.get("room_id").and_then(Value::as_str) else {
                    continue;
                };
                if child_id == room_id || inaccessible.contains(child_id) || !remote_summary_usable(child) {
                    continue;
                }
                remote_rooms.entry(child_id.to_owned()).or_insert_with(|| child.clone());
            }
        }
        if let Some(blocked) = value.get("inaccessible_children").and_then(Value::as_array) {
            for blocked_id in blocked.iter().filter_map(Value::as_str) {
                inaccessible.insert(blocked_id.to_owned());
                remote_rooms.remove(blocked_id);
            }
        }
        return;
    }
}
