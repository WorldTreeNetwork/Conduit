//! Event relationships: `/relations` and `/threads` (conduit-y99.19).
//!
//! Children are found through the cleartext `m.relates_to` (indexed in
//! PostgreSQL by `events_relates_to`). Ordering is topological — stream
//! position — and pagination tokens are inclusive stream cursors, so
//! `/messages` and `/sync` tokens are accepted as `from`/`to`.

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Map, Value};

use conduit::event::Event;
use conduit::room_content::relation;

use super::events::visible_event;
use super::serve::Viewer;
use super::{
    invalid_param, limit_param, not_found, parse_position, position_token, storage_error,
    visible_events, RoomAccess,
};
use crate::api::client::{AuthState, AuthedUser, MatrixError};

/// How deep `recurse=true` follows relations (spec: at least 3).
pub const RECURSION_DEPTH: usize = 3;

pub async fn relations<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_id)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    relations_inner(&state, &authed, &room_id, &event_id, None, None, &query).await
}

pub async fn relations_by_type<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_id, rel_type)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    relations_inner(&state, &authed, &room_id, &event_id, Some(&rel_type), None, &query).await
}

pub async fn relations_by_type_and_event_type<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_id, rel_type, event_type)): Path<(String, String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    relations_inner(&state, &authed, &room_id, &event_id, Some(&rel_type), Some(&event_type), &query)
        .await
}

async fn relations_inner<S: AuthState>(
    state: &S,
    authed: &AuthedUser,
    room_id: &str,
    event_id: &str,
    rel_type: Option<&str>,
    event_type: Option<&str>,
    query: &HashMap<String, String>,
) -> Response {
    let storage = state.storage().as_ref();
    let forward = match query.get("dir").map(String::as_str) {
        None | Some("b") => false,
        Some("f") => true,
        Some(_) => return invalid_param("dir must be f or b"),
    };
    let limit = match limit_param(query, "limit", 50, 100) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let recurse = match query.get("recurse").map(String::as_str) {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) => return invalid_param("recurse must be true or false"),
    };
    let token = |name: &str| -> Result<Option<i64>, Response> {
        match query.get(name) {
            None => Ok(None),
            Some(raw) => parse_position(raw)
                .map(Some)
                .ok_or_else(|| invalid_param(format!("invalid {name} token"))),
        }
    };
    let (from, to) = match (token("from"), token("to")) {
        (Ok(from), Ok(to)) => (from, to),
        (Err(response), _) | (_, Err(response)) => return response,
    };
    let access = match RoomAccess::load(storage, room_id, &authed.user_id).await {
        Ok(access) => access,
        Err(e) => return storage_error(e),
    };
    // 404 for an unknown parent and for one the user may not see alike.
    match visible_event(storage, &access, room_id, &authed.user_id, event_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("Event not found."),
        Err(response) => return response,
    }
    let viewer = match Viewer::load(storage, &authed.user_id).await {
        Ok(viewer) => viewer,
        Err(e) => return storage_error(e),
    };
    let depth = if recurse == Some(true) { RECURSION_DEPTH } else { 1 };
    let mut found: Vec<(i64, Event)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::from([event_id.to_owned()]);
    let mut parents = vec![event_id.to_owned()];
    for _ in 0..depth {
        if parents.is_empty() {
            break;
        }
        let children = match viewer.children(room_id, &parents).await {
            Ok(children) => children,
            Err(e) => return storage_error(e),
        };
        parents = Vec::new();
        for (position, child) in children {
            let matches_rel = relation(&child).is_some_and(|(kind, _)| rel_type.is_none_or(|wanted| wanted == kind));
            if !matches_rel || !seen.insert(child.event_id.clone()) {
                continue;
            }
            parents.push(child.event_id.clone());
            found.push((position, child));
        }
    }
    found.retain(|(position, event)| {
        event_type.is_none_or(|wanted| wanted == event.event_type)
            && from.is_none_or(|from| if forward { *position >= from } else { *position <= from })
            && to.is_none_or(|to| if forward { *position < to } else { *position > to })
    });
    found.sort_by_key(|(position, _)| *position);
    if !forward {
        found.reverse();
    }
    let more = found.len() > limit;
    found.truncate(limit);
    let next_batch = more
        .then(|| found.last().map(|(position, _)| if forward { position + 1 } else { position - 1 }))
        .flatten();
    let events: Vec<Event> = found.into_iter().map(|(_, event)| event).collect();
    let chunk = match viewer.serve(&events, true).await {
        Ok(chunk) => chunk,
        Err(e) => return storage_error(e),
    };
    let mut body = Map::new();
    body.insert("chunk".into(), Value::Array(chunk));
    if let Some(next) = next_batch {
        body.insert("next_batch".into(), json!(position_token(next)));
    }
    if let Some(from) = query.get("from") {
        body.insert("prev_batch".into(), json!(from));
    }
    if recurse.is_some() {
        body.insert("recursion_depth".into(), json!(depth));
    }
    (StatusCode::OK, Json(Value::Object(body))).into_response()
}

// ---------------------------------------------------------------------------
// GET /_matrix/client/v1/rooms/:roomId/threads
// ---------------------------------------------------------------------------

pub async fn threads<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let storage = state.storage().as_ref();
    let participated_only = match query.get("include").map(String::as_str) {
        None | Some("all") => false,
        Some("participated") => true,
        Some(_) => return invalid_param("include must be all or participated"),
    };
    let limit = match limit_param(&query, "limit", 50, 100) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let from = match query.get("from") {
        None => None,
        Some(raw) => match parse_position(raw) {
            Some(position) => Some(position),
            None => return invalid_param("invalid from token"),
        },
    };
    let access = match RoomAccess::load(storage, &room_id, &authed.user_id).await {
        Ok(access) => access,
        Err(e) => return storage_error(e),
    };
    if !access.may_read_history() {
        return MatrixError::forbidden(format!("{} cannot view {room_id}", authed.user_id)).into_response();
    }
    let roots = match storage.thread_roots(&room_id, &authed.user_id).await {
        Ok(roots) => roots,
        Err(e) => return storage_error(e),
    };
    let viewer = match Viewer::load(storage, &authed.user_id).await {
        Ok(viewer) => viewer,
        Err(e) => return storage_error(e),
    };
    let mut page: Vec<Event> = Vec::new();
    let mut next_batch = None;
    for (root_id, latest, user_replied) in roots {
        if from.is_some_and(|from| latest >= from) {
            continue;
        }
        if page.len() >= limit {
            // Resume at this root: `from` keeps roots active strictly
            // before it, and each child position belongs to one thread.
            next_batch = Some(latest + 1);
            break;
        }
        let root = match storage.get_event(&root_id).await {
            Ok(Some(root)) if root.room_id == room_id && relation(&root).is_none() => root,
            Ok(_) => continue,
            Err(e) => return storage_error(e),
        };
        if participated_only && !user_replied && root.sender != authed.user_id {
            continue;
        }
        match visible_events(storage, &access, &room_id, &authed.user_id, vec![root]).await {
            Ok(mut visible) => {
                if let Some(root) = visible.pop() {
                    page.push(root);
                }
            }
            Err(e) => return storage_error(e),
        }
    }
    // Roots sent by an ignored user are returned redacted (spec), as a
    // client aggregating the thread locally would show them.
    let mut chunk = match viewer.serve(&page, true).await {
        Ok(chunk) => chunk,
        Err(e) => return storage_error(e),
    };
    for (value, root) in chunk.iter_mut().zip(&page) {
        if viewer.ignored.contains(&root.sender) {
            let relations = value["unsigned"].get("m.relations").cloned();
            *value = conduit::room_content::client_event(
                &conduit::redaction::redact_event(root),
                super::now_ms(),
            );
            if let Some(relations) = relations {
                value["unsigned"]["m.relations"] = relations;
            }
        }
    }
    let mut body = json!({"chunk": chunk});
    if let Some(next) = next_batch {
        body["next_batch"] = json!(position_token(next));
    }
    (StatusCode::OK, Json(body)).into_response()
}
