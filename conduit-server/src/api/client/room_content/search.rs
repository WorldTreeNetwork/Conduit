//! POST /search, `room_events` category (conduit-y99.19).
//!
//! PostgreSQL full-text search (`websearch_to_tsquery`, English stemming)
//! over `content.body` of messages, `content.name` of room names and
//! `content.topic` of topics. Candidates come from every room the user is
//! or was in (spec: "including those that they have left"); each hit is
//! then checked against history visibility, the forget rule, ignored
//! users, redactions and the request filter before pagination, so `count`
//! and `next_batch` describe what the user may actually see.

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use conduit::event::Event;
use conduit::filter::RoomEventFilter;
use conduit::room_content::{search_tokens, SearchHit, SearchKeys};

use super::events::collect_window;
use super::serve::Viewer;
use super::{invalid_param, position_token, state_at, storage_error, visible_events, RoomAccess};
use crate::api::client::{AuthState, AuthedUser, MatrixError};

/// Upper bound on candidate hits considered per request.
const CANDIDATE_CAP: i64 = 1000;

#[derive(Debug, Deserialize)]
struct SearchRequest {
    search_categories: Categories,
}

#[derive(Debug, Deserialize)]
struct Categories {
    room_events: Option<RoomEventsCriteria>,
}

#[derive(Debug, Deserialize)]
struct RoomEventsCriteria {
    search_term: String,
    keys: Option<Vec<String>>,
    #[serde(default)]
    filter: RoomEventFilter,
    order_by: Option<String>,
    event_context: Option<EventContext>,
    #[serde(default)]
    include_state: bool,
    groupings: Option<Groupings>,
}

#[derive(Debug, Deserialize)]
struct EventContext {
    before_limit: Option<u64>,
    after_limit: Option<u64>,
    #[serde(default)]
    include_profile: bool,
}

#[derive(Debug, Deserialize)]
struct Groupings {
    #[serde(default)]
    group_by: Vec<Group>,
}

#[derive(Debug, Deserialize)]
struct Group {
    key: String,
}

pub async fn search<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Response {
    let request: SearchRequest = match serde_json::from_value(body) {
        Ok(request) => request,
        Err(e) => return MatrixError::bad_json(e.to_string()).into_response(),
    };
    let Some(criteria) = request.search_categories.room_events else {
        return (StatusCode::OK, Json(json!({"search_categories": {}}))).into_response();
    };
    let offset = match query.get("next_batch") {
        None => 0,
        Some(token) => match token.strip_prefix('o').and_then(|raw| raw.parse::<usize>().ok()) {
            Some(offset) => offset,
            None => return invalid_param("invalid next_batch token"),
        },
    };
    match room_events(&state, &authed.user_id, criteria, offset).await {
        Ok(result) => (StatusCode::OK, Json(json!({"search_categories": {"room_events": result}})))
            .into_response(),
        Err(response) => response,
    }
}

async fn room_events<S: AuthState>(
    state: &S,
    user_id: &str,
    criteria: RoomEventsCriteria,
    offset: usize,
) -> Result<Value, Response> {
    let storage = state.storage().as_ref();
    let keys = SearchKeys::parse(criteria.keys.as_deref()).map_err(invalid_param)?;
    let recent = match criteria.order_by.as_deref() {
        None | Some("rank") => false,
        Some("recent") => true,
        Some(_) => return Err(invalid_param("order_by must be rank or recent")),
    };
    for group in criteria.groupings.iter().flat_map(|groupings| &groupings.group_by) {
        if group.key != "room_id" && group.key != "sender" {
            return Err(invalid_param(format!("unsupported group key: {}", group.key)));
        }
    }
    let filter = &criteria.filter;
    let limit = filter.events.limit.unwrap_or(10).min(100);

    // Rooms the user is in or has left; filter rooms/not_rooms narrow it.
    let memberships = storage.current_memberships(user_id).await.map_err(storage_error)?;
    let mut rooms: Vec<String> = memberships
        .iter()
        .filter(|event| matches!(event.content["membership"].as_str(), Some("join" | "leave" | "ban")))
        .map(|event| event.room_id.clone())
        .filter(|room| {
            filter.rooms.as_ref().is_none_or(|rooms| rooms.contains(room)) && !filter.not_rooms.contains(room)
        })
        .collect();
    rooms.sort();
    rooms.dedup();
    let hits = storage
        .search_room_events(&rooms, &criteria.search_term, keys, recent, CANDIDATE_CAP)
        .await
        .map_err(storage_error)?;

    // Visibility per room, then ignore/filter/redaction.
    let viewer = Viewer::load(storage, user_id).await.map_err(storage_error)?;
    let mut accesses: HashMap<String, RoomAccess> = HashMap::new();
    let mut allowed: HashSet<String> = HashSet::new();
    let mut by_room: HashMap<String, Vec<Event>> = HashMap::new();
    for hit in &hits {
        by_room.entry(hit.event.room_id.clone()).or_default().push(hit.event.clone());
    }
    for (room, events) in by_room {
        let access = RoomAccess::load(storage, &room, user_id).await.map_err(storage_error)?;
        let visible = visible_events(storage, &access, &room, user_id, events).await.map_err(storage_error)?;
        allowed.extend(visible.into_iter().map(|event| event.event_id));
        accesses.insert(room, access);
    }
    let candidates: Vec<Event> = hits.iter().map(|hit| hit.event.clone()).collect();
    let redacted = viewer.redactions(&candidates).await.map_err(storage_error)?;
    let hits: Vec<SearchHit> = hits
        .into_iter()
        .filter(|hit| {
            allowed.contains(&hit.event.event_id)
                && !redacted.contains_key(&hit.event.event_id)
                && !viewer.hides(&hit.event)
                && filter.matches(&hit.event.room_id, &serde_json::to_value(&hit.event).unwrap_or(Value::Null))
        })
        .collect();
    let count = hits.len();
    let page: Vec<SearchHit> = hits.into_iter().skip(offset).take(limit).collect();
    let page_events: Vec<Event> = page.iter().map(|hit| hit.event.clone()).collect();
    let served = viewer.serve(&page_events, true).await.map_err(storage_error)?;

    let mut results = Vec::new();
    for (hit, value) in page.iter().zip(served) {
        let mut result = json!({"rank": hit.rank, "result": value});
        if let Some(context) = &criteria.event_context {
            let access = &accesses[&hit.event.room_id];
            result["context"] = event_context(storage, &viewer, access, hit, context, filter).await?;
        }
        results.push(result);
    }

    let mut body = json!({
        "count": count,
        "highlights": search_tokens(&criteria.search_term),
        "results": results,
    });
    if offset + limit < count {
        body["next_batch"] = json!(format!("o{}", offset + limit));
    }
    if let Some(groupings) = &criteria.groupings {
        let mut groups = Map::new();
        for group in &groupings.group_by {
            let mut buckets: Map<String, Value> = Map::new();
            for hit in &page {
                let value = if group.key == "room_id" { &hit.event.room_id } else { &hit.event.sender };
                let next_order = buckets.len() + 1;
                let bucket = buckets
                    .entry(value.clone())
                    .or_insert_with(|| json!({"results": [], "order": next_order}));
                bucket["results"].as_array_mut().expect("results array").push(json!(hit.event.event_id));
            }
            groups.insert(group.key.clone(), Value::Object(buckets));
        }
        body["groups"] = Value::Object(groups);
    }
    if criteria.include_state {
        let mut state_map = Map::new();
        let page_rooms: HashSet<&str> = page.iter().map(|hit| hit.event.room_id.as_str()).collect();
        for room in page_rooms {
            let access = &accesses[room];
            let events = state_at(storage, room, access.state_horizon()).await.map_err(storage_error)?;
            let values = viewer.serve(&events, false).await.map_err(storage_error)?;
            state_map.insert(room.to_owned(), Value::Array(values));
        }
        body["state"] = Value::Object(state_map);
    }
    Ok(body)
}

async fn event_context(
    storage: &dyn conduit::storage::Storage,
    viewer: &Viewer<'_>,
    access: &RoomAccess,
    hit: &SearchHit,
    context: &EventContext,
    filter: &RoomEventFilter,
) -> Result<Value, Response> {
    let room = &hit.event.room_id;
    let before_limit = context.before_limit.unwrap_or(5).min(100) as usize;
    let after_limit = context.after_limit.unwrap_or(5).min(100) as usize;
    let (before, before_edge) =
        collect_window(storage, access, viewer, room, 'b', hit.position - 1, before_limit, Some(filter)).await?;
    let (after, after_edge) =
        collect_window(storage, access, viewer, room, 'f', hit.position + 1, after_limit, Some(filter)).await?;
    let mut value = json!({
        "events_before": viewer.serve(&before, false).await.map_err(storage_error)?,
        "events_after": viewer.serve(&after, false).await.map_err(storage_error)?,
        "start": position_token(before_edge.unwrap_or(hit.position) - 1),
        "end": position_token(after_edge.unwrap_or(hit.position) + 1),
    });
    if context.include_profile {
        // Historic profiles: each sender's membership as of the result.
        let mut profiles = Map::new();
        let senders: HashSet<&str> = before
            .iter()
            .chain(after.iter())
            .chain(std::iter::once(&hit.event))
            .map(|event| event.sender.as_str())
            .collect();
        for sender in senders {
            let members = storage.member_events_for_user(room, sender).await.map_err(storage_error)?;
            if let Some((_, member)) = members.iter().rfind(|(position, _)| *position <= hit.position) {
                let mut profile = Map::new();
                for field in ["displayname", "avatar_url"] {
                    if let Some(value) = member.content.get(field).filter(|value| value.is_string()) {
                        profile.insert(field.into(), value.clone());
                    }
                }
                profiles.insert(sender.to_owned(), Value::Object(profile));
            }
        }
        value["profile_info"] = Value::Object(profiles);
    }
    Ok(value)
}
