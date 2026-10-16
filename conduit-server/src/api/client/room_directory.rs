//! Published room directory (conduit-y99.20, subsumes conduit-wwy).
//!
//! - `GET  /_matrix/client/v3/publicRooms`                       (no auth)
//! - `POST /_matrix/client/v3/publicRooms`                       (filter)
//! - `GET  /_matrix/client/v3/directory/list/room/{roomId}`      (no auth)
//! - `PUT  /_matrix/client/v3/directory/list/room/{roomId}`
//! - `PUT  /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}` (as_token)
//!
//! Rooms are listed largest-first by joined member count, then by room
//! ID, which is the stable order the spec recommends. Pagination tokens
//! are opaque offsets: `n{offset}` for `next_batch`, `p{offset}` for
//! `prev_batch`.
//!
//! Who may change a room's listing: a server admin, or a member joined
//! to the room with the power to send `m.room.canonical_alias` (the
//! spec leaves this to the server; this is Synapse's rule too).

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use conduit::auth::{current_state_map, may_send_state_event, StateMap};
use conduit::event::Event;
use conduit::storage::{DirectoryScope, Storage};

use super::{AuthState, AuthedUser, MatrixError};
use crate::app_service::{AsAuthed, AsState};

pub fn router<S: AuthState + AsState>() -> Router<S> {
    Router::new()
        .route(
            "/_matrix/client/v3/publicRooms",
            get(get_public_rooms::<S>).post(post_public_rooms::<S>),
        )
        .route(
            "/_matrix/client/v3/directory/list/room/:roomId",
            get(get_visibility::<S>).put(put_visibility::<S>),
        )
        .route(
            "/_matrix/client/v3/directory/list/appservice/:networkId/:roomId",
            put(put_appservice_visibility::<S>),
        )
}

fn invalid_param(msg: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"errcode": "M_INVALID_PARAM", "error": msg.into()})),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Room summaries
// ---------------------------------------------------------------------------

fn state_content<'a>(state: &'a StateMap<Event>, kind: &str) -> Option<&'a Value> {
    state.get(&(kind.to_owned(), String::new())).map(|e| &e.content)
}

fn non_empty(value: &Value) -> Option<String> {
    value.as_str().filter(|s| !s.is_empty()).map(str::to_owned)
}

/// The plain-text topic: the `text/plain` entry of the `m.topic` content
/// block when present, else the legacy `topic` string.
pub fn plain_topic(content: &Value) -> Option<String> {
    if let Some(blocks) = content["m.topic"]["m.text"].as_array() {
        let plain = blocks.iter().find(|b| {
            b["mimetype"].is_null() || b["mimetype"].as_str() == Some("text/plain")
        });
        if let Some(body) = plain.and_then(|b| non_empty(&b["body"])) {
            return Some(body);
        }
    }
    non_empty(&content["topic"])
}

/// A `PublishedRoomsChunk` for a room, from its current state. `None`
/// when the room is unknown to this server (no `m.room.create`).
pub fn room_chunk(room_id: &str, state: &StateMap<Event>) -> Option<Map<String, Value>> {
    let create = state_content(state, "m.room.create")?;
    let mut chunk = Map::new();
    chunk.insert("room_id".into(), json!(room_id));
    let joined = state
        .iter()
        .filter(|((kind, _), event)| {
            kind == "m.room.member" && event.content["membership"] == "join"
        })
        .count();
    chunk.insert("num_joined_members".into(), json!(joined));
    if let Some(name) = state_content(state, "m.room.name").and_then(|c| non_empty(&c["name"])) {
        chunk.insert("name".into(), json!(name));
    }
    if let Some(topic) = state_content(state, "m.room.topic").and_then(plain_topic) {
        chunk.insert("topic".into(), json!(topic));
    }
    if let Some(alias) =
        state_content(state, "m.room.canonical_alias").and_then(|c| non_empty(&c["alias"]))
    {
        chunk.insert("canonical_alias".into(), json!(alias));
    }
    if let Some(url) = state_content(state, "m.room.avatar").and_then(|c| non_empty(&c["url"])) {
        chunk.insert("avatar_url".into(), json!(url));
    }
    let world_readable = state_content(state, "m.room.history_visibility")
        .is_some_and(|c| c["history_visibility"] == "world_readable");
    chunk.insert("world_readable".into(), json!(world_readable));
    let guest_can_join = state_content(state, "m.room.guest_access")
        .is_some_and(|c| c["guest_access"] == "can_join");
    chunk.insert("guest_can_join".into(), json!(guest_can_join));
    if let Some(rule) =
        state_content(state, "m.room.join_rules").and_then(|c| non_empty(&c["join_rule"]))
    {
        chunk.insert("join_rule".into(), json!(rule));
    }
    if let Some(room_type) = non_empty(&create["type"]) {
        chunk.insert("room_type".into(), json!(room_type));
    }
    Some(chunk)
}

/// Lower-cased text the generic search term is matched against.
fn searchable_text(chunk: &Map<String, Value>, state: &StateMap<Event>) -> String {
    let mut text = String::new();
    for key in ["name", "topic", "canonical_alias", "room_id"] {
        if let Some(value) = chunk.get(key).and_then(Value::as_str) {
            text.push_str(value);
            text.push('\n');
        }
    }
    if let Some(alt) = state_content(state, "m.room.canonical_alias")
        .and_then(|c| c["alt_aliases"].as_array())
    {
        for alias in alt.iter().filter_map(Value::as_str) {
            text.push_str(alias);
            text.push('\n');
        }
    }
    text.to_lowercase()
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct PublicRoomsFilter {
    pub generic_search_term: Option<String>,
    /// `null` entries select rooms without a type.
    pub room_types: Option<Vec<Option<String>>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PublicRoomsBody {
    pub limit: Option<i64>,
    pub since: Option<String>,
    pub filter: Option<PublicRoomsFilter>,
    pub include_all_networks: Option<bool>,
    pub third_party_instance_id: Option<String>,
}

/// Parse a `next_batch` / `prev_batch` token into an offset.
fn parse_since(token: &str) -> Option<usize> {
    let digits = token.strip_prefix('n').or_else(|| token.strip_prefix('p'))?;
    digits.parse().ok()
}

/// `{appservice_id}|{network_id}` — the `instance_id` this server stamps
/// onto protocol instances (`GET /thirdparty/protocols`).
pub fn instance_id(appservice_id: &str, network_id: &str) -> String {
    format!("{appservice_id}|{network_id}")
}

pub(crate) async fn list_local(storage: &dyn Storage, body: PublicRoomsBody) -> Response {
    let scope = match (body.include_all_networks.unwrap_or(false), body.third_party_instance_id) {
        (true, Some(_)) => {
            return invalid_param(
                "third_party_instance_id cannot be combined with include_all_networks",
            )
        }
        (true, None) => DirectoryScope::AllNetworks,
        (false, None) => DirectoryScope::Local,
        (false, Some(instance)) => match instance.split_once('|') {
            Some((appservice_id, network_id)) => DirectoryScope::Network {
                appservice_id: appservice_id.to_owned(),
                network_id: network_id.to_owned(),
            },
            None => return invalid_param("unknown third_party_instance_id"),
        },
    };
    let offset = match body.since.as_deref() {
        None => 0,
        Some(token) => match parse_since(token) {
            Some(offset) => offset,
            None => return invalid_param("invalid since token"),
        },
    };
    let limit = body.limit.filter(|l| *l > 0).map(|l| l as usize);

    let room_ids = match storage.published_rooms(&scope).await {
        Ok(ids) => ids,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let filter = body.filter.unwrap_or_default();
    let needle = filter
        .generic_search_term
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_lowercase);

    let mut chunks = Vec::new();
    for room_id in room_ids {
        let room_state = match current_state_map(storage, &room_id).await {
            Ok(s) => s,
            Err(e) => return MatrixError::from_conduit(e).into_response(),
        };
        let Some(chunk) = room_chunk(&room_id, &room_state) else {
            continue; // published but unknown (e.g. purged) — not listable
        };
        if let Some(types) = &filter.room_types {
            let room_type = chunk.get("room_type").and_then(Value::as_str);
            if !types.iter().any(|t| t.as_deref() == room_type) {
                continue;
            }
        }
        if let Some(needle) = &needle {
            if !searchable_text(&chunk, &room_state).contains(needle.as_str()) {
                continue;
            }
        }
        chunks.push(chunk);
    }
    chunks.sort_by(|a, b| {
        let members = |c: &Map<String, Value>| c["num_joined_members"].as_u64().unwrap_or(0);
        members(b)
            .cmp(&members(a))
            .then_with(|| a["room_id"].as_str().cmp(&b["room_id"].as_str()))
    });

    let total = chunks.len();
    let start = offset.min(total);
    let end = limit.map_or(total, |l| (start + l).min(total));
    let page: Vec<Value> = chunks[start..end].iter().cloned().map(Value::Object).collect();
    let mut response = Map::new();
    response.insert("chunk".into(), Value::Array(page));
    if end < total {
        response.insert("next_batch".into(), json!(format!("n{end}")));
    }
    if start > 0 {
        let prev = limit.map_or(0, |l| start.saturating_sub(l));
        response.insert("prev_batch".into(), json!(format!("p{prev}")));
    }
    response.insert("total_room_count_estimate".into(), json!(total));
    (StatusCode::OK, Json(Value::Object(response))).into_response()
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Remote directories are read with the federation `GET /publicRooms`.
/// A POST filter is applied to the page the remote returned.
async fn list_remote<S: AuthState>(state: &S, server: &str, body: PublicRoomsBody) -> Response {
    let Some(client) = state.federation_client() else {
        return MatrixError::new_not_found("federation is not available").into_response();
    };
    let mut params = Vec::new();
    if let Some(limit) = body.limit {
        params.push(format!("limit={limit}"));
    }
    if let Some(since) = &body.since {
        params.push(format!("since={}", encode(since)));
    }
    if body.include_all_networks == Some(true) {
        params.push("include_all_networks=true".to_owned());
    }
    if let Some(instance) = &body.third_party_instance_id {
        params.push(format!("third_party_instance_id={}", encode(instance)));
    }
    let mut path = "/_matrix/federation/v1/publicRooms".to_owned();
    if !params.is_empty() {
        path = format!("{path}?{}", params.join("&"));
    }
    let remote: Value = match client.get_raw(server, &path).await {
        Ok(resp) => match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"errcode": "M_UNKNOWN", "error": format!("bad directory response: {e}")})),
                )
                    .into_response()
            }
        },
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"errcode": "M_UNKNOWN", "error": format!("failed to fetch room directory: {e}")})),
            )
                .into_response()
        }
    };
    let mut remote = remote;
    if let Some(filter) = body.filter {
        let needle = filter.generic_search_term.map(|t| t.to_lowercase());
        if let Some(chunk) = remote["chunk"].as_array_mut() {
            chunk.retain(|room| {
                let type_ok = filter.room_types.as_ref().is_none_or(|types| {
                    types.iter().any(|t| t.as_deref() == room["room_type"].as_str())
                });
                let text_ok = needle.as_ref().is_none_or(|n| {
                    ["name", "topic", "canonical_alias"].iter().any(|k| {
                        room[*k].as_str().is_some_and(|v| v.to_lowercase().contains(n.as_str()))
                    })
                });
                type_ok && text_ok
            });
        }
    }
    (StatusCode::OK, Json(remote)).into_response()
}

async fn list<S: AuthState>(state: &S, server: Option<String>, body: PublicRoomsBody) -> Response {
    match server {
        Some(server) if server != state.server_name() => list_remote(state, &server, body).await,
        _ => list_local(state.storage().as_ref(), body).await,
    }
}

/// `GET /_matrix/client/v3/publicRooms?limit=&since=&server=`
pub async fn get_public_rooms<S: AuthState>(
    State(state): State<S>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let limit = match query.get("limit").map(|l| l.parse::<i64>()) {
        None => None,
        Some(Ok(limit)) => Some(limit),
        Some(Err(_)) => return invalid_param("limit must be an integer"),
    };
    let body = PublicRoomsBody {
        limit,
        since: query.get("since").cloned(),
        ..Default::default()
    };
    list(&state, query.get("server").cloned(), body).await
}

/// `POST /_matrix/client/v3/publicRooms?server=`
pub async fn post_public_rooms<S: AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<PublicRoomsBody>,
) -> Response {
    list(&state, query.get("server").cloned(), body).await
}

// ---------------------------------------------------------------------------
// Visibility
// ---------------------------------------------------------------------------

async fn room_known(storage: &dyn Storage, room_id: &str) -> Result<bool, Response> {
    storage
        .get_state_entry(room_id, "m.room.create", "")
        .await
        .map(|e| e.is_some())
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())
}

fn room_not_found() -> Response {
    MatrixError::new_not_found("Room not found").into_response()
}

/// `GET /_matrix/client/v3/directory/list/room/{roomId}`
pub async fn get_visibility<S: AuthState>(
    State(state): State<S>,
    Path(room_id): Path<String>,
) -> Response {
    let storage = state.storage().as_ref();
    match room_known(storage, &room_id).await {
        Ok(true) => {}
        Ok(false) => return room_not_found(),
        Err(r) => return r,
    }
    match storage.is_room_published(&room_id).await {
        Ok(published) => (
            StatusCode::OK,
            Json(json!({"visibility": if published { "public" } else { "private" }})),
        )
            .into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct VisibilityBody {
    pub visibility: Option<String>,
}

/// `Some(publish)` for `public` / `private` (absent means `public`).
fn parse_visibility(value: Option<&str>) -> Option<bool> {
    match value.unwrap_or("public") {
        "public" => Some(true),
        "private" => Some(false),
        _ => None,
    }
}

/// `PUT /_matrix/client/v3/directory/list/room/{roomId}`
pub async fn put_visibility<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Json(body): Json<VisibilityBody>,
) -> Response {
    let Some(publish) = parse_visibility(body.visibility.as_deref()) else {
        return invalid_param("visibility must be public or private");
    };
    let storage = state.storage().as_ref();
    let room_state = match current_state_map(storage, &room_id).await {
        Ok(s) => s,
        Err(e) => return MatrixError::from_conduit(e).into_response(),
    };
    if !room_state.contains_key(&("m.room.create".to_owned(), String::new())) {
        return room_not_found();
    }
    let is_admin = match storage.get_account(&authed.user_id).await {
        Ok(account) => account.is_some_and(|a| a.is_admin),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    if !is_admin && !may_send_state_event(&room_state, &authed.user_id, "m.room.canonical_alias") {
        return MatrixError::forbidden(
            "You must be joined with permission to set the room's canonical alias to change its directory visibility",
        )
        .into_response();
    }
    match storage.set_room_published(&room_id, publish).await {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct AppserviceVisibilityBody {
    pub visibility: String,
}

/// `PUT /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}`
pub async fn put_appservice_visibility<S: AuthState + AsState>(
    State(state): State<S>,
    authed: AsAuthed,
    Path((network_id, room_id)): Path<(String, String)>,
    Json(body): Json<AppserviceVisibilityBody>,
) -> Response {
    let Some(publish) = parse_visibility(Some(&body.visibility)) else {
        return invalid_param("visibility must be public or private");
    };
    match AuthState::storage(&state)
        .set_appservice_room_published(&authed.service.id, &network_id, &room_id, publish)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str, key: &str, content: Value) -> Event {
        Event {
            event_id: format!("${kind}{key}"),
            pdu: conduit::event::Pdu {
                room_id: "!r:x".into(),
                sender: "@a:x".into(),
                event_type: kind.into(),
                content,
                state_key: Some(key.into()),
                origin_server_ts: 0,
                auth_events: vec![],
                prev_events: vec![],
                hashes: json!({}),
                signatures: json!({}),
                depth: 1,
                extensions: Default::default(),
            },
            unsigned: None,
        }
    }

    fn state(events: Vec<Event>) -> StateMap<Event> {
        events
            .into_iter()
            .map(|e| ((e.event_type.clone(), e.state_key.clone().unwrap()), e))
            .collect()
    }

    #[test]
    fn unknown_room_has_no_chunk() {
        assert!(room_chunk("!r:x", &state(vec![])).is_none());
    }

    #[test]
    fn chunk_carries_every_spec_field() {
        let s = state(vec![
            ev("m.room.create", "", json!({"room_version": "11", "type": "m.space"})),
            ev("m.room.member", "@a:x", json!({"membership": "join"})),
            ev("m.room.member", "@b:x", json!({"membership": "invite"})),
            ev("m.room.name", "", json!({"name": "Cheese"})),
            ev("m.room.topic", "", json!({"topic": "Tasty"})),
            ev("m.room.canonical_alias", "", json!({"alias": "#cheese:x"})),
            ev("m.room.avatar", "", json!({"url": "mxc://x/y"})),
            ev("m.room.history_visibility", "", json!({"history_visibility": "world_readable"})),
            ev("m.room.guest_access", "", json!({"guest_access": "can_join"})),
            ev("m.room.join_rules", "", json!({"join_rule": "public"})),
        ]);
        let chunk = Value::Object(room_chunk("!r:x", &s).unwrap());
        assert_eq!(
            chunk,
            json!({
                "room_id": "!r:x", "num_joined_members": 1, "name": "Cheese",
                "topic": "Tasty", "canonical_alias": "#cheese:x",
                "avatar_url": "mxc://x/y", "world_readable": true,
                "guest_can_join": true, "join_rule": "public", "room_type": "m.space"
            })
        );
    }

    #[test]
    fn topic_prefers_plain_text_block() {
        let content = json!({
            "topic": "fallback",
            "m.topic": {"m.text": [
                {"body": "<b>rich</b>", "mimetype": "text/html"},
                {"body": "plain"}
            ]}
        });
        assert_eq!(plain_topic(&content).as_deref(), Some("plain"));
        assert_eq!(plain_topic(&json!({"topic": ""})), None);
    }

    #[test]
    fn since_tokens_round_trip() {
        assert_eq!(parse_since("n10"), Some(10));
        assert_eq!(parse_since("p0"), Some(0));
        assert_eq!(parse_since("10"), None);
        assert_eq!(parse_since("nx"), None);
    }
}
