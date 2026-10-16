//! Federation endpoints required by Matrix v1.19 that were not on the
//! original inbound router: key query, event auth, timestamp lookup,
//! knock, v1 invite (mounted beside v2), leave, public rooms, hierarchy,
//! OpenID userinfo, remote devices, and remote key claim/query.
//!
//! Third-party invite exchange checks the identity-server key, then issues
//! the invite to the invitee's server.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::Signer as _;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use conduit::auth::{auth_event_keys, current_state_map, third_party_signed_matches};
use conduit::event::{Event, Pdu, WirePdu};
use conduit::signing::{server_of_user_id, sign_authored};
use conduit::storage::Storage;
use conduit::wire::{decode_pdu, decode_pdu_for_version};

use crate::identity_service::IdentityClient;

use super::middleware::FederationOrigin;
use super::pipeline::{process_received, PipelineError};
use super::server::{
    bad_json, build_auth_chain, forbidden, internal, invalid_param, not_found, unauthorized, wire_pdus,
    FedState,
};

fn origin_of(origin_ext: Option<axum::extract::Extension<FederationOrigin>>) -> Result<String, Response> {
    match origin_ext {
        Some(axum::extract::Extension(origin)) => Ok(origin.server_name),
        None => Err(unauthorized("Not authenticated")),
    }
}

fn hash_bearer(token: &str) -> String {
    crate::api::client::probe::hash_bearer(token)
}

/// Signed server-key document for this process.
fn local_server_keys(state: &FedState) -> Value {
    let server_name = &*state.server_name;
    let key_id = &state.server_key.key_id;
    let pub_b64 = STANDARD_NO_PAD.encode(conduit::keys::public_bytes(&state.server_key));
    let now_ms = chrono::Utc::now().timestamp_millis();
    let valid_until_ts = now_ms + 24 * 60 * 60 * 1000;
    let unsigned = json!({
        "server_name": server_name,
        "verify_keys": { key_id: { "key": pub_b64 } },
        "old_verify_keys": {},
        "valid_until_ts": valid_until_ts,
    });
    let canonical = conduit::canonical_json::to_canonical_bytes(&unsigned)
        .expect("server key document is canonical JSON");
    let signature = state.server_key.signing_key.sign(&canonical);
    let mut response = unsigned;
    response["signatures"] = json!({
        server_name: { key_id: STANDARD_NO_PAD.encode(signature.to_bytes()) }
    });
    response
}

/// Sign `document` with this server's key, leaving every other signature in
/// place. The signed bytes are the document with `signatures` and `unsigned`
/// removed, which is the same payload the origin signed.
fn notarize(state: &FedState, mut document: Value) -> Option<Value> {
    let mut unsigned = document.clone();
    let obj = unsigned.as_object_mut()?;
    obj.remove("signatures");
    obj.remove("unsigned");
    let bytes = conduit::canonical_json::to_canonical_bytes(&unsigned).ok()?;
    let signature = state.server_key.signing_key.sign(&bytes);
    let signatures = document.as_object_mut()?.entry("signatures").or_insert_with(|| json!({}));
    let ours = signatures.as_object_mut()?.entry(state.server_name.to_string()).or_insert_with(|| json!({}));
    ours.as_object_mut()?.insert(
        state.server_key.key_id.clone(),
        json!(STANDARD_NO_PAD.encode(signature.to_bytes())),
    );
    Some(document)
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Highest `minimum_valid_until_ts` in the criteria. An absent timestamp means
/// the current time.
fn requested_minimum(criteria: &Value) -> i64 {
    let mut minimum = now_ms();
    if let Some(keys) = criteria.as_object() {
        for spec in keys.values() {
            if let Some(ts) = spec.get("minimum_valid_until_ts").and_then(Value::as_i64) {
                minimum = minimum.max(ts);
            }
        }
    }
    minimum
}

async fn fetch_origin_document(state: &FedState, server_name: &str) -> bool {
    let Ok(response) = state.fed_client.get_raw(server_name, "/_matrix/key/v2/server").await else {
        return false;
    };
    let Ok(value) = response.json::<Value>().await else {
        return false;
    };
    if value.get("server_name").and_then(Value::as_str) != Some(server_name) {
        return false;
    }
    state.remote_keys.store_verified_document(&value).await.is_ok()
}

/// The origin's key document, signed by this server. Offline origins with no
/// cache are omitted. A cached document is reused for half its lifetime unless
/// `minimum_valid_until_ts` asks for a longer validity, in which case a failed
/// refetch still returns the last document.
async fn notarized_document(state: &FedState, server_name: &str, minimum_valid_until_ts: i64) -> Option<Value> {
    if server_name == state.server_name.as_ref() {
        return Some(local_server_keys(state));
    }
    if let Some(document) = state.remote_keys.fresh_document(server_name, minimum_valid_until_ts).await {
        return notarize(state, document);
    }
    if fetch_origin_document(state, server_name).await {
        if let Some(document) = state.remote_keys.any_document(server_name).await {
            return notarize(state, document);
        }
    }
    state.remote_keys.any_document(server_name).await.and_then(|document| notarize(state, document))
}

/// `POST /_matrix/key/v2/query`. No authentication.
pub async fn key_query(State(state): State<FedState>, Json(body): Json<Value>) -> Response {
    let Some(requested) = body.get("server_keys").and_then(Value::as_object) else {
        return bad_json("server_keys is required");
    };
    let mut server_keys = Vec::new();
    for (name, criteria) in requested {
        if let Some(document) = notarized_document(&state, name, requested_minimum(criteria)).await {
            server_keys.push(document);
        }
    }
    (StatusCode::OK, Json(json!({ "server_keys": server_keys }))).into_response()
}

/// `GET /_matrix/key/v2/query/{serverName}`. No authentication. An unreachable
/// server with nothing cached is `200` and an empty `server_keys` array.
pub async fn key_query_server(
    State(state): State<FedState>,
    Path(server_name): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let minimum = query
        .get("minimum_valid_until_ts")
        .and_then(|raw| raw.parse::<i64>().ok())
        .unwrap_or_else(now_ms);
    let server_keys = match notarized_document(&state, &server_name, minimum).await {
        Some(document) => vec![document],
        None => Vec::new(),
    };
    (StatusCode::OK, Json(json!({ "server_keys": server_keys }))).into_response()
}

async fn room_version(state: &FedState, room_id: &str) -> Result<u32, Response> {
    match state.storage.get_state_entry(room_id, "m.room.create", "").await {
        Ok(Some(create)) => Ok(conduit::room_version::version_of_event(&create)),
        Ok(None) => Err(not_found("Room not found")),
        Err(error) => Err(internal(&error.to_string())),
    }
}

/// `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}`.
pub async fn event_auth(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path((room_id, event_id)): Path<(String, String)>,
) -> Response {
    let origin = match origin_of(origin_ext) {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    if let Some(response) = super::server::ensure_server_acl(&state, &origin, &room_id).await {
        return response;
    }
    let event = match state.storage.get_event(&event_id).await {
        Ok(Some(event)) if event.room_id == room_id => event,
        Ok(_) => return not_found("Event not found"),
        Err(error) => return internal(&error.to_string()),
    };
    let chain = build_auth_chain(&state.storage, &[event]).await;
    match wire_pdus(&state.storage, &origin, &chain).await {
        Ok(auth_chain) => (StatusCode::OK, Json(json!({ "auth_chain": auth_chain }))).into_response(),
        Err(error) => internal(&error.to_string()),
    }
}

/// `GET /_matrix/federation/v1/timestamp_to_event/{roomId}?ts=&dir=`.
pub async fn timestamp_to_event(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(room_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if origin_of(origin_ext).is_err() {
        return unauthorized("Not authenticated");
    }
    let Some(ts) = query.get("ts").and_then(|raw| raw.parse::<u64>().ok()) else {
        return invalid_param("ts is required");
    };
    let dir = query.get("dir").map(String::as_str).unwrap_or("f");
    if dir != "f" && dir != "b" {
        return invalid_param("dir must be f or b");
    }
    let events = match state.storage.room_events(&room_id).await {
        Ok(events) if !events.is_empty() => events,
        Ok(_) => return not_found("Room not found"),
        Err(error) => return internal(&error.to_string()),
    };
    let chosen = events.into_iter().filter(|event| match dir {
        "f" => event.origin_server_ts >= ts,
        _ => event.origin_server_ts <= ts,
    }).min_by_key(|event| {
        let distance = event.origin_server_ts.abs_diff(ts);
        (distance, event.depth, event.event_id.clone())
    });
    match chosen {
        Some(event) => (
            StatusCode::OK,
            Json(json!({
                "event_id": event.event_id,
                "origin_server_ts": event.origin_server_ts,
            })),
        )
            .into_response(),
        None => not_found("No event on that side of the timestamp"),
    }
}

fn public_body_from_query(query: &HashMap<String, String>) -> Result<crate::api::client::room_directory::PublicRoomsBody, Response> {
    let limit = match query.get("limit").map(|raw| raw.parse::<i64>()) {
        None => None,
        Some(Ok(limit)) => Some(limit),
        Some(Err(_)) => return Err(invalid_param("limit must be an integer")),
    };
    Ok(crate::api::client::room_directory::PublicRoomsBody {
        limit,
        since: query.get("since").cloned(),
        filter: None,
        include_all_networks: query.get("include_all_networks").map(|value| value == "true"),
        third_party_instance_id: query.get("third_party_instance_id").cloned(),
    })
}

/// `GET /_matrix/federation/v1/publicRooms`.
pub async fn public_rooms_get(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if origin_of(origin_ext).is_err() {
        return unauthorized("Not authenticated");
    }
    let body = match public_body_from_query(&query) {
        Ok(body) => body,
        Err(response) => return response,
    };
    crate::api::client::room_directory::list_local(state.storage.as_ref(), body).await
}

/// `POST /_matrix/federation/v1/publicRooms`.
pub async fn public_rooms_post(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Json(body): Json<crate::api::client::room_directory::PublicRoomsBody>,
) -> Response {
    if origin_of(origin_ext).is_err() {
        return unauthorized("Not authenticated");
    }
    crate::api::client::room_directory::list_local(state.storage.as_ref(), body).await
}

/// `GET /_matrix/federation/v1/hierarchy/{roomId}`.
///
/// Returns `{room, children, inaccessible_children}`. `children` is the flat
/// list of descendants the requesting server can peek or join. A known child
/// it cannot peek is named in `inaccessible_children` and is not walked.
/// A child this server has not created is left out of both lists; its
/// `m.space.child` event stays on the parent's `children_state`.
pub async fn hierarchy(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(room_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let origin = match origin_of(origin_ext) {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    let suggested_only = matches!(query.get("suggested_only").map(String::as_str), Some("true"));
    let root = match current_state_map(state.storage.as_ref(), &room_id).await {
        Ok(root) if root.contains_key(&("m.room.create".into(), String::new())) => root,
        Ok(_) => return not_found("Room not found"),
        Err(error) => return internal(&error.to_string()),
    };
    if !server_may_peek(state.storage.as_ref(), &root, &origin).await {
        return not_found("You cannot view or peek on this room");
    }
    let root_children = crate::api::client::room_content::hierarchy::ordered_children(&root, suggested_only);
    let room = federation_summary(&room_id, &root, &root_children);
    let mut children = Vec::new();
    let mut inaccessible = Vec::new();
    let mut seen = std::collections::HashSet::new();
    seen.insert(room_id);
    let mut stack = Vec::new();
    for child in root_children.iter().rev() {
        let Some(child_id) = child.state_key.clone() else { continue };
        if !seen.contains(&child_id) {
            stack.push(child_id);
        }
    }
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        let child_state = match current_state_map(state.storage.as_ref(), &id).await {
            Ok(child_state) if child_state.contains_key(&("m.room.create".into(), String::new())) => child_state,
            Ok(_) => continue,
            Err(error) => return internal(&error.to_string()),
        };
        if !server_may_peek(state.storage.as_ref(), &child_state, &origin).await {
            inaccessible.push(id);
            continue;
        }
        let child_edges = crate::api::client::room_content::hierarchy::ordered_children(&child_state, suggested_only);
        for edge in child_edges.iter().rev() {
            let Some(next_id) = edge.state_key.clone() else { continue };
            if !seen.contains(&next_id) {
                stack.push(next_id);
            }
        }
        children.push(federation_summary(&id, &child_state, &child_edges));
    }
    (
        StatusCode::OK,
        Json(json!({
            "room": room,
            "children": children,
            "inaccessible_children": inaccessible,
        })),
    )
        .into_response()
}

/// Hierarchy summary. A missing join rule is omitted so callers treat the
/// room as public, which is the federation default.
fn federation_summary(
    room_id: &str,
    state: &conduit::auth::StateMap<Event>,
    children: &[Event],
) -> Value {
    let mut room = crate::api::client::room_content::hierarchy::summary(room_id, state, children);
    if !state.contains_key(&("m.room.join_rules".to_owned(), String::new())) {
        if let Some(object) = room.as_object_mut() {
            object.remove("join_rule");
        }
    }
    room
}

async fn server_may_peek(storage: &dyn Storage, state: &conduit::auth::StateMap<Event>, origin: &str) -> bool {
    if state.iter().any(|((kind, key), event)| {
        kind == "m.room.member"
            && event.content["membership"] == "join"
            && server_of_user_id(key) == Some(origin)
    }) {
        return true;
    }
    let history = state
        .get(&("m.room.history_visibility".into(), String::new()))
        .and_then(|event| event.content["history_visibility"].as_str());
    if history == Some("world_readable") {
        return true;
    }
    let rule = state
        .get(&("m.room.join_rules".into(), String::new()))
        .and_then(|event| event.content["join_rule"].as_str());
    if matches!(rule, Some("public" | "knock" | "knock_restricted")) {
        return true;
    }
    if rule == Some("restricted") {
        let allow = state
            .get(&("m.room.join_rules".into(), String::new()))
            .and_then(|event| event.content["allow"].as_array());
        if let Some(allow) = allow {
            for condition in allow {
                if condition["type"] != "m.room_membership" {
                    continue;
                }
                let Some(room) = condition["room_id"].as_str() else { continue };
                let Ok(members) = storage.member_events_for_server(room, origin).await else {
                    continue;
                };
                if members.iter().any(|(_, event)| event.content["membership"] == "join") {
                    return true;
                }
            }
        }
    }
    false
}

/// `GET /_matrix/federation/v1/openid/userinfo?access_token=`.
pub async fn openid_userinfo(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if origin_of(origin_ext).is_err() {
        return unauthorized("Not authenticated");
    }
    let Some(token) = query.get("access_token").filter(|token| !token.is_empty()) else {
        return bad_json("access_token is required");
    };
    match state.storage.lookup_token(&hash_bearer(token)).await {
        Ok(Some(owner)) => (StatusCode::OK, Json(json!({ "sub": owner.user_id }))).into_response(),
        Ok(None) => unauthorized("OpenID token is not valid"),
        Err(error) => internal(&error.to_string()),
    }
}

/// `GET /_matrix/federation/v1/user/devices/{userId}`.
pub async fn user_devices(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(user_id): Path<String>,
) -> Response {
    if origin_of(origin_ext).is_err() {
        return unauthorized("Not authenticated");
    }
    if server_of_user_id(&user_id) != Some(state.server_name.as_ref()) {
        return not_found("User is not local");
    }
    let devices = match state.storage.list_devices_for_user(&user_id).await {
        Ok(devices) => devices,
        Err(error) => return internal(&error.to_string()),
    };
    let keys = match state.storage.get_device_keys_for_user(&user_id).await {
        Ok(keys) => keys,
        Err(error) => return internal(&error.to_string()),
    };
    let stream_id = match state.storage.device_list_max_position().await {
        Ok(stream_id) => stream_id,
        Err(error) => return internal(&error.to_string()),
    };
    let devices: Vec<Value> = devices
        .into_iter()
        .map(|device| {
            let mut entry = json!({
                "device_id": device.device_id,
                "device_display_name": device.display_name,
            });
            if let Some(device_keys) = keys.get(&device.device_id) {
                entry["keys"] = device_keys.clone();
            }
            entry
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "user_id": user_id,
            "stream_id": stream_id,
            "devices": devices,
        })),
    )
        .into_response()
}

/// `POST /_matrix/federation/v1/user/keys/query`.
pub async fn user_keys_query(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Json(body): Json<Value>,
) -> Response {
    if origin_of(origin_ext).is_err() {
        return unauthorized("Not authenticated");
    }
    let Some(requested) = body.get("device_keys").and_then(Value::as_object) else {
        return bad_json("device_keys is required");
    };
    let mut device_keys = serde_json::Map::new();
    let mut master_keys = serde_json::Map::new();
    let mut self_signing_keys = serde_json::Map::new();
    for (user_id, device_ids) in requested {
        if server_of_user_id(user_id) != Some(state.server_name.as_ref()) {
            continue;
        }
        let filter: Vec<String> = device_ids
            .as_array()
            .map(|ids| ids.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default();
        let published = match crate::api::client::keys::query_local_user_keys(
            state.storage.as_ref(),
            user_id,
            &filter,
            None,
        )
        .await
        {
            Ok(published) => published,
            Err(error) => return internal(&error.to_string()),
        };
        device_keys.insert(user_id.clone(), Value::Object(published.devices));
        if let Some(master) = published.master {
            master_keys.insert(user_id.clone(), master);
        }
        if let Some(self_signing) = published.self_signing {
            self_signing_keys.insert(user_id.clone(), self_signing);
        }
    }
    (
        StatusCode::OK,
        Json(json!({
            "device_keys": device_keys,
            "master_keys": master_keys,
            "self_signing_keys": self_signing_keys,
        })),
    )
        .into_response()
}

/// `POST /_matrix/federation/v1/user/keys/claim`.
pub async fn user_keys_claim(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Json(body): Json<Value>,
) -> Response {
    if origin_of(origin_ext).is_err() {
        return unauthorized("Not authenticated");
    }
    let Some(requested) = body.get("one_time_keys").and_then(Value::as_object) else {
        return bad_json("one_time_keys is required");
    };
    let mut one_time_keys = serde_json::Map::new();
    for (user_id, devices) in requested {
        if server_of_user_id(user_id) != Some(state.server_name.as_ref()) {
            continue;
        }
        let Some(devices) = devices.as_object() else { continue };
        let mut for_user = serde_json::Map::new();
        for (device_id, algorithm) in devices {
            let Some(algorithm) = algorithm.as_str() else { continue };
            let claimed = match state.storage.claim_one_time_key(user_id, device_id, algorithm).await {
                Ok(Some(key)) => Some(key),
                Ok(None) => match state.storage.claim_fallback_key(user_id, device_id, algorithm).await {
                    Ok(key) => key,
                    Err(error) => return internal(&error.to_string()),
                },
                Err(error) => return internal(&error.to_string()),
            };
            if let Some((key_id, key_json)) = claimed {
                for_user.insert(device_id.clone(), json!({ key_id: key_json }));
            }
        }
        one_time_keys.insert(user_id.clone(), Value::Object(for_user));
    }
    (StatusCode::OK, Json(json!({ "one_time_keys": one_time_keys }))).into_response()
}

async fn membership_template(
    state: &FedState,
    room_id: &str,
    user_id: &str,
    membership: &str,
) -> Result<(Value, String), Response> {
    let create = match state.storage.get_state_entry(room_id, "m.room.create", "").await {
        Ok(Some(create)) => create,
        Ok(None) => return Err(not_found("Room not found")),
        Err(error) => return Err(internal(&error.to_string())),
    };
    let room_version = create.content["room_version"].as_str().unwrap_or("11").to_owned();
    let events = state.storage.room_events(room_id).await.map_err(|error| internal(&error.to_string()))?;
    let (prev_events, depth) = match events.iter().max_by_key(|event| event.depth) {
        Some(event) => (vec![event.event_id.clone()], event.depth + 1),
        None => (vec![], 1),
    };
    let template_event = Event {
        event_id: String::new(),
        pdu: Pdu::new(
            room_id,
            user_id,
            "m.room.member",
            Some(user_id.to_owned()),
            json!({ "membership": membership }),
            0,
            vec![],
            prev_events.clone(),
            depth,
        ),
        unsigned: None,
    };
    let mut auth_events = Vec::new();
    let version_num = conduit::room_version::version_of_content(&create.content);
    for (kind, key) in auth_event_keys(&template_event) {
        if kind == "m.room.create" && !conduit::room_version::cites_room_create(version_num) {
            continue;
        }
        if let Ok(Some(event)) = state.storage.get_state_entry(room_id, &kind, &key).await {
            auth_events.push(event.event_id);
        }
    }
    let event = json!({
        "room_id": room_id,
        "sender": user_id,
        "type": "m.room.member",
        "content": { "membership": membership },
        "state_key": user_id,
        "auth_events": auth_events,
        "prev_events": prev_events,
        "depth": depth,
        "origin_server_ts": super::now_ms(),
    });
    Ok((event, room_version))
}

/// `GET /_matrix/federation/v1/make_knock/{roomId}/{userId}`.
pub async fn make_knock(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path((room_id, user_id)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let origin = match origin_of(origin_ext) {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    if let Some(response) = super::server::ensure_server_acl(&state, &origin, &room_id).await {
        return response;
    }
    if server_of_user_id(&user_id) != Some(origin.as_str()) {
        return invalid_param("user is not on the requesting server");
    }
    let version = match room_version(&state, &room_id).await {
        Ok(version) => version,
        Err(response) => return response,
    };
    if version < 7 {
        return matrix_incompatible("This room version does not support knocking");
    }
    let rule = state
        .storage
        .get_state_entry(&room_id, "m.room.join_rules", "")
        .await
        .ok()
        .flatten()
        .and_then(|event| event.content["join_rule"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "invite".into());
    let min = if rule == "knock_restricted" { 10 } else { 7 };
    if rule != "knock" && rule != "knock_restricted" || version < min {
        return forbidden("Knocking is not allowed");
    }
    if let Some(versions) = query.get("ver") {
        if !versions.split(',').any(|offered| offered == version.to_string()) {
            return matrix_incompatible("Room version is not in ver");
        }
    }
    match membership_template(&state, &room_id, &user_id, "knock").await {
        Ok((event, room_version)) => {
            (StatusCode::OK, Json(json!({ "event": event, "room_version": room_version }))).into_response()
        }
        Err(response) => response,
    }
}

/// `GET /_matrix/federation/v1/make_leave/{roomId}/{userId}`.
pub async fn make_leave(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path((room_id, user_id)): Path<(String, String)>,
) -> Response {
    let origin = match origin_of(origin_ext) {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    if let Some(response) = super::server::ensure_server_acl(&state, &origin, &room_id).await {
        return response;
    }
    if server_of_user_id(&user_id) != Some(origin.as_str()) {
        return invalid_param("user is not on the requesting server");
    }
    let membership = state
        .storage
        .get_state_entry(&room_id, "m.room.member", &user_id)
        .await
        .ok()
        .flatten()
        .and_then(|event| event.content["membership"].as_str().map(str::to_owned));
    if !matches!(membership.as_deref(), Some("join" | "invite" | "knock")) {
        return forbidden("User is not in the room");
    }
    match membership_template(&state, &room_id, &user_id, "leave").await {
        Ok((event, room_version)) => {
            (StatusCode::OK, Json(json!({ "event": event, "room_version": room_version }))).into_response()
        }
        Err(response) => response,
    }
}

fn matrix_incompatible(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "errcode": "M_INCOMPATIBLE_ROOM_VERSION", "error": message })),
    )
        .into_response()
}

async fn accept_membership(
    state: &FedState,
    origin: &str,
    room_id: &str,
    path_event_id: &str,
    pdu_val: Value,
    membership: &str,
) -> Result<conduit::signing::Received, Response> {
    let decoded = decode_pdu(pdu_val, super::now_ms()).map_err(|error| bad_json(&error.to_string()))?;
    let pdu = decoded.pdu;
    if pdu.room_id != room_id {
        return Err(invalid_param("PDU room_id does not match the path"));
    }
    if pdu.event_type != "m.room.member" || pdu.content["membership"] != membership {
        return Err(invalid_param("membership does not match this endpoint"));
    }
    if pdu.state_key.as_deref() != Some(pdu.sender.as_str()) {
        return Err(invalid_param("state_key must equal sender"));
    }
    if server_of_user_id(&pdu.sender) != Some(origin) {
        return Err(invalid_param("sender is not a user on the requesting server"));
    }
    let received = super::pipeline::verify_received(&state.remote_keys, &state.http, pdu, None)
        .await
        .map_err(|_| invalid_param("signature check failed"))?;
    if received.event_id != path_event_id {
        return Err(invalid_param("event id does not match the path"));
    }
    process_received(
        &state.storage,
        &state.remote_keys,
        &state.http,
        &state.events_tx,
        Some(&state.fed_client),
        Some(&state.recent),
        received.clone(),
        decoded.unsigned,
        origin,
    )
    .await
    .map_err(|error| match error {
        PipelineError::AuthFailed(message) => forbidden(&message),
        other => internal(&other.to_string()),
    })?;
    Ok(received)
}

/// `PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}`.
pub async fn send_knock(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path((room_id, event_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Response {
    let origin = match origin_of(origin_ext) {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    if let Some(response) = super::server::ensure_server_acl(&state, &origin, &room_id).await {
        return response;
    }
    let version = match room_version(&state, &room_id).await {
        Ok(version) => version,
        Err(response) => return response,
    };
    if version < 7 {
        return matrix_incompatible("This room version does not support knocking");
    }
    match accept_membership(&state, &origin, &room_id, &event_id, body, "knock").await {
        Ok(_) => knock_room_state(&state, &origin, &room_id).await,
        Err(response) => response,
    }
}

/// Identifying state returned with an accepted knock. Full federation PDUs,
/// including `m.room.create`.
const KNOCK_ROOM_STATE: &[&str] = &[
    "m.room.create",
    "m.room.name",
    "m.room.avatar",
    "m.room.topic",
    "m.room.join_rules",
    "m.room.canonical_alias",
    "m.room.encryption",
    "m.room.history_visibility",
];

async fn knock_room_state(state: &FedState, origin: &str, room_id: &str) -> Response {
    let events = match state.storage.get_current_state(room_id).await {
        Ok(events) => events
            .into_iter()
            .filter(|event| KNOCK_ROOM_STATE.contains(&event.event_type.as_str()))
            .collect::<Vec<_>>(),
        Err(error) => return internal(&error.to_string()),
    };
    let pdus = match wire_pdus(&state.storage, origin, &events).await {
        Ok(pdus) => pdus,
        Err(error) => return internal(&error.to_string()),
    };
    (StatusCode::OK, Json(json!({ "knock_room_state": pdus }))).into_response()
}

/// `PUT /_matrix/federation/v1/invite/{roomId}/{eventId}`.
///
/// Room versions 1 and 2. The body is the event itself. The response is that
/// event with this server's signature added and every other field left as it
/// arrived, including `event_id` and tuple `auth_events` / `prev_events`.
pub async fn invite_v1(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path((room_id, path_event_id)): Path<(String, String)>,
    Json(mut event): Json<Value>,
) -> Response {
    let origin = match origin_of(origin_ext) {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    if let Some(response) = super::server::ensure_server_acl(&state, &origin, &room_id).await {
        return response;
    }
    if event.get("type").and_then(Value::as_str) != Some("m.room.member") {
        return invalid_param("Expected an m.room.member event");
    }
    if event["content"]["membership"].as_str() != Some("invite") {
        return invalid_param("Expected invite membership");
    }
    if event["room_id"].as_str() != Some(room_id.as_str()) {
        return invalid_param("PDU room_id does not match the path");
    }
    let Some(sender) = event["sender"].as_str() else {
        return bad_json("sender is required");
    };
    if server_of_user_id(sender) != Some(origin.as_str()) {
        return invalid_param("sender is not a user on the requesting server");
    }
    let Some(target) = event["state_key"].as_str() else {
        return bad_json("state_key is required");
    };
    if server_of_user_id(target) != Some(state.server_name.as_ref()) {
        return invalid_param("Invite target is not on this server");
    }
    if event["event_id"].as_str() != Some(path_event_id.as_str()) {
        return invalid_param("Invite event ID must match the event ID in the path");
    }
    match v1_content_matches(&event) {
        Ok(true) => {}
        Ok(false) => return invalid_param("Invite content hash does not match"),
        Err(response) => return response,
    }
    if let Err(response) = verify_v1_signature(&state, &event, &origin).await {
        return response;
    }
    if crate::api::client::room_membership::blocks_invites(state.storage.as_ref(), target).await {
        return super::server::matrix_error(
            StatusCode::FORBIDDEN,
            "M_INVITE_BLOCKED",
            &format!("{target} is not accepting invites"),
        );
    }
    if insert_v1_signature(&mut event, &state.server_key, &state.server_name).is_err() {
        return internal("Failed to sign invite");
    }
    let decoded = match decode_pdu_for_version(event.clone(), 1, super::now_ms()) {
        Ok(decoded) => decoded,
        Err(error) => return bad_json(&error.to_string()),
    };
    let Some(event_id) = decoded.explicit_event_id else {
        return bad_json("event_id is required");
    };
    let stored = Event { event_id, pdu: decoded.pdu, unsigned: decoded.unsigned };
    if let Err(error) = state.storage.publish_event(&stored).await {
        return internal(&error.to_string());
    }
    if let Ok(position) = state.storage.global_max_stream_position().await {
        let _ = state.events_tx.send(position);
    }
    (StatusCode::OK, Json(json!({ "event": event }))).into_response()
}

/// `PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}`.
pub async fn send_leave(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path((room_id, event_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Response {
    let origin = match origin_of(origin_ext) {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    if let Some(response) = super::server::ensure_server_acl(&state, &origin, &room_id).await {
        return response;
    }
    match accept_membership(&state, &origin, &room_id, &event_id, body, "leave").await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(response) => response,
    }
}

/// `PUT /_matrix/federation/v1/exchange_third_party_invite/{roomId}`.
///
/// The body is a partial member event. A matching signature must also pass
/// `key_validity_url`. The invite is then issued to the invitee's server and
/// only the co-signed event is stored.
pub async fn exchange_third_party_invite(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(room_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let origin = match origin_of(origin_ext) {
        Ok(origin) => origin,
        Err(response) => return response,
    };
    if let Some(response) = super::server::ensure_server_acl(&state, &origin, &room_id).await {
        return response;
    }
    if body["type"].as_str() != Some("m.room.member") || body["content"]["membership"].as_str() != Some("invite") {
        return invalid_param("Expected an m.room.member invite");
    }
    if body["room_id"].as_str() != Some(room_id.as_str()) {
        return invalid_param("PDU room_id does not match the path");
    }
    let Some(sender) = body["sender"].as_str() else {
        return bad_json("sender is required");
    };
    if server_of_user_id(sender) != Some(state.server_name.as_ref()) {
        return invalid_param("sender is not a user of this server");
    }
    let Some(mxid) = body["state_key"].as_str() else {
        return bad_json("state_key is required");
    };
    if server_of_user_id(mxid) != Some(origin.as_str()) {
        return invalid_param("state_key is not a user on the requesting server");
    }
    let signed = &body["content"]["third_party_invite"]["signed"];
    let Some(token) = signed["token"].as_str() else {
        return bad_json("signed.token is required");
    };
    let invite = match state.storage.get_state_entry(&room_id, "m.room.third_party_invite", token).await {
        Ok(Some(invite)) => invite,
        Ok(None) => return not_found("No third-party invite for that token"),
        Err(error) => return internal(&error.to_string()),
    };
    if invite.sender != sender {
        return forbidden("sender does not match the third-party invite");
    }
    let third_party = body["content"]["third_party_invite"].clone();
    let content = json!({ "membership": "invite", "third_party_invite": third_party });
    let events = match state.storage.room_events(&room_id).await {
        Ok(events) => events,
        Err(error) => return internal(&error.to_string()),
    };
    let (prev_events, depth) = match events.iter().max_by_key(|event| event.depth) {
        Some(event) => (vec![event.event_id.clone()], event.depth + 1),
        None => (vec![], 1),
    };
    let provisional = Event {
        event_id: String::new(),
        pdu: Pdu::new(
            room_id.clone(),
            sender,
            "m.room.member",
            Some(mxid.to_owned()),
            content.clone(),
            super::now_ms(),
            vec![],
            prev_events.clone(),
            depth,
        ),
        unsigned: None,
    };
    let mut auth_events = Vec::new();
    let version_num = match state.storage.get_state_entry(&room_id, "m.room.create", "").await {
        Ok(Some(create)) => conduit::room_version::version_of_content(&create.content),
        _ => 11,
    };
    for (kind, key) in auth_event_keys(&provisional) {
        if kind == "m.room.create" && !conduit::room_version::cites_room_create(version_num) {
            continue;
        }
        if let Ok(Some(event)) = state.storage.get_state_entry(&room_id, &kind, &key).await {
            auth_events.push(event.event_id);
        }
    }
    let mut pdu = Pdu::new(
        room_id.clone(),
        sender,
        "m.room.member",
        Some(mxid.to_owned()),
        content,
        super::now_ms(),
        auth_events,
        prev_events,
        depth,
    );
    let candidate = Event { event_id: String::new(), pdu: pdu.clone(), unsigned: None };
    let auth_state = match current_state_map(state.storage.as_ref(), &room_id).await {
        Ok(auth_state) => auth_state,
        Err(error) => return internal(&error.to_string()),
    };
    if let Err(error) = conduit::auth::check_auth(&candidate, &auth_state) {
        return forbidden(&error.to_string());
    }
    if !third_party_key_is_valid(signed, &invite.content).await {
        return forbidden("third-party invite key is not valid");
    }
    if let Err(error) = sign_authored(&mut pdu, &state.server_key, &state.server_name) {
        return internal(&error.to_string());
    }
    let event_id = match conduit::hashing::event_id(&pdu) {
        Ok(event_id) => event_id,
        Err(error) => return internal(&error.to_string()),
    };
    let Some(wire) = WirePdu::checked(&event_id, pdu) else {
        return internal("invite does not reproduce its event id");
    };
    let room_version = match room_version(&state, &room_id).await {
        Ok(version) => version.to_string(),
        Err(response) => return response,
    };
    let stripped = match stripped_invite_state(&state, &room_id).await {
        Ok(stripped) => stripped,
        Err(response) => return response,
    };
    let returned = match state.fed_client.invite(mxid_server(mxid), &room_id, &room_version, stripped, &wire).await {
        Ok(returned) => returned,
        Err(_) => return invite_rejected(),
    };
    let admitted = match super::admit::admit_cosigned(
        &state.remote_keys,
        &state.http,
        returned,
        &wire,
        mxid_server(mxid),
    )
    .await
    {
        Ok(admitted) => admitted,
        Err(_) => return invite_rejected(),
    };
    if let Err(error) = state.storage.publish_event(&admitted.into_event()).await {
        return internal(&error.to_string());
    }
    if let Ok(position) = state.storage.global_max_stream_position().await {
        let _ = state.events_tx.send(position);
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

fn mxid_server(mxid: &str) -> &str {
    server_of_user_id(mxid).unwrap_or(mxid)
}

fn invite_rejected() -> Response {
    super::server::matrix_error(
        StatusCode::BAD_GATEWAY,
        "M_UNKNOWN",
        "invitee did not accept the invite",
    )
}

async fn stripped_invite_state(state: &FedState, room_id: &str) -> Result<Vec<Value>, Response> {
    let events = state.storage.get_current_state(room_id).await.map_err(|error| internal(&error.to_string()))?;
    Ok(events
        .into_iter()
        .filter(|event| {
            KNOCK_ROOM_STATE.contains(&event.event_type.as_str()) || event.event_type == "m.room.member"
        })
        .map(|event| {
            json!({
                "type": event.event_type,
                "state_key": event.state_key,
                "sender": event.sender,
                "content": event.content,
            })
        })
        .collect())
}

/// Keys from `public_key` / `key_validity_url` and each `public_keys` entry.
fn third_party_keys(content: &Value) -> Vec<(String, Option<String>)> {
    let mut keys = Vec::new();
    if let Some(key) = content["public_key"].as_str() {
        keys.push((key.to_owned(), content["key_validity_url"].as_str().map(str::to_owned)));
    }
    if let Some(list) = content["public_keys"].as_array() {
        for entry in list {
            let Some(key) = entry["public_key"].as_str() else { continue };
            let url = entry["key_validity_url"]
                .as_str()
                .or(content["key_validity_url"].as_str())
                .map(str::to_owned);
            keys.push((key.to_owned(), url));
        }
    }
    keys
}

/// `check_auth` accepts any matching key. Federation also requires that a
/// signature-matching key is currently valid at its `key_validity_url`.
async fn third_party_key_is_valid(signed: &Value, invite_content: &Value) -> bool {
    let identity = IdentityClient::shared();
    for (key, url) in third_party_keys(invite_content) {
        if !third_party_signed_matches(signed, &key) {
            continue;
        }
        let Some(url) = url else { continue };
        if identity.key_is_valid(&url, &key).await.unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Room versions 1 and 2 keep these fields when redacting for signatures.
const V1_SIGN_FIELDS: &[&str] = &[
    "auth_events",
    "content",
    "depth",
    "event_id",
    "hashes",
    "membership",
    "origin",
    "origin_server_ts",
    "prev_events",
    "prev_state",
    "room_id",
    "sender",
    "state_key",
    "type",
];

fn v1_redact_content(event_type: &str, content: &Value) -> Value {
    let Some(map) = content.as_object() else {
        return json!({});
    };
    let fields: &[&str] = match event_type {
        "m.room.member" => &["membership"],
        "m.room.create" => &["creator"],
        "m.room.join_rules" => &["join_rule"],
        "m.room.power_levels" => &[
            "ban",
            "events",
            "events_default",
            "kick",
            "redact",
            "state_default",
            "users",
            "users_default",
        ],
        "m.room.aliases" => &["aliases"],
        "m.room.history_visibility" => &["history_visibility"],
        _ => &[],
    };
    let mut redacted = Map::new();
    for field in fields {
        if let Some(value) = map.get(*field) {
            redacted.insert((*field).to_owned(), value.clone());
        }
    }
    Value::Object(redacted)
}

fn v1_signing_bytes(event: &Value) -> Result<Vec<u8>, ()> {
    let map = event.as_object().ok_or(())?;
    let mut kept = Map::new();
    for key in V1_SIGN_FIELDS {
        if let Some(value) = map.get(*key) {
            kept.insert((*key).to_owned(), value.clone());
        }
    }
    if let Some(content) = kept.get("content").cloned() {
        let event_type = kept.get("type").and_then(Value::as_str).unwrap_or("");
        kept.insert("content".into(), v1_redact_content(event_type, &content));
    }
    conduit::canonical_json::to_canonical_bytes(&Value::Object(kept)).map_err(|_| ())
}

fn v1_content_digest(event: &Value) -> Result<Vec<u8>, ()> {
    let mut copy = event.as_object().cloned().ok_or(())?;
    copy.remove("hashes");
    copy.remove("signatures");
    copy.remove("unsigned");
    let bytes = conduit::canonical_json::to_canonical_bytes(&Value::Object(copy)).map_err(|_| ())?;
    Ok(Sha256::digest(&bytes).to_vec())
}

fn v1_content_matches(event: &Value) -> Result<bool, Response> {
    let Some(claimed) = event["hashes"]["sha256"].as_str() else {
        return Err(invalid_param("Invite content hash does not match"));
    };
    let claimed = conduit::hashing::decode_unpadded_base64(claimed)
        .map_err(|_| invalid_param("Invite content hash does not match"))?;
    let actual = v1_content_digest(event).map_err(|_| invalid_param("Invite content hash does not match"))?;
    Ok(claimed == actual)
}

async fn verify_v1_signature(state: &FedState, event: &Value, origin: &str) -> Result<(), Response> {
    let bytes = v1_signing_bytes(event).map_err(|_| invalid_param("signature check failed"))?;
    let timestamp = event["origin_server_ts"].as_u64().unwrap_or(0);
    let Some(signatures) = event["signatures"].get(origin).and_then(Value::as_object) else {
        return Err(invalid_param("signature check failed"));
    };
    let mut eligible = 0usize;
    for (key_id, signature) in signatures {
        let Some(public) = state.remote_keys.eligible_key(&state.http, origin, key_id, timestamp).await else {
            continue;
        };
        eligible += 1;
        verify_ed25519(&bytes, signature, &public).map_err(|_| invalid_param("signature check failed"))?;
    }
    if eligible == 0 {
        return Err(invalid_param("signature check failed"));
    }
    Ok(())
}

fn insert_v1_signature(event: &mut Value, server_key: &conduit::keys::ServerKey, server_name: &str) -> Result<(), ()> {
    let bytes = v1_signing_bytes(event)?;
    let signature = server_key.signing_key.sign(&bytes);
    let encoded = STANDARD_NO_PAD.encode(signature.to_bytes());
    let signatures = event.as_object_mut().ok_or(())?.entry("signatures").or_insert_with(|| json!({}));
    if !signatures.is_object() {
        *signatures = json!({});
    }
    let server_sigs = signatures
        .as_object_mut()
        .ok_or(())?
        .entry(server_name.to_owned())
        .or_insert_with(|| json!({}));
    if !server_sigs.is_object() {
        *server_sigs = json!({});
    }
    server_sigs.as_object_mut().ok_or(())?.insert(server_key.key_id.clone(), Value::String(encoded));
    Ok(())
}

fn verify_ed25519(bytes: &[u8], signature: &Value, public: &[u8]) -> Result<(), ()> {
    let encoded = signature.as_str().ok_or(())?;
    let raw = conduit::hashing::decode_unpadded_base64(encoded).map_err(|_| ())?;
    let sig_bytes: [u8; 64] = raw.as_slice().try_into().map_err(|_| ())?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let public: [u8; 32] = public.try_into().map_err(|_| ())?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&public).map_err(|_| ())?;
    key.verify_strict(bytes, &signature).map_err(|_| ())
}
