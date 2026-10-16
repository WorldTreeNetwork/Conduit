//! Federation endpoints required by Matrix v1.19 that were not on the
//! original inbound router: key query, event auth, timestamp lookup,
//! knock, v1 invite (mounted beside v2), leave, public rooms, hierarchy,
//! OpenID userinfo, remote devices, and remote key claim/query.
//!
//! Third-party invite exchange signs a membership invite as this server.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::Signer as _;
use serde_json::{json, Value};

use conduit::auth::{auth_event_keys, current_state_map};
use conduit::event::{Event, Pdu};
use conduit::signing::{server_of_user_id, sign_authored};
use conduit::storage::Storage;
use conduit::wire::decode_pdu;

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

async fn server_key_document(state: &FedState, server_name: &str) -> Option<Value> {
    if server_name == state.server_name.as_ref() {
        return Some(local_server_keys(state));
    }
    let response = state.fed_client.get_raw(server_name, "/_matrix/key/v2/server").await.ok()?;
    response.json().await.ok()
}

/// `POST /_matrix/key/v2/query`.
pub async fn key_query(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Json(body): Json<Value>,
) -> Response {
    if origin_of(origin_ext).is_err() {
        return unauthorized("Not authenticated");
    }
    let Some(requested) = body.get("server_keys").and_then(Value::as_object) else {
        return bad_json("server_keys is required");
    };
    let mut server_keys = Vec::new();
    for name in requested.keys() {
        if let Some(document) = server_key_document(&state, name).await {
            server_keys.push(document);
        }
    }
    (StatusCode::OK, Json(json!({ "server_keys": server_keys }))).into_response()
}

/// `GET /_matrix/key/v2/query/{serverName}`.
pub async fn key_query_server(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(server_name): Path<String>,
) -> Response {
    if origin_of(origin_ext).is_err() {
        return unauthorized("Not authenticated");
    }
    match server_key_document(&state, &server_name).await {
        Some(document) => (StatusCode::OK, Json(json!({ "server_keys": [document] }))).into_response(),
        None => not_found("Server keys not available"),
    }
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
    match wire_pdus(&state.storage, &chain).await {
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
    for (user_id, device_ids) in requested {
        if server_of_user_id(user_id) != Some(state.server_name.as_ref()) {
            continue;
        }
        let stored = match state.storage.get_device_keys_for_user(user_id).await {
            Ok(stored) => stored,
            Err(error) => return internal(&error.to_string()),
        };
        let mut for_user = serde_json::Map::new();
        let filter: Option<Vec<&str>> = device_ids.as_array().map(|ids| ids.iter().filter_map(Value::as_str).collect());
        for (device_id, keys) in stored {
            let wanted = filter.as_ref().is_none_or(|ids| ids.is_empty() || ids.contains(&device_id.as_str()));
            if wanted {
                for_user.insert(device_id, keys);
            }
        }
        device_keys.insert(user_id.clone(), Value::Object(for_user));
    }
    (StatusCode::OK, Json(json!({ "device_keys": device_keys }))).into_response()
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
    for (kind, key) in auth_event_keys(&template_event) {
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
    let min = if rule == "knock_restricted" { 9 } else { 7 };
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
        Ok(received) => {
            let event = state.storage.get_wire_pdu(&received.event_id).await.ok().flatten();
            (StatusCode::OK, Json(json!({ "knock_room_state": event }))).into_response()
        }
        Err(response) => response,
    }
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
pub async fn exchange_third_party_invite(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(room_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if origin_of(origin_ext).is_err() {
        return unauthorized("Not authenticated");
    }
    let Some(sender) = body["sender"].as_str() else {
        return bad_json("sender is required");
    };
    let Some(mxid) = body["mxid"].as_str() else {
        return bad_json("mxid is required");
    };
    if server_of_user_id(sender) != Some(state.server_name.as_ref()) {
        return invalid_param("sender is not a user of this server");
    }
    let signed = &body["signed"];
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
    let content = json!({
        "membership": "invite",
        "third_party_invite": {
            "display_name": invite.content["display_name"].clone(),
            "signed": signed,
        },
    });
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
        pdu: Pdu::new(room_id.clone(), sender, "m.room.member", Some(mxid.to_owned()), content.clone(), super::now_ms(), vec![], prev_events.clone(), depth),
        unsigned: None,
    };
    let mut auth_events = Vec::new();
    for (kind, key) in auth_event_keys(&provisional) {
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
    if let Err(error) = sign_authored(&mut pdu, &state.server_key, &state.server_name) {
        return internal(&error.to_string());
    }
    let event_id = match conduit::hashing::event_id(&pdu) {
        Ok(event_id) => event_id,
        Err(error) => return internal(&error.to_string()),
    };
    let event = Event::new(event_id.clone(), pdu);
    let auth_state = match current_state_map(state.storage.as_ref(), &room_id).await {
        Ok(auth_state) => auth_state,
        Err(error) => return internal(&error.to_string()),
    };
    if let Err(error) = conduit::auth::check_auth(&event, &auth_state) {
        return forbidden(&error.to_string());
    }
    if let Err(error) = state.storage.publish_event(&event).await {
        return internal(&error.to_string());
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}
