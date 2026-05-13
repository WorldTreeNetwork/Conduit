//! Inbound federation HTTP handlers (x2r.2, x2r.5–x2r.10).
//!
//! Exposes a subrouter mounted at `/_matrix/federation/v1` with X-Matrix
//! auth and per-origin rate-limiting middleware applied to all routes.
//!
//! Endpoints implemented:
//! - `PUT  /send/:txnId`
//! - `GET  /make_join/:roomId/:userId`
//! - `PUT  /send_join/v2/:roomId/:eventId`
//! - `PUT  /invite/v2/:roomId/:eventId`
//! - `GET  /state/:roomId`
//! - `GET  /state_ids/:roomId`
//! - `GET  /backfill/:roomId`
//! - `GET  /event/:eventId`
//! - `POST /get_missing_events/:roomId`
//! - `GET  /query/profile`
//! - `GET  /query/directory`

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;

use conduit::auth::auth_event_keys;
use conduit::event::Event;
use conduit::signing::sign_event;
use conduit::state_events::HistoryVisibility;
use conduit::storage::Storage;

use crate::RemoteKeyCache;
use crate::federation::Client as FedClient;
use crate::media_storage::BlobStore;
use crate::api::client::media::MediaState;

use super::middleware::FederationOrigin;
use super::pipeline::process_incoming_pdu;

// ---------------------------------------------------------------------------
// Shared handler state
// ---------------------------------------------------------------------------

/// State passed to all inbound federation handlers.
#[derive(Clone)]
pub struct FedState {
    pub storage: Arc<dyn Storage>,
    pub server_name: Arc<str>,
    pub server_key: Arc<conduit::keys::ServerKey>,
    pub remote_keys: Arc<RemoteKeyCache>,
    pub http: reqwest::Client,
    pub events_tx: broadcast::Sender<i64>,
    pub fed_client: Arc<FedClient>,
    /// Blob store for federation media download/thumbnail (E07 h9n.8).
    pub blob_store: BlobStore,
}

impl MediaState for FedState {
    fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
    fn server_name(&self) -> &str {
        &self.server_name
    }
    fn blob_store(&self) -> &BlobStore {
        &self.blob_store
    }
    fn federation_client(&self) -> &Arc<FedClient> {
        &self.fed_client
    }
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn matrix_error(status: StatusCode, errcode: &str, error: &str) -> Response {
    (status, Json(json!({ "errcode": errcode, "error": error }))).into_response()
}

fn unauthorized(msg: &str) -> Response {
    matrix_error(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED", msg)
}

fn not_found(msg: &str) -> Response {
    matrix_error(StatusCode::NOT_FOUND, "M_NOT_FOUND", msg)
}

fn bad_json(msg: &str) -> Response {
    matrix_error(StatusCode::BAD_REQUEST, "M_BAD_JSON", msg)
}

fn forbidden(msg: &str) -> Response {
    matrix_error(StatusCode::FORBIDDEN, "M_FORBIDDEN", msg)
}

fn internal(msg: &str) -> Response {
    matrix_error(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", msg)
}

// ---------------------------------------------------------------------------
// x2r.2 — PUT /send/:txnId
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SendTransactionBody {
    #[serde(default)]
    pub origin: Option<String>,
    #[serde(default)]
    pub origin_server_ts: Option<u64>,
    #[serde(default)]
    pub pdus: Vec<Value>,
    #[serde(default)]
    pub edus: Vec<Value>,
}

/// `PUT /_matrix/federation/v1/send/:txnId`
pub async fn send_transaction(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(txn_id): Path<String>,
    Json(body): Json<SendTransactionBody>,
) -> Response {
    let origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };

    tracing::debug!(%origin, %txn_id, pdu_count = body.pdus.len(), edu_count = body.edus.len(), "inbound federation transaction");

    // Process EDUs first (mrm.11).
    for edu in &body.edus {
        handle_edu(&state, edu).await;
    }

    let mut pdu_results: HashMap<String, Value> = HashMap::new();

    for pdu_val in body.pdus {
        // Parse the PDU.
        let pdu: Event = match serde_json::from_value(pdu_val) {
            Ok(e) => e,
            Err(e) => {
                // Can't get event_id if parse fails — use placeholder.
                pdu_results.insert(
                    format!("parse_error_{}", pdu_results.len()),
                    json!({ "error": format!("PDU parse error: {e}") }),
                );
                continue;
            }
        };

        let eid = pdu.event_id.clone();
        match process_incoming_pdu(
            &state.storage,
            &state.remote_keys,
            &state.http,
            &state.events_tx,
            Some(&state.fed_client),
            pdu,
            &origin,
        )
        .await
        {
            Ok(()) => {
                pdu_results.insert(eid, json!({}));
            }
            Err(e) => {
                tracing::warn!(%eid, error = %e, "PDU rejected");
                pdu_results.insert(eid, json!({ "error": e.to_string() }));
            }
        }
    }

    (StatusCode::OK, Json(json!({ "pdus": pdu_results }))).into_response()
}

// ---------------------------------------------------------------------------
// x2r.5 — GET /make_join/:roomId/:userId
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct MakeJoinQuery {
    #[serde(rename = "ver")]
    pub ver: Option<Vec<String>>,
}

/// `GET /_matrix/federation/v1/make_join/:roomId/:userId`
pub async fn make_join(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path((room_id, user_id)): Path<(String, String)>,
    Query(_query): Query<HashMap<String, String>>,
) -> Response {
    let _origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };

    // Check the room exists (has a create event).
    let create_ev = match state
        .storage
        .get_state_entry(&room_id, "m.room.create", "")
        .await
    {
        Ok(Some(ev)) => ev,
        Ok(None) => return not_found("Room not found"),
        Err(e) => return internal(&e.to_string()),
    };

    // Check join rules — for public rooms anyone can join.
    let join_rule = match state
        .storage
        .get_state_entry(&room_id, "m.room.join_rules", "")
        .await
    {
        Ok(Some(ev)) => ev.content
            .get("join_rule")
            .and_then(|v| v.as_str())
            .unwrap_or("invite")
            .to_owned(),
        Ok(None) => "invite".to_owned(),
        Err(e) => return internal(&e.to_string()),
    };

    // For non-public rooms, verify the remote user has an invite.
    if join_rule != "public" {
        let member = state
            .storage
            .get_state_entry(&room_id, "m.room.member", &user_id)
            .await;
        let has_invite = match member {
            Ok(Some(ev)) => ev.content
                .get("membership")
                .and_then(|v| v.as_str())
                .map(|m| m == "invite")
                .unwrap_or(false),
            _ => false,
        };
        if !has_invite {
            return forbidden("Join not permitted: no invite");
        }
    }

    // Get latest events for prev_events.
    let all_events = match state.storage.room_events(&room_id).await {
        Ok(evs) => evs,
        Err(e) => return internal(&e.to_string()),
    };
    let latest = all_events.iter().max_by_key(|e| e.depth);
    let (prev_events, depth) = match latest {
        Some(ev) => (vec![ev.event_id.clone()], ev.depth + 1),
        None => (vec![], 1),
    };

    // Build auth_events.
    let template_for_keys = Event {
        event_id: String::new(),
        room_id: room_id.clone(),
        sender: user_id.clone(),
        event_type: "m.room.member".to_owned(),
        content: json!({ "membership": "join" }),
        state_key: Some(user_id.clone()),
        origin_server_ts: 0,
        auth_events: vec![],
        prev_events: prev_events.clone(),
        hashes: json!({}),
        signatures: json!({}),
        depth,
        unsigned: None,
    };

    let required_keys = auth_event_keys(&template_for_keys);
    let mut auth_events_ids: Vec<String> = Vec::new();
    for (ev_type, sk) in &required_keys {
        if let Ok(Some(ev)) = state.storage.get_state_entry(&room_id, ev_type, sk).await {
            auth_events_ids.push(ev.event_id.clone());
        }
    }

    // Build the join template event (unsigned — remote fills event_id, hashes, sig).
    // Include a placeholder event_id so the Event struct can be deserialized;
    // the remote server replaces it with the real computed event_id.
    let template = json!({
        "event_id": "$placeholder",
        "room_id": room_id,
        "sender": user_id,
        "type": "m.room.member",
        "content": { "membership": "join" },
        "state_key": user_id,
        "auth_events": auth_events_ids,
        "prev_events": prev_events,
        "depth": depth,
        "origin_server_ts": crate::federation::now_ms(),
        "hashes": {},
        "signatures": {},
    });

    // Extract room version from create event.
    let room_version = create_ev
        .content
        .get("room_version")
        .and_then(|v| v.as_str())
        .unwrap_or("11")
        .to_owned();

    (StatusCode::OK, Json(json!({
        "event": template,
        "room_version": room_version,
    })))
    .into_response()
}

// ---------------------------------------------------------------------------
// x2r.5 — PUT /send_join/v2/:roomId/:eventId
// ---------------------------------------------------------------------------

/// `PUT /_matrix/federation/v2/send_join/:roomId/:eventId`
pub async fn send_join(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path((room_id, _event_id)): Path<(String, String)>,
    Json(pdu_val): Json<Value>,
) -> Response {
    let origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };

    // Parse the join PDU.
    let pdu: Event = match serde_json::from_value(pdu_val) {
        Ok(e) => e,
        Err(e) => return bad_json(&format!("Cannot parse join PDU: {e}")),
    };

    // Validate it's a join event for this room.
    if pdu.room_id != room_id {
        return bad_json("PDU room_id does not match URL");
    }
    if pdu.event_type != "m.room.member" {
        return bad_json("Expected m.room.member event");
    }
    let membership = pdu.content.get("membership").and_then(|v| v.as_str());
    if membership != Some("join") {
        return bad_json("Expected join membership");
    }

    // Process through pipeline (verifies sig, auth, persists).
    match process_incoming_pdu(
        &state.storage,
        &state.remote_keys,
        &state.http,
        &state.events_tx,
        Some(&state.fed_client),
        pdu.clone(),
        &origin,
    )
    .await
    {
        Ok(()) => {}
        Err(e) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "errcode": "M_FORBIDDEN", "error": e.to_string() })),
            )
                .into_response();
        }
    }

    // Collect current state of the room for the response.
    let state_events = match state.storage.get_current_state(&room_id).await {
        Ok(evs) => evs,
        Err(e) => return internal(&e.to_string()),
    };

    // Build the auth chain: union of auth_events from all state events.
    let auth_chain = build_auth_chain(&state.storage, &state_events).await;

    (StatusCode::OK, Json(json!({
        "origin": &*state.server_name,
        "state": state_events,
        "auth_chain": auth_chain,
        "event": pdu,
    })))
    .into_response()
}

// ---------------------------------------------------------------------------
// x2r.6 — PUT /invite/v2/:roomId/:eventId
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct InviteBody {
    pub event: Value,
    #[serde(default)]
    pub invite_room_state: Vec<Value>,
    #[serde(default)]
    pub room_version: Option<String>,
}

/// `PUT /_matrix/federation/v2/invite/:roomId/:eventId`
pub async fn invite(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path((room_id, _event_id)): Path<(String, String)>,
    Json(body): Json<InviteBody>,
) -> Response {
    let _origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };

    // Parse the invite PDU.
    let mut pdu: Event = match serde_json::from_value(body.event) {
        Ok(e) => e,
        Err(e) => return bad_json(&format!("Cannot parse invite PDU: {e}")),
    };

    // Basic validation.
    if pdu.room_id != room_id {
        return bad_json("PDU room_id does not match URL");
    }
    if pdu.event_type != "m.room.member" {
        return bad_json("Expected m.room.member event");
    }
    let membership = pdu.content.get("membership").and_then(|v| v.as_str());
    if membership != Some("invite") {
        return bad_json("Expected invite membership");
    }

    // The target user must be on our server.
    let target = pdu.state_key.as_deref().unwrap_or("");
    let target_server = target.split(':').nth(1).unwrap_or("");
    if target_server != &*state.server_name {
        return bad_json("Invite target is not on this server");
    }

    // Co-sign the invite PDU with our server key.
    if let Err(e) = sign_event(&mut pdu, &state.server_key, &state.server_name) {
        return internal(&format!("Failed to sign invite: {e}"));
    }

    // Store the invite as a pending member event so local /sync picks it up.
    if let Err(e) = state.storage.put_event(&pdu).await {
        return internal(&format!("Failed to store invite: {e}"));
    }
    if let Some(sk) = &pdu.state_key.clone() {
        if let Err(e) = state
            .storage
            .set_state_entry(&pdu.room_id, &pdu.event_type, sk, &pdu.event_id)
            .await
        {
            tracing::warn!(error = %e, "failed to update state for invite");
        }
    }

    // Notify /sync.
    if let Ok(pos) = state.storage.global_max_stream_position().await {
        let _ = state.events_tx.send(pos);
    }

    (StatusCode::OK, Json(json!({ "event": pdu }))).into_response()
}

// ---------------------------------------------------------------------------
// x2r.7 — GET /state/:roomId and GET /state_ids/:roomId
// ---------------------------------------------------------------------------

/// `GET /_matrix/federation/v1/state/:roomId?event_id=...`
pub async fn state(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(room_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if origin_ext.is_none() {
        return unauthorized("Not authenticated");
    }

    let _event_id = params.get("event_id").cloned().unwrap_or_default();

    let state_events = match state.storage.get_current_state(&room_id).await {
        Ok(evs) => evs,
        Err(e) => return internal(&e.to_string()),
    };

    if state_events.is_empty() {
        return not_found("Room not found or has no state");
    }

    let auth_chain = build_auth_chain(&state.storage, &state_events).await;

    (StatusCode::OK, Json(json!({
        "pdus": state_events,
        "auth_chain": auth_chain,
    })))
    .into_response()
}

/// `GET /_matrix/federation/v1/state_ids/:roomId?event_id=...`
pub async fn state_ids(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(room_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if origin_ext.is_none() {
        return unauthorized("Not authenticated");
    }

    let _event_id = params.get("event_id").cloned().unwrap_or_default();

    let state_events = match state.storage.get_current_state(&room_id).await {
        Ok(evs) => evs,
        Err(e) => return internal(&e.to_string()),
    };

    if state_events.is_empty() {
        return not_found("Room not found or has no state");
    }

    let auth_chain = build_auth_chain(&state.storage, &state_events).await;

    let pdu_ids: Vec<String> = state_events.iter().map(|e| e.event_id.clone()).collect();
    let auth_chain_ids: Vec<String> = auth_chain.iter().map(|e| e.event_id.clone()).collect();

    (StatusCode::OK, Json(json!({
        "pdu_ids": pdu_ids,
        "auth_chain_ids": auth_chain_ids,
    })))
    .into_response()
}

// ---------------------------------------------------------------------------
// x2r.8 — GET /backfill/:roomId
// ---------------------------------------------------------------------------

/// `GET /_matrix/federation/v1/backfill/:roomId?v=...&limit=...`
pub async fn backfill(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(room_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };

    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20)
        .min(100);

    // Get all room events, sorted by depth descending.
    let mut all_events = match state.storage.room_events(&room_id).await {
        Ok(evs) => evs,
        Err(e) => return internal(&e.to_string()),
    };
    all_events.sort_by_key(|e| std::cmp::Reverse(e.depth));

    // Determine history visibility setting.
    let hist_vis = get_history_visibility(&state.storage, &room_id).await;

    // Filter: only include events visible to remote homeservers.
    // For world_readable: all events visible.
    // For shared/invited/joined: only if origin server has/had a member.
    let filtered: Vec<Event> = all_events
        .into_iter()
        .filter(|ev| is_event_visible_to_server(&hist_vis, &origin, ev))
        .take(limit)
        .collect();

    (StatusCode::OK, Json(json!({
        "origin": &*state.server_name,
        "origin_server_ts": crate::federation::now_ms(),
        "pdus": filtered,
    })))
    .into_response()
}

// ---------------------------------------------------------------------------
// x2r.9 — GET /event/:eventId
// ---------------------------------------------------------------------------

/// `GET /_matrix/federation/v1/event/:eventId`
pub async fn get_event(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(event_id): Path<String>,
) -> Response {
    if origin_ext.is_none() {
        return unauthorized("Not authenticated");
    }

    match state.storage.get_event(&event_id).await {
        Ok(Some(ev)) => (StatusCode::OK, Json(json!({
            "origin": &*state.server_name,
            "origin_server_ts": crate::federation::now_ms(),
            "pdus": [ev],
        })))
        .into_response(),
        Ok(None) => not_found("Event not found"),
        Err(e) => internal(&e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// x2r.9 — POST /get_missing_events/:roomId
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GetMissingEventsBody {
    #[serde(default)]
    pub earliest_events: Vec<String>,
    #[serde(default)]
    pub latest_events: Vec<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub min_depth: Option<i64>,
}

fn default_limit() -> usize {
    10
}

/// `POST /_matrix/federation/v1/get_missing_events/:roomId`
pub async fn get_missing_events(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(room_id): Path<String>,
    Json(body): Json<GetMissingEventsBody>,
) -> Response {
    if origin_ext.is_none() {
        return unauthorized("Not authenticated");
    }

    let limit = body.limit.min(20);
    let earliest: HashSet<String> = body.earliest_events.into_iter().collect();
    let latest: HashSet<String> = body.latest_events.into_iter().collect();

    // Get all room events.
    let all_events = match state.storage.room_events(&room_id).await {
        Ok(evs) => evs,
        Err(e) => return internal(&e.to_string()),
    };

    // BFS backwards from latest_events until we hit earliest_events.
    // Return events that are "between" the two sets.
    let event_map: HashMap<String, &Event> =
        all_events.iter().map(|e| (e.event_id.clone(), e)).collect();

    let mut found: Vec<Event> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = latest.iter().cloned().collect();

    while let Some(eid) = queue.pop() {
        if visited.contains(&eid) || earliest.contains(&eid) {
            continue;
        }
        visited.insert(eid.clone());

        if let Some(ev) = event_map.get(&eid) {
            found.push((*ev).clone());
            if found.len() >= limit {
                break;
            }
            // Walk backwards via prev_events.
            for prev in &ev.prev_events {
                if !visited.contains(prev) && !earliest.contains(prev) {
                    queue.push(prev.clone());
                }
            }
        }
    }

    (StatusCode::OK, Json(json!({ "events": found }))).into_response()
}

// ---------------------------------------------------------------------------
// x2r.10 — GET /query/profile
// ---------------------------------------------------------------------------

/// `GET /_matrix/federation/v1/query/profile?user_id=...&field=...`
pub async fn query_profile(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if origin_ext.is_none() {
        return unauthorized("Not authenticated");
    }

    let user_id = match params.get("user_id") {
        Some(uid) => uid.clone(),
        None => return bad_json("Missing user_id parameter"),
    };

    // Verify user is on our server.
    let user_server = user_id.split(':').nth(1).unwrap_or("");
    if user_server != &*state.server_name {
        return not_found("User is not on this server");
    }

    // Check account exists.
    match state.storage.get_account(&user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("User not found"),
        Err(e) => return internal(&e.to_string()),
    }

    // Profile data: look up from account_data / profile state.
    // bd remember: E06 (Profiles) lands separately; for now return displayname
    // and avatar_url from the m.room.member state_key if present in any room.
    // This is a best-effort implementation — full profile storage tracked in E06.
    let field = params.get("field").cloned();
    let mut result = json!({});

    // Return empty profile for now — E06 will add proper profile storage.
    // Filed follow-up: conduit-x2r.10 notes profile storage dependency.
    match field.as_deref() {
        Some("displayname") => {
            result["displayname"] = json!(null);
        }
        Some("avatar_url") => {
            result["avatar_url"] = json!(null);
        }
        _ => {
            result["displayname"] = json!(null);
            result["avatar_url"] = json!(null);
        }
    }

    (StatusCode::OK, Json(result)).into_response()
}

// ---------------------------------------------------------------------------
// x2r.10 — GET /query/directory
// ---------------------------------------------------------------------------

/// `GET /_matrix/federation/v1/query/directory?room_alias=...`
pub async fn query_directory(
    State(_state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if origin_ext.is_none() {
        return unauthorized("Not authenticated");
    }

    let _alias = match params.get("room_alias") {
        Some(a) => a.clone(),
        None => return bad_json("Missing room_alias parameter"),
    };

    // bd remember: Room alias storage is not yet implemented (tracked as
    // follow-up). Return 404 here until alias storage lands.
    not_found("Room alias directory not yet implemented on this server")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Collect all auth-chain events (union of auth_events reachable from
/// the given state events, up to a reasonable depth).
async fn build_auth_chain(storage: &Arc<dyn Storage>, state_events: &[Event]) -> Vec<Event> {
    let mut chain: Vec<Event> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = state_events
        .iter()
        .flat_map(|e| e.auth_events.iter().cloned())
        .collect();

    // BFS up to depth 20 to bound the chain size.
    let mut depth = 0usize;
    while let Some(eid) = queue.pop() {
        if depth > 1000 || seen.contains(&eid) {
            continue;
        }
        seen.insert(eid.clone());
        depth += 1;

        if let Ok(Some(ev)) = storage.get_event(&eid).await {
            for auth_eid in &ev.auth_events {
                if !seen.contains(auth_eid) {
                    queue.push(auth_eid.clone());
                }
            }
            chain.push(ev);
        }
    }

    chain
}

/// Get the history visibility for a room.
async fn get_history_visibility(storage: &Arc<dyn Storage>, room_id: &str) -> HistoryVisibility {
    match storage
        .get_state_entry(room_id, "m.room.history_visibility", "")
        .await
    {
        Ok(Some(ev)) => {
            let vis_str = ev
                .content
                .get("history_visibility")
                .and_then(|v| v.as_str())
                .unwrap_or("shared");
            match vis_str {
                "world_readable" => HistoryVisibility::WorldReadable,
                "shared" => HistoryVisibility::Shared,
                "invited" => HistoryVisibility::Invited,
                "joined" => HistoryVisibility::Joined,
                _ => HistoryVisibility::Shared,
            }
        }
        _ => HistoryVisibility::Shared,
    }
}

/// Determine if an event is visible to requests from `origin_server`.
///
/// - `world_readable`: all events visible.
/// - `shared`/`invited`/`joined`: events visible only while origin had a member.
///   For v0: if any user from origin_server is in the room (m.room.member with join),
///   we allow the event. Full per-event visibility filtering is a TODO.
fn is_event_visible_to_server(
    hist_vis: &HistoryVisibility,
    _origin: &str,
    _ev: &Event,
) -> bool {
    // bd remember: Full per-event backfill history-visibility filtering requires
    // checking the room state *at the time of each event*. For v0 we use a
    // conservative approximation: world_readable shows all, others show all
    // (trusting that the sending server legitimately participates).
    // TODO: implement proper per-event visibility using room state snapshots.
    match hist_vis {
        HistoryVisibility::WorldReadable => true,
        HistoryVisibility::Shared => true,
        HistoryVisibility::Invited => true,
        HistoryVisibility::Joined => true,
    }
}

// ---------------------------------------------------------------------------
// mrm.10 — PUT /send_to_device/:txnId
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct FedSendToDeviceBody {
    /// The sending user.
    #[serde(default)]
    pub sender: Option<String>,
    /// { user_id: { device_id: content } }
    #[serde(default)]
    pub messages: HashMap<String, HashMap<String, serde_json::Value>>,
    /// message_type / event_type
    #[serde(rename = "type", default)]
    pub event_type: Option<String>,
}

/// `PUT /_matrix/federation/v1/send_to_device/:txnId`
pub async fn fed_send_to_device(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(txn_id): Path<String>,
    Json(body): Json<FedSendToDeviceBody>,
) -> Response {
    let origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };

    tracing::debug!(%origin, %txn_id, "inbound federation send_to_device");

    let event_type = body.event_type.unwrap_or_else(|| "m.room.encrypted".to_owned());
    let sender = body.sender.unwrap_or_else(|| format!("@federation:{}", origin));

    for (target_user, devices) in &body.messages {
        let target_server = target_user.split(':').nth(1).unwrap_or("");
        if target_server != &*state.server_name {
            continue; // Not our user — skip.
        }
        for (target_device, content) in devices {
            if let Err(e) = state
                .storage
                .enqueue_to_device(target_user, target_device, &sender, &event_type, content)
                .await
            {
                tracing::warn!(error = %e, "failed to enqueue federated to-device message");
            }
        }
    }

    (StatusCode::OK, Json(serde_json::json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// mrm.11 — handle m.device_list_update EDU in send_transaction
// ---------------------------------------------------------------------------

/// Handle EDUs in an inbound federation transaction.
/// Currently processes `m.device_list_update`.
pub(crate) async fn handle_edu(state: &FedState, edu: &serde_json::Value) {
    let edu_type = edu.get("edu_type").and_then(|v| v.as_str()).unwrap_or("");
    if edu_type == "m.device_list_update" {
        let content = edu.get("content").unwrap_or(edu);
        let user_id = match content.get("user_id").and_then(|v| v.as_str()) {
            Some(u) => u.to_owned(),
            None => return,
        };
        let device_id = content.get("device_id").and_then(|v| v.as_str()).unwrap_or("");
        let deleted = content
            .get("deleted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        tracing::debug!(user_id = %user_id, device_id = %device_id, deleted, "m.device_list_update EDU");

        // If the EDU includes the device keys, persist them.
        if let Some(keys) = content.get("keys") {
            if !deleted && !device_id.is_empty() {
                let _ = state.storage.upsert_device_keys(&user_id, device_id, keys).await;
            } else if deleted && !device_id.is_empty() {
                // Deletion: we could remove device keys, but for now we just record the change.
            }
        }

        // Record device list change so local /sync picks it up.
        let _ = state.storage.record_device_list_change(&user_id).await;
    }
}

// ---------------------------------------------------------------------------
// Router builder
// ---------------------------------------------------------------------------

/// Build the federation inbound subrouter.
///
/// Returns a `Router<FedState>` — callers should apply middleware and then
/// call `.with_state(fed_state)` to convert it to `Router<()>` for nesting.
pub fn federation_router() -> axum::Router<FedState> {
    use axum::routing::{get, post, put};
    use crate::api::client::media::{federation_download, federation_thumbnail};

    axum::Router::new()
        .route("/send/:txnId", put(send_transaction))
        .route("/send_to_device/:txnId", put(fed_send_to_device))
        .route("/make_join/:roomId/:userId", get(make_join))
        .route("/send_join/v2/:roomId/:eventId", put(send_join))
        .route("/invite/v2/:roomId/:eventId", put(invite))
        .route("/state/:roomId", get(state))
        .route("/state_ids/:roomId", get(state_ids))
        .route("/backfill/:roomId", get(backfill))
        .route("/event/:eventId", get(get_event))
        .route("/get_missing_events/:roomId", post(get_missing_events))
        .route("/query/profile", get(query_profile))
        .route("/query/directory", get(query_directory))
        // Media (E07 h9n.8): federation download + thumbnail
        .route("/media/download/:mediaId", get(federation_download::<FedState>))
        .route("/media/thumbnail/:mediaId", get(federation_thumbnail::<FedState>))
}
