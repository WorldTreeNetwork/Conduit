//! Inbound federation HTTP handlers (x2r.2, x2r.5–x2r.10).
//!
//! Exposes versioned subrouters mounted at `/_matrix/federation` with X-Matrix
//! auth and per-origin rate-limiting middleware applied to all routes.
//!
//! Endpoints implemented:
//! - `PUT  /send/:txnId`
//! - `GET  /make_join/:roomId/:userId`
//! - `PUT  /v2/send_join/:roomId/:eventId`
//! - `PUT  /v2/invite/:roomId/:eventId`
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
use conduit::event::{Event, WirePdu};
use conduit::signing::{add_signature, is_third_party_invite, server_of_user_id};
use conduit::wire::decode_pdu;
use conduit::storage::Storage;

use crate::RemoteKeyCache;
use crate::federation::Client as FedClient;
use crate::federation::recent::RecentEventCache;
use crate::media_storage::BlobStore;
use crate::api::client::media::MediaState;

use super::middleware::FederationOrigin;
use super::pipeline::{process_incoming_pdu, process_received, verify_received, verify_received_as, PipelineError};

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
    /// In-memory dedup cache for inbound PDUs (conduit-3qj).
    pub recent: Arc<RecentEventCache>,
    /// Application Service registrations — used to query unknown users/aliases
    /// that fall in an AS namespace (conduit-dhd).
    pub app_services: Arc<Vec<crate::app_service::AppService>>,
    /// Ephemeral typing state shared with client /sync.
    pub typing: Arc<crate::api::client::TypingStore>,
    /// Ephemeral presence state shared with client /sync.
    pub presence: Arc<crate::api::client::PresenceStore>,
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

#[async_trait::async_trait]
impl conduit::room::RoomEventSender for FedState {
    async fn send_event(
        &self,
        sender: &str,
        room_id: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: Value,
    ) -> conduit::Result<String> {
        // Local leaves authored because a remote server revoked guest access.
        // Joins still go through the client pipeline so they carry a profile.
        crate::api::client::event_pipeline::author_event(
            self.storage.as_ref(),
            &self.server_key,
            &self.server_name,
            &self.events_tx,
            Some(&self.fed_client),
            sender,
            room_id,
            event_type,
            state_key,
            content,
            None,
        )
        .await
        .map_err(|(status, err)| {
            if status == StatusCode::FORBIDDEN {
                conduit::Error::Forbidden(err.0.error)
            } else if status == StatusCode::PAYLOAD_TOO_LARGE {
                conduit::Error::TooLarge(err.0.error)
            } else {
                conduit::Error::Storage(err.0.error)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn matrix_error(status: StatusCode, errcode: &str, error: &str) -> Response {
    (status, Json(json!({ "errcode": errcode, "error": error }))).into_response()
}

pub(crate) fn unauthorized(msg: &str) -> Response {
    matrix_error(StatusCode::UNAUTHORIZED, "M_UNAUTHORIZED", msg)
}

pub(crate) fn not_found(msg: &str) -> Response {
    matrix_error(StatusCode::NOT_FOUND, "M_NOT_FOUND", msg)
}

pub(crate) fn bad_json(msg: &str) -> Response {
    matrix_error(StatusCode::BAD_REQUEST, "M_BAD_JSON", msg)
}

pub(crate) fn invalid_param(msg: &str) -> Response {
    matrix_error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", msg)
}

/// The federation form of stored events, in order. Events whose bytes do not
/// reproduce their ID are omitted; content-mismatched ones are redacted.
pub(crate) async fn wire_pdus(storage: &Arc<dyn Storage>, events: &[Event]) -> conduit::Result<Vec<WirePdu>> {
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        if let Some(wire) = storage.get_wire_pdu(&event.event_id).await? {
            out.push(wire);
        }
    }
    Ok(out)
}

pub(crate) fn forbidden(msg: &str) -> Response {
    matrix_error(StatusCode::FORBIDDEN, "M_FORBIDDEN", msg)
}

/// `Some` when the origin must not touch this room (403) or the ACL
/// lookup failed. Absent ACL allows the server.
pub(crate) async fn ensure_server_acl(state: &FedState, origin: &str, room_id: &str) -> Option<Response> {
    match conduit::server_acl::server_allowed_by_room(state.storage.as_ref(), room_id, origin).await {
        Ok(true) => None,
        Ok(false) => Some(forbidden("Server is denied access to this room by the server ACL")),
        Err(error) => Some(internal(&error.to_string())),
    }
}

pub(crate) fn internal(msg: &str) -> Response {
    matrix_error(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", msg)
}

/// Per-PDU error text for `/send` results: a fixed vocabulary that never
/// echoes values taken from the PDU (they may hold U+0000 or private data).
fn pdu_error_text(error: &PipelineError) -> &'static str {
    match error {
        PipelineError::SignatureError(_) => "signature verification failed",
        PipelineError::AuthFailed(_) => "auth check failed",
        PipelineError::Storage(_) => "storage error",
        PipelineError::StateRes(_) => "state resolution failed",
        PipelineError::UnsupportedRoomVersion(_) => "unsupported room version",
        PipelineError::AuthEventFetch(_) => "auth event fetch failed",
        PipelineError::MissingAuthEvent { .. } => "missing auth event",
    }
}

// ---------------------------------------------------------------------------
// x2r.2 — PUT /send/:txnId
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SendTransactionBody {
    pub origin: String,
    pub origin_server_ts: u64,
    pub pdus: Vec<Value>,
    #[serde(default)]
    pub edus: Vec<Value>,
}

/// Room version used to pick a PDU decoder. Version 1 is selected only when
/// `content.room_version` is exactly `"1"` on a create, or when the stored
/// create says version 1. Anything else, including a missing field, stays on
/// the v3+ decoder.
async fn received_room_version(storage: &dyn Storage, pdu: &Value) -> u32 {
    let Some(map) = pdu.as_object() else { return 11 };
    if map.get("type").and_then(Value::as_str) == Some("m.room.create") {
        return match map.get("content").and_then(|c| c.get("room_version")).and_then(Value::as_str) {
            Some("1") => 1,
            _ => 11,
        };
    }
    let Some(room_id) = map.get("room_id").and_then(Value::as_str) else { return 11 };
    match storage.get_state_entry(room_id, "m.room.create", "").await {
        Ok(Some(create)) if conduit::room_version::version_of_event(&create) == 1 => 1,
        _ => 11,
    }
}

/// `PUT /_matrix/federation/v1/send/:txnId`
pub async fn send_transaction(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path(txn_id): Path<String>,
    request: axum::extract::Request,
) -> Response {
    let origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };

    let key = conduit::storage::TransactionKey::federation_request(&origin, &txn_id);
    let mut replay = match crate::replay::Replay::start(state.storage.clone(), key).await {
        Ok(crate::replay::Start::Cached(response)) => return response,
        Ok(crate::replay::Start::Execute(replay)) => replay,
        Err(error) => return error,
    };
    let original = match replay.body(request).await {
        Ok(body) => body,
        Err(error) => return error,
    };
    let body = match serde_json::from_value::<SendTransactionBody>(original) {
        Ok(body) => body,
        Err(error) => {
            return replay
                .finish(
                    StatusCode::BAD_REQUEST,
                    json!({"errcode": "M_BAD_JSON", "error": error.to_string()}),
                )
                .await
        }
    };
    if body.origin != origin {
        return replay.finish(StatusCode::BAD_REQUEST, json!({"errcode": "M_BAD_JSON", "error": "transaction origin does not match authenticated origin"})).await;
    }
    if body.pdus.len() > 50 || body.edus.len() > 100 {
        return replay.finish(StatusCode::BAD_REQUEST, json!({"errcode": "M_BAD_JSON", "error": "transaction exceeds 50 PDUs or 100 EDUs"})).await;
    }
    tracing::debug!(%origin, %txn_id, pdu_count = body.pdus.len(), edu_count = body.edus.len(), "inbound federation transaction");

    // Process EDUs first (mrm.11). Each EDU persists in its own statement;
    // a deterministic data exception (SQLSTATE class 22, e.g. U+0000 in a
    // JSONB sink) drops that EDU, while transient failures still return 500
    // so the origin retries.
    for edu in &body.edus {
        match handle_edu(&state, &origin, edu).await {
            Ok(()) => {}
            Err(conduit::Error::StorageData(error)) => {
                tracing::warn!(%origin, %txn_id, %error, "dropped EDU the database refused as data");
            }
            Err(error) => return internal(&error.to_string()),
        }
    }

    let mut pdu_results: HashMap<String, Value> = HashMap::new();
    let received_ts = crate::federation::now_ms();

    for pdu_val in body.pdus {
        // "Is a valid event, otherwise it is dropped": no result entry, since
        // an invalid PDU's ID cannot be trusted (as Synapse _handle_pdus_in_txn).
        // Only an explicit room version of "1" (on create, or on the stored
        // create) selects the v1 tuple format. A missing room_version stays
        // on the v3+ decoder.
        let version = received_room_version(state.storage.as_ref(), &pdu_val).await;
        let decoded = match conduit::wire::decode_pdu_for_version(pdu_val, version, received_ts) {
            Ok(decoded) => decoded,
            Err(error) => {
                tracing::info!(%origin, %txn_id, %error, "dropped invalid PDU");
                continue;
            }
        };
        let eid = match decoded.explicit_event_id.clone() {
            Some(event_id) => event_id,
            None => conduit::hashing::event_id(&decoded.pdu).unwrap_or_default(),
        };
        let room_id = decoded.pdu.room_id.clone();
        let event_type = decoded.pdu.event_type.clone();
        let state_key = decoded.pdu.state_key.clone();
        let content = decoded.pdu.content.clone();
        match conduit::server_acl::server_allowed_by_room(state.storage.as_ref(), &decoded.pdu.room_id, &origin).await {
            Ok(false) => {
                pdu_results.insert(eid, json!({ "error": "server ACL denies this server" }));
                continue;
            }
            Ok(true) => {}
            Err(error) => return internal(&error.to_string()),
        }
        match process_incoming_pdu(
            &state.storage,
            &state.remote_keys,
            &state.http,
            &state.events_tx,
            Some(&state.fed_client),
            Some(&state.recent),
            decoded,
            &origin,
        )
        .await
        {
            Ok(event_id) => {
                pdu_results.insert(event_id, json!({}));
                // A remote guest_access change must remove this server's guests.
                if state_key.as_deref() == Some("") {
                    crate::api::client::guest_access::after_state_event(
                        state.storage.as_ref(),
                        &state.server_name,
                        &state,
                        &room_id,
                        &event_type,
                        &content,
                    )
                    .await;
                }
            }
            Err(e) => {
                tracing::warn!(%eid, error = %e, "PDU rejected");
                pdu_results.insert(eid, json!({ "error": pdu_error_text(&e) }));
            }
        }
    }

    replay
        .finish(StatusCode::OK, json!({"pdus": pdu_results}))
        .await
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
    let origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };
    if let Some(response) = ensure_server_acl(&state, &origin, &room_id).await {
        return response;
    }

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

    // Invite and an existing join skip allow conditions. A restricted join
    // through an allow condition names a local user who can invite.
    let membership = match state.storage.get_state_entry(&room_id, "m.room.member", &user_id).await {
        Ok(Some(ev)) => ev.content.get("membership").and_then(|v| v.as_str()).unwrap_or("").to_owned(),
        Ok(None) => String::new(),
        Err(e) => return internal(&e.to_string()),
    };
    let mut authoriser = None;
    let restricted = join_rule == "restricted" || join_rule == "knock_restricted";
    if restricted && membership != "invite" && membership != "join" {
        use crate::api::client::room_membership::{decide_restricted_join, RestrictedDecision};
        match decide_restricted_join(state.storage.as_ref(), &state.server_name, &user_id, &room_id).await {
            Ok(RestrictedDecision::Authorise(via)) => authoriser = Some(via),
            Ok(RestrictedDecision::UnableToAuthorise) => {
                return matrix_error(
                    StatusCode::BAD_REQUEST,
                    "M_UNABLE_TO_AUTHORISE_JOIN",
                    "Unable to authorise the join through any allow condition",
                );
            }
            Ok(RestrictedDecision::UnableToGrant) => {
                return matrix_error(
                    StatusCode::BAD_REQUEST,
                    "M_UNABLE_TO_GRANT_JOIN",
                    "This server cannot grant the join; try another resident server",
                );
            }
            Ok(_) => return forbidden("Join not permitted"),
            Err(e) => return internal(&e.to_string()),
        }
    } else if join_rule != "public" && membership != "invite" && membership != "join" {
        return forbidden("Join not permitted: no invite");
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
    let mut join_content = json!({ "membership": "join" });
    if let Some(via) = &authoriser {
        join_content["join_authorised_via_users_server"] = json!(via);
    }
    let template_for_keys = Event {
        event_id: String::new(),
        pdu: conduit::event::Pdu {
            room_id: room_id.clone(),
            sender: user_id.clone(),
            event_type: "m.room.member".to_owned(),
            content: join_content.clone(),
            state_key: Some(user_id.clone()),
            origin_server_ts: 0,
            auth_events: vec![],
            prev_events: prev_events.clone(),
            hashes: json!({}),
            signatures: json!({}),
            depth,
            extensions: Default::default(),
        },
        unsigned: None,
    };

    let required_keys = auth_event_keys(&template_for_keys);
    let mut auth_events_ids: Vec<String> = Vec::new();
    for (ev_type, sk) in &required_keys {
        if let Ok(Some(ev)) = state.storage.get_state_entry(&room_id, ev_type, sk).await {
            auth_events_ids.push(ev.event_id.clone());
        }
    }

    // Build the join template (v11 wire format: no event_id, hashes or signatures;
    // the joining server signs it and the ID is derived from its reference hash).
    let template = json!({
        "room_id": room_id,
        "sender": user_id,
        "type": "m.room.member",
        "content": join_content,
        "state_key": user_id,
        "auth_events": auth_events_ids,
        "prev_events": prev_events,
        "depth": depth,
        "origin_server_ts": crate::federation::now_ms(),
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
///
/// 1. Decode ("is a valid event"): failure is `400 M_BAD_JSON`.
/// 2. `room_id`, `m.room.member`, `join`, `state_key == sender`, sender on
///    the authenticated origin: failures are `400 M_INVALID_PARAM` (the
///    v1.19 send_join v2 400 response; Synapse uses 403/M_BAD_JSON here,
///    a recorded deliberate difference).
/// 3. Restricted join: `join_authorised_via_users_server` must name a user
///    on this server, and we co-sign with `add_signature` before verifying.
/// 4. Signature stage + derived ID == path ID: `400 M_INVALID_PARAM`.
/// 5. Auth: `403 M_FORBIDDEN`.
/// 6. Respond with the join (incl. our co-signature), state and auth chain
///    as `WirePdu`s. `state` is still current state (conduit-y99.22.1).
pub async fn send_join(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path((room_id, path_event_id)): Path<(String, String)>,
    Json(pdu_val): Json<Value>,
) -> Response {
    let origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };
    if let Some(response) = ensure_server_acl(&state, &origin, &room_id).await {
        return response;
    }

    let decoded = match decode_pdu(pdu_val, crate::federation::now_ms()) {
        Ok(decoded) => decoded,
        Err(error) => return bad_json(&error.to_string()),
    };
    let mut pdu = decoded.pdu;

    if pdu.room_id != room_id {
        return invalid_param("PDU room_id does not match the path");
    }
    if pdu.event_type != "m.room.member" {
        return invalid_param("Expected an m.room.member event");
    }
    if pdu.content.get("membership").and_then(|v| v.as_str()) != Some("join") {
        return invalid_param("Expected join membership");
    }
    if pdu.state_key.as_deref() != Some(pdu.sender.as_str()) {
        return invalid_param("state_key must equal sender");
    }
    if server_of_user_id(&pdu.sender) != Some(origin.as_str()) {
        return invalid_param("sender is not a user on the requesting server");
    }

    // Restricted join: as resident we are the authorising server.
    if let Some(authoriser) = pdu.content.get("join_authorised_via_users_server") {
        match authoriser.as_str().and_then(server_of_user_id) {
            Some(server) if server == &*state.server_name => {
                if let Err(e) = add_signature(&mut pdu, &state.server_key, &state.server_name) {
                    return internal(&format!("Failed to co-sign join: {e}"));
                }
            }
            _ => return invalid_param("We can only authorise joins for users on this server"),
        }
    }

    let received = match verify_received_as(&state.remote_keys, &state.http, pdu.clone(),
        &state.server_name, &state.server_key, None).await
    {
        Ok(received) => received,
        Err(_) => return invalid_param("Join event signature check failed"),
    };
    if received.event_id != path_event_id {
        return invalid_param("Join event ID does not match the path");
    }

    match process_received(
        &state.storage,
        &state.remote_keys,
        &state.http,
        &state.events_tx,
        Some(&state.fed_client),
        Some(&state.recent),
        received.clone(),
        decoded.unsigned,
        &origin,
    )
    .await
    {
        Ok(_) => {}
        Err(PipelineError::AuthFailed(e)) => return forbidden(&e),
        Err(e) => return internal(&e.to_string()),
    }

    let state_events = match state.storage.get_current_state(&room_id).await {
        Ok(evs) => evs,
        Err(e) => return internal(&e.to_string()),
    };
    let auth_chain = build_auth_chain(&state.storage, &state_events).await;
    let (state_pdus, chain_pdus) = match (
        wire_pdus(&state.storage, &state_events).await,
        wire_pdus(&state.storage, &auth_chain).await,
    ) {
        (Ok(s), Ok(c)) => (s, c),
        (Err(e), _) | (_, Err(e)) => return internal(&e.to_string()),
    };
    // The join exactly as received plus our co-signature (when restricted).
    let Some(event) = WirePdu::checked(&received.event_id, pdu) else {
        return internal("join no longer reproduces its ID");
    };

    (StatusCode::OK, Json(json!({
        "origin": &*state.server_name,
        "state": state_pdus,
        "auth_chain": chain_pdus,
        "event": event,
    })))
    .into_response()
}

// ---------------------------------------------------------------------------
// x2r.6 — PUT /v2/invite/:roomId/:eventId
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
///
/// Decode; check room, type, membership, local target, and the sender's
/// server == origin (3rd-party invites exempt); verify required signatures
/// with event-time keys; require derived ID == path ID and a matching
/// content hash (an invite never takes the redact-on-mismatch path); only
/// then co-sign with `add_signature` and persist. Failures after decode are
/// `400 M_INVALID_PARAM` with nothing signed or stored.
pub async fn invite(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Path((room_id, path_event_id)): Path<(String, String)>,
    Json(body): Json<InviteBody>,
) -> Response {
    let origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };
    if let Some(response) = ensure_server_acl(&state, &origin, &room_id).await {
        return response;
    }

    let decoded = match decode_pdu(body.event, crate::federation::now_ms()) {
        Ok(decoded) => decoded,
        Err(error) => return bad_json(&error.to_string()),
    };
    let mut pdu = decoded.pdu;

    if pdu.room_id != room_id {
        return invalid_param("PDU room_id does not match the path");
    }
    if pdu.event_type != "m.room.member" {
        return invalid_param("Expected an m.room.member event");
    }
    if pdu.content.get("membership").and_then(|v| v.as_str()) != Some("invite") {
        return invalid_param("Expected invite membership");
    }
    let target_server = pdu.state_key.as_deref().and_then(server_of_user_id);
    if target_server != Some(&*state.server_name) {
        return invalid_param("Invite target is not on this server");
    }
    if !is_third_party_invite(&pdu) && server_of_user_id(&pdu.sender) != Some(origin.as_str()) {
        return invalid_param("sender is not a user on the requesting server");
    }

    let received = match verify_received(&state.remote_keys, &state.http, pdu.clone(), None).await {
        Ok(received) => received,
        Err(_) => return invalid_param("Invite signature check failed"),
    };
    if received.event_id != path_event_id {
        return invalid_param("Invite event ID must match the event ID in the path");
    }
    if received.redacted_on_receipt {
        return invalid_param("Invite content hash does not match");
    }

    // Invite permission (v1.18): a local user who blocks invites is refused
    // before this server co-signs or stores the membership.
    if let Some(target) = pdu.state_key.as_deref() {
        if crate::api::client::room_membership::blocks_invites(state.storage.as_ref(), target).await {
            return matrix_error(
                StatusCode::FORBIDDEN,
                "M_INVITE_BLOCKED",
                &format!("{target} is not accepting invites"),
            );
        }
    }

    if let Err(e) = add_signature(&mut pdu, &state.server_key, &state.server_name) {
        return internal(&format!("Failed to sign invite: {e}"));
    }

    let mut unsigned = decoded.unsigned.unwrap_or_else(|| json!({}));
    if !body.invite_room_state.is_empty() {
        unsigned["invite_room_state"] = Value::Array(body.invite_room_state);
    }
    let unsigned = unsigned.as_object().is_some_and(|m| !m.is_empty()).then_some(unsigned);
    let stored = Event { event_id: received.event_id.clone(), pdu: pdu.clone(), unsigned };
    if let Err(e) = state.storage.publish_event(&stored).await {
        return internal(&format!("Failed to store invite: {e}"));
    }
    if let Ok(pos) = state.storage.global_max_stream_position().await {
        let _ = state.events_tx.send(pos);
    }

    let Some(event) = WirePdu::checked(&received.event_id, pdu) else {
        return internal("co-signed invite no longer reproduces its ID");
    };
    (StatusCode::OK, Json(json!({ "event": event }))).into_response()
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
    let origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };
    if let Some(response) = ensure_server_acl(&state, &origin, &room_id).await {
        return response;
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
    let (pdus, auth_chain) = match (
        wire_pdus(&state.storage, &state_events).await,
        wire_pdus(&state.storage, &auth_chain).await,
    ) {
        (Ok(p), Ok(a)) => (p, a),
        (Err(e), _) | (_, Err(e)) => return internal(&e.to_string()),
    };

    (StatusCode::OK, Json(json!({
        "pdus": pdus,
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
    let origin = match origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name,
        None => return unauthorized("Not authenticated"),
    };
    if let Some(response) = ensure_server_acl(&state, &origin, &room_id).await {
        return response;
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
    if let Some(response) = ensure_server_acl(&state, &origin, &room_id).await {
        return response;
    }

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

    // History visibility, against the requesting origin's membership —
    // the same derivation the client-server read paths use, not a
    // second one, and not "true for every value".
    let visible = match conduit::auth::filter_visible_for_server(
        state.storage.as_ref(),
        &room_id,
        &origin,
        all_events,
    )
    .await
    {
        Ok(evs) => evs,
        Err(e) => return internal(&e.to_string()),
    };
    let filtered: Vec<Event> = visible.into_iter().take(limit).collect();
    let filtered = match wire_pdus(&state.storage, &filtered).await {
        Ok(pdus) => pdus,
        Err(e) => return internal(&e.to_string()),
    };

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

    // Only bytes that reproduce their ID are served; content-mismatched
    // legacy rows are served as their redaction, ID mismatches as 404.
    match state.storage.get_wire_pdu(&event_id).await {
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
    let origin = match &origin_ext {
        Some(axum::extract::Extension(o)) => o.server_name.clone(),
        None => return unauthorized("Not authenticated"),
    };
    if let Some(response) = ensure_server_acl(&state, &origin, &room_id).await {
        return response;
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

    // Same visibility filter as backfill: the walk finds candidates,
    // the origin's membership decides which of them it may have.
    let found = match conduit::auth::filter_visible_for_server(
        state.storage.as_ref(),
        &room_id,
        &origin,
        found,
    )
    .await
    {
        Ok(evs) => evs,
        Err(e) => return internal(&e.to_string()),
    };

    let found = match wire_pdus(&state.storage, &found).await {
        Ok(pdus) => pdus,
        Err(e) => return internal(&e.to_string()),
    };
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

    // The user id's server name is everything after the first colon, so a
    // port survives. Homeservers only answer for their own users.
    if conduit::signing::server_of_user_id(&user_id) != Some(state.server_name.as_ref()) {
        return not_found("User is not on this server");
    }

    // Check account exists. If absent, give the matching AS (if any) a chance
    // to bring the user into existence (conduit-dhd / AS6).
    let mut have_account = matches!(
        state.storage.get_account(&user_id).await,
        Ok(Some(_))
    );
    if !have_account
        && crate::app_service::query_as_user(&state.http, &state.app_services, &user_id).await
    {
        have_account = matches!(
            state.storage.get_account(&user_id).await,
            Ok(Some(_))
        );
    }
    if !have_account {
        return not_found("User not found");
    }

    let account = match state.storage.get_account(&user_id).await {
        Ok(Some(account)) if account.deactivated_at.is_none() => account,
        Ok(_) => return not_found("User not found"),
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"errcode": "M_UNKNOWN", "error": error.to_string()})),
            )
                .into_response()
        }
    };
    let mut profile = match state.storage.profile_fields(&user_id).await {
        Ok(fields) => fields.into_iter().collect::<serde_json::Map<String, Value>>(),
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"errcode": "M_UNKNOWN", "error": error.to_string()})),
            )
                .into_response()
        }
    };
    if let Some(displayname) = account.displayname {
        profile.insert("displayname".into(), json!(displayname));
    }
    if let Some(avatar_url) = account.avatar_url {
        profile.insert("avatar_url".into(), json!(avatar_url));
    }
    // A requested field is the only key. An unset field is null. The full
    // profile omits keys the user has not set.
    let result = match params.get("field").map(String::as_str) {
        Some(field) => json!({ field: profile.get(field).cloned().unwrap_or(Value::Null) }),
        None => Value::Object(profile),
    };
    (StatusCode::OK, Json(result)).into_response()
}

// ---------------------------------------------------------------------------
// x2r.10 — GET /query/directory
// ---------------------------------------------------------------------------

/// `GET /_matrix/federation/v1/query/directory?room_alias=...`
pub async fn query_directory(
    State(state): State<FedState>,
    origin_ext: Option<axum::extract::Extension<FederationOrigin>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if origin_ext.is_none() {
        return unauthorized("Not authenticated");
    }

    let alias = match params.get("room_alias") {
        Some(a) => a.clone(),
        None => return bad_json("Missing room_alias parameter"),
    };

    // Try the local directory first (conduit-v0y).
    if let Ok(Some(room_id)) = state.storage.get_room_for_alias(&alias).await {
        return (
            StatusCode::OK,
            Json(json!({
                "room_id": room_id,
                "servers": [&*state.server_name],
            })),
        )
            .into_response();
    }

    // Otherwise give the matching AS (if any) a chance to register the alias
    // (conduit-dhd / AS6); on confirmation, re-check the directory.
    if crate::app_service::query_as_alias(&state.http, &state.app_services, &alias).await {
        if let Ok(Some(room_id)) = state.storage.get_room_for_alias(&alias).await {
            return (
                StatusCode::OK,
                Json(json!({
                    "room_id": room_id,
                    "servers": [&*state.server_name],
                })),
            )
                .into_response();
        }
    }

    not_found("Room alias not found")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Collect all auth-chain events (union of auth_events reachable from
/// the given state events, up to a reasonable depth).
pub(crate) async fn build_auth_chain(storage: &Arc<dyn Storage>, state_events: &[Event]) -> Vec<Event> {
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
        let target_server = target_user.split_once(':').map(|(_, server)| server).unwrap_or("");
        if target_server != &*state.server_name {
            continue; // Not our user — skip.
        }
        for (target_device, content) in devices {
            if let Err(e) = crate::api::client::keys::enqueue_local_to_device(
                state.storage.as_ref(), target_user, target_device, &sender, &event_type, content,
            ).await
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
pub(crate) async fn handle_edu(
    state: &FedState,
    origin: &str,
    edu: &serde_json::Value,
) -> conduit::Result<()> {
    let edu_type = edu.get("edu_type").and_then(|v| v.as_str()).unwrap_or("");
    if edu_type == "m.typing" || edu_type == "m.receipt" {
        if let Some(room_id) = edu.get("content").and_then(|content| content.get("room_id")).and_then(|id| id.as_str()) {
            if !conduit::server_acl::server_allowed_by_room(state.storage.as_ref(), room_id, origin).await? {
                return Ok(());
            }
        }
    }
    if edu_type == "m.typing" {
        crate::api::client::typing::apply_inbound_typing(
            &state.typing,
            state.storage.as_ref(),
            origin,
            edu,
        )
        .await?;
    }
    if edu_type == "m.receipt" {
        crate::api::client::receipts::apply_inbound_receipt(state.storage.as_ref(), origin, edu).await?;
    }
    if edu_type == "m.presence" {
        crate::api::client::presence::apply_inbound_presence(&state.presence, origin, edu).await?;
    }
    if edu_type == "m.direct_to_device" {
        #[derive(Deserialize)]
        struct DirectToDevice {
            sender: String,
            #[serde(rename = "type")]
            event_type: String,
            message_id: String,
            messages: HashMap<String, HashMap<String, Value>>,
        }
        let Some(content) = edu.get("content") else {
            return Ok(());
        };
        let Ok(message) = serde_json::from_value::<DirectToDevice>(content.clone()) else {
            return Ok(());
        };
        let Some((localpart, sender_server)) = message.sender.split_once(':') else {
            return Ok(());
        };
        if !localpart.starts_with('@')
            || localpart.len() < 2
            || sender_server != origin
            || message.message_id.chars().count() > 32
        {
            return Ok(());
        }
        if message
            .messages
            .values()
            .flat_map(|devices| devices.values())
            .any(|content| !content.is_object())
        {
            return Ok(());
        }
        let mut deliveries = Vec::new();
        for (target, devices) in message.messages {
            let Some((localpart, server)) = target.split_once(':') else {
                continue;
            };
            if !localpart.starts_with('@') || localpart.len() < 2 || server != &*state.server_name {
                continue;
            }
            for (device, content) in devices {
                deliveries.push(conduit::storage::ToDeviceDelivery {
                    target_user: target.clone(),
                    target_device: device,
                    sender: message.sender.clone(),
                    event_type: message.event_type.clone(),
                    content,
                });
            }
        }
        let key = conduit::storage::TransactionKey::federation(origin, &message.message_id);
        state
            .storage
            .deliver_to_device_once(&key, &deliveries, &[])
            .await?;
    }
    if edu_type == "m.device_list_update" {
        let content = edu.get("content").unwrap_or(edu);
        let user_id = match content.get("user_id").and_then(|v| v.as_str()) {
            Some(u) => u.to_owned(),
            None => return Ok(()),
        };
        if user_id.split_once(':').map(|(_, server)| server) != Some(origin) {
            return Ok(());
        }
        let device_id = content
            .get("device_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let deleted = content
            .get("deleted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        tracing::debug!(user_id = %user_id, device_id = %device_id, deleted, "m.device_list_update EDU");

        // If the EDU includes the device keys, persist them.
        if let Some(keys) = content.get("keys") {
            if !deleted && !device_id.is_empty() {
                state
                    .storage
                    .upsert_device_keys(&user_id, device_id, keys)
                    .await?;
            }
        }

        // Tombstone the device when the EDU signals deletion (conduit-ub5).
        if deleted && !device_id.is_empty() {
            state
                .storage
                .delete_device_keys(&user_id, device_id)
                .await?;
        }

        // Record device list change so local /sync picks it up.
        state.storage.record_device_list_change(&user_id).await?;
    }
    Ok(())
}
// ---------------------------------------------------------------------------
// Router builder
// ---------------------------------------------------------------------------

/// Build the federation inbound subrouter.
///
/// Paths include the API version. Mount at `/_matrix/federation`.
/// Prefer [`authenticated_federation_router`] for the production mount and
/// authentication/rate-limit layers.
pub fn federation_router() -> axum::Router<FedState> {
    use axum::routing::{get, post, put};
    use crate::api::client::media::{federation_download, federation_thumbnail};

    let v1 = axum::Router::new()
        .route("/send/:txnId", put(send_transaction))
        .route("/make_join/:roomId/:userId", get(make_join))
        .route("/state/:roomId", get(state))
        .route("/state_ids/:roomId", get(state_ids))
        .route("/backfill/:roomId", get(backfill))
        .route("/event/:eventId", get(get_event))
        .route("/get_missing_events/:roomId", post(get_missing_events))
        .route("/query/profile", get(query_profile))
        .route("/query/directory", get(query_directory))
        .route("/event_auth/:roomId/:eventId", get(super::spec_v119::event_auth))
        .route("/timestamp_to_event/:roomId", get(super::spec_v119::timestamp_to_event))
        .route("/publicRooms", get(super::spec_v119::public_rooms_get).post(super::spec_v119::public_rooms_post))
        .route("/hierarchy/:roomId", get(super::spec_v119::hierarchy))
        .route("/openid/userinfo", get(super::spec_v119::openid_userinfo))
        .route("/user/devices/:userId", get(super::spec_v119::user_devices))
        .route("/user/keys/query", post(super::spec_v119::user_keys_query))
        .route("/user/keys/claim", post(super::spec_v119::user_keys_claim))
        .route("/make_knock/:roomId/:userId", get(super::spec_v119::make_knock))
        .route("/send_knock/:roomId/:eventId", put(super::spec_v119::send_knock))
        .route("/make_leave/:roomId/:userId", get(super::spec_v119::make_leave))
        .route("/invite/:roomId/:eventId", put(invite))
        .route("/exchange_third_party_invite/:roomId", put(super::spec_v119::exchange_third_party_invite))
        // Media (E07 h9n.8): federation download + thumbnail
        .route("/media/download/:mediaId", get(federation_download::<FedState>))
        .route("/media/thumbnail/:mediaId", get(federation_thumbnail::<FedState>));
    let v2 = axum::Router::new()
        .route("/send_join/:roomId/:eventId", put(send_join))
        .route("/invite/:roomId/:eventId", put(invite))
        .route("/send_leave/:roomId/:eventId", put(super::spec_v119::send_leave));
    axum::Router::new().nest("/v1", v1).nest("/v2", v2)
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024))
}

/// Mount the federation APIs with the same middleware used by the binary.
/// Nested routers preserve `OriginalUri`, which must be signed in full.
pub fn authenticated_federation_router<S>(
    state: FedState,
    limiter: super::rate_limit::RateLimiter,
) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    use super::middleware::{verify_xmatrix, XMatrixMiddlewareState};
    use super::rate_limit::rate_limit;
    use axum::middleware;

    let auth = XMatrixMiddlewareState {
        server_name: Arc::clone(&state.server_name),
        remote_keys: Arc::clone(&state.remote_keys),
        http: state.http.clone(),
    };
    let authed = |router: axum::Router<FedState>| {
        router
            .layer(middleware::from_fn_with_state(limiter.clone(), rate_limit))
            .layer(middleware::from_fn_with_state(auth.clone(), verify_xmatrix))
            .with_state::<S>(state.clone())
    };
    let routes = authed(federation_router());
    let key_query = authed(
        axum::Router::new()
            .route("/_matrix/key/v2/query", axum::routing::post(super::spec_v119::key_query))
            .route("/_matrix/key/v2/query/:serverName", axum::routing::get(super::spec_v119::key_query_server)),
    );
    // `/version` is unauthenticated. Spec: GET /_matrix/federation/v1/version.
    let version = axum::Router::new()
        .route("/_matrix/federation/v1/version", axum::routing::get(federation_version))
        .with_state::<S>(state);
    axum::Router::new().merge(version).merge(key_query).merge(axum::Router::new().nest("/_matrix/federation", routes))
}

/// `GET /_matrix/federation/v1/version`. No signature. `server.name` is this
/// homeserver's server name; `server.version` is the crate version.
async fn federation_version(State(state): State<FedState>) -> Json<Value> {
    Json(json!({
        "server": {
            "name": state.server_name.as_ref(),
            "version": env!("CARGO_PKG_VERSION"),
        }
    }))
}
