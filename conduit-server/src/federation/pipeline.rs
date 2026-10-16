//! Incoming PDU processing pipeline (x2r.3, x2r.4; add-pdu-wire).
//!
//! `process_incoming_pdu` is the single entry point for inbound federation
//! events that arrive pushed (`/send`, `/send_join`). Callers decode first
//! ([`conduit::wire::decode_pdu`], "is a valid event"); then:
//!
//! 1. **Signatures** — required signers (sender's server; the authorising
//!    server of a restricted join) with keys eligible at the event's
//!    `origin_server_ts`; failure drops the PDU. Observed signers (the
//!    authoriser on non-join memberships) are recorded in `SignedBy`.
//! 2. **ID + content hash** — v3+ ids are derived; room version 1 keeps the
//!    PDU's `event_id`. A hash mismatch
//!    keeps the redacted copy under the same ID.
//! 3. **Dedup** on the derived ID.
//! 4. **Auth-event fetch** through [`super::admit::admit_fetched`]
//!    (`Exactly(id)`), so a substituted event is never stored.
//! 5. **Auth chain + state resolution**.
//! 6. **Auth check** — the v11 rules plus rule 4.2 against `SignedBy`.
//! 7. **Persist** `Event { event_id, pdu, unsigned }` and update state.
//! 8. **Fanout** — notify local `/sync`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;
use tokio::sync::broadcast;

use conduit::auth::{StateMap, auth_event_keys, check_auth, check_authoriser_signature};
use conduit::event::{Event, Pdu};
use conduit::room::state_res;
use conduit::signing::{check_received, signers, Received, VerifyError};
use conduit::storage::Storage;
use conduit::wire::DecodedPdu;

use crate::RemoteKeyCache;
use crate::federation::Client as FedClient;
use crate::federation::recent::RecentEventCache;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PipelineError {
    /// Signature stage failure: the PDU is dropped.
    #[error("event signature verification failed: {0}")]
    SignatureError(#[from] VerifyError),

    #[error("auth check failed: {0}")]
    AuthFailed(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("state resolution error: {0}")]
    StateRes(String),

    #[error("unsupported room version: {0}")]
    UnsupportedRoomVersion(String),

    #[error("auth event fetch failed: {0}")]
    AuthEventFetch(String),

    #[error("missing auth event: {event_id} — cannot build auth chain")]
    MissingAuthEvent { event_id: String },
}

// ---------------------------------------------------------------------------
// Event-time key lookup
// ---------------------------------------------------------------------------

/// Fetch the keys that may verify `pdu`: for each required and observed
/// signer, every key ID it signed with, if eligible at `origin_server_ts`.
pub async fn eligible_keys(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    pdu: &Pdu,
) -> HashMap<(String, String), Vec<u8>> {
    let mut keys = HashMap::new();
    let Ok(signers) = signers(pdu) else { return keys };
    let servers = signers.required.iter().chain(signers.observed.iter());
    for server in servers {
        let Some(key_ids) = pdu.signatures.get(server).and_then(Value::as_object) else { continue };
        for key_id in key_ids.keys() {
            if let Some(public) = remote_keys.eligible_key(http, server, key_id, pdu.origin_server_ts).await {
                keys.insert((server.clone(), key_id.clone()), public);
            }
        }
    }
    keys
}

/// A synchronous lookup over an [`eligible_keys`] result.
pub fn lookup(keys: HashMap<(String, String), Vec<u8>>) -> impl Fn(&str, &str) -> Option<Vec<u8>> {
    move |server: &str, key_id: &str| keys.get(&(server.to_owned(), key_id.to_owned())).cloned()
}

/// Signature stage + ID derivation + content-hash check for a received PDU.
pub async fn verify_received(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    pdu: Pdu,
    explicit_event_id: Option<String>,
) -> Result<Received, VerifyError> {
    let keys = eligible_keys(remote_keys, http, &pdu).await;
    let mut received = check_received(pdu, lookup(keys))?;
    // Room versions 1 and 2 keep the PDU's event id. Later versions derive it.
    if let Some(event_id) = explicit_event_id {
        received.event_id = event_id;
    }
    Ok(received)
}

/// [`verify_received`] where this server is itself a required signer (the
/// authorising resident of a restricted join): our own key is used directly
/// instead of being fetched from ourselves.
pub async fn verify_received_as(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    pdu: Pdu,
    local_server: &str,
    local_key: &conduit::keys::ServerKey,
    explicit_event_id: Option<String>,
) -> Result<Received, VerifyError> {
    let mut keys = HashMap::new();
    if let Ok(signers) = signers(&pdu) {
        for server in signers.required.iter().chain(signers.observed.iter()).filter(|s| s.as_str() != local_server) {
            let Some(key_ids) = pdu.signatures.get(server).and_then(Value::as_object) else { continue };
            for key_id in key_ids.keys() {
                if let Some(public) = remote_keys.eligible_key(http, server, key_id, pdu.origin_server_ts).await {
                    keys.insert((server.clone(), key_id.clone()), public);
                }
            }
        }
    }
    keys.insert((local_server.to_owned(), local_key.key_id.clone()), conduit::keys::public_bytes(local_key));
    let mut received = check_received(pdu, lookup(keys))?;
    if let Some(event_id) = explicit_event_id {
        received.event_id = event_id;
    }
    Ok(received)
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Process one decoded PDU pushed by a remote server. Returns the derived
/// event ID on acceptance.
///
/// `origin` is the server that sent the transaction (from X-Matrix auth).
/// `fed_client` is used to fetch missing auth events if needed.
#[allow(clippy::too_many_arguments)]
pub async fn process_incoming_pdu(
    storage: &Arc<dyn Storage>,
    remote_keys: &Arc<RemoteKeyCache>,
    http: &reqwest::Client,
    events_tx: &broadcast::Sender<i64>,
    fed_client: Option<&Arc<FedClient>>,
    recent: Option<&Arc<RecentEventCache>>,
    decoded: DecodedPdu,
    origin: &str,
) -> Result<String, PipelineError> {
    let explicit_event_id = decoded.explicit_event_id.clone();
    let received = verify_received(remote_keys, http, decoded.pdu, explicit_event_id).await?;
    process_received(storage, remote_keys, http, events_tx, fed_client, recent, received, decoded.unsigned, origin).await
}

/// Steps 3–8 for a PDU that already passed the signature stage.
#[allow(clippy::too_many_arguments)]
pub async fn process_received(
    storage: &Arc<dyn Storage>,
    remote_keys: &Arc<RemoteKeyCache>,
    http: &reqwest::Client,
    events_tx: &broadcast::Sender<i64>,
    fed_client: Option<&Arc<FedClient>>,
    recent: Option<&Arc<RecentEventCache>>,
    received: Received,
    unsigned: Option<Value>,
    origin: &str,
) -> Result<String, PipelineError> {
    let Received { event_id, pdu, signed_by, .. } = received;
    let pdu = Event { event_id, pdu, unsigned };

    // --- Dedup — skip if we already have this event -------------------------
    if let Some(cache) = recent {
        if cache.contains(&pdu.event_id).await {
            return Ok(pdu.event_id);
        }
    }
    if let Ok(Some(_)) = storage.get_event(&pdu.event_id).await {
        if let Some(cache) = recent {
            cache.insert(&pdu.event_id).await;
        }
        if storage.event_disposition(&pdu.event_id).await.ok().flatten().as_deref() == Some("rejected") {
            return Err(PipelineError::AuthFailed("rejected".into()));
        }
        return Ok(pdu.event_id);
    }

    // Room version 11 only (kernel gate — in-process cannot bypass).
    {
        let version = if pdu.event_type == "m.room.create" {
            pdu.content
                .get("room_version")
                .and_then(|v| v.as_str())
                .unwrap_or("1")
                .to_owned()
        } else {
            match storage
                .get_state_entry(&pdu.room_id, "m.room.create", "")
                .await
            {
                Ok(Some(create)) => create
                    .content
                    .get("room_version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1")
                    .to_owned(),
                _ => "1".to_owned(),
            }
        };
        conduit::require_room_version(&version)
            .map_err(|e| PipelineError::UnsupportedRoomVersion(e.to_string()))?;
    }

    // --- Resolve auth events (immediate) -----------------------------------
    fetch_missing_auth_events(storage, remote_keys, http, fed_client, &pdu, origin).await?;

    // --- Full state resolution ---------------------------------------------
    let current_state_events = storage
        .get_current_state(&pdu.room_id)
        .await
        .map_err(|e| PipelineError::Storage(e.to_string()))?;

    let current_state_map: StateMap<Event> = current_state_events
        .into_iter()
        .filter_map(|ev| {
            ev.state_key
                .as_ref()
                .map(|sk| ((ev.event_type.clone(), sk.clone()), ev.clone()))
        })
        .collect();
    // Authorization reads the room from before this event. State resolution
    // below may select the event itself, which would make a leave look like
    // Leave -> Leave.
    let prior_state = current_state_map.clone();
    // Auth-event selection and the state-at-event check happen before state
    // resolution so a bad `auth_events` list is rejected instead of failing
    // the chain walk. A PDU that passes there but fails against the room's
    // current state is soft-failed: stored, not served to clients, not current.
    if prior_state.contains_key(&("m.room.create".to_owned(), String::new()))
        && pdu.event_type != "m.room.create"
    {
        let state_at = selection_state(storage.as_ref(), &pdu, &prior_state).await;
        let expected = expected_auth_ids(&pdu, &state_at);
        let cited: BTreeSet<String> = pdu.auth_events.iter().cloned().collect();
        if cited != expected {
            persist_held(storage, &pdu, "rejected").await?;
            return Err(PipelineError::AuthFailed("auth events selection".into()));
        }
        if let Err(error) = check_auth(&pdu, &state_at) {
            persist_held(storage, &pdu, "rejected").await?;
            return Err(PipelineError::AuthFailed(error.to_string()));
        }
        if check_auth(&pdu, &prior_state).is_err() {
            persist_held(storage, &pdu, "soft_failed").await?;
            if let Some(cache) = recent {
                cache.insert(&pdu.event_id).await;
            }
            return Ok(pdu.event_id);
        }
    }
    // Resolution needs every auth event of both snapshots, not only the
    // incoming PDU's. A conflicting leave otherwise fails closed on a
    // create-power or membership auth event that the PDU does not list.
    let mut auth_chain = build_auth_chain(storage, &pdu).await?;
    for event in prior_state.values() {
        auth_chain.extend(build_auth_chain(storage, event).await?);
    }
    auth_chain.insert(pdu.event_id.clone(), pdu.clone());

    let resolved_state = if current_state_map.is_empty() {
        if let Some(state_key) = &pdu.state_key {
            let mut m = StateMap::new();
            m.insert((pdu.event_type.clone(), state_key.clone()), pdu.clone());
            m
        } else {
            current_state_map
        }
    } else {
        let mut incoming_state = current_state_map.clone();
        if let Some(state_key) = &pdu.state_key {
            incoming_state.insert((pdu.event_type.clone(), state_key.clone()), pdu.clone());
        }
        let state_sets = vec![current_state_map.clone(), incoming_state];
        state_res::resolve(state_sets, auth_chain)
            .map_err(|e| PipelineError::StateRes(e.to_string()))?
    };

    // --- Auth check against resolved state ---------------------------------
    let have_room_create = resolved_state.contains_key(&("m.room.create".to_owned(), String::new()))
        || pdu.event_type == "m.room.create";
    if have_room_create {
        let auth_state = build_auth_state_from_resolved(&pdu, &auth_state_before(&pdu, &prior_state, &resolved_state));
        check_auth(&pdu, &auth_state)
            .map_err(|e| PipelineError::AuthFailed(e.to_string()))?;
    }
    // v11 rule 4.2 against the servers whose signatures verified. Joins never
    // get here without the authoriser (dropped at the signature stage);
    // other memberships are rejected here instead of dropped.
    check_authoriser_signature(&pdu, &signed_by)
        .map_err(|e| PipelineError::AuthFailed(e.to_string()))?;

    // --- Persist ------------------------------------------------------------
    storage
        .publish_event(&pdu)
        .await
        .map_err(|e| PipelineError::Storage(e.to_string()))?;

    // --- Notify local /sync ---------------------------------------------------
    notify_sync(storage, events_tx).await;

    if let Some(cache) = recent {
        cache.insert(&pdu.event_id).await;
    }

    Ok(pdu.event_id)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn expected_auth_ids(event: &Event, state: &StateMap<Event>) -> BTreeSet<String> {
    let version = state
        .get(&("m.room.create".to_owned(), String::new()))
        .map(|event| conduit::room_version::version_of_content(&event.content))
        .unwrap_or(11);
    auth_event_keys(event)
        .into_iter()
        .filter(|(event_type, _)| conduit::room_version::cites_room_create(version) || event_type != "m.room.create")
        .filter_map(|(event_type, state_key)| {
            state.get(&(event_type, state_key)).map(|event| event.event_id.clone())
        })
        .collect()
}

/// State used to decide which auth events a PDU must cite.
///
/// At the room tip this is the current state. A PDU whose `prev_events` are
/// older is checked against those events and their auth events, which is the
/// state at that point for the auth-event subset.
async fn selection_state(storage: &dyn Storage, event: &Event, current: &StateMap<Event>) -> StateMap<Event> {
    if event.prev_events.is_empty() {
        return current.clone();
    }
    let mut prevs = Vec::new();
    for event_id in &event.prev_events {
        match storage.get_event(event_id).await {
            Ok(Some(prev)) => prevs.push(prev),
            _ => return current.clone(),
        }
    }
    let tip = current.values().map(|event| event.depth).max().unwrap_or(0);
    if prevs.iter().any(|event| event.depth >= tip) {
        return current.clone();
    }
    let mut map = StateMap::new();
    for prev in &prevs {
        for auth_id in &prev.auth_events {
            if let Ok(Some(auth)) = storage.get_event(auth_id).await {
                if let Some(state_key) = &auth.state_key {
                    map.insert((auth.event_type.clone(), state_key.clone()), auth);
                }
            }
        }
        if let Some(state_key) = &prev.state_key {
            map.insert((prev.event_type.clone(), state_key.clone()), prev.clone());
        }
    }
    // Room version 12 does not cite create, but auth rules still require it.
    let create_key = ("m.room.create".to_owned(), String::new());
    if !map.contains_key(&create_key) {
        if let Some(create) = current.get(&create_key) {
            map.insert(create_key, create.clone());
        }
    }
    map
}

async fn persist_held(storage: &Arc<dyn Storage>, event: &Event, kind: &str) -> Result<(), PipelineError> {
    storage.put_event(event).await.map_err(|error| PipelineError::Storage(error.to_string()))?;
    storage
        .set_event_disposition(&event.event_id, kind)
        .await
        .map_err(|error| PipelineError::Storage(error.to_string()))?;
    Ok(())
}

/// Resolved state with this event's own key put back to the prior entry.
///
/// A membership event must be authorised against the membership it replaces.
fn auth_state_before(event: &Event, prior: &StateMap<Event>, resolved: &StateMap<Event>) -> StateMap<Event> {
    let mut view = resolved.clone();
    let Some(state_key) = &event.state_key else { return view };
    let key = (event.event_type.clone(), state_key.clone());
    if view.get(&key).is_some_and(|current| current.event_id == event.event_id) {
        match prior.get(&key) {
            Some(previous) => {
                view.insert(key, previous.clone());
            }
            None => {
                view.remove(&key);
            }
        }
    }
    view
}

/// Build a `StateMap` suitable for `check_auth` by extracting the auth-event
/// keys from the resolved room state.
fn build_auth_state_from_resolved(
    event: &Event,
    resolved_state: &StateMap<Event>,
) -> StateMap<Event> {
    let keys = auth_event_keys(event);
    let mut auth_state: StateMap<Event> = HashMap::new();
    for key in keys {
        if let Some(ev) = resolved_state.get(&key) {
            auth_state.insert(key, ev.clone());
        }
    }
    auth_state
}

/// Recursively build the full auth chain reachable from `event` via
/// `auth_events` references.
async fn build_auth_chain(
    storage: &Arc<dyn Storage>,
    event: &Event,
) -> Result<HashMap<String, Event>, PipelineError> {
    let mut chain: HashMap<String, Event> = HashMap::new();
    let mut stack: Vec<String> = event.auth_events.clone();
    let mut visited: HashSet<String> = HashSet::new();

    if let Ok(Some(existing)) = storage.get_event(&event.event_id).await {
        chain.insert(event.event_id.clone(), existing);
    }

    while let Some(eid) = stack.pop() {
        if !visited.insert(eid.clone()) {
            continue;
        }
        match storage.get_event(&eid).await {
            Ok(Some(ev)) => {
                chain.insert(eid, ev.clone());
                for auth_eid in &ev.auth_events {
                    if !visited.contains(auth_eid.as_str()) {
                        stack.push(auth_eid.clone());
                    }
                }
            }
            Ok(None) => {
                return Err(PipelineError::MissingAuthEvent { event_id: eid });
            }
            Err(e) => {
                return Err(PipelineError::Storage(e.to_string()));
            }
        }
    }

    Ok(chain)
}

/// Ensure all auth_events for `pdu` are in storage, fetching missing ones
/// from the origin. Each fetched event passes decode, the signature stage
/// and `derived == requested` before it is stored; a substituted answer is
/// discarded. Deep recursive auth of fetched events stays with conduit-g12.
async fn fetch_missing_auth_events(
    storage: &Arc<dyn Storage>,
    remote_keys: &Arc<RemoteKeyCache>,
    http: &reqwest::Client,
    fed_client: Option<&Arc<FedClient>>,
    pdu: &Event,
    origin: &str,
) -> Result<(), PipelineError> {
    for auth_eid in &pdu.auth_events {
        match storage.get_event(auth_eid).await {
            Ok(Some(_)) => continue,
            Ok(None) => {
                let Some(client) = fed_client else { continue };
                let fetched = match client.event(origin, auth_eid).await {
                    Ok(value) => value,
                    Err(e) => {
                        tracing::warn!(event_id = %pdu.event_id, auth_event_id = %auth_eid, error = %e,
                            "could not fetch missing auth event");
                        continue;
                    }
                };
                match super::admit::admit_fetched(remote_keys, http, fetched, super::admit::Expect::Exactly(auth_eid)).await {
                    Ok(admitted) => {
                        storage
                            .put_event(&admitted.into_event())
                            .await
                            .map_err(|e| PipelineError::AuthEventFetch(e.to_string()))?;
                    }
                    Err(e) => {
                        tracing::warn!(event_id = %pdu.event_id, auth_event_id = %auth_eid, error = %e,
                            "refused fetched auth event");
                    }
                }
            }
            Err(e) => {
                return Err(PipelineError::Storage(e.to_string()));
            }
        }
    }
    Ok(())
}

/// Broadcast the latest stream position to wake up /sync long-pollers.
async fn notify_sync(storage: &Arc<dyn Storage>, events_tx: &broadcast::Sender<i64>) {
    if let Ok(pos) = storage.global_max_stream_position().await {
        let _ = events_tx.send(pos);
    }
}
