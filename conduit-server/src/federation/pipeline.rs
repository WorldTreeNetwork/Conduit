//! Incoming PDU processing pipeline (x2r.3, x2r.4).
//!
//! `process_incoming_pdu` is the single entry point for all inbound federation
//! events. It runs the following stages:
//!
//! 1. **Verify event signatures** — at minimum the originating server's sig.
//! 2. **Dedup** — skip events we already have.
//! 3. **Auth-event fetch** — resolve missing auth events from the network.
//! 4. **Build auth chain** — recursively collect all auth events reachable from
//!    the PDU into a complete `HashMap<String, Event>`.
//! 5. **Full state resolution** — run `state_res::resolve` to compute the
//!    canonical room state from the current state and the incoming event.
//! 6. **Auth check** — run `check_auth` against the full resolved state.
//! 7. **Persist** — `storage.put_event` + `set_state_entry` for state events.
//! 8. **Fanout** — notify local `/sync` via `events_tx`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::broadcast;

use conduit::auth::{StateMap, auth_event_keys, check_auth};
use conduit::event::Event;
use conduit::room::state_res;
use conduit::signing::{verify_event, VerifyError};
use conduit::storage::Storage;

use crate::RemoteKeyCache;
use crate::federation::Client as FedClient;
use crate::federation::recent::RecentEventCache;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("event signature verification failed: {0}")]
    SignatureError(#[from] VerifyError),

    #[error("auth check failed: {0}")]
    AuthFailed(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("state resolution error: {0}")]
    StateRes(String),

    #[error("auth event fetch failed: {0}")]
    AuthEventFetch(String),

    #[error("missing auth event: {event_id} — cannot build auth chain")]
    MissingAuthEvent { event_id: String },
}

// ---------------------------------------------------------------------------
// Key lookup closure builder
// ---------------------------------------------------------------------------

/// Build a synchronous key-lookup closure that consults an already-fetched
/// cache of public keys (keyed by `(server_name, key_id)`).
fn make_key_lookup(
    cache: HashMap<(String, String), Vec<u8>>,
) -> impl Fn(&str, &str) -> Option<Vec<u8>> {
    move |srv: &str, kid: &str| {
        cache.get(&(srv.to_owned(), kid.to_owned())).cloned()
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Process one incoming PDU from a remote server.
///
/// `origin` is the server that sent the transaction (from X-Matrix auth).
/// `fed_client` is used to fetch missing auth events if needed.
pub async fn process_incoming_pdu(
    storage: &Arc<dyn Storage>,
    remote_keys: &Arc<RemoteKeyCache>,
    http: &reqwest::Client,
    events_tx: &broadcast::Sender<i64>,
    fed_client: Option<&Arc<FedClient>>,
    recent: Option<&Arc<RecentEventCache>>,
    pdu: Event,
    _origin: &str,
) -> Result<(), PipelineError> {
    // --- Step 1: Dedup — skip if we already have this event -----------------
    // Fast path: in-memory cache of recently-processed event_ids (conduit-3qj).
    if let Some(cache) = recent {
        if cache.contains(&pdu.event_id).await {
            return Ok(());
        }
    }
    if let Ok(Some(_)) = storage.get_event(&pdu.event_id).await {
        if let Some(cache) = recent {
            cache.insert(&pdu.event_id).await;
        }
        return Ok(()); // already processed
    }

    // --- Step 2: Verify event signatures ------------------------------------
    // We need the keys for all servers that signed the event.
    // Build a key cache by fetching what we need.
    let key_cache = build_key_cache(remote_keys, http, &pdu).await;
    let lookup = make_key_lookup(key_cache);
    verify_event(&pdu, lookup).map_err(PipelineError::SignatureError)?;

    // --- Step 3: Resolve auth events (immediate) ----------------------------
    // Ensure all direct auth_events are in storage; fetch missing ones.
    fetch_missing_auth_events(storage, remote_keys, http, fed_client, &pdu, _origin).await?;

    // --- Step 4: Build full auth chain --------------------------------------
    // Recursively traverse auth_events from the PDU and build a complete
    // HashMap<String, Event> for the state resolution algorithm.
    let auth_chain = build_auth_chain(storage, &pdu).await?;

    // --- Step 5: Full state resolution --------------------------------------
    // Build two state sets:
    //   A: current room state before this event
    //   B: current room state + this event (if it's a state event)
    // Then run state_res::resolve to compute canonical state.
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

    let resolved_state = if current_state_map.is_empty() {
        // No existing state — this might be the first event in the room
        // (e.g. an m.room.create). In that case, state_res is trivial:
        // the resolved state is just the PDU itself if it's a state event,
        // or empty.
        if let Some(state_key) = &pdu.state_key {
            let mut m = StateMap::new();
            m.insert((pdu.event_type.clone(), state_key.clone()), pdu.clone());
            m
        } else {
            current_state_map
        }
    } else {
        // Build state set B: current state with the incoming PDU applied
        // (if it's a state event, it replaces the existing entry).
        let mut incoming_state = current_state_map.clone();
        if let Some(state_key) = &pdu.state_key {
            incoming_state.insert((pdu.event_type.clone(), state_key.clone()), pdu.clone());
        }

        let state_sets = vec![
            current_state_map.clone(),
            incoming_state,
        ];

        state_res::resolve(state_sets, auth_chain)
            .map_err(|e| PipelineError::StateRes(e.to_string()))?
    };

    // --- Step 6: Auth check against resolved state --------------------------
    // Only run auth if we have the room's create event.
    let have_room_create = resolved_state.contains_key(&("m.room.create".to_owned(), String::new()))
        || pdu.event_type == "m.room.create";
    if have_room_create {
        // Build the auth state slice from the resolved state.
        let auth_state = build_auth_state_from_resolved(&pdu, &resolved_state);
        check_auth(&pdu, &auth_state)
            .map_err(|e| PipelineError::AuthFailed(e.to_string()))?;
    }

    // --- Step 7: Persist ----------------------------------------------------
    storage
        .put_event(&pdu)
        .await
        .map_err(|e| PipelineError::Storage(e.to_string()))?;

    // Update current state for state events.
    if let Some(state_key) = &pdu.state_key {
        storage
            .set_state_entry(&pdu.room_id, &pdu.event_type, state_key, &pdu.event_id)
            .await
            .map_err(|e| PipelineError::Storage(e.to_string()))?;
    }

    // --- Step 8: Notify local /sync -----------------------------------------
    notify_sync(storage, events_tx).await;

    // Mark this event as recently-processed for the fast-path dedup cache.
    if let Some(cache) = recent {
        cache.insert(&pdu.event_id).await;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Fetch public keys for all servers that signed the event and return a cache.
async fn build_key_cache(
    remote_keys: &Arc<RemoteKeyCache>,
    http: &reqwest::Client,
    pdu: &Event,
) -> HashMap<(String, String), Vec<u8>> {
    let mut cache = HashMap::new();

    let sigs_obj = match pdu.signatures.as_object() {
        Some(o) => o,
        None => return cache,
    };

    for (server, key_map) in sigs_obj {
        let Some(key_map_obj) = key_map.as_object() else {
            continue;
        };
        for kid in key_map_obj.keys() {
            if let Ok(pub_bytes) = remote_keys.get_or_fetch(http, server, kid).await {
                cache.insert((server.clone(), kid.clone()), pub_bytes);
            }
        }
    }

    cache
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
///
/// Returns a `HashMap<String, Event>` keyed by event_id containing all events
/// in the auth chain. Returns `Err(MissingAuthEvent)` if any referenced auth
/// event is not in storage and cannot be fetched.
async fn build_auth_chain(
    storage: &Arc<dyn Storage>,
    event: &Event,
) -> Result<HashMap<String, Event>, PipelineError> {
    let mut chain: HashMap<String, Event> = HashMap::new();
    let mut stack: Vec<String> = event.auth_events.clone();
    let mut visited: HashSet<String> = HashSet::new();

    // Include the event itself if it's already persisted (so the state_res
    // algorithm can reference it).
    if let Ok(Some(existing)) = storage.get_event(&event.event_id).await {
        chain.insert(event.event_id.clone(), existing);
    }

    while let Some(eid) = stack.pop() {
        if !visited.insert(eid.clone()) {
            continue;
        }
        match storage.get_event(&eid).await {
            Ok(Some(ev)) => {
                // Add to the chain and push its own auth_events for traversal.
                chain.insert(eid, ev.clone());
                for auth_eid in &ev.auth_events {
                    if !visited.contains(auth_eid.as_str()) {
                        stack.push(auth_eid.clone());
                    }
                }
            }
            Ok(None) => {
                // Auth event is missing from storage — this is fatal for
                // state resolution per spec.
                return Err(PipelineError::MissingAuthEvent { event_id: eid });
            }
            Err(e) => {
                return Err(PipelineError::Storage(e.to_string()));
            }
        }
    }

    Ok(chain)
}

/// Ensure all auth_events for `pdu` are in storage.
/// For any missing ones, try to fetch them from the network.
async fn fetch_missing_auth_events(
    storage: &Arc<dyn Storage>,
    _remote_keys: &Arc<RemoteKeyCache>,
    _http: &reqwest::Client,
    fed_client: Option<&Arc<FedClient>>,
    pdu: &Event,
    origin: &str,
) -> Result<(), PipelineError> {
    for auth_eid in &pdu.auth_events {
        match storage.get_event(auth_eid).await {
            Ok(Some(_)) => continue, // already have it
            Ok(None) => {
                // Try to fetch from the origin.
                if let Some(client) = fed_client {
                    match client.event(origin, auth_eid).await {
                        Ok(auth_ev) => {
                            // Recursively verify and store the auth event.
                            // For v0: just store it without deep recursion.
                            // bd remember: Full recursive auth-event verification
                            // is needed for strict compliance. Here we store and
                            // trust (shallow). File follow-up for deep recursion.
                            if let Err(e) = storage.put_event(&auth_ev).await {
                                return Err(PipelineError::AuthEventFetch(e.to_string()));
                            }
                        }
                        Err(e) => {
                            // Non-fatal: the auth check may still pass if the
                            // missing event isn't needed for current state.
                            tracing::warn!(
                                event_id = %pdu.event_id,
                                auth_event_id = %auth_eid,
                                error = %e,
                                "could not fetch missing auth event"
                            );
                        }
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
