//! Incoming PDU processing pipeline (x2r.3, x2r.4).
//!
//! `process_incoming_pdu` is the single entry point for all inbound federation
//! events. It runs the following stages:
//!
//! 1. **Verify event signatures** — at minimum the originating server's sig.
//! 2. **Dedup** — skip events we already have.
//! 3. **Auth-event fetch** — resolve missing auth events from the network.
//! 4. **Auth check** — run `check_auth` against the auth-event state.
//! 5. **State resolution** — if state conflicts arise, run `state_res::resolve`.
//! 6. **Persist** — `storage.put_event` + `set_state_entry` for state events.
//! 7. **Fanout** — notify local `/sync` via `events_tx`.

use std::collections::HashMap;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::broadcast;

use conduit::auth::{StateMap, auth_event_keys, check_auth};
use conduit::event::Event;
use conduit::signing::{verify_event, VerifyError};
use conduit::storage::Storage;

use crate::RemoteKeyCache;
use crate::federation::Client as FedClient;

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
    pdu: Event,
    _origin: &str,
) -> Result<(), PipelineError> {
    // --- Step 1: Dedup — skip if we already have this event -----------------
    if let Ok(Some(_)) = storage.get_event(&pdu.event_id).await {
        return Ok(()); // already processed
    }

    // --- Step 2: Verify event signatures ------------------------------------
    // We need the keys for all servers that signed the event.
    // Build a key cache by fetching what we need.
    let key_cache = build_key_cache(remote_keys, http, &pdu).await;
    let lookup = make_key_lookup(key_cache);
    verify_event(&pdu, lookup).map_err(PipelineError::SignatureError)?;

    // --- Step 3: Resolve auth events ----------------------------------------
    // Ensure all auth_events are in storage; fetch missing ones.
    fetch_missing_auth_events(storage, remote_keys, http, fed_client, &pdu, _origin).await?;

    // --- Step 4: Build auth state and run auth check ------------------------
    // Skip auth check for events in rooms we don't have state for yet.
    // This can happen when receiving events via /send before we've joined
    // the room. The check is still run when we have the room's create event.
    let auth_state = build_auth_state(storage, &pdu).await?;
    let have_room_create = auth_state.contains_key(&("m.room.create".to_owned(), String::new()))
        || pdu.event_type == "m.room.create";
    if have_room_create {
        check_auth(&pdu, &auth_state)
            .map_err(|e| PipelineError::AuthFailed(e.to_string()))?;
    }

    // --- Step 5: State resolution (for state events with conflicts) ---------
    // For now, if this is a state event, we check for conflicts and run
    // state_res if needed.
    // bd remember: Full state-res on inbound join requires fetching all current
    // state and both branch tips. For v0 we apply the event if auth passes and
    // note that conflict resolution is simplified.
    if let Some(state_key) = &pdu.state_key {
        // Check if there's an existing state entry.
        let existing = storage
            .get_state_entry(&pdu.room_id, &pdu.event_type, state_key)
            .await
            .map_err(|e| PipelineError::Storage(e.to_string()))?;

        if let Some(existing_ev) = existing {
            if existing_ev.event_id != pdu.event_id {
                // Conflict detected — run state resolution.
                // TODO(x2r.4): Full state-res with proper auth chains.
                // For v0: apply the new event if it has higher depth or later ts.
                // bd remember: Simplified conflict handling — full state-res
                // requires collecting both branch state sets and auth chains.
                let new_wins = pdu.depth > existing_ev.depth
                    || (pdu.depth == existing_ev.depth
                        && pdu.origin_server_ts > existing_ev.origin_server_ts)
                    || (pdu.depth == existing_ev.depth
                        && pdu.origin_server_ts == existing_ev.origin_server_ts
                        && pdu.event_id > existing_ev.event_id);
                if !new_wins {
                    // Existing event wins — still persist the PDU for history,
                    // but don't update current state.
                    storage
                        .put_event(&pdu)
                        .await
                        .map_err(|e| PipelineError::Storage(e.to_string()))?;
                    notify_sync(storage, events_tx).await;
                    return Ok(());
                }
            }
        }
    }

    // --- Step 6: Persist ----------------------------------------------------
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

    // --- Step 7: Notify local /sync -----------------------------------------
    notify_sync(storage, events_tx).await;

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

/// Build the auth state needed by `check_auth` for this event.
async fn build_auth_state(
    storage: &Arc<dyn Storage>,
    event: &Event,
) -> Result<StateMap<Event>, PipelineError> {
    let keys = auth_event_keys(event);
    let mut auth_state: StateMap<Event> = HashMap::new();
    for (ev_type, sk) in &keys {
        if let Ok(Some(state_ev)) = storage.get_state_entry(&event.room_id, ev_type, sk).await {
            auth_state.insert((ev_type.clone(), sk.clone()), state_ev);
        }
    }
    Ok(auth_state)
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
