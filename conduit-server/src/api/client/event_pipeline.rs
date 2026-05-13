//! Event authoring pipeline.
//!
//! `build_sign_and_persist` is the single entry-point used by every
//! state-changing endpoint. It:
//!
//! 1. Fills in the PDU template fields (prev_events, depth, auth_events,
//!    origin_server_ts).
//! 2. Computes the content hash and signs the event.
//! 3. Derives the event_id (reference hash).
//! 4. Runs the v11 auth check.
//! 5. Persists the event and, if it is a state event, updates
//!    `room_current_state`.
//!
//! Returns the canonical `event_id` string on success.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

use conduit::auth::{StateMap, auth_event_keys, check_auth};
use conduit::event::Event;
use conduit::hashing::event_id;
use conduit::signing::sign_event;

use super::{AuthState, MatrixError};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build, sign, auth-check, and persist a single Matrix event.
///
/// Returns the `event_id` on success, or a `MatrixError` response on failure.
pub async fn build_sign_and_persist<S: AuthState>(
    state: &S,
    sender: &str,
    room_id: &str,
    type_: &str,
    state_key: Option<&str>,
    content: serde_json::Value,
) -> Result<String, (StatusCode, Json<MatrixError>)> {
    let storage = state.storage();
    let server_name = state.server_name();

    // ------------------------------------------------------------------
    // Step 2 — prev_events and depth
    // ------------------------------------------------------------------
    let (prev_events, depth) = match storage.room_latest_stream_position(room_id).await {
        Ok(Some(_)) => {
            // Get the latest event in the room as the single prev_event.
            let all = storage.room_events(room_id).await.map_err(|e| {
                MatrixError::unknown(format!("storage error: {e}"))
            })?;
            let latest = all.into_iter().max_by_key(|e| e.depth);
            match latest {
                Some(ev) => {
                    let d = ev.depth + 1;
                    (vec![ev.event_id.clone()], d)
                }
                None => (vec![], 1),
            }
        }
        Ok(None) => (vec![], 1),
        Err(e) => return Err(MatrixError::unknown(format!("storage error: {e}"))),
    };

    // ------------------------------------------------------------------
    // Build the unsigned event template (no event_id yet, no hashes, no sig)
    // ------------------------------------------------------------------
    let mut event = Event {
        event_id: String::new(), // filled in after hashing
        room_id: room_id.to_owned(),
        sender: sender.to_owned(),
        event_type: type_.to_owned(),
        content,
        state_key: state_key.map(|s| s.to_owned()),
        origin_server_ts: now_ms(),
        auth_events: vec![], // filled in below
        prev_events,
        hashes: json!({}),
        signatures: json!({}),
        depth,
        unsigned: None,
    };

    // ------------------------------------------------------------------
    // Step 4 — auth_events: look up current state for required keys
    // ------------------------------------------------------------------
    let required_keys = auth_event_keys(&event);
    let mut auth_events_ids: Vec<String> = Vec::new();
    let mut auth_state: StateMap<Event> = HashMap::new();

    for (ev_type, sk) in &required_keys {
        if let Ok(Some(state_ev)) = storage.get_state_entry(room_id, ev_type, sk).await {
            auth_events_ids.push(state_ev.event_id.clone());
            auth_state.insert((ev_type.clone(), sk.clone()), state_ev);
        }
    }
    event.auth_events = auth_events_ids;

    // ------------------------------------------------------------------
    // Step 5 & 6 — content hash + sign (sign_event sets hashes internally)
    // ------------------------------------------------------------------
    sign_event(&mut event, &state.server_key(), server_name).map_err(|e| {
        MatrixError::unknown(format!("signing error: {e}"))
    })?;

    // ------------------------------------------------------------------
    // Step 7 — event_id (reference hash)
    // ------------------------------------------------------------------
    let eid = event_id(&event).map_err(|e| {
        MatrixError::unknown(format!("event_id error: {e}"))
    })?;
    event.event_id = eid.clone();

    // ------------------------------------------------------------------
    // Step 8 — auth check
    // ------------------------------------------------------------------
    check_auth(&event, &auth_state).map_err(|e| {
        MatrixError::forbidden(format!("auth check failed: {e}"))
    })?;

    // ------------------------------------------------------------------
    // Step 9 — persist
    // ------------------------------------------------------------------
    storage.put_event(&event).await.map_err(|e| {
        MatrixError::unknown(format!("storage error: {e}"))
    })?;

    // ------------------------------------------------------------------
    // Step 10 — update current state if this is a state event
    // ------------------------------------------------------------------
    if let Some(sk) = state_key {
        storage
            .set_state_entry(room_id, type_, sk, &eid)
            .await
            .map_err(|e| MatrixError::unknown(format!("state update error: {e}")))?;
    }

    Ok(eid)
}
