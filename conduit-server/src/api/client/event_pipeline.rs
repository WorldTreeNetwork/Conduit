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
use serde_json::Value;

use conduit::auth::{StateMap, auth_event_keys, check_auth};
use conduit::event::{Event, Pdu};
use conduit::hashing::event_id;
use conduit::room::RoomEventSender;
use conduit::signing::{sign_authored, SigningError};
use conduit::Result as ConduitResult;

use super::{AuthState, MatrixError};

// ---------------------------------------------------------------------------
// RoomEventSender wrapper for any AuthState
// ---------------------------------------------------------------------------

/// A wrapper that implements [`RoomEventSender`] for any `S: AuthState`.
///
/// This exists solely to work around Rust's orphan rules — we can't
/// implement a foreign trait (`RoomEventSender` from `conduit`) for a
/// generic foreign type (`S: AuthState` from this crate). By wrapping
/// `&S` in a local tuple struct we sidestep the problem.
pub struct RoomEventSenderWrapper<'a, S>(pub &'a S);

#[async_trait::async_trait]
impl<S: AuthState + Send + Sync> RoomEventSender for RoomEventSenderWrapper<'_, S> {
    async fn send_event(
        &self,
        sender: &str,
        room_id: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: Value,
    ) -> ConduitResult<String> {
        build_sign_and_persist(self.0, sender, room_id, event_type, state_key, content)
            .await
            .map_err(|(status, json_err)| {
                // Preserve auth rejections (403) so handlers can surface a real
                // M_FORBIDDEN instead of a generic 500 (conduit-29w).
                if status == StatusCode::FORBIDDEN {
                    conduit::Error::Forbidden(json_err.0.error.clone())
                } else {
                    conduit::Error::Storage(json_err.0.error.clone())
                }
            })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

tokio::task_local! {
    /// `origin_server_ts` override for events authored in this task:
    /// application-service timestamp massaging (`?ts=`, conduit-y99.35).
    pub static ORIGIN_SERVER_TS: u64;
}

fn now_ms() -> u64 {
    if let Ok(ts) = ORIGIN_SERVER_TS.try_with(|ts| *ts) {
        return ts;
    }
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
    build_sign_and_persist_inner(state, sender, room_id, type_, state_key, content, None).await
}

pub async fn build_sign_and_persist_transaction<S: AuthState>(
    state: &S, sender: &str, room_id: &str, type_: &str, content: Value,
    key: &conduit::storage::TransactionKey,
) -> Result<String, (StatusCode, Json<MatrixError>)> {
    build_sign_and_persist_inner(state, sender, room_id, type_, None, content, Some(key)).await
}

async fn build_sign_and_persist_inner<S: AuthState>(
    state: &S, sender: &str, room_id: &str, type_: &str, state_key: Option<&str>, content: Value,
    transaction_key: Option<&conduit::storage::TransactionKey>,
) -> Result<String, (StatusCode, Json<MatrixError>)> {
    let storage = state.storage();
    let server_name = state.server_name();
    // Own joins carry the member's profile (spec §Profiles, conduit-y99.38).
    let content = super::profile::with_join_profile(state, sender, type_, state_key, content).await;

    // PostgreSQL TEXT key columns cannot hold U+0000, and a U+FFFD stand-in
    // could merge two state keys, so refuse it before building the event.
    if type_.contains('\0') || state_key.is_some_and(|k| k.contains('\0')) {
        return Err(MatrixError::invalid_param("event type and state key must not contain U+0000"));
    }
    if type_.len() > conduit::wire::MAX_ID_BYTES || state_key.is_some_and(|k| k.len() > conduit::wire::MAX_ID_BYTES) {
        return Err(MatrixError::too_large("event type and state key are limited to 255 bytes"));
    }

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
    let mut event = Event::new(String::new(), Pdu::new(
        room_id, sender, type_, state_key.map(|s| s.to_owned()), content,
        now_ms(), vec![], prev_events, depth,
    ));

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
    sign_authored(&mut event.pdu, &state.server_key(), server_name).map_err(|e| match e {
        SigningError::TooLarge { .. } => MatrixError::too_large("event exceeds the 65536-byte PDU limit"),
        e => MatrixError::unknown(format!("signing error: {e}")),
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
    if let Some(key) = transaction_key {
        let (event_id, inserted) = storage.put_event_once(key, &event).await
            .map_err(|error| MatrixError::unknown(format!("storage error: {error}")))?;
        if !inserted { return Ok(event_id); }
    } else {
        storage.put_event(&event).await.map_err(|error| MatrixError::unknown(format!("storage error: {error}")))?;
    }

    // ------------------------------------------------------------------
    // Step 10 — update current state if this is a state event
    // ------------------------------------------------------------------
    if let Some(sk) = state_key {
        storage
            .set_state_entry(room_id, type_, sk, &eid)
            .await
            .map_err(|e| MatrixError::unknown(format!("state update error: {e}")))?;
    }

    // ------------------------------------------------------------------
    // Step 11 — notify /sync long-pollers of the new stream position
    // ------------------------------------------------------------------
    if let Ok(pos) = storage.global_max_stream_position().await {
        // Ignore send errors: no subscribers is fine.
        let _ = state.events_tx().send(pos);
    }

    Ok(eid)
}
