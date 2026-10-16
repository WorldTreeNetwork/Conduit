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
use std::sync::Arc;
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
                // M_FORBIDDEN instead of a generic 500 (conduit-29w). Size
                // rejections stay M_TOO_LARGE for the same reason.
                if status == StatusCode::FORBIDDEN {
                    conduit::Error::Forbidden(json_err.0.error.clone())
                } else if status == StatusCode::PAYLOAD_TOO_LARGE {
                    conduit::Error::TooLarge(json_err.0.error.clone())
                } else {
                    conduit::Error::Storage(json_err.0.error.clone())
                }
            })
    }

    async fn bind_room_alias(&self, creator: &str, alias: &str, room_id: &str) -> ConduitResult<()> {
        self.0.storage().upsert_alias(alias, room_id, creator).await
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

/// Self-joins into `restricted` / `knock_restricted` rooms carry
/// `join_authorised_via_users_server` when an allow condition matches.
/// An invite, or a room that is not restricted, is left unchanged.
async fn apply_restricted_join(
    storage: &dyn conduit::storage::Storage,
    server_name: &str,
    sender: &str,
    room_id: &str,
    type_: &str,
    state_key: Option<&str>,
    mut content: Value,
) -> Result<Value, (StatusCode, Json<MatrixError>)> {
    if type_ != "m.room.member" || state_key != Some(sender) {
        return Ok(content);
    }
    if content.get("membership").and_then(Value::as_str) != Some("join") {
        return Ok(content);
    }
    use super::room_membership::{decide_restricted_join, RestrictedDecision};
    match decide_restricted_join(storage, server_name, sender, room_id).await {
        Ok(RestrictedDecision::Open) => Ok(content),
        Ok(RestrictedDecision::Authorise(via)) => {
            content["join_authorised_via_users_server"] = serde_json::json!(via);
            Ok(content)
        }
        Ok(RestrictedDecision::UnableToGrant) => {
            Err(MatrixError::forbidden("No resident user can authorise this join"))
        }
        Ok(RestrictedDecision::UnableToAuthorise | RestrictedDecision::Forbidden) => {
            Err(MatrixError::forbidden("You do not meet the requirements to join this room"))
        }
        Err(error) => Err(MatrixError::unknown(format!("storage error: {error}"))),
    }
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
    // Own joins carry the member's profile (spec §Profiles, conduit-y99.38).
    let content = super::profile::with_join_profile(state, sender, type_, state_key, content).await;
    let revoke = state_key == Some("") && type_ == "m.room.guest_access";
    let revoke_content = revoke.then(|| content.clone());
    let event_id = author_event(
        state.storage().as_ref(),
        &state.server_key(),
        state.server_name(),
        state.events_tx(),
        state.federation_client(),
        sender,
        room_id,
        type_,
        state_key,
        content,
        transaction_key,
    ).await?;
    if let Some(content) = revoke_content {
        super::guest_access::after_state_event(
            state.storage().as_ref(),
            state.server_name(),
            &RoomEventSenderWrapper(state),
            room_id,
            type_,
            &content,
        ).await;
    }
    Ok(event_id)
}

/// Sign and store one locally authored event. Callers that have an account
/// profile pass content through [`super::profile::with_join_profile`] first.
pub async fn author_event(
    storage: &dyn conduit::storage::Storage,
    server_key: &conduit::keys::ServerKey,
    server_name: &str,
    events_tx: &tokio::sync::broadcast::Sender<i64>,
    federation: Option<&Arc<crate::federation::Client>>,
    sender: &str,
    room_id: &str,
    type_: &str,
    state_key: Option<&str>,
    content: Value,
    transaction_key: Option<&conduit::storage::TransactionKey>,
) -> Result<String, (StatusCode, Json<MatrixError>)> {
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
            let mut accepted = Vec::new();
            for event in all {
                if storage.event_disposition(&event.event_id).await.map_err(|e| {
                    MatrixError::unknown(format!("storage error: {e}"))
                })?.is_none() {
                    accepted.push(event);
                }
            }
            let latest = accepted.into_iter().max_by_key(|e| e.depth);
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
    // Restricted joins name a local authoriser before auth events are chosen.
    // ------------------------------------------------------------------
    let content = apply_restricted_join(storage, server_name, sender, room_id, type_, state_key, content).await?;

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
    let room_version = match storage.get_state_entry(room_id, "m.room.create", "").await {
        Ok(Some(create)) => conduit::room_version::version_of_content(&create.content),
        _ => 11,
    };
    let mut auth_events_ids: Vec<String> = Vec::new();
    let mut auth_state: StateMap<Event> = HashMap::new();

    for (ev_type, sk) in &required_keys {
        if let Ok(Some(state_ev)) = storage.get_state_entry(room_id, ev_type, sk).await {
            // Auth rules still read create. Version 12 must not cite it.
            if ev_type != "m.room.create" || conduit::room_version::cites_room_create(room_version) {
                auth_events_ids.push(state_ev.event_id.clone());
            }
            auth_state.insert((ev_type.clone(), sk.clone()), state_ev);
        }
    }
    event.auth_events = auth_events_ids;

    // ------------------------------------------------------------------
    // Step 5 & 6 — content hash + sign (sign_event sets hashes internally)
    // ------------------------------------------------------------------
    sign_authored(&mut event.pdu, server_key, server_name).map_err(|e| match e {
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

    // A room with an enabled policy server must have that server's
    // signature on the event before the event is stored or sent.
    crate::federation::policy::ensure_policy_signature(storage, federation, &mut event).await?;

    // ------------------------------------------------------------------
    // Step 9 — persist
    // ------------------------------------------------------------------
    if let Some(key) = transaction_key {
        let (event_id, inserted) = storage.put_event_once(key, &event).await
            .map_err(|error| MatrixError::unknown(format!("storage error: {error}")))?;
        if !inserted { return Ok(event_id); }
    } else if event.state_key.is_some() {
        // The event row and its current-state pointer commit together.
        storage.publish_event(&event).await.map_err(|error| MatrixError::unknown(format!("storage error: {error}")))?;
    } else {
        storage.put_event(&event).await.map_err(|error| MatrixError::unknown(format!("storage error: {error}")))?;
    }

    // ------------------------------------------------------------------
    // Step 11 — notify /sync long-pollers of the new stream position
    // ------------------------------------------------------------------
    if let Ok(pos) = storage.global_max_stream_position().await {
        // Ignore send errors: no subscribers is fine.
        let _ = events_tx.send(pos);
    }

    Ok(eid)
}
