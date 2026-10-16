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
use conduit::room::RoomEventSender;
use conduit::signing::sign_authored_for_version;
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
        state.federation_queue(),
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

/// Key under which a room-version-1 or 2 event keeps the JSON that was signed.
/// Client responses omit extensions, so this stays off the client wire.
pub(crate) const LEGACY_WIRE: &str = conduit::event::LEGACY_EVENT_DOCUMENT;

/// An event signed for one room version.
pub(crate) struct SignedDocument {
    pub event_id: String,
    pub document: Value,
}

/// Sign `body` with the rules of `version`.
///
/// Versions 1 and 2 keep `event_id` and the tuple form of `auth_events` and
/// `prev_events` on `document`. Versions 3 and later return the PDU without
/// `event_id`; the id is the version's reference hash.
pub(crate) fn sign_for_room_version(
    version: u32,
    mut body: Value,
    server_key: &conduit::keys::ServerKey,
    server_name: &str,
) -> Result<SignedDocument, String> {
    if version < 3 {
        let object = body.as_object_mut().ok_or("event is not an object")?;
        object.entry("origin".to_owned()).or_insert_with(|| serde_json::json!(server_name));
        if object.get("event_id").and_then(Value::as_str).unwrap_or("").is_empty() {
            let event_id = format!("${}:{}", uuid::Uuid::new_v4().simple(), server_name);
            object.insert("event_id".into(), serde_json::json!(event_id));
        }
        let event_id = body.get("event_id").and_then(Value::as_str).unwrap_or("").to_owned();
        crate::federation::spec_v119::seal_v1_event(&mut body, server_key, server_name)
            .map_err(|_| "v1 signing failed".to_owned())?;
        return Ok(SignedDocument { event_id, document: body });
    }
    if version < 11 {
        if let Some(object) = body.as_object_mut() {
            object.entry("origin".to_owned()).or_insert_with(|| serde_json::json!(server_name));
        }
    }
    let mut pdu: Pdu = serde_json::from_value(body).map_err(|error| error.to_string())?;
    sign_authored_for_version(&mut pdu, version, server_key, server_name).map_err(|error| error.to_string())?;
    let event_id = conduit::room_version::event_id_for(&pdu, version)
        .map_err(|error| format!("{error:?}"))?
        .ok_or_else(|| "room version has no reference hash".to_owned())?;
    let document = serde_json::to_value(&pdu).map_err(|error| error.to_string())?;
    Ok(SignedDocument { event_id, document })
}

async fn legacy_refs(storage: &dyn conduit::storage::Storage, ids: &[String]) -> Result<Vec<Value>, String> {
    let mut refs = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(event) = storage.get_event(id).await.map_err(|error| error.to_string())? else {
            return Err(format!("missing event {id}"));
        };
        let Some(raw) = event.extensions.get(LEGACY_WIRE).and_then(Value::as_str) else {
            return Err(format!("event {id} has no room-version-1 document"));
        };
        let document: Value = serde_json::from_str(raw).map_err(|error| error.to_string())?;
        let hash = crate::federation::spec_v119::v1_reference_hash(&document)
            .map_err(|_| format!("event {id} has no reference hash"))?;
        refs.push(serde_json::json!([id, {"sha256": hash}]));
    }
    Ok(refs)
}

fn signing_failure(error: String) -> (StatusCode, Json<MatrixError>) {
    if error.contains("event too large") {
        MatrixError::too_large("event exceeds the 65536-byte PDU limit")
    } else {
        MatrixError::unknown(format!("signing error: {error}"))
    }
}

/// Sign and store one locally authored event. Callers that have an account
/// profile pass content through [`super::profile::with_join_profile`] first.
pub async fn author_event(
    storage: &dyn conduit::storage::Storage,
    server_key: &conduit::keys::ServerKey,
    server_name: &str,
    events_tx: &tokio::sync::broadcast::Sender<i64>,
    federation: Option<&Arc<crate::federation::Client>>,
    queue: Option<&Arc<crate::federation::Queue>>,
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
    // A remote invite is co-signed before it is queued. Fan-out of the
    // locally signed copy would deliver an event the invitee has not signed.
    let defer_remote_invite = type_ == "m.room.member"
        && content.get("membership").and_then(Value::as_str) == Some("invite")
        && state_key
            .and_then(conduit::signing::server_of_user_id)
            .is_some_and(|server| server != server_name);

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
    // The create event is not stored yet, so its version comes from its content.
    // A later event with no create event at all still uses room version 11.
    let room_version = if event.event_type == "m.room.create" {
        conduit::room_version::version_of_content(&event.content)
    } else {
        match storage.get_state_entry(room_id, "m.room.create", "").await {
            Ok(Some(create)) => conduit::room_version::version_of_content(&create.content),
            _ => 11,
        }
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
    event.auth_events = auth_events_ids.clone();

    // ------------------------------------------------------------------
    // Step 5–7 — sign and id with this room's version
    // ------------------------------------------------------------------
    let eid = if room_version < 3 {
        let auth_events = legacy_refs(storage, &auth_events_ids).await.map_err(signing_failure)?;
        let prev_events = legacy_refs(storage, &event.prev_events).await.map_err(signing_failure)?;
        let mut body = serde_json::json!({
            "auth_events": auth_events,
            "content": event.content,
            "depth": event.depth,
            "origin_server_ts": event.origin_server_ts,
            "prev_events": prev_events,
            "room_id": event.room_id,
            "sender": event.sender,
            "type": event.event_type,
        });
        if let Some(state_key) = &event.state_key {
            body["state_key"] = serde_json::json!(state_key);
        }
        let signed = sign_for_room_version(room_version, body, server_key, server_name).map_err(signing_failure)?;
        let decoded = conduit::wire::decode_pdu_for_version(signed.document.clone(), 1, now_ms()).map_err(|error| {
            MatrixError::unknown(format!("v1 event does not decode: {error}"))
        })?;
        let mut pdu = decoded.pdu;
        pdu.extensions.insert(LEGACY_WIRE.to_owned(), serde_json::json!(signed.document.to_string()));
        event.pdu = pdu;
        event.event_id = signed.event_id.clone();
        signed.event_id
    } else {
        let template = serde_json::to_value(&event.pdu).map_err(|error| MatrixError::unknown(format!("signing error: {error}")))?;
        let signed = sign_for_room_version(room_version, template, server_key, server_name).map_err(signing_failure)?;
        event.pdu = serde_json::from_value(signed.document).map_err(|error| MatrixError::unknown(format!("signing error: {error}")))?;
        event.event_id = signed.event_id.clone();
        signed.event_id
    };

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

    if !defer_remote_invite {
        fan_out_authored(storage, server_name, queue, room_id, &eid).await;
    }

    Ok(eid)
}

/// Queue one stored PDU to every other server joined to the room.
/// Soft-failed and rejected events stay local. `CONDUIT_FEDERATION=0` and a
/// missing queue (library stubs) send nothing.
pub(crate) async fn fan_out_authored(
    storage: &dyn conduit::storage::Storage,
    server_name: &str,
    queue: Option<&Arc<crate::federation::Queue>>,
    room_id: &str,
    event_id: &str,
) {
    if std::env::var("CONDUIT_FEDERATION").ok().as_deref() == Some("0") {
        return;
    }
    let Some(queue) = queue else { return };
    match storage.event_disposition(event_id).await {
        Ok(Some(kind)) if kind == "soft_failed" || kind == "rejected" => return,
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(%error, "federation fan-out skipped: disposition");
            return;
        }
    }
    let wire = match storage.get_wire_pdu(event_id).await {
        Ok(Some(wire)) => wire,
        Ok(None) => {
            tracing::warn!(event_id, "federation fan-out skipped: PDU does not reproduce its event id");
            return;
        }
        Err(error) => {
            tracing::warn!(%error, "federation fan-out skipped: event missing");
            return;
        }
    };
    let dests = match storage.joined_remote_servers(room_id, server_name).await {
        Ok(dests) => dests,
        Err(error) => {
            tracing::warn!(%error, "federation fan-out skipped: destinations");
            return;
        }
    };
    for dest in dests {
        match conduit::server_acl::server_allowed_by_room(storage, room_id, &dest).await {
            Ok(true) => queue.enqueue(&dest, vec![wire.clone()], vec![]).await,
            Ok(false) => {}
            Err(error) => tracing::warn!(%error, dest, "federation fan-out skipped a destination"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sign_for_room_version;
    use conduit::keys::generate_server_key;
    use serde_json::json;

    #[test]
    fn signed_events_follow_the_room_version() {
        let key = generate_server_key();
        let legacy = json!({
            "auth_events": [["$create:example.org", {"sha256": "abc"}]],
            "content": {"membership": "invite"},
            "depth": 2,
            "origin_server_ts": 1_700_000_000_000u64,
            "prev_events": [["$prev:example.org", {"sha256": "def"}]],
            "room_id": "!room:example.org",
            "sender": "@alice:example.org",
            "state_key": "@bob:example.org",
            "type": "m.room.member",
        });
        for version in [1u32, 2] {
            let signed = sign_for_room_version(version, legacy.clone(), &key, "example.org").unwrap();
            let id = signed.document["event_id"].as_str().unwrap();
            assert_eq!(id, signed.event_id);
            assert!(id.starts_with('$') && id.contains(':'), "{id}");
            assert!(signed.document["auth_events"][0].is_array(), "{version}");
            assert!(signed.document["prev_events"][0].is_array(), "{version}");
            assert!(signed.document["signatures"].is_object());
        }

        let modern = json!({
            "auth_events": [],
            "content": {"body": "hi"},
            "depth": 1,
            "origin_server_ts": 5,
            "prev_events": [],
            "room_id": "!room:example.org",
            "sender": "@alice:example.org",
            "type": "m.room.message",
        });
        let v3 = sign_for_room_version(3, modern.clone(), &key, "example.org").unwrap();
        assert!(v3.document.get("event_id").is_none());
        let pdu3: conduit::event::Pdu = serde_json::from_value(v3.document).unwrap();
        let expected3 = conduit::room_version::event_id_for(&pdu3, 3).ok().flatten().unwrap();
        assert_eq!(v3.event_id, expected3);
        assert!(!expected3[1..].contains('_') && !expected3[1..].contains('-'), "{expected3}");
        assert_ne!(expected3, conduit::hashing::event_id(&pdu3).unwrap());

        let v12 = sign_for_room_version(12, modern, &key, "example.org").unwrap();
        assert!(v12.document.get("event_id").is_none());
        let pdu12: conduit::event::Pdu = serde_json::from_value(v12.document).unwrap();
        assert_eq!(v12.event_id, conduit::hashing::event_id(&pdu12).unwrap());
        assert_eq!(v12.event_id, conduit::room_version::event_id_for(&pdu12, 12).ok().flatten().unwrap());
    }
}
