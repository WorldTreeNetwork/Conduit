//! PDU content hashing and event ID derivation.
//!
//! Two operations per the Matrix Server-Server API spec:
//!
//! - **Content hash** (`hashes.sha256`): strip `hashes`, `signatures`, `unsigned`
//!   from the PDU, canonical-JSON-encode, sha256, standard-base64 (no padding).
//!   <https://spec.matrix.org/latest/server-server-api/#calculating-the-content-hash-for-a-pdu>
//!
//! - **Reference hash / event ID** (room v11): strip `signatures`, `unsigned`
//!   from the PDU, canonical-JSON-encode, sha256, URL-safe-base64 (no padding),
//!   then prefix with `$`.
//!   <https://spec.matrix.org/latest/server-server-api/#calculating-the-reference-hash-for-a-pdu>
//!   <https://spec.matrix.org/latest/rooms/v11/>

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonical_json::{CanonicalJsonError, to_canonical_bytes};
use crate::event::Event;

/// Errors from the hashing operations.
#[derive(Debug, Error)]
pub enum HashingError {
    /// The event could not be serialized to a `serde_json::Value`.
    #[error("serde_json serialization error: {0}")]
    Serialize(#[from] serde_json::Error),

    /// Canonical JSON encoding failed.
    #[error("canonical JSON error: {0}")]
    CanonicalJson(#[from] CanonicalJsonError),
}

/// Remove `fields` (by name) from the top-level object of `value`.
///
/// Silently ignores any field that does not exist.
fn strip_fields(value: &mut serde_json::Value, fields: &[&str]) {
    if let Some(map) = value.as_object_mut() {
        for &field in fields {
            map.remove(field);
        }
    }
}

/// Compute `hashes.sha256` for a PDU.
///
/// Strips `hashes`, `signatures`, and `unsigned` from a copy of the event,
/// serializes to canonical JSON, and returns the SHA-256 digest encoded as
/// **standard base64 without padding**.
pub fn content_hash(event: &Event) -> Result<String, HashingError> {
    let mut value = serde_json::to_value(event)?;
    strip_fields(&mut value, &["hashes", "signatures", "unsigned"]);
    let canonical = to_canonical_bytes(&value)?;
    let digest = Sha256::digest(&canonical);
    Ok(STANDARD_NO_PAD.encode(digest))
}

/// Derive the event ID (reference hash) for a room-v11 PDU.
///
/// Strips `signatures` and `unsigned` from a copy of the event (NOT `hashes`),
/// serializes to canonical JSON, and returns `$` followed by the SHA-256
/// digest encoded as **URL-safe base64 without padding**.
pub fn event_id(event: &Event) -> Result<String, HashingError> {
    let mut value = serde_json::to_value(event)?;
    strip_fields(&mut value, &["signatures", "unsigned"]);
    let canonical = to_canonical_bytes(&value)?;
    let digest = Sha256::digest(&canonical);
    Ok(format!("${}", URL_SAFE_NO_PAD.encode(digest)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a minimal valid Event for testing.
    fn make_event() -> Event {
        Event {
            event_id: "$test_event_id".to_string(),
            room_id: "!room:example.org".to_string(),
            sender: "@user:example.org".to_string(),
            event_type: "m.room.message".to_string(),
            content: json!({ "msgtype": "m.text", "body": "Hello" }),
            state_key: None,
            origin_server_ts: 1_000_000,
            auth_events: vec!["$auth1".to_string()],
            prev_events: vec!["$prev1".to_string()],
            hashes: json!({ "sha256": "AAAA" }),
            signatures: json!({ "example.org": { "ed25519:key1": "BBBB" } }),
            depth: 42,
            unsigned: Some(json!({ "age": 100 })),
        }
    }

    /// Build the same event but with default (empty) hashes, signatures, and unsigned.
    fn make_event_no_extras() -> Event {
        Event {
            hashes: json!({}),
            signatures: json!({}),
            unsigned: None,
            ..make_event()
        }
    }

    /// Build the same event but with default (empty) signatures and unsigned.
    fn make_event_no_sig_unsigned() -> Event {
        Event {
            signatures: json!({}),
            unsigned: None,
            ..make_event()
        }
    }

    /// content_hash must be identical regardless of `hashes`, `signatures`, `unsigned` values.
    #[test]
    fn content_hash_strips_three_fields() {
        let with_extras = content_hash(&make_event()).unwrap();
        let without_extras = content_hash(&make_event_no_extras()).unwrap();
        assert_eq!(
            with_extras, without_extras,
            "content_hash must not depend on hashes/signatures/unsigned"
        );
    }

    /// event_id must be identical regardless of `signatures` and `unsigned` values,
    /// but MUST differ when `hashes` differs (since hashes is NOT stripped).
    #[test]
    fn event_id_strips_two_fields() {
        let with_sig = event_id(&make_event()).unwrap();
        let without_sig = event_id(&make_event_no_sig_unsigned()).unwrap();
        assert_eq!(
            with_sig, without_sig,
            "event_id must not depend on signatures/unsigned"
        );

        // Sanity: changing `hashes` (which is NOT stripped) must change the event_id.
        let mut different_hashes = make_event();
        different_hashes.hashes = json!({ "sha256": "ZZZZ" });
        let with_different_hashes = event_id(&different_hashes).unwrap();
        assert_ne!(
            with_sig, with_different_hashes,
            "event_id must depend on hashes (not stripped)"
        );
    }

    /// event_id must start with `$`.
    #[test]
    fn event_id_starts_with_dollar() {
        let id = event_id(&make_event()).unwrap();
        assert!(id.starts_with('$'), "event_id must start with '$', got: {id}");
    }

    /// The suffix of event_id (after `$`) must be URL-safe base64:
    /// no `+` or `/` characters.
    #[test]
    fn event_id_is_url_safe_base64() {
        let id = event_id(&make_event()).unwrap();
        let suffix = &id[1..]; // strip leading `$`
        assert!(
            !suffix.contains('+') && !suffix.contains('/'),
            "event_id suffix must be URL-safe base64 (no '+' or '/'), got: {suffix}"
        );
    }

    /// content_hash uses standard base64: may contain `+` or `/`, but NOT `_` or `-`.
    #[test]
    fn content_hash_is_standard_base64() {
        // Run many events to increase chance of hitting all alphabet chars.
        // Our single test event may already demonstrate this; just check it.
        let hash = content_hash(&make_event()).unwrap();
        assert!(
            !hash.contains('_') && !hash.contains('-'),
            "content_hash must be standard base64 (no '_' or '-'), got: {hash}"
        );
    }

    /// Same event → same results across two calls (determinism).
    #[test]
    fn deterministic() {
        let event = make_event();
        assert_eq!(content_hash(&event).unwrap(), content_hash(&event).unwrap());
        assert_eq!(event_id(&event).unwrap(), event_id(&event).unwrap());
    }

    /// content_hash and event_id must produce DIFFERENT hashes because they
    /// strip different fields and use different base64 alphabets.
    #[test]
    fn content_hash_and_event_id_differ() {
        let event = make_event_no_extras(); // hashes={}, signatures={}, unsigned=None
        let ch = content_hash(&event).unwrap();
        let eid = event_id(&event).unwrap();
        // event_id starts with $; strip it before comparing
        assert_ne!(ch, &eid[1..], "content_hash and event_id reference hash must differ");
    }
}
