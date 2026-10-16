//! PDU content hashing and event ID derivation.
//!
//! Two operations per the Matrix Server-Server API spec:
//!
//! - **Content hash** (`hashes.sha256`): strip `hashes`, `signatures`, `unsigned`
//!   from the PDU, canonical-JSON-encode, sha256, standard-base64 (no padding).
//!   <https://spec.matrix.org/v1.19/server-server-api/#calculating-the-content-hash-for-an-event>
//!
//! - **Reference hash / event ID** (room v11): redact, strip `signatures`,
//!   `unsigned`, then canonical-JSON-encode, sha256, URL-safe-base64 (no padding),
//!   then prefix with `$`.
//!   <https://spec.matrix.org/v1.19/server-server-api/#calculating-the-reference-hash-for-an-event>
//!   <https://spec.matrix.org/v1.19/rooms/v11/>
//!
//! Both operate on [`Pdu`] only: a local event ID can never affect them.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonical_json::{to_canonical_bytes, CanonicalJsonError};
use crate::event::Pdu;
use crate::redaction::redact;

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
fn strip_fields(value: &mut serde_json::Value, fields: &[&str]) {
    if let Some(map) = value.as_object_mut() {
        for &field in fields {
            map.remove(field);
        }
    }
}

/// Compute `hashes.sha256` for a PDU.
///
/// Hashes the unredacted PDU, extensions included. Strips `hashes` and
/// `signatures` (a [`Pdu`] never holds `unsigned`), serializes to canonical
/// JSON, and returns the SHA-256 digest encoded as **standard base64 without
/// padding**. Unlike Synapse, `age_ts`, `outlier` and `destinations` are not
/// stripped: the spec removes only `unsigned`, `signatures` and `hashes`.
pub fn content_hash(pdu: &Pdu) -> Result<String, HashingError> {
    let mut value = serde_json::to_value(pdu)?;
    strip_fields(&mut value, &["hashes", "signatures", "unsigned"]);
    let canonical = to_canonical_bytes(&value)?;
    let digest = Sha256::digest(&canonical);
    Ok(STANDARD_NO_PAD.encode(digest))
}

/// Standard Base64, padding optional. Encoding in this crate stays unpadded.
/// <https://spec.matrix.org/v1.19/appendices/#unpadded-base64>
pub fn decode_unpadded_base64(input: impl AsRef<[u8]>) -> Result<Vec<u8>, base64::DecodeError> {
    let decoder = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    decoder.decode(input)
}

/// Check the transmitted content hash. A mismatch indicates that the received
/// event must be redacted after its signature is verified, rather than rejected.
/// Compare decoded bytes, accepting both padded and unpadded base64.
pub fn content_hash_matches(pdu: &Pdu) -> Result<bool, HashingError> {
    let Some(expected) = pdu.hashes.get("sha256").and_then(serde_json::Value::as_str) else {
        return Ok(false);
    };
    let Ok(expected) = decode_unpadded_base64(expected) else {
        return Ok(false);
    };
    let actual = STANDARD_NO_PAD
        .decode(content_hash(pdu)?)
        .expect("generated SHA-256 base64");
    Ok(expected == actual)
}

/// Derive the event ID (reference hash) for a room-v11 PDU.
///
/// Redacts (clearing extensions), strips `signatures`, serializes to
/// canonical JSON, and returns `$` followed by the SHA-256 digest encoded as
/// **URL-safe base64 without padding**. `hashes` is kept.
pub fn event_id(pdu: &Pdu) -> Result<String, HashingError> {
    let redacted = redact(pdu);
    let mut value = serde_json::to_value(&redacted)?;
    strip_fields(&mut value, &["signatures", "unsigned"]);
    let canonical = to_canonical_bytes(&value)?;
    let digest = Sha256::digest(&canonical);
    Ok(format!("${}", URL_SAFE_NO_PAD.encode(digest)))
}

/// Alias of [`event_id`] under the spec's name.
pub fn reference_hash(pdu: &Pdu) -> Result<String, HashingError> {
    event_id(pdu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a minimal valid Pdu for testing.
    fn make_event() -> Pdu {
        Pdu {
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
            extensions: Default::default(),
        }
    }

    fn make_event_no_extras() -> Pdu {
        Pdu { hashes: json!({}), signatures: json!({}), ..make_event() }
    }

    fn make_event_no_sig() -> Pdu {
        Pdu { signatures: json!({}), ..make_event() }
    }

    /// content_hash must be identical regardless of `hashes` and `signatures`.
    #[test]
    fn content_hash_strips_hashes_and_signatures() {
        assert_eq!(content_hash(&make_event()).unwrap(), content_hash(&make_event_no_extras()).unwrap());
    }

    /// event_id ignores signatures but depends on hashes (which are not stripped).
    #[test]
    fn event_id_strips_signatures_only() {
        let with_sig = event_id(&make_event()).unwrap();
        assert_eq!(with_sig, event_id(&make_event_no_sig()).unwrap());
        let mut different_hashes = make_event();
        different_hashes.hashes = json!({ "sha256": "ZZZZ" });
        assert_ne!(with_sig, event_id(&different_hashes).unwrap());
    }

    #[test]
    fn extension_changes_content_hash_but_not_reference_hash() {
        let plain = make_event();
        let mut extended = make_event();
        extended.extensions.insert("org.example.x".into(), json!("y"));
        assert_ne!(content_hash(&plain).unwrap(), content_hash(&extended).unwrap());
        assert_eq!(event_id(&plain).unwrap(), event_id(&extended).unwrap());
    }

    #[test]
    fn synapse_internal_keys_are_hashed_per_spec() {
        // Synapse pops age_ts/outlier/destinations from the content hash; the
        // spec does not, and Conduit follows the spec (recorded divergence).
        let plain = make_event();
        for key in ["age_ts", "outlier", "destinations"] {
            let mut extended = make_event();
            extended.extensions.insert(key.into(), json!(1));
            assert_ne!(content_hash(&plain).unwrap(), content_hash(&extended).unwrap(), "{key}");
            assert_eq!(event_id(&plain).unwrap(), event_id(&extended).unwrap(), "{key}");
        }
    }

    #[test]
    fn event_id_is_dollar_prefixed_url_safe_base64() {
        let id = event_id(&make_event()).unwrap();
        assert!(id.starts_with('$'));
        assert!(!id[1..].contains('+') && !id[1..].contains('/') && id.len() == 44);
    }

    #[test]
    fn content_hash_is_standard_base64() {
        let hash = content_hash(&make_event()).unwrap();
        assert!(!hash.contains('_') && !hash.contains('-'));
        assert!(!hash.contains('='));
    }

    #[test]
    fn padded_content_hash_is_accepted() {
        let mut event = make_event_no_extras();
        let hash = content_hash(&event).unwrap();
        let mut padded = hash.clone();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }
        assert!(padded.ends_with('='));
        event.hashes = json!({ "sha256": padded });
        assert!(content_hash_matches(&event).unwrap());
        event.hashes = json!({ "sha256": hash });
        assert!(content_hash_matches(&event).unwrap());
    }

    #[test]
    fn deterministic_and_distinct() {
        let event = make_event_no_extras();
        assert_eq!(content_hash(&event).unwrap(), content_hash(&event).unwrap());
        assert_eq!(event_id(&event).unwrap(), event_id(&event).unwrap());
        assert_ne!(content_hash(&event).unwrap(), event_id(&event).unwrap()[1..]);
    }
}
