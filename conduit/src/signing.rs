//! Matrix event signing and signature verification.
//!
//! Implements the server-server signing protocol described at:
//! <https://spec.matrix.org/latest/server-server-api/#signing-events>
//! <https://spec.matrix.org/latest/server-server-api/#checking-for-a-signature>
//!
//! # V0 scope note
//!
//! For now only `signatures` and `unsigned` are stripped before signing /
//! verifying (matching what [`crate::hashing::event_id`] does).  Full v11
//! redaction (per-event-type allowed content fields) is tracked separately
//! and must be implemented before federation interop.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::{Signature, Signer as _, VerifyingKey};
use thiserror::Error;

use crate::canonical_json::{CanonicalJsonError, to_canonical_bytes};
use crate::event::Event;
use crate::hashing::{HashingError, content_hash};
use crate::keys::ServerKey;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur while signing an event.
#[derive(Debug, Error)]
pub enum SigningError {
    /// Computing the content hash failed.
    #[error("content hash error: {0}")]
    Hashing(#[from] HashingError),

    /// Canonical JSON serialization failed.
    #[error("canonical JSON error: {0}")]
    CanonicalJson(#[from] CanonicalJsonError),

    /// `serde_json` serialization failed.
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

/// Errors that can occur while verifying an event signature.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Canonical JSON serialization failed.
    #[error("canonical JSON error: {0}")]
    CanonicalJson(#[from] CanonicalJsonError),

    /// `serde_json` serialization failed.
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    /// The base64-encoded signature could not be decoded.
    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// The signature bytes could not be interpreted as a valid Ed25519 signature.
    #[error("invalid signature bytes: {0}")]
    SignatureDecode(#[from] ed25519_dalek::SignatureError),

    /// The public key bytes were not a valid Ed25519 public key.
    #[error("invalid public key bytes: {0}")]
    InvalidPublicKey(ed25519_dalek::SignatureError),

    /// The Ed25519 signature did not verify.
    #[error("signature verification failed: {0}")]
    VerifyFailed(ed25519_dalek::SignatureError),

    /// A required signature was missing or could not be looked up.
    #[error("no valid signature found for server '{server_name}' with key '{key_id}'")]
    MissingSignature {
        server_name: String,
        key_id: String,
    },

    /// The key lookup closure returned `None` for this (server, key_id) pair.
    #[error("unknown key: server '{server_name}', key_id '{key_id}'")]
    UnknownKey {
        server_name: String,
        key_id: String,
    },

    /// The originating server (sender's server) had no valid signature at all.
    #[error("no valid signature from originating server '{server_name}'")]
    NoOriginatingServerSignature { server_name: String },

    /// The `signatures` field was not a JSON object.
    #[error("event signatures field is not an object")]
    SignaturesNotObject,

    /// The `sender` field does not contain a `:` separator to extract the server name.
    #[error("cannot parse server name from sender '{sender}'")]
    InvalidSender { sender: String },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the canonical JSON bytes that are signed / verified.
///
/// This is a clone of the event with `signatures` set to `{}` and
/// `unsigned` removed — identical to what [`crate::hashing::event_id`] uses.
fn signing_bytes(event: &Event) -> Result<Vec<u8>, SigningError> {
    let mut value = serde_json::to_value(event)?;
    if let Some(map) = value.as_object_mut() {
        map.insert("signatures".to_owned(), serde_json::json!({}));
        map.remove("unsigned");
    }
    Ok(to_canonical_bytes(&value)?)
}

/// Same as `signing_bytes` but returns a `VerifyError`.
fn signing_bytes_for_verify(event: &Event) -> Result<Vec<u8>, VerifyError> {
    let mut value = serde_json::to_value(event)?;
    if let Some(map) = value.as_object_mut() {
        map.insert("signatures".to_owned(), serde_json::json!({}));
        map.remove("unsigned");
    }
    Ok(to_canonical_bytes(&value)?)
}

/// Extract the server name from a Matrix user ID (`@user:server.name`).
fn server_name_from_sender(sender: &str) -> Result<&str, VerifyError> {
    sender
        .find(':')
        .map(|pos| &sender[pos + 1..])
        .ok_or_else(|| VerifyError::InvalidSender {
            sender: sender.to_owned(),
        })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Sign a Matrix event in-place.
///
/// Steps:
/// 1. Compute and set `event.hashes.sha256` via [`content_hash`].
/// 2. Build the canonical JSON signing bytes (clone with `signatures={}`,
///    `unsigned` removed).
/// 3. Sign with the server's Ed25519 key.
/// 4. Encode as standard base64 (no padding) and insert into
///    `event.signatures[server_name][key_id]`, preserving any pre-existing
///    signatures from other servers.
pub fn sign_event(
    event: &mut Event,
    server_key: &ServerKey,
    server_name: &str,
) -> Result<(), SigningError> {
    // Step 1 — content hash.
    let hash = content_hash(event)?;
    event.hashes = serde_json::json!({ "sha256": hash });

    // Step 2 — canonical JSON of (clone with signatures={}, unsigned removed).
    let bytes = signing_bytes(event)?;

    // Step 3 — sign.
    let signature = server_key.signing_key.sign(&bytes);
    let sig_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());

    // Step 4 — merge into event.signatures preserving existing entries.
    //
    // `event.signatures` starts as whatever JSON value it held (could be
    // `{}`, could have entries from other servers).  We treat it as an
    // object and insert/overwrite only the (server_name, key_id) slot.
    if !event.signatures.is_object() {
        event.signatures = serde_json::json!({});
    }
    let sigs = event.signatures.as_object_mut().expect("just ensured object");

    // Get or create the inner object for this server.
    let server_obj = sigs
        .entry(server_name.to_owned())
        .or_insert_with(|| serde_json::json!({}));

    if !server_obj.is_object() {
        *server_obj = serde_json::json!({});
    }
    server_obj
        .as_object_mut()
        .expect("just ensured object")
        .insert(server_key.key_id.clone(), serde_json::Value::String(sig_b64));

    Ok(())
}

/// Verify a single server's signature on a Matrix event.
///
/// Reads `event.signatures[server_name][key_id]`, decodes the base64
/// signature, rebuilds the canonical JSON signing bytes (same strip as
/// [`sign_event`]), and verifies with the provided Ed25519 public key bytes.
pub fn verify_event_signature(
    event: &Event,
    server_name: &str,
    key_id: &str,
    public_key_bytes: &[u8],
) -> Result<(), VerifyError> {
    // Extract the base64 signature.
    let sig_b64 = event
        .signatures
        .get(server_name)
        .and_then(|v| v.get(key_id))
        .and_then(|v| v.as_str())
        .ok_or_else(|| VerifyError::MissingSignature {
            server_name: server_name.to_owned(),
            key_id: key_id.to_owned(),
        })?;

    let sig_bytes = STANDARD_NO_PAD.decode(sig_b64)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ed25519_dalek::SignatureError::new())?;
    let signature = Signature::from_bytes(&sig_array);

    // Rebuild the signing bytes.
    let bytes = signing_bytes_for_verify(event)?;

    // Build the verifying key and verify.
    let pub_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidPublicKey(ed25519_dalek::SignatureError::new()))?;
    let verifying_key =
        VerifyingKey::from_bytes(&pub_array).map_err(VerifyError::InvalidPublicKey)?;

    verifying_key
        .verify_strict(&bytes, &signature)
        .map_err(VerifyError::VerifyFailed)?;

    Ok(())
}

/// Verify that a Matrix event has at least one valid signature from its
/// originating server (the server part of `event.sender`).
///
/// `key_lookup(server_name, key_id)` should return the raw 32-byte Ed25519
/// public key for that (server, key) pair, or `None` if the key is unknown.
///
/// All signatures in `event.signatures` are attempted in order. Signatures
/// from non-originating servers are bonus checks — they are verified if the
/// key is available but are not required. If `key_lookup` returns `None` for
/// a (server, key_id) pair, that slot is recorded as `UnknownKey` but does
/// not immediately fail the call.
///
/// The function succeeds if **at least one** valid signature was found for
/// the originating server. If the originating server appears in
/// `event.signatures` but every key lookup returned `None`, the last
/// `UnknownKey` error is returned. If no entry exists for the originating
/// server at all, `NoOriginatingServerSignature` is returned.
pub fn verify_event<F>(event: &Event, key_lookup: F) -> Result<(), VerifyError>
where
    F: Fn(&str, &str) -> Option<Vec<u8>>,
{
    let originating_server = server_name_from_sender(&event.sender)?;

    let sigs_obj = event
        .signatures
        .as_object()
        .ok_or(VerifyError::SignaturesNotObject)?;

    // Rebuild signing bytes once — shared across all verification attempts.
    let bytes = signing_bytes_for_verify(event)?;

    let mut originating_server_found = false;
    let mut last_originating_error: Option<VerifyError> = None;

    for (srv, key_map) in sigs_obj {
        let is_originating = srv == originating_server;
        if is_originating {
            originating_server_found = true;
        }

        let Some(key_map_obj) = key_map.as_object() else {
            continue;
        };

        for (kid, sig_val) in key_map_obj {
            let Some(pub_bytes) = key_lookup(srv, kid) else {
                if is_originating {
                    last_originating_error = Some(VerifyError::UnknownKey {
                        server_name: srv.clone(),
                        key_id: kid.clone(),
                    });
                }
                continue;
            };

            // Attempt verification.
            let result = verify_with_bytes(&bytes, sig_val, &pub_bytes);
            match result {
                Ok(()) => {
                    if is_originating {
                        // At least one valid sig from the originating server — success.
                        return Ok(());
                    }
                    // Non-originating server — bonus, keep going.
                }
                Err(e) => {
                    if is_originating {
                        last_originating_error = Some(e);
                    }
                    // Non-originating failures are silently ignored.
                }
            }
        }
    }

    if !originating_server_found {
        return Err(VerifyError::NoOriginatingServerSignature {
            server_name: originating_server.to_owned(),
        });
    }

    // Originating server was found in signatures but no valid sig won.
    Err(last_originating_error.unwrap_or(VerifyError::NoOriginatingServerSignature {
        server_name: originating_server.to_owned(),
    }))
}

/// Inner helper: verify `sig_val` (a JSON string holding base64 sig) against
/// pre-computed `bytes` using `pub_bytes`.
fn verify_with_bytes(
    bytes: &[u8],
    sig_val: &serde_json::Value,
    pub_bytes: &[u8],
) -> Result<(), VerifyError> {
    let sig_b64 = sig_val.as_str().ok_or_else(|| VerifyError::MissingSignature {
        server_name: String::new(),
        key_id: String::new(),
    })?;

    let sig_bytes = STANDARD_NO_PAD.decode(sig_b64)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ed25519_dalek::SignatureError::new())?;
    let signature = Signature::from_bytes(&sig_array);

    let pub_array: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidPublicKey(ed25519_dalek::SignatureError::new()))?;
    let verifying_key =
        VerifyingKey::from_bytes(&pub_array).map_err(VerifyError::InvalidPublicKey)?;

    verifying_key
        .verify_strict(bytes, &signature)
        .map_err(VerifyError::VerifyFailed)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_server_key;
    use serde_json::json;

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
            hashes: json!({}),
            signatures: json!({}),
            depth: 42,
            unsigned: None,
        }
    }

    /// sign_event followed by verify_event_signature with matching public key succeeds.
    #[test]
    fn sign_then_verify_roundtrip() {
        let server_key = generate_server_key();
        let pub_bytes = crate::keys::public_bytes(&server_key);
        let mut event = make_event();

        sign_event(&mut event, &server_key, "example.org").expect("sign_event failed");

        verify_event_signature(&event, "example.org", &server_key.key_id, &pub_bytes)
            .expect("verify_event_signature failed");
    }

    /// Mutating event content after signing must break verification.
    #[test]
    fn tamper_content_breaks_verify() {
        let server_key = generate_server_key();
        let pub_bytes = crate::keys::public_bytes(&server_key);
        let mut event = make_event();

        sign_event(&mut event, &server_key, "example.org").expect("sign_event failed");

        // Tamper with content.
        event.content = json!({ "msgtype": "m.text", "body": "TAMPERED" });

        let result = verify_event_signature(&event, "example.org", &server_key.key_id, &pub_bytes);
        assert!(
            result.is_err(),
            "verification should fail after content tampering"
        );
    }

    /// Verifying with the wrong public key must fail.
    #[test]
    fn wrong_public_key_breaks_verify() {
        let key_a = generate_server_key();
        let key_b = generate_server_key();
        let pub_bytes_b = crate::keys::public_bytes(&key_b);
        let mut event = make_event();

        sign_event(&mut event, &key_a, "example.org").expect("sign_event failed");

        // Verify with key_b's public bytes — must fail.
        let result = verify_event_signature(&event, "example.org", &key_a.key_id, &pub_bytes_b);
        assert!(
            result.is_err(),
            "verification should fail with wrong public key"
        );
    }

    /// verify_event with a closure returning the correct key for sender's server succeeds.
    #[test]
    fn verify_event_high_level_ok() {
        let server_key = generate_server_key();
        let pub_bytes = crate::keys::public_bytes(&server_key);
        let key_id = server_key.key_id.clone();
        let mut event = make_event();

        sign_event(&mut event, &server_key, "example.org").expect("sign_event failed");

        let result = verify_event(&event, |srv, kid| {
            if srv == "example.org" && kid == key_id {
                Some(pub_bytes.clone())
            } else {
                None
            }
        });
        result.expect("verify_event should succeed");
    }

    /// verify_event where key_lookup returns None for sender's server fails with UnknownKey.
    #[test]
    fn verify_event_unknown_key() {
        let server_key = generate_server_key();
        let mut event = make_event();

        sign_event(&mut event, &server_key, "example.org").expect("sign_event failed");

        let result = verify_event(&event, |_srv, _kid| None);
        assert!(
            matches!(result, Err(VerifyError::UnknownKey { .. })),
            "expected UnknownKey error, got: {:?}",
            result
        );
    }

    /// Pre-existing signatures from other servers are preserved after sign_event.
    #[test]
    fn sign_preserves_other_signatures() {
        let server_key = generate_server_key();
        let mut event = make_event();

        // Pre-populate a signature from another server.
        event.signatures = json!({
            "other.org": {
                "ed25519:abc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
        });

        sign_event(&mut event, &server_key, "example.org").expect("sign_event failed");

        // The other.org entry must still be present.
        assert!(
            event.signatures.get("other.org").is_some(),
            "other.org signature was lost after signing"
        );
        assert!(
            event.signatures.get("other.org")
                .and_then(|v| v.get("ed25519:abc"))
                .is_some(),
            "other.org key entry was lost after signing"
        );

        // And our own signature must also be present.
        assert!(
            event.signatures.get("example.org").is_some(),
            "example.org signature not added"
        );
    }
}
