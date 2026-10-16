//! Matrix event signing and signature verification.
//!
//! <https://spec.matrix.org/v1.19/server-server-api/#signing-events>
//! <https://spec.matrix.org/v1.19/server-server-api/#validating-hashes-and-signatures-on-received-events>
//!
//! Signatures cover the v11 redacted PDU. Everything here takes [`Pdu`]: the
//! locally derived event ID is metadata and is never signed.
//!
//! - [`sign_authored`] is for PDUs this server authors: it sets
//!   `hashes.sha256` and signs.
//! - [`add_signature`] co-signs a foreign PDU without touching `hashes`, so
//!   the author's content hash and event ID survive byte-for-byte.
//! - [`check_received`] verifies the [required signers](signers) with keys
//!   that are eligible at the event's `origin_server_ts`, derives the ID, and
//!   redacts on a content-hash mismatch.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, VerifyingKey};
use thiserror::Error;

use serde_json::Value;

use crate::canonical_json::{to_canonical_bytes, CanonicalJsonError};
use crate::event::{Pdu, SignedBy};
use crate::hashing::{content_hash, content_hash_matches, HashingError};
use crate::keys::ServerKey;
use crate::redaction::redact;

/// The v11 PDU size limit, in canonical-JSON bytes.
pub const MAX_PDU_BYTES: usize = 65_536;
/// Authored PDUs keep this margin under [`MAX_PDU_BYTES`] so that `unsigned`
/// added in transit (Synapse counts `unsigned.age_ts`) cannot push our own
/// events over a peer's limit.
pub const AUTHORED_PDU_MARGIN: usize = 64;
/// The largest PDU [`sign_authored`] accepts.
pub const MAX_AUTHORED_PDU_BYTES: usize = MAX_PDU_BYTES - AUTHORED_PDU_MARGIN;

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

    /// The authored PDU exceeds [`MAX_AUTHORED_PDU_BYTES`].
    #[error("event too large: {size} bytes exceeds {limit}")]
    TooLarge { size: usize, limit: usize },
}

/// Errors that can occur while verifying an event signature.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Computing the received event's content hash failed.
    #[error("content hash error: {0}")]
    Hashing(#[from] HashingError),
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

    /// A required signature was missing.
    #[error("no signature for server '{server_name}' with key '{key_id}'")]
    MissingSignature { server_name: String, key_id: String },

    /// A required server has no signature made with a key that is eligible
    /// at the event's `origin_server_ts`.
    #[error("no eligible signature from required server '{server_name}'")]
    NoEligibleSignature { server_name: String },

    /// A signature made with an eligible key did not verify.
    #[error("invalid signature from '{server_name}' with key '{key_id}'")]
    InvalidSignature { server_name: String, key_id: String },

    /// The `signatures` field was not a JSON object.
    #[error("event signatures field is not an object")]
    SignaturesNotObject,

    /// A user ID (sender or authorising user) has no server name.
    #[error("cannot parse server name from user ID")]
    InvalidUserId,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Canonical JSON bytes that are signed / verified: the redacted PDU
/// without `signatures`. An empty signatures object would change the bytes.
fn signing_bytes(pdu: &Pdu) -> Result<Vec<u8>, CanonicalJsonError> {
    let mut value = serde_json::to_value(redact(pdu))?;
    if let Some(map) = value.as_object_mut() {
        map.remove("signatures");
        map.remove("unsigned");
    }
    to_canonical_bytes(&value)
}

/// The server name of a user ID (`@local:server`). `None` when malformed.
pub fn server_of_user_id(user_id: &str) -> Option<&str> {
    let rest = user_id.strip_prefix('@')?;
    let (_, server) = rest.split_once(':')?;
    (!server.is_empty()).then_some(server)
}

fn insert_signature(pdu: &mut Pdu, server_key: &ServerKey, server_name: &str) -> Result<(), SigningError> {
    let bytes = signing_bytes(pdu)?;
    let signature = server_key.signing_key.sign(&bytes);
    let sig_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());
    if !pdu.signatures.is_object() {
        pdu.signatures = serde_json::json!({});
    }
    let sigs = pdu.signatures.as_object_mut().expect("just ensured object");
    let server_obj = sigs.entry(server_name.to_owned()).or_insert_with(|| serde_json::json!({}));
    if !server_obj.is_object() {
        *server_obj = serde_json::json!({});
    }
    server_obj
        .as_object_mut()
        .expect("just ensured object")
        .insert(server_key.key_id.clone(), serde_json::Value::String(sig_b64));
    Ok(())
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Sign a PDU this server authors.
///
/// Sets `hashes.sha256` to the content hash, then signs the redacted bytes,
/// preserving any pre-existing signatures. Refuses a PDU whose signed
/// canonical size exceeds [`MAX_AUTHORED_PDU_BYTES`].
/// Sign a JSON object: canonical bytes without `signatures` or `unsigned`,
/// then put both back with this key's signature added.
///
/// <https://spec.matrix.org/v1.19/appendices/#signing-details>
pub fn sign_json(mut object: Value, server_key: &ServerKey, name: &str) -> Result<Value, SigningError> {
    let mut unsigned = None;
    let mut signatures = serde_json::json!({});
    if let Some(map) = object.as_object_mut() {
        if let Some(existing) = map.remove("signatures") {
            signatures = existing;
        }
        unsigned = map.remove("unsigned");
    }
    let bytes = to_canonical_bytes(&object)?;
    let signature = server_key.signing_key.sign(&bytes);
    if !signatures.is_object() {
        signatures = serde_json::json!({});
    }
    let entry = signatures
        .as_object_mut()
        .expect("object")
        .entry(name.to_owned())
        .or_insert_with(|| serde_json::json!({}));
    if !entry.is_object() {
        *entry = serde_json::json!({});
    }
    entry.as_object_mut().expect("object").insert(
        server_key.key_id.clone(),
        serde_json::Value::String(STANDARD_NO_PAD.encode(signature.to_bytes())),
    );
    object["signatures"] = signatures;
    if let Some(unsigned) = unsigned {
        object["unsigned"] = unsigned;
    }
    Ok(object)
}

pub fn sign_authored(pdu: &mut Pdu, server_key: &ServerKey, server_name: &str) -> Result<(), SigningError> {
    pdu.hashes = serde_json::json!({ "sha256": content_hash(pdu)? });
    insert_signature(pdu, server_key, server_name)?;
    let size = to_canonical_bytes(pdu)?.len();
    if size > MAX_AUTHORED_PDU_BYTES {
        return Err(SigningError::TooLarge { size, limit: MAX_AUTHORED_PDU_BYTES });
    }
    Ok(())
}

/// Co-sign a foreign PDU: add one signature over the redacted bytes and leave
/// `hashes` and every other field untouched.
pub fn add_signature(pdu: &mut Pdu, server_key: &ServerKey, server_name: &str) -> Result<(), SigningError> {
    insert_signature(pdu, server_key, server_name)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a single server's signature on a PDU with known key bytes.
pub fn verify_event_signature(
    pdu: &Pdu,
    server_name: &str,
    key_id: &str,
    public_key_bytes: &[u8],
) -> Result<(), VerifyError> {
    let sig_val = pdu
        .signatures
        .get(server_name)
        .and_then(|v| v.get(key_id))
        .ok_or_else(|| VerifyError::MissingSignature {
            server_name: server_name.to_owned(),
            key_id: key_id.to_owned(),
        })?;
    verify_with_bytes(&signing_bytes(pdu)?, sig_val, public_key_bytes)
}

/// The servers whose signatures a received PDU is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signers {
    /// Each must have a valid eligible signature, or the PDU is dropped.
    pub required: Vec<String>,
    /// Verified like a required server, but the outcome is only recorded in
    /// [`SignedBy`] for the auth rules (v11 rule 4.2 on non-join members).
    pub observed: Option<String>,
}

/// True for a membership invite created from a third-party invite, which is
/// exempt from the sender-server signature requirement (server-server API:
/// "the server which actually sends the event may be a different server").
pub fn is_third_party_invite(pdu: &Pdu) -> bool {
    pdu.event_type == "m.room.member"
        && pdu.content.get("membership").and_then(|v| v.as_str()) == Some("invite")
        && pdu.content.get("third_party_invite").is_some()
}

/// The required and observed signers of `pdu`.
///
/// - The sender's server, except for a third-party invite.
/// - For an `m.room.member` **join** carrying
///   `join_authorised_via_users_server`, that user's server is also required
///   (Synapse `_check_sigs_on_pdu`; v11 auth rule 4.2 for joins). A malformed
///   authoriser drops the PDU.
/// - For a **non-join** member event carrying the key, that user's server is
///   observed: verified and recorded, never a reason to drop.
pub fn signers(pdu: &Pdu) -> Result<Signers, VerifyError> {
    let mut required = Vec::new();
    if !is_third_party_invite(pdu) {
        required.push(server_of_user_id(&pdu.sender).ok_or(VerifyError::InvalidUserId)?.to_owned());
    }
    let mut observed = None;
    if pdu.event_type == "m.room.member" {
        if let Some(authoriser) = pdu.content.get("join_authorised_via_users_server") {
            let server = authoriser.as_str().and_then(server_of_user_id);
            let is_join = pdu.content.get("membership").and_then(|v| v.as_str()) == Some("join");
            if is_join {
                let server = server.ok_or(VerifyError::InvalidUserId)?.to_owned();
                if !required.contains(&server) {
                    required.push(server);
                }
            } else if let Some(server) = server {
                if !required.iter().any(|s| s == server) {
                    observed = Some(server.to_owned());
                }
            }
        }
    }
    Ok(Signers { required, observed })
}

/// Verify one server's signatures: every signature whose key `lookup`
/// returns must verify, and at least one must exist.
fn verify_server<F>(pdu: &Pdu, bytes: &[u8], server: &str, lookup: &F) -> Result<(), VerifyError>
where
    F: Fn(&str, &str) -> Option<Vec<u8>>,
{
    let no_eligible = || VerifyError::NoEligibleSignature { server_name: server.to_owned() };
    let sigs = pdu.signatures.get(server).and_then(|v| v.as_object()).ok_or_else(no_eligible)?;
    let mut eligible = 0usize;
    for (key_id, sig_val) in sigs {
        // Unknown and ineligible keys are ignored, not failures.
        let Some(public) = lookup(server, key_id) else { continue };
        eligible += 1;
        verify_with_bytes(bytes, sig_val, &public).map_err(|_| VerifyError::InvalidSignature {
            server_name: server.to_owned(),
            key_id: key_id.clone(),
        })?;
    }
    if eligible == 0 {
        return Err(no_eligible());
    }
    Ok(())
}

/// Verify the required and observed signers of `pdu`.
///
/// `lookup(server, key_id)` must return key bytes only for keys that are
/// eligible at `pdu.origin_server_ts` (room v11 "Signing key validity
/// period"); the host is responsible for event-time eligibility and refetch.
/// Returns the set of servers whose verification passed. A required server
/// failing is an error (the PDU is dropped); an observed server failing is
/// only absent from the result.
pub fn verify_signatures<F>(pdu: &Pdu, lookup: F) -> Result<SignedBy, VerifyError>
where
    F: Fn(&str, &str) -> Option<Vec<u8>>,
{
    if !pdu.signatures.is_object() {
        return Err(VerifyError::SignaturesNotObject);
    }
    let signers = signers(pdu)?;
    let bytes = signing_bytes(pdu)?;
    let mut signed_by = SignedBy::new();
    for server in &signers.required {
        verify_server(pdu, &bytes, server, &lookup)?;
        signed_by.insert(server.clone());
    }
    if let Some(server) = &signers.observed {
        if verify_server(pdu, &bytes, server, &lookup).is_ok() {
            signed_by.insert(server.clone());
        }
    }
    Ok(signed_by)
}

/// The result of the receipt checks on a PDU.
#[derive(Debug, Clone, PartialEq)]
pub struct Received {
    /// Derived from the unmodified PDU's reference hash.
    pub event_id: String,
    /// The PDU to keep: redacted when the content hash did not match.
    pub pdu: Pdu,
    pub redacted_on_receipt: bool,
    pub signed_by: SignedBy,
}

/// Run the receipt checks: signatures (drop on failure), ID derivation, then
/// the content hash. On a mismatch the redacted PDU is kept with the same ID
/// and unchanged `hashes`/`signatures` ("the receiving server should use the
/// redacted copy it calculated").
pub fn check_received<F>(pdu: Pdu, lookup: F) -> Result<Received, VerifyError>
where
    F: Fn(&str, &str) -> Option<Vec<u8>>,
{
    let signed_by = verify_signatures(&pdu, lookup)?;
    let event_id = crate::hashing::event_id(&pdu)?;
    if content_hash_matches(&pdu)? {
        Ok(Received { event_id, pdu, redacted_on_receipt: false, signed_by })
    } else {
        Ok(Received { event_id, pdu: redact(&pdu), redacted_on_receipt: true, signed_by })
    }
}

fn verify_with_bytes(bytes: &[u8], sig_val: &serde_json::Value, pub_bytes: &[u8]) -> Result<(), VerifyError> {
    let sig_b64 = sig_val.as_str().ok_or_else(|| VerifyError::MissingSignature {
        server_name: String::new(),
        key_id: String::new(),
    })?;
    let sig_bytes = crate::hashing::decode_unpadded_base64(sig_b64)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ed25519_dalek::SignatureError::new())?;
    let signature = Signature::from_bytes(&sig_array);
    let pub_array: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidPublicKey(ed25519_dalek::SignatureError::new()))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_array).map_err(VerifyError::InvalidPublicKey)?;
    verifying_key.verify_strict(bytes, &signature).map_err(VerifyError::VerifyFailed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::keys::{generate_server_key, public_bytes};
    use serde_json::json;

    fn make_pdu() -> Pdu {
        Pdu::new(
            "!room:example.org", "@user:example.org", "m.room.message", None,
            json!({ "msgtype": "m.text", "body": "Hello" }), 1_000_000,
            vec!["$auth1".into()], vec!["$prev1".into()], 42,
        )
    }

    fn lookup_for(keys: Vec<(&'static str, &ServerKey)>) -> impl Fn(&str, &str) -> Option<Vec<u8>> {
        let table: Vec<(String, String, Vec<u8>)> = keys
            .into_iter()
            .map(|(server, key)| (server.to_owned(), key.key_id.clone(), public_bytes(key)))
            .collect();
        move |server, key_id| {
            table.iter().find(|(s, k, _)| s == server && k == key_id).map(|(_, _, p)| p.clone())
        }
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let key = generate_server_key();
        let mut pdu = make_pdu();
        sign_authored(&mut pdu, &key, "example.org").unwrap();
        verify_event_signature(&pdu, "example.org", &key.key_id, &public_bytes(&key)).unwrap();
    }

    #[test]
    fn tamper_protected_content_breaks_verify() {
        let key = generate_server_key();
        let mut pdu = Pdu { event_type: "m.room.member".into(), content: json!({"membership": "join"}), ..make_pdu() };
        sign_authored(&mut pdu, &key, "example.org").unwrap();
        pdu.content = json!({"membership": "ban"});
        assert!(verify_event_signature(&pdu, "example.org", &key.key_id, &public_bytes(&key)).is_err());
    }

    #[test]
    fn padded_signature_still_verifies() {
        let key = generate_server_key();
        let mut pdu = make_pdu();
        sign_authored(&mut pdu, &key, "example.org").unwrap();
        let sig = pdu.signatures["example.org"][&key.key_id].as_str().unwrap().to_owned();
        assert!(!sig.contains('='));
        let mut padded = sig.clone();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }
        assert!(padded.ends_with('='));
        pdu.signatures["example.org"][&key.key_id] = json!(padded);
        verify_event_signature(&pdu, "example.org", &key.key_id, &public_bytes(&key)).unwrap();
    }

    #[test]
    fn wrong_public_key_breaks_verify() {
        let key_a = generate_server_key();
        let key_b = generate_server_key();
        let mut pdu = make_pdu();
        sign_authored(&mut pdu, &key_a, "example.org").unwrap();
        assert!(verify_event_signature(&pdu, "example.org", &key_a.key_id, &public_bytes(&key_b)).is_err());
    }

    #[test]
    fn sign_preserves_other_signatures() {
        let key = generate_server_key();
        let mut pdu = make_pdu();
        pdu.signatures = json!({"other.org": {"ed25519:abc": "AAAA"}});
        sign_authored(&mut pdu, &key, "example.org").unwrap();
        assert!(pdu.signatures["other.org"]["ed25519:abc"].is_string());
        assert!(pdu.signatures["example.org"].is_object());
    }

    #[test]
    fn local_id_never_affects_signature_or_hashes() {
        let key = generate_server_key();
        let mut pdu = make_pdu();
        sign_authored(&mut pdu, &key, "example.org").unwrap();
        let before = (content_hash(&pdu).unwrap(), crate::hashing::event_id(&pdu).unwrap(), pdu.signatures.clone());
        for id in ["", "$anything", "not even an id"] {
            let event = Event::new(id, pdu.clone());
            assert_eq!(content_hash(&event).unwrap(), before.0);
            assert_eq!(crate::hashing::event_id(&event).unwrap(), before.1);
            assert_eq!(event.signatures, before.2);
            verify_event_signature(&event, "example.org", &key.key_id, &public_bytes(&key)).unwrap();
        }
    }

    #[test]
    fn add_signature_is_hash_neutral() {
        let inviter = generate_server_key();
        let invitee = generate_server_key();
        let mut pdu = Pdu { event_type: "m.room.member".into(), state_key: Some("@b:b.org".into()),
            content: json!({"membership": "invite"}), ..make_pdu() };
        pdu.extensions.insert("org.example.ext".into(), json!(1));
        sign_authored(&mut pdu, &inviter, "example.org").unwrap();
        let hashes = pdu.hashes.clone();
        let id = crate::hashing::event_id(&pdu).unwrap();
        add_signature(&mut pdu, &invitee, "b.org").unwrap();
        assert_eq!(pdu.hashes, hashes);
        assert_eq!(crate::hashing::event_id(&pdu).unwrap(), id);
        let signed_by = verify_signatures(&pdu, lookup_for(vec![("example.org", &inviter), ("b.org", &invitee)])).unwrap();
        assert!(signed_by.contains("example.org"));
        verify_event_signature(&pdu, "b.org", &invitee.key_id, &public_bytes(&invitee)).unwrap();
    }

    #[test]
    fn authored_size_margin() {
        let key = generate_server_key();
        let mut pdu = make_pdu();
        pdu.content = json!({"body": "x".repeat(MAX_AUTHORED_PDU_BYTES)});
        assert!(matches!(sign_authored(&mut pdu, &key, "example.org"), Err(SigningError::TooLarge { .. })));
    }

    #[test]
    fn unknown_keys_are_ignored_but_one_eligible_signature_is_required() {
        let key = generate_server_key();
        let mut pdu = make_pdu();
        sign_authored(&mut pdu, &key, "example.org").unwrap();
        pdu.signatures["example.org"]["ed25519:unknown"] = json!("AAAA");
        verify_signatures(&pdu, lookup_for(vec![("example.org", &key)])).unwrap();
        assert!(matches!(
            verify_signatures(&pdu, |_: &str, _: &str| None),
            Err(VerifyError::NoEligibleSignature { .. })
        ));
    }

    #[test]
    fn an_invalid_eligible_signature_fails_even_with_a_valid_one() {
        let key = generate_server_key();
        let other = generate_server_key();
        let mut pdu = make_pdu();
        sign_authored(&mut pdu, &key, "example.org").unwrap();
        let mut forged = pdu.clone();
        add_signature(&mut forged, &other, "example.org").unwrap();
        // `other` signs correctly, but we hand out `key`'s public bytes for it.
        let other_id = other.key_id.clone();
        let key_id = key.key_id.clone();
        let wrong = public_bytes(&key);
        let lookup = move |_: &str, kid: &str| (kid == key_id || kid == other_id).then(|| wrong.clone());
        if other.key_id != key.key_id {
            assert!(matches!(verify_signatures(&forged, lookup), Err(VerifyError::InvalidSignature { .. })));
        }
    }

    fn member(membership: &str, authoriser: Option<&str>) -> Pdu {
        let mut content = json!({"membership": membership});
        if let Some(a) = authoriser {
            content["join_authorised_via_users_server"] = json!(a);
        }
        Pdu { event_type: "m.room.member".into(), sender: "@joiner:a.org".into(),
            state_key: Some("@joiner:a.org".into()), content, ..make_pdu() }
    }

    #[test]
    fn restricted_join_requires_authorising_server() {
        let sender = generate_server_key();
        let resident = generate_server_key();
        let lookup = || lookup_for(vec![("a.org", &sender), ("c.org", &resident)]);

        let mut sender_only = member("join", Some("@admin:c.org"));
        sign_authored(&mut sender_only, &sender, "a.org").unwrap();
        assert!(matches!(verify_signatures(&sender_only, lookup()), Err(VerifyError::NoEligibleSignature { .. })));

        let mut co_signed = sender_only.clone();
        add_signature(&mut co_signed, &resident, "c.org").unwrap();
        let signed_by = verify_signatures(&co_signed, lookup()).unwrap();
        assert_eq!(signed_by, ["a.org".to_owned(), "c.org".to_owned()].into_iter().collect());

        let mut invalid = sender_only.clone();
        invalid.signatures["c.org"] = json!({ resident.key_id.clone(): STANDARD_NO_PAD.encode([0u8; 64]) });
        assert!(matches!(verify_signatures(&invalid, lookup()), Err(VerifyError::InvalidSignature { .. })));

        let mut malformed = member("join", Some("not-a-user"));
        sign_authored(&mut malformed, &sender, "a.org").unwrap();
        assert!(matches!(verify_signatures(&malformed, lookup()), Err(VerifyError::InvalidUserId)));
    }

    #[test]
    fn non_join_authoriser_is_observed_not_required() {
        let sender = generate_server_key();
        let resident = generate_server_key();
        for membership in ["invite", "leave"] {
            let lookup = || lookup_for(vec![("a.org", &sender), ("c.org", &resident)]);
            let mut missing = member(membership, Some("@admin:c.org"));
            sign_authored(&mut missing, &sender, "a.org").unwrap();
            assert_eq!(verify_signatures(&missing, lookup()).unwrap(), ["a.org".to_owned()].into_iter().collect());

            let mut valid = missing.clone();
            add_signature(&mut valid, &resident, "c.org").unwrap();
            assert_eq!(verify_signatures(&valid, lookup()).unwrap().len(), 2);

            let mut invalid = missing.clone();
            invalid.signatures["c.org"] = json!({ resident.key_id.clone(): STANDARD_NO_PAD.encode([0u8; 64]) });
            assert_eq!(verify_signatures(&invalid, lookup()).unwrap(), ["a.org".to_owned()].into_iter().collect());
        }
    }

    #[test]
    fn third_party_invite_is_exempt_from_sender_signature() {
        let other = generate_server_key();
        let mut invite = member("invite", None);
        invite.sender = "@inviter:x.org".into();
        invite.content["third_party_invite"] = json!({"signed": {"token": "t"}});
        add_signature(&mut invite, &other, "elsewhere.org").unwrap();
        assert!(verify_signatures(&invite, |_: &str, _: &str| None).unwrap().is_empty());
        let mut plain = invite.clone();
        plain.content.as_object_mut().unwrap().remove("third_party_invite");
        assert!(verify_signatures(&plain, |_: &str, _: &str| None).is_err());
    }

    #[test]
    fn check_received_redacts_on_hash_mismatch_keeping_identity() {
        let key = generate_server_key();
        let mut pdu = make_pdu();
        sign_authored(&mut pdu, &key, "example.org").unwrap();
        let id = crate::hashing::event_id(&pdu).unwrap();
        let ok = check_received(pdu.clone(), lookup_for(vec![("example.org", &key)])).unwrap();
        assert!(!ok.redacted_on_receipt);
        assert_eq!(ok.event_id, id);
        pdu.content = json!({"body": "changed"});
        let redacted = check_received(pdu.clone(), lookup_for(vec![("example.org", &key)])).unwrap();
        assert!(redacted.redacted_on_receipt);
        assert_eq!(redacted.event_id, id);
        assert_eq!(redacted.pdu.content, json!({}));
        assert_eq!(redacted.pdu.hashes, pdu.hashes);
        assert_eq!(redacted.pdu.signatures, pdu.signatures);
    }

    /// Appendix cryptographic test vectors for JSON signing.
    /// <https://spec.matrix.org/v1.19/appendices/#json-signing>
    #[test]
    fn appendix_json_signing_vectors() {
        let seed = decode_spec_seed("YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1");
        let key = crate::keys::server_key_from_bytes("ed25519:1", &seed).unwrap();
        let empty = sign_json(json!({}), &key, "domain").unwrap();
        assert_eq!(
            empty["signatures"]["domain"]["ed25519:1"],
            "K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"
        );
        let data = sign_json(json!({"one": 1, "two": "Two"}), &key, "domain").unwrap();
        assert_eq!(data["one"], 1);
        assert_eq!(data["two"], "Two");
        assert_eq!(
            data["signatures"]["domain"]["ed25519:1"],
            "KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw"
        );
    }

    /// The appendix seed's last character has non-zero discarded bits. RFC 4648
    /// decoders may reject that; the published 32 bytes are the ones Python and
    /// the spec vectors sign.
    fn decode_spec_seed(input: &str) -> Vec<u8> {
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = 0u32;
        let mut nbits = 0;
        let mut out = Vec::new();
        for byte in input.bytes() {
            let value = ALPHA.iter().position(|char| *char == byte).expect("base64") as u32;
            bits = (bits << 6) | value;
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push((bits >> nbits) as u8);
                bits &= (1 << nbits) - 1;
            }
        }
        out
    }
}
