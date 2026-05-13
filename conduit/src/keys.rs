//! Server signing-key primitives.
//!
//! Pure crypto — no I/O.  Provides key generation, rehydration, and
//! public-byte extraction for the server's Ed25519 signing key.

use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A server signing keypair together with its Matrix key identifier.
///
/// The `key_id` has the form `ed25519:<6 url-safe-base64-nopad chars>`,
/// e.g. `ed25519:aBcDeF`.
pub struct ServerKey {
    pub key_id: String,
    pub signing_key: SigningKey,
}

/// Errors returned by key operations.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("private key bytes must be exactly 32 bytes, got {0}")]
    InvalidLength(usize),
}

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/// Generate a fresh Ed25519 server signing keypair with a random key_id.
///
/// The key_id is `ed25519:` followed by 6 url-safe base64-nopad characters
/// derived from 4 random bytes (≈ 24 bits of entropy in the id suffix —
/// enough to distinguish keys; security comes from the key material itself).
pub fn generate_server_key() -> ServerKey {
    let mut id_bytes = [0u8; 4];
    use rand_core::RngCore as _;
    OsRng.fill_bytes(&mut id_bytes);
    let suffix = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id_bytes);
    // Take the first 6 chars (4 raw bytes → 6 base64 chars exactly).
    let key_id = format!("ed25519:{}", &suffix[..6]);

    let signing_key = SigningKey::generate(&mut OsRng);

    ServerKey { key_id, signing_key }
}

/// Rehydrate a [`ServerKey`] from raw private-key bytes (32-byte Ed25519 seed).
pub fn server_key_from_bytes(key_id: &str, private: &[u8]) -> Result<ServerKey, KeyError> {
    let bytes: [u8; 32] = private
        .try_into()
        .map_err(|_| KeyError::InvalidLength(private.len()))?;
    let signing_key = SigningKey::from_bytes(&bytes);
    Ok(ServerKey {
        key_id: key_id.to_owned(),
        signing_key,
    })
}

/// Return the 32-byte compressed public key for a [`ServerKey`].
pub fn public_bytes(key: &ServerKey) -> Vec<u8> {
    let vk: VerifyingKey = key.signing_key.verifying_key();
    vk.to_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use ed25519_dalek::Verifier as _;

    #[test]
    fn generate_produces_32_byte_private_key() {
        let sk = generate_server_key();
        assert_eq!(sk.signing_key.to_bytes().len(), 32);
        assert!(sk.key_id.starts_with("ed25519:"), "key_id={}", sk.key_id);
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk = generate_server_key();
        let message = b"hello conduit";
        let signature = sk.signing_key.sign(message);
        let vk = sk.signing_key.verifying_key();
        vk.verify(message, &signature)
            .expect("signature must verify");
    }

    #[test]
    fn rehydrate_round_trip() {
        let sk = generate_server_key();
        let priv_bytes = sk.signing_key.to_bytes().to_vec();
        let pub_bytes = public_bytes(&sk);
        let key_id = sk.key_id.clone();

        let sk2 = server_key_from_bytes(&key_id, &priv_bytes).expect("rehydrate");
        assert_eq!(public_bytes(&sk2), pub_bytes);
        assert_eq!(sk2.key_id, key_id);
    }
}
