//! Server signing-key startup orchestration.
//!
//! [`load_or_generate`] ensures a current Ed25519 signing key exists in
//! storage, generating and persisting one if none is found.

use conduit::{
    keys::{generate_server_key, public_bytes, server_key_from_bytes, ServerKey},
    storage::Storage,
    Error,
};

/// Load the current signing key from storage, or generate and persist a fresh one.
///
/// Returns the rehydrated or newly-generated [`ServerKey`].
pub async fn load_or_generate(storage: &(impl Storage + ?Sized)) -> Result<ServerKey, Error> {
    if let Some(stored) = storage.current_signing_key().await? {
        let sk = server_key_from_bytes(&stored.key_id, &stored.private_key)
            .map_err(|e| Error::Storage(format!("failed to rehydrate signing key: {e}")))?;
        return Ok(sk);
    }

    // No key found — generate a fresh one and persist it.
    let sk = generate_server_key();
    let priv_bytes = sk.signing_key.to_bytes().to_vec();
    let pub_bytes = public_bytes(&sk);

    storage
        .insert_signing_key(&sk.key_id, &priv_bytes, &pub_bytes, None)
        .await?;

    Ok(sk)
}
