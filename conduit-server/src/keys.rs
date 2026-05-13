//! Server signing-key startup orchestration.
//!
//! [`load_or_generate`] ensures a current Ed25519 signing key exists in
//! storage, generating and persisting one if none is found.
//!
//! [`rotate`] generates a fresh signing key and retires the previous one by
//! setting its `valid_until_ts` to `now + grace_window`.

use chrono::Utc;
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

/// Rotate the server signing key.
///
/// If a current key exists it is retired: its `valid_until_ts` is set to
/// `now + grace_window` so that remote servers can still verify signatures
/// made with the old key during the grace period.  A fresh key is then
/// generated, persisted, and returned.
///
/// If no current key exists the function behaves identically to
/// [`load_or_generate`] — it simply creates the first key.
pub async fn rotate<S: Storage + ?Sized>(
    storage: &S,
    grace_window: chrono::Duration,
) -> Result<ServerKey, Box<dyn std::error::Error>> {
    // Retire the current key if one exists.
    if let Some(current) = storage.current_signing_key().await? {
        let expiry_ms = Utc::now().timestamp_millis()
            + grace_window.num_milliseconds();
        storage
            .set_signing_key_expiry(&current.key_id, expiry_ms)
            .await?;
    }

    // Generate and persist the new key.
    let sk = generate_server_key();
    let priv_bytes = sk.signing_key.to_bytes().to_vec();
    let pub_bytes = public_bytes(&sk);
    storage
        .insert_signing_key(&sk.key_id, &priv_bytes, &pub_bytes, None)
        .await?;

    Ok(sk)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use conduit::storage::MemoryStorage;

    #[tokio::test]
    async fn rotate_with_no_prior_key() {
        let store = MemoryStorage::default();
        let sk = rotate(&store, chrono::Duration::hours(24))
            .await
            .expect("rotate must succeed on empty storage");

        let current = store
            .current_signing_key()
            .await
            .unwrap()
            .expect("must have a current key after rotate");
        assert_eq!(current.key_id, sk.key_id);
    }

    #[tokio::test]
    async fn rotate_creates_new_current_key() {
        let store = MemoryStorage::default();

        // Seed an initial key.
        store
            .insert_signing_key("ed25519:old", b"old_priv", b"old_pub", None)
            .await
            .unwrap();

        let grace = chrono::Duration::hours(24);
        let before_rotate_ms = Utc::now().timestamp_millis();

        let new_sk = rotate(&store, grace)
            .await
            .expect("rotate must succeed");

        // current_signing_key must be the new one.
        let current = store
            .current_signing_key()
            .await
            .unwrap()
            .expect("must have a current key");
        assert_eq!(current.key_id, new_sk.key_id);
        assert_ne!(current.key_id, "ed25519:old");

        // The old key must still be in verification keys with an expiry set.
        let all = store.signing_keys_for_verification().await.unwrap();
        assert_eq!(all.len(), 2);

        let old = all
            .iter()
            .find(|k| k.key_id == "ed25519:old")
            .expect("old key must still be present");
        let expiry = old.valid_until_ts.expect("old key must have expiry set");

        // Expiry must be roughly now + 24h (within a 5s tolerance).
        let expected_min = before_rotate_ms + grace.num_milliseconds();
        let expected_max = expected_min + 5_000;
        assert!(
            expiry >= expected_min && expiry <= expected_max,
            "expiry={expiry} not in [{expected_min}, {expected_max}]"
        );
    }
}
