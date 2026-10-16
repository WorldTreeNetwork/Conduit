//! Remote server key fetch + cache.
//!
//! Fetches a remote Matrix homeserver's public keys via
//! `GET /_matrix/key/v2/server`, verifies the self-signature on the response,
//! and caches each key with an **effective validity** used for event
//! verification (room v11 "Signing key validity period"):
//!
//! - `verify_keys`: `min(valid_until_ts, fetched_at + 7 days)` — "Servers
//!   MUST use the lesser of `valid_until_ts` and 7 days into the future".
//! - `old_verify_keys`: `expired_ts` — keys "known to have expired prior to
//!   the event's `origin_server_ts` are ignored".
//!
//! [`RemoteKeyCache::eligible_key`] answers "may this key verify an event
//! sent at `origin_server_ts`?", refetching (rate-limited) when the key is
//! unknown or not eligible. Wall-clock expiry only decides when
//! [`RemoteKeyCache::get_or_fetch`] (request authentication) refetches; it
//! never makes a key eligible for an event.
//!
//! # Server discovery
//!
//! Out of scope for this module (tracked in E08).  For now we fetch directly:
//! `https://{server_name}/_matrix/key/v2/server`.  A test override base URL
//! can be set via [`RemoteKeyCache::with_test_base_url`].

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use tokio::sync::RwLock;

use conduit::canonical_json::to_canonical_bytes;

/// Seven days in milliseconds: the v11 cap on a key's `valid_until_ts`.
pub const SEVEN_DAYS_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// At most one refetch per server per this many milliseconds when a key is
/// unknown or ineligible, so a peer cannot use event checks to amplify traffic.
pub const REFETCH_INTERVAL_MS: i64 = 5 * 60 * 1000;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by [`RemoteKeyCache`] operations.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// An HTTP-level error occurred while contacting the remote server.
    #[error("HTTP error fetching keys for '{server_name}': {source}")]
    Http {
        server_name: String,
        #[source]
        source: reqwest::Error,
    },

    /// The response body could not be parsed as the expected key document.
    #[error("parse error for '{server_name}': {source}")]
    Parse {
        server_name: String,
        #[source]
        source: reqwest::Error,
    },

    /// The response did not contain a valid self-signature from the server.
    #[error("invalid self-signature in key response from '{server_name}': {reason}")]
    InvalidSignature {
        server_name: String,
        reason: String,
    },

    /// The requested key was not present in the response.
    #[error("key '{key_id}' not found in response from '{server_name}'")]
    MissingKey {
        server_name: String,
        key_id: String,
    },

    /// The response contained no valid self-signature from its own server_name.
    #[error("no valid self-signature found in response from '{server_name}'")]
    NoValidSignature { server_name: String },
}

// ---------------------------------------------------------------------------
// Wire types (deserialised from the JSON response)
// ---------------------------------------------------------------------------

/// `GET /_matrix/key/v2/server` response shape.
#[derive(Debug, Deserialize)]
struct KeyResponse {
    server_name: String,
    /// `{ key_id: { "key": "<unpadded-std-base64>" } }`
    verify_keys: HashMap<String, VerifyKeyEntry>,
    /// `{ key_id: { "key": "...", "expired_ts": ms } }`
    #[serde(default)]
    old_verify_keys: HashMap<String, OldVerifyKeyEntry>,
    /// `valid_until_ts` in Unix milliseconds.
    valid_until_ts: i64,
    /// `{ server_name: { key_id: "<unpadded-std-base64-sig>" } }`
    signatures: HashMap<String, HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct VerifyKeyEntry {
    key: String,
}

#[derive(Debug, Deserialize)]
struct OldVerifyKeyEntry {
    key: String,
    expired_ts: i64,
}

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CachedKey {
    /// Raw 32-byte Ed25519 public key.
    public: Vec<u8>,
    /// Published `valid_until_ts` (current keys) or `expired_ts` (old keys);
    /// used only to decide when request authentication refetches.
    valid_until_ts: i64,
    /// The last event `origin_server_ts` this key may verify.
    effective_until_ts: i64,
}

/// The v11 effective validity of a key from a key response fetched at
/// `fetched_at`: current keys are capped at seven days after the fetch, old
/// keys are valid until their `expired_ts`.
pub fn effective_until(valid_until_ts: i64, fetched_at: i64, old_expired_ts: Option<i64>) -> i64 {
    match old_expired_ts {
        Some(expired_ts) => expired_ts,
        None => valid_until_ts.min(fetched_at.saturating_add(SEVEN_DAYS_MS)),
    }
}

// ---------------------------------------------------------------------------
// RemoteKeyCache
// ---------------------------------------------------------------------------

/// Thread-safe cache of remote server public keys with lazy network fetch.
pub struct RemoteKeyCache {
    inner: RwLock<HashMap<(String, String), CachedKey>>,
    /// Last eligibility-driven refetch attempt per server (Unix ms).
    last_refetch: RwLock<HashMap<String, i64>>,
    /// When `Some`, all requests go to `{base_url}/_matrix/key/v2/server`
    /// regardless of the actual `server_name`.  Useful for test setups.
    base_url_override: Option<String>,
}

impl RemoteKeyCache {
    /// Create a new empty cache that fetches `https://{server_name}/…`.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            last_refetch: RwLock::new(HashMap::new()),
            base_url_override: None,
        }
    }

    /// Override the base URL used for all fetches.
    ///
    /// When set, requests go to `{base_url}/_matrix/key/v2/server` instead of
    /// `https://{server_name}/_matrix/key/v2/server`.  Intended for tests only.
    pub fn with_test_base_url(self, base_url: String) -> Self {
        Self {
            base_url_override: Some(base_url),
            ..self
        }
    }

    /// Build the fetch URL for the given server.
    fn key_url(&self, server_name: &str) -> String {
        match &self.base_url_override {
            Some(base) => format!("{}/_matrix/key/v2/server", base.trim_end_matches('/')),
            None => format!("https://{}/_matrix/key/v2/server", server_name),
        }
    }

    /// Return the current time in Unix milliseconds.
    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Insert a key as if it came from a key response fetched at
    /// `fetched_at`. `old_expired_ts` marks an `old_verify_keys` entry.
    /// Used by the fetch path and by tests that need fixed timestamps.
    pub async fn insert_key(
        &self,
        server_name: &str,
        key_id: &str,
        public: Vec<u8>,
        valid_until_ts: i64,
        fetched_at: i64,
        old_expired_ts: Option<i64>,
    ) {
        let entry = CachedKey {
            public,
            valid_until_ts: old_expired_ts.unwrap_or(valid_until_ts),
            effective_until_ts: effective_until(valid_until_ts, fetched_at, old_expired_ts),
        };
        self.inner.write().await.insert((server_name.to_owned(), key_id.to_owned()), entry);
    }

    /// The cached key if it may verify an event sent at `origin_server_ts`.
    pub async fn cached_eligible_key(&self, server_name: &str, key_id: &str, origin_server_ts: u64) -> Option<Vec<u8>> {
        let guard = self.inner.read().await;
        let entry = guard.get(&(server_name.to_owned(), key_id.to_owned()))?;
        (entry.effective_until_ts >= origin_server_ts as i64).then(|| entry.public.clone())
    }

    /// The key for `(server_name, key_id)` if it is eligible for an event sent
    /// at `origin_server_ts`. Unknown or ineligible keys trigger one refetch
    /// per server per [`REFETCH_INTERVAL_MS`] before the answer is `None`.
    pub async fn eligible_key(
        &self,
        http: &reqwest::Client,
        server_name: &str,
        key_id: &str,
        origin_server_ts: u64,
    ) -> Option<Vec<u8>> {
        if let Some(public) = self.cached_eligible_key(server_name, key_id, origin_server_ts).await {
            return Some(public);
        }
        let now = Self::now_ms();
        {
            let mut attempts = self.last_refetch.write().await;
            if let Some(last) = attempts.get(server_name) {
                if now - last < REFETCH_INTERVAL_MS {
                    return None;
                }
            }
            attempts.insert(server_name.to_owned(), now);
        }
        if let Err(error) = self.fetch(http, server_name).await {
            tracing::debug!(%server_name, %error, "key refetch for event verification failed");
            return None;
        }
        self.cached_eligible_key(server_name, key_id, origin_server_ts).await
    }

    /// Get the public key bytes for `(server_name, key_id)` for request
    /// authentication (X-Matrix): a cached key until its published expiry,
    /// otherwise fetch.
    pub async fn get_or_fetch(
        &self,
        http: &reqwest::Client,
        server_name: &str,
        key_id: &str,
    ) -> Result<Vec<u8>, FetchError> {
        let cache_key = (server_name.to_owned(), key_id.to_owned());

        // Fast path: read-lock, check cache.
        {
            let guard = self.inner.read().await;
            if let Some(entry) = guard.get(&cache_key) {
                if entry.valid_until_ts > Self::now_ms() {
                    return Ok(entry.public.clone());
                }
            }
        }

        // Slow path: fetch (holds no lock during network I/O).
        self.fetch(http, server_name).await?;

        // Read again after populating the cache.
        let guard = self.inner.read().await;
        guard
            .get(&cache_key)
            .map(|e| e.public.clone())
            .ok_or_else(|| FetchError::MissingKey {
                server_name: server_name.to_owned(),
                key_id: key_id.to_owned(),
            })
    }

    /// Fetch and verify the key document for `server_name`, then populate the
    /// cache with its `verify_keys` and `old_verify_keys`.
    ///
    /// This is a direct network fetch — it does **not** check the cache first.
    pub async fn fetch(
        &self,
        http: &reqwest::Client,
        server_name: &str,
    ) -> Result<(), FetchError> {
        let url = self.key_url(server_name);
        let fetched_at = Self::now_ms();

        // 1. Fetch raw JSON (keep it for signature verification).
        let raw_value: serde_json::Value = http
            .get(&url)
            .send()
            .await
            .map_err(|e| FetchError::Http {
                server_name: server_name.to_owned(),
                source: e,
            })?
            .json()
            .await
            .map_err(|e| FetchError::Parse {
                server_name: server_name.to_owned(),
                source: e,
            })?;

        // 2. Deserialise into our typed struct (for ergonomic field access).
        let response: KeyResponse =
            serde_json::from_value(raw_value.clone()).map_err(|e| {
                FetchError::InvalidSignature {
                    server_name: server_name.to_owned(),
                    reason: format!("malformed key document: {e}"),
                }
            })?;

        // 3. Verify self-signature(s).
        self.verify_self_signatures(&raw_value, &response)?;

        // 4. Store all keys into the cache.
        let decode = |kid: &str, key: &str| {
            conduit::hashing::decode_unpadded_base64(key).map_err(|e| FetchError::InvalidSignature {
                server_name: server_name.to_owned(),
                reason: format!("base64 decode of verify_key '{kid}': {e}"),
            })
        };
        let mut entries = Vec::new();
        for (kid, entry) in &response.verify_keys {
            entries.push((kid.clone(), decode(kid, &entry.key)?, None));
        }
        for (kid, entry) in &response.old_verify_keys {
            if !response.verify_keys.contains_key(kid) {
                entries.push((kid.clone(), decode(kid, &entry.key)?, Some(entry.expired_ts)));
            }
        }
        for (kid, public, old) in entries {
            self.insert_key(&response.server_name, &kid, public, response.valid_until_ts, fetched_at, old).await;
        }
        Ok(())
    }

    /// Verify that the response carries at least one valid self-signature from
    /// the server identified by `response.server_name`.
    fn verify_self_signatures(
        &self,
        raw_value: &serde_json::Value,
        response: &KeyResponse,
    ) -> Result<(), FetchError> {
        let server_name = &response.server_name;

        // Build the signing bytes: strip `signatures`, canonical-JSON encode.
        let mut stripped = raw_value.clone();
        if let Some(obj) = stripped.as_object_mut() {
            obj.remove("signatures");
        }
        let signing_bytes = to_canonical_bytes(&stripped).map_err(|e| {
            FetchError::InvalidSignature {
                server_name: server_name.clone(),
                reason: format!("canonical JSON encode failed: {e}"),
            }
        })?;

        let Some(server_sigs) = response.signatures.get(server_name) else {
            return Err(FetchError::NoValidSignature {
                server_name: server_name.clone(),
            });
        };

        for (kid, sig_b64) in server_sigs {
            let Some(vk_entry) = response.verify_keys.get(kid) else {
                continue;
            };
            let Ok(pub_bytes) = conduit::hashing::decode_unpadded_base64(&vk_entry.key) else { continue };
            let Ok(sig_bytes) = conduit::hashing::decode_unpadded_base64(sig_b64) else { continue };
            let Ok(pub_array): Result<[u8; 32], _> = pub_bytes.try_into() else {
                continue;
            };
            let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_array) else {
                continue;
            };
            let Ok(sig_array): Result<[u8; 64], _> = sig_bytes.try_into() else {
                continue;
            };
            let signature = Signature::from_bytes(&sig_array);
            if verifying_key.verify_strict(&signing_bytes, &signature).is_ok() {
                return Ok(());
            }
        }

        Err(FetchError::NoValidSignature {
            server_name: server_name.clone(),
        })
    }
}

impl Default for RemoteKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrap a `RemoteKeyCache` in an `Arc` — the standard way to share it.
pub type SharedRemoteKeyCache = Arc<RemoteKeyCache>;

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 24 * 60 * 60 * 1000;

    async fn cache_with(fetched_at: i64, valid_until: i64, old: Option<i64>) -> RemoteKeyCache {
        // Dead base URL: every refetch fails, so eligibility is decided by the entry.
        let cache = RemoteKeyCache::new().with_test_base_url("http://127.0.0.1:1".into());
        cache.insert_key("a.org", "ed25519:k", vec![7; 32], valid_until, fetched_at, old).await;
        cache
    }

    #[tokio::test]
    async fn key_validity_boundary_is_inclusive() {
        let f = 1_000 * DAY;
        let t = f + 3 * DAY;
        let cache = cache_with(f, t, None).await;
        let http = reqwest::Client::new();
        assert!(cache.eligible_key(&http, "a.org", "ed25519:k", t as u64).await.is_some());
        assert!(cache.eligible_key(&http, "a.org", "ed25519:k", (t + 1) as u64).await.is_none());
    }

    #[tokio::test]
    async fn seven_day_cap_applies_from_fetch_time() {
        let f = 1_000 * DAY;
        let cache = cache_with(f, f + 365 * DAY, None).await;
        let http = reqwest::Client::new();
        assert!(cache.eligible_key(&http, "a.org", "ed25519:k", (f + 7 * DAY) as u64).await.is_some());
        assert!(cache.eligible_key(&http, "a.org", "ed25519:k", (f + 7 * DAY + 1) as u64).await.is_none());
    }

    #[tokio::test]
    async fn old_verify_key_verifies_history_until_expired_ts() {
        let r = 2_000 * DAY;
        let cache = cache_with(r + DAY, r + 30 * DAY, Some(r)).await;
        assert!(cache.cached_eligible_key("a.org", "ed25519:k", (r - 1) as u64).await.is_some());
        assert!(cache.cached_eligible_key("a.org", "ed25519:k", r as u64).await.is_some());
        assert!(cache.cached_eligible_key("a.org", "ed25519:k", (r + 1) as u64).await.is_none());
    }

    #[tokio::test]
    async fn wall_clock_expiry_never_makes_a_key_eligible() {
        // Published validity far in the future, but fetched long ago: the
        // seven-day cap from the fetch governs events, not the wall clock.
        let f = 10 * DAY;
        let cache = cache_with(f, i64::MAX / 2, None).await;
        assert!(cache.cached_eligible_key("a.org", "ed25519:k", (f + 8 * DAY) as u64).await.is_none());
    }

    #[tokio::test]
    async fn refetch_is_rate_limited_per_server() {
        let cache = RemoteKeyCache::new().with_test_base_url("http://127.0.0.1:1".into());
        let http = reqwest::Client::new();
        assert!(cache.eligible_key(&http, "a.org", "ed25519:x", 1).await.is_none());
        let first = *cache.last_refetch.read().await.get("a.org").unwrap();
        assert!(cache.eligible_key(&http, "a.org", "ed25519:y", 1).await.is_none());
        assert_eq!(*cache.last_refetch.read().await.get("a.org").unwrap(), first);
    }
}
