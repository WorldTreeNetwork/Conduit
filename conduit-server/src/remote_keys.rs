//! Remote server key fetch + cache.
//!
//! Fetches a remote Matrix homeserver's public keys via
//! `GET /_matrix/key/v2/server`, verifies the self-signature on the response,
//! and caches each key until its `valid_until_ts` (Unix ms).
//!
//! # Server discovery
//!
//! Out of scope for this module (tracked in E08).  For now we fetch directly:
//! `https://{server_name}/_matrix/key/v2/server`.  A test override base URL
//! can be set via [`RemoteKeyCache::with_test_base_url`].

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use tokio::sync::RwLock;

use conduit::canonical_json::to_canonical_bytes;

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
///
/// Only the fields we need are captured; the rest pass through via the raw
/// `serde_json::Value` we keep for signature verification.
#[derive(Debug, Deserialize)]
struct KeyResponse {
    server_name: String,
    /// `{ key_id: { "key": "<unpadded-std-base64>" } }`
    verify_keys: HashMap<String, VerifyKeyEntry>,
    /// `valid_until_ts` in Unix milliseconds.
    valid_until_ts: i64,
    /// `{ server_name: { key_id: "<unpadded-std-base64-sig>" } }`
    signatures: HashMap<String, HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct VerifyKeyEntry {
    key: String,
}

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

struct CachedKey {
    /// Raw 32-byte Ed25519 public key.
    public: Vec<u8>,
    /// Expiry expressed as Unix milliseconds.
    valid_until_ts: i64,
}

// ---------------------------------------------------------------------------
// RemoteKeyCache
// ---------------------------------------------------------------------------

/// Thread-safe cache of remote server public keys with lazy network fetch.
pub struct RemoteKeyCache {
    inner: RwLock<HashMap<(String, String), CachedKey>>,
    /// When `Some`, all requests go to `{base_url}/_matrix/key/v2/server`
    /// regardless of the actual `server_name`.  Useful for test setups.
    base_url_override: Option<String>,
}

impl RemoteKeyCache {
    /// Create a new empty cache that fetches `https://{server_name}/…`.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
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

    /// Get the public key bytes for `(server_name, key_id)`.
    ///
    /// Returns a cached value if one exists and has not yet expired.
    /// Otherwise fetches, verifies, and caches the remote server's key
    /// document, then returns the requested key.
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
    /// cache with all `verify_keys` entries from the response.
    ///
    /// This is a direct network fetch — it does **not** check the cache first.
    /// Callers that want cache-aware behaviour should use [`Self::get_or_fetch`].
    pub async fn fetch(
        &self,
        http: &reqwest::Client,
        server_name: &str,
    ) -> Result<(), FetchError> {
        let url = self.key_url(server_name);

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

        // 4. Store all keys from verify_keys into the cache.
        let valid_until_ts = response.valid_until_ts;
        let mut guard = self.inner.write().await;
        for (kid, entry) in &response.verify_keys {
            let pub_bytes = STANDARD_NO_PAD
                .decode(&entry.key)
                .map_err(|e| FetchError::InvalidSignature {
                    server_name: server_name.to_owned(),
                    reason: format!("base64 decode of verify_key '{kid}': {e}"),
                })?;
            guard.insert(
                (response.server_name.clone(), kid.clone()),
                CachedKey {
                    public: pub_bytes,
                    valid_until_ts,
                },
            );
        }
        Ok(())
    }

    /// Verify that the response carries at least one valid self-signature from
    /// the server identified by `response.server_name`.
    ///
    /// Algorithm:
    /// 1. Clone the raw JSON object and remove the `signatures` field.
    /// 2. Canonical-JSON encode the stripped object.
    /// 3. For each `(key_id, sig_b64)` in `signatures[server_name]`:
    ///    - Look up `verify_keys[key_id].key` — if absent, skip.
    ///    - Decode both sig and pubkey from base64.
    ///    - dalek verify.
    ///    - If any one succeeds, return `Ok(())`.
    /// 4. If none succeeded, return `NoValidSignature`.
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

        // Walk signatures[server_name].
        let Some(server_sigs) = response.signatures.get(server_name) else {
            return Err(FetchError::NoValidSignature {
                server_name: server_name.clone(),
            });
        };

        for (kid, sig_b64) in server_sigs {
            // Only consider keys that appear in verify_keys.
            let Some(vk_entry) = response.verify_keys.get(kid) else {
                continue;
            };

            let pub_bytes = match STANDARD_NO_PAD.decode(&vk_entry.key) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let sig_bytes = match STANDARD_NO_PAD.decode(sig_b64) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Build dalek types.
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
