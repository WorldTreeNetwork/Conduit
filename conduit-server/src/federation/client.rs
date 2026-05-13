//! High-level federation HTTP client.
//!
//! Wraps discovery + X-Matrix signing into typed async methods that correspond
//! to the Matrix Server-Server API endpoints used by an *outbound* federation
//! client (i.e., what *we* call on *other* servers).
//!
//! See: <https://spec.matrix.org/latest/server-server-api/>

use std::sync::Arc;
#[cfg(feature = "iroh")]
use std::collections::HashMap;
#[cfg(feature = "iroh")]
use std::time::{Duration, Instant};

use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
#[cfg(feature = "iroh")]
use tokio::sync::RwLock;

use conduit::event::Event;
use conduit::keys::ServerKey;

use crate::RemoteKeyCache;

use super::auth::sign_request;
use super::discovery::{self, DiscoveryCache, DiscoveryError, Resolved};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum FederationError {
    #[error("discovery failed: {0}")]
    Discovery(#[from] DiscoveryError),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("remote returned {status}: {body}")]
    RemoteError { status: u16, body: String },

    #[error("response parse error: {0}")]
    Parse(String),
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Response body for `PUT /_matrix/federation/v1/send/{txnId}`.
#[derive(Debug, Deserialize)]
pub struct TransactionResponse {
    /// Map of event_id → processing result; empty map on full success.
    #[serde(default)]
    pub pdus: std::collections::HashMap<String, Value>,
}

/// Response body for `GET /_matrix/federation/v1/make_join/{roomId}/{userId}`.
#[derive(Debug, Deserialize)]
pub struct MakeJoinResponse {
    /// The template event the joining server should fill in and sign.
    pub event: Value,
    /// Room version string.
    #[serde(default)]
    pub room_version: Option<String>,
}

/// Response body for `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}`.
#[derive(Debug, Deserialize)]
pub struct SendJoinResponse {
    /// Current state of the room.
    #[serde(default)]
    pub state: Vec<Value>,
    /// State event auth chain.
    #[serde(default)]
    pub auth_chain: Vec<Value>,
    /// The event itself (echoed back).
    #[serde(default)]
    pub event: Option<Value>,
}

/// Response body for `GET /_matrix/federation/v1/state/{roomId}`.
#[derive(Debug, Deserialize)]
pub struct StateResponse {
    /// Auth chain events.
    #[serde(default)]
    pub auth_chain: Vec<Value>,
    /// Room state PDUs.
    #[serde(default)]
    pub pdus: Vec<Value>,
}

/// Response body for `GET /_matrix/federation/v1/state_ids/{roomId}`.
#[derive(Debug, Deserialize)]
pub struct StateIdsResponse {
    /// Auth chain event IDs.
    #[serde(default)]
    pub auth_chain_ids: Vec<String>,
    /// State event IDs.
    #[serde(default)]
    pub pdu_ids: Vec<String>,
}

/// Response body for `GET /_matrix/federation/v1/query/directory`.
#[derive(Debug, Deserialize)]
pub struct DirectoryResponse {
    /// The room ID.
    pub room_id: String,
    /// List of server names that know about this room.
    #[serde(default)]
    pub servers: Vec<String>,
}

// ---------------------------------------------------------------------------
// Iroh NodeId cache (91r.7)
// ---------------------------------------------------------------------------

/// Cached per-destination iroh NodeId with a TTL of 5 minutes.
#[cfg(feature = "iroh")]
struct IrohNodeEntry {
    /// `None` means the peer does not advertise an iroh NodeId.
    node_id: Option<iroh::PublicKey>,
    fetched_at: Instant,
}

#[cfg(feature = "iroh")]
const IROH_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Outbound federation HTTP client.
///
/// Holds shared infrastructure (HTTP client, DNS resolver, key cache, signing
/// key, server name) and exposes typed async methods for each Server-Server
/// API endpoint.
pub struct Client {
    pub(crate) http: reqwest::Client,
    pub(crate) resolver: TokioAsyncResolver,
    pub(crate) _keys: Arc<RemoteKeyCache>,
    pub(crate) server_key: Arc<ServerKey>,
    pub(crate) server_name: Arc<str>,
    pub(crate) discovery_cache: Arc<DiscoveryCache>,
    /// Optional override: if set, all requests go to this base URL regardless
    /// of the destination server name.  Used by tests only.
    pub(crate) test_base_url: Option<String>,
    /// Cache of per-destination iroh NodeIds (feature `iroh`, 91r.7).
    #[cfg(feature = "iroh")]
    pub(crate) iroh_node_cache: Arc<RwLock<HashMap<String, IrohNodeEntry>>>,
    /// Our own iroh endpoint for outbound connections (feature `iroh`, 91r.5).
    #[cfg(feature = "iroh")]
    pub(crate) iroh_endpoint: Option<Arc<iroh::Endpoint>>,
}

impl Client {
    /// Create a new `Client`.
    pub fn new(
        http: reqwest::Client,
        resolver: TokioAsyncResolver,
        keys: Arc<RemoteKeyCache>,
        server_key: Arc<ServerKey>,
        server_name: Arc<str>,
    ) -> Self {
        Self {
            http,
            resolver,
            _keys: keys,
            server_key,
            server_name,
            discovery_cache: Arc::new(DiscoveryCache::new()),
            test_base_url: None,
            #[cfg(feature = "iroh")]
            iroh_node_cache: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "iroh")]
            iroh_endpoint: None,
        }
    }

    /// Override the base URL for all outgoing requests (tests only).
    pub fn with_test_base_url(self, url: String) -> Self {
        Self {
            test_base_url: Some(url),
            ..self
        }
    }

    /// Attach an iroh endpoint for P2P outbound federation (91r.5).
    #[cfg(feature = "iroh")]
    pub fn with_iroh_endpoint(self, endpoint: Arc<iroh::Endpoint>) -> Self {
        Self {
            iroh_endpoint: Some(endpoint),
            ..self
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Resolve `dest` and build the full URL for `path`.
    async fn resolve_url(&self, dest: &str, path: &str) -> Result<(String, Resolved), FederationError> {
        let resolved = if let Some(base) = &self.test_base_url {
            // In test mode, bypass discovery and use the provided base URL.
            Resolved {
                host: base
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .to_owned(),
                port: 0, // unused in test mode
                host_header: dest.to_owned(),
            }
        } else {
            discovery::resolve(dest, &self.http, &self.resolver, &self.discovery_cache).await?
        };

        let url = if let Some(base) = &self.test_base_url {
            format!("{}{}", base.trim_end_matches('/'), path)
        } else {
            format!("https://{}:{}{}", resolved.host, resolved.port, path)
        };

        Ok((url, resolved))
    }

    /// Issue a signed `GET` request and return the response body as `T`.
    async fn signed_get<T: for<'de> Deserialize<'de>>(
        &self,
        dest: &str,
        path: &str,
    ) -> Result<T, FederationError> {
        let (url, resolved) = self.resolve_url(dest, path).await?;

        let auth = sign_request::<()>(
            "GET",
            path,
            &self.server_name,
            dest,
            None,
            &self.server_key,
        );

        let resp = self
            .http
            .get(&url)
            .header("Host", &resolved.host_header)
            .header("Authorization", &auth)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(FederationError::RemoteError {
                status: status.as_u16(),
                body,
            });
        }

        resp.json::<T>().await.map_err(|e| FederationError::Parse(e.to_string()))
    }

    /// Issue a signed `GET` request and return the raw `reqwest::Response`.
    /// Used for media download where we want to stream bytes rather than
    /// deserialize JSON.
    pub async fn get_raw(
        &self,
        dest: &str,
        path: &str,
    ) -> Result<reqwest::Response, FederationError> {
        let (url, resolved) = self.resolve_url(dest, path).await?;

        let auth = sign_request::<()>(
            "GET",
            path,
            &self.server_name,
            dest,
            None,
            &self.server_key,
        );

        let resp = self
            .http
            .get(&url)
            .header("Host", &resolved.host_header)
            .header("Authorization", &auth)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(FederationError::RemoteError {
                status: status.as_u16(),
                body,
            });
        }

        Ok(resp)
    }

    /// Issue a signed `PUT` request and return the response body as `T`.
    async fn signed_put<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        dest: &str,
        path: &str,
        body: &B,
    ) -> Result<T, FederationError> {
        let (url, resolved) = self.resolve_url(dest, path).await?;

        let auth = sign_request(
            "PUT",
            path,
            &self.server_name,
            dest,
            Some(body),
            &self.server_key,
        );

        let resp = self
            .http
            .put(&url)
            .header("Host", &resolved.host_header)
            .header("Authorization", &auth)
            .json(body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(FederationError::RemoteError {
                status: status.as_u16(),
                body: body_text,
            });
        }

        resp.json::<T>().await.map_err(|e| FederationError::Parse(e.to_string()))
    }

    /// Issue a signed `POST` request and return the response body as `T`.
    async fn signed_post<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        dest: &str,
        path: &str,
        body: &B,
    ) -> Result<T, FederationError> {
        let (url, resolved) = self.resolve_url(dest, path).await?;

        let auth = sign_request(
            "POST",
            path,
            &self.server_name,
            dest,
            Some(body),
            &self.server_key,
        );

        let resp = self
            .http
            .post(&url)
            .header("Host", &resolved.host_header)
            .header("Authorization", &auth)
            .json(body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(FederationError::RemoteError {
                status: status.as_u16(),
                body: body_text,
            });
        }

        resp.json::<T>().await.map_err(|e| FederationError::Parse(e.to_string()))
    }

    // ------------------------------------------------------------------
    // iroh helpers (91r.5, 91r.7)
    // ------------------------------------------------------------------

    /// Look up the iroh NodeId advertised by `dest` in its server-key response.
    ///
    /// Results are cached for 5 minutes.  Returns `None` if the peer does not
    /// advertise an iroh NodeId or if the lookup fails.
    #[cfg(feature = "iroh")]
    async fn iroh_node_id_for(&self, dest: &str) -> Option<iroh::PublicKey> {
        // Check cache first.
        {
            let cache = self.iroh_node_cache.read().await;
            if let Some(entry) = cache.get(dest) {
                if entry.fetched_at.elapsed() < IROH_CACHE_TTL {
                    return entry.node_id.clone();
                }
            }
        }

        // Fetch /_matrix/key/v2/server from the destination.
        let node_id: Option<iroh::PublicKey> = async {
            let (url, resolved) = self.resolve_url(dest, "/_matrix/key/v2/server").await.ok()?;
            let resp = self
                .http
                .get(&url)
                .header("Host", &resolved.host_header)
                .send()
                .await
                .ok()?;
            if !resp.status().is_success() {
                return None;
            }
            let body: Value = resp.json().await.ok()?;
            let node_id_str = body
                .get("x_conduit_iroh")?
                .get("node_id")?
                .as_str()?;
            node_id_str.parse::<iroh::PublicKey>().ok()
        }
        .await;

        // Store in cache.
        {
            let mut cache = self.iroh_node_cache.write().await;
            cache.insert(
                dest.to_owned(),
                IrohNodeEntry {
                    node_id: node_id.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }

        node_id
    }

    /// Send a signed request to `dest` preferring iroh when both ends support
    /// it (91r.5 + 91r.7).  Falls back to HTTPS on any iroh-side error.
    #[cfg(feature = "iroh")]
    async fn signed_put_with_iroh_fallback<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        dest: &str,
        path: &str,
        body: &B,
    ) -> Result<T, FederationError> {
        // Only attempt iroh if we have a bound endpoint.
        if let Some(ep) = self.iroh_endpoint.as_ref() {
            // Look up peer's NodeId.
            if let Some(node_id) = self.iroh_node_id_for(dest).await {
                let auth = sign_request(
                    "PUT",
                    path,
                    &self.server_name,
                    dest,
                    Some(body),
                    &self.server_key,
                );
                let body_bytes = serde_json::to_vec(body)
                    .map_err(|e| FederationError::Parse(e.to_string()))?;

                match super::iroh_client::send_via_iroh(
                    ep,
                    node_id,
                    "PUT",
                    path,
                    &auth,
                    &body_bytes,
                )
                .await
                {
                    Ok((_status, resp_bytes)) => {
                        return serde_json::from_slice(&resp_bytes)
                            .map_err(|e| FederationError::Parse(e.to_string()));
                    }
                    Err(e) => {
                        tracing::warn!(
                            dest,
                            error = %e,
                            "iroh send failed, falling back to HTTPS"
                        );
                        // Fall through to HTTPS.
                    }
                }
            }
        }

        // HTTPS path (fallback or no iroh).
        self.signed_put(dest, path, body).await
    }

    // ------------------------------------------------------------------
    // Public API methods (7t4.5, 7t4.7-11)
    // ------------------------------------------------------------------

    /// `PUT /_matrix/federation/v1/send/{txnId}`
    ///
    /// Send a transaction of PDUs and EDUs to `dest`.
    /// When the `iroh` feature is enabled and the peer advertises an iroh
    /// NodeId, prefers the QUIC transport and falls back to HTTPS on error.
    pub async fn send_transaction(
        &self,
        dest: &str,
        txn_id: &str,
        pdus: Vec<Event>,
        edus: Vec<Value>,
    ) -> Result<TransactionResponse, FederationError> {
        let path = format!("/_matrix/federation/v1/send/{}", txn_id);
        let body = serde_json::json!({
            "origin": &*self.server_name,
            "origin_server_ts": crate::federation::now_ms(),
            "pdus": pdus,
            "edus": edus,
        });
        #[cfg(feature = "iroh")]
        {
            return self.signed_put_with_iroh_fallback(dest, &path, &body).await;
        }
        #[cfg(not(feature = "iroh"))]
        self.signed_put(dest, &path, &body).await
    }

    /// `GET /_matrix/federation/v1/make_join/{roomId}/{userId}`
    pub async fn make_join(
        &self,
        dest: &str,
        room_id: &str,
        user_id: &str,
    ) -> Result<MakeJoinResponse, FederationError> {
        let path = format!(
            "/_matrix/federation/v1/make_join/{}/{}",
            urlencoding(room_id),
            urlencoding(user_id)
        );
        self.signed_get(dest, &path).await
    }

    /// `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}`
    pub async fn send_join(
        &self,
        dest: &str,
        room_id: &str,
        event_id: &str,
        pdu: &Event,
    ) -> Result<SendJoinResponse, FederationError> {
        let path = format!(
            "/_matrix/federation/v2/send_join/{}/{}",
            urlencoding(room_id),
            urlencoding(event_id)
        );
        self.signed_put(dest, &path, pdu).await
    }

    /// `PUT /_matrix/federation/v2/invite/{roomId}/{eventId}`
    pub async fn invite(
        &self,
        dest: &str,
        room_id: &str,
        event_id: &str,
        invite_room_state: Vec<Value>,
        pdu: &Event,
    ) -> Result<Event, FederationError> {
        let path = format!(
            "/_matrix/federation/v2/invite/{}/{}",
            urlencoding(room_id),
            urlencoding(event_id)
        );
        let body = serde_json::json!({
            "event": pdu,
            "invite_room_state": invite_room_state,
            "room_version": "11",
        });
        let resp: Value = self.signed_put(dest, &path, &body).await?;
        serde_json::from_value(resp["event"].clone())
            .map_err(|e| FederationError::Parse(e.to_string()))
    }

    /// `GET /_matrix/federation/v1/state/{roomId}?event_id={eventId}`
    pub async fn state(
        &self,
        dest: &str,
        room_id: &str,
        event_id: &str,
    ) -> Result<StateResponse, FederationError> {
        let path = format!(
            "/_matrix/federation/v1/state/{}?event_id={}",
            urlencoding(room_id),
            urlencoding(event_id)
        );
        self.signed_get(dest, &path).await
    }

    /// `GET /_matrix/federation/v1/state_ids/{roomId}?event_id={eventId}`
    pub async fn state_ids(
        &self,
        dest: &str,
        room_id: &str,
        event_id: &str,
    ) -> Result<StateIdsResponse, FederationError> {
        let path = format!(
            "/_matrix/federation/v1/state_ids/{}?event_id={}",
            urlencoding(room_id),
            urlencoding(event_id)
        );
        self.signed_get(dest, &path).await
    }

    /// `GET /_matrix/federation/v1/backfill/{roomId}?v=...&limit={limit}`
    pub async fn backfill(
        &self,
        dest: &str,
        room_id: &str,
        event_ids: Vec<String>,
        limit: u32,
    ) -> Result<TransactionResponse, FederationError> {
        let v_params: String = event_ids
            .iter()
            .map(|id| format!("v={}", urlencoding(id)))
            .collect::<Vec<_>>()
            .join("&");
        let path = format!(
            "/_matrix/federation/v1/backfill/{}?{}&limit={}",
            urlencoding(room_id),
            v_params,
            limit
        );
        self.signed_get(dest, &path).await
    }

    /// `GET /_matrix/federation/v1/event/{eventId}`
    pub async fn event(
        &self,
        dest: &str,
        event_id: &str,
    ) -> Result<Event, FederationError> {
        let path = format!("/_matrix/federation/v1/event/{}", urlencoding(event_id));
        // Response is a transaction-shaped object with a single PDU.
        let resp: Value = self.signed_get(dest, &path).await?;
        let pdus = resp
            .get("pdus")
            .and_then(|v| v.as_array())
            .ok_or_else(|| FederationError::Parse("missing 'pdus' array".to_owned()))?;
        let first = pdus
            .first()
            .ok_or_else(|| FederationError::Parse("empty 'pdus' array".to_owned()))?;
        serde_json::from_value(first.clone())
            .map_err(|e| FederationError::Parse(e.to_string()))
    }

    /// `POST /_matrix/federation/v1/get_missing_events/{roomId}`
    pub async fn get_missing_events(
        &self,
        dest: &str,
        room_id: &str,
        earliest: Vec<String>,
        latest: Vec<String>,
        limit: u32,
    ) -> Result<Vec<Event>, FederationError> {
        let path = format!(
            "/_matrix/federation/v1/get_missing_events/{}",
            urlencoding(room_id)
        );
        let body = serde_json::json!({
            "earliest_events": earliest,
            "latest_events": latest,
            "limit": limit,
        });
        let resp: Value = self.signed_post(dest, &path, &body).await?;
        let events = resp
            .get("events")
            .and_then(|v| v.as_array())
            .ok_or_else(|| FederationError::Parse("missing 'events' array".to_owned()))?;
        events
            .iter()
            .map(|v| {
                serde_json::from_value(v.clone())
                    .map_err(|e| FederationError::Parse(e.to_string()))
            })
            .collect()
    }

    /// `GET /_matrix/federation/v1/query/profile?user_id={userId}[&field={field}]`
    pub async fn query_profile(
        &self,
        dest: &str,
        user_id: &str,
        field: Option<&str>,
    ) -> Result<Value, FederationError> {
        let path = match field {
            Some(f) => format!(
                "/_matrix/federation/v1/query/profile?user_id={}&field={}",
                urlencoding(user_id),
                urlencoding(f)
            ),
            None => format!(
                "/_matrix/federation/v1/query/profile?user_id={}",
                urlencoding(user_id)
            ),
        };
        self.signed_get(dest, &path).await
    }

    /// `PUT /_matrix/federation/v1/send_to_device/{txnId}`
    ///
    /// Send to-device messages to devices on `dest`.
    /// `messages` is `{ user_id: { device_id: content } }`.
    pub async fn send_to_device(
        &self,
        dest: &str,
        txn_id: &str,
        event_type: &str,
        messages: serde_json::Value,
    ) -> Result<Value, FederationError> {
        let path = format!("/_matrix/federation/v1/send_to_device/{}/{}", urlencoding(event_type), urlencoding(txn_id));
        let body = serde_json::json!({
            "sender": &*self.server_name,
            "type": event_type,
            "messages": messages,
        });
        self.signed_put(dest, &path, &body).await
    }

    /// `GET /_matrix/federation/v1/query/directory?room_alias={alias}`
    pub async fn query_directory(
        &self,
        dest: &str,
        room_alias: &str,
    ) -> Result<DirectoryResponse, FederationError> {
        let path = format!(
            "/_matrix/federation/v1/query/directory?room_alias={}",
            urlencoding(room_alias)
        );
        self.signed_get(dest, &path).await
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Percent-encode a string for use in a URL path/query component.
///
/// Encodes everything except unreserved characters (A-Z a-z 0-9 - _ . ~).
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            other => {
                out.push('%');
                out.push(hex_nibble(other >> 4));
                out.push(hex_nibble(other & 0xf));
            }
        }
    }
    out
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'A' + n - 10) as char,
    }
}
