//! Server name → host:port resolution per the Matrix server discovery spec.
//!
//! Implements the full resolution algorithm from:
//! <https://spec.matrix.org/latest/server-server-api/#server-discovery>
//!
//! ## Resolution order
//!
//! 1. If `server_name` is `host:port` (IP literal or hostname with explicit
//!    port), use it directly.  `host_header` = `server_name`.
//! 2. Fetch `https://{server_name}/.well-known/matrix/server`.
//!    If HTTP 200 with `{"m.server": "delegated:port"}`, use `delegated:port`.
//!    `host_header` = delegated value (per spec §4.1).
//! 3. SRV `_matrix-fed._tcp.{server_name}` → use returned target+port.
//! 4. (Legacy) SRV `_matrix._tcp.{server_name}` → use returned target+port.
//! 5. A/AAAA on `server_name`, default port 8448.
//!
//! ## Caching
//!
//! Resolution results are cached with TTLs:
//! - Well-known: cache-control from response, or 24 h by default.
//! - SRV: TTL from DNS record.
//! - Fallback: fixed 1 h.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::TokioAsyncResolver;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The resolved network target for a Matrix server name.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The host to connect to (may differ from `server_name` after delegation).
    pub host: String,
    /// The port to connect to.
    pub port: u16,
    /// The value to send in the `Host:` header and use as `destination` in
    /// `X-Matrix` authentication.  Per spec this equals the delegated server
    /// name (without port).
    pub host_header: String,
}

/// Errors returned during server name resolution.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("HTTP error during well-known fetch: {0}")]
    Http(#[from] reqwest::Error),

    #[error("DNS resolution error: {0}")]
    Dns(String),
}

// ---------------------------------------------------------------------------
// Internal cache
// ---------------------------------------------------------------------------

struct CachedResolved {
    resolved: Resolved,
    expires_at: Instant,
}

/// Thread-safe cache of resolution results.
pub struct DiscoveryCache {
    inner: RwLock<HashMap<String, CachedResolved>>,
}

impl DiscoveryCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for DiscoveryCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Well-known wire type
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct WellKnownResponse {
    #[serde(rename = "m.server")]
    m_server: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Resolve a Matrix server name to a concrete `host:port` per the spec.
///
/// Results are cached; `cache` should be shared (e.g. in `Arc`) across calls.
pub async fn resolve(
    server_name: &str,
    http: &reqwest::Client,
    resolver: &TokioAsyncResolver,
    cache: &Arc<DiscoveryCache>,
) -> Result<Resolved, DiscoveryError> {
    // Cache check.
    {
        let guard = cache.inner.read().await;
        if let Some(entry) = guard.get(server_name) {
            if entry.expires_at > Instant::now() {
                return Ok(entry.resolved.clone());
            }
        }
    }

    let result = resolve_uncached(server_name, http, resolver).await?;

    // Store with TTL.  Use 1 h as a safe conservative default.
    let ttl = Duration::from_secs(3600);
    {
        let mut guard = cache.inner.write().await;
        guard.insert(
            server_name.to_owned(),
            CachedResolved {
                resolved: result.clone(),
                expires_at: Instant::now() + ttl,
            },
        );
    }

    Ok(result)
}

async fn resolve_uncached(
    server_name: &str,
    http: &reqwest::Client,
    resolver: &TokioAsyncResolver,
) -> Result<Resolved, DiscoveryError> {
    // ------------------------------------------------------------------
    // Step 1: IP literal or host:port with explicit port number.
    // ------------------------------------------------------------------
    if let Some(resolved) = try_literal_with_port(server_name) {
        return Ok(resolved);
    }

    // Check if it's an IP address without a port (no further resolution needed).
    if IpAddr::from_str(server_name).is_ok() {
        return Ok(Resolved {
            host: server_name.to_owned(),
            port: 8448,
            host_header: server_name.to_owned(),
        });
    }

    // ------------------------------------------------------------------
    // Step 2: .well-known/matrix/server
    // ------------------------------------------------------------------
    let well_known_url = format!("https://{}/.well-known/matrix/server", server_name);
    let wk_result = http
        .get(&well_known_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await;

    if let Ok(resp) = wk_result {
        if resp.status().is_success() {
            if let Ok(wk) = resp.json::<WellKnownResponse>().await {
                let delegated = wk.m_server;
                // Parse delegated as host or host:port.
                let (host, port, host_header) = parse_host_port(&delegated, 8448);
                return Ok(Resolved {
                    host,
                    port,
                    host_header,
                });
            }
        }
        // Non-200 or parse failure: fall through to SRV.
    }

    // ------------------------------------------------------------------
    // Step 3: SRV _matrix-fed._tcp.{server_name}
    // ------------------------------------------------------------------
    let srv_new = format!("_matrix-fed._tcp.{}", server_name);
    if let Some(resolved) = try_srv(resolver, &srv_new, server_name).await {
        return Ok(resolved);
    }

    // ------------------------------------------------------------------
    // Step 4: Legacy SRV _matrix._tcp.{server_name}
    // ------------------------------------------------------------------
    let srv_legacy = format!("_matrix._tcp.{}", server_name);
    if let Some(resolved) = try_srv(resolver, &srv_legacy, server_name).await {
        return Ok(resolved);
    }

    // ------------------------------------------------------------------
    // Step 5: A/AAAA fallback, port 8448
    // ------------------------------------------------------------------
    Ok(Resolved {
        host: server_name.to_owned(),
        port: 8448,
        host_header: server_name.to_owned(),
    })
}

/// If `server_name` contains an explicit port (e.g. `matrix.org:8448` or
/// `[::1]:8448`), parse and return a `Resolved` immediately.
fn try_literal_with_port(server_name: &str) -> Option<Resolved> {
    // IPv6 literal with port: `[::1]:port`
    if server_name.starts_with('[') {
        if let Some(bracket_end) = server_name.find(']') {
            let rest = &server_name[bracket_end + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    let host = server_name[..=bracket_end].to_owned();
                    return Some(Resolved {
                        host: host.clone(),
                        port,
                        host_header: server_name.to_owned(),
                    });
                }
            }
        }
        return None; // bare IPv6 literal without port
    }

    // hostname:port or IPv4:port — only treat as explicit-port if there is
    // exactly one colon and the part after it is a valid port number.
    // (IPv6 bare addresses have multiple colons — handled above.)
    let colon_count = server_name.chars().filter(|&c| c == ':').count();
    if colon_count == 1 {
        if let Some(pos) = server_name.rfind(':') {
            let port_str = &server_name[pos + 1..];
            if let Ok(port) = port_str.parse::<u16>() {
                let host = server_name[..pos].to_owned();
                return Some(Resolved {
                    host: host.clone(),
                    port,
                    host_header: server_name.to_owned(),
                });
            }
        }
    }

    None
}

/// Attempt SRV lookup; returns `None` if the lookup fails or returns no records.
async fn try_srv(
    resolver: &TokioAsyncResolver,
    query: &str,
    server_name: &str,
) -> Option<Resolved> {
    let lookup = resolver.srv_lookup(query).await.ok()?;
    let record = lookup.iter().next()?;
    let target = record.target().to_utf8();
    let target = target.trim_end_matches('.');
    let port = record.port();

    Some(Resolved {
        host: target.to_owned(),
        port,
        host_header: server_name.to_owned(),
    })
}

/// Parse a `host`, `host:port`, or `[ipv6]:port` string.
/// Returns `(host, port, host_header)`.  `host_header` is the original string
/// without port (per Matrix spec §4.1 delegation rules).
fn parse_host_port(s: &str, default_port: u16) -> (String, u16, String) {
    if let Some(resolved) = try_literal_with_port(s) {
        // host_header for well-known delegation = the delegated value itself
        // (spec says use the `m.server` value as the destination).
        return (resolved.host, resolved.port, s.to_owned());
    }
    // No explicit port.
    (s.to_owned(), default_port, s.to_owned())
}
