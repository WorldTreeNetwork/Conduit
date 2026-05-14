//! Per-token / per-IP rate limiter for CS-API (conduit-9m4).
//!
//! Same token-bucket shape as `federation::rate_limit` but keyed on either
//! the SHA256 of the access token (authenticated paths) or the remote IP
//! (unauthenticated paths like /register and /login). Two separate rate
//! settings let us be generous with logged-in users while clamping down on
//! pre-auth flood attempts.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self, rate: f64, burst: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Shared limiter with separate buckets for authenticated tokens and
/// pre-auth IPs.
#[derive(Clone)]
pub struct CsRateLimiter {
    inner: Arc<Mutex<HashMap<String, Bucket>>>,
    /// Rate for authenticated requests (keyed on token hash).
    auth_rate: f64,
    auth_burst: f64,
    /// Rate for unauthenticated requests (keyed on remote IP). Tighter so
    /// a single host can't flood /register or /login.
    anon_rate: f64,
    anon_burst: f64,
}

impl CsRateLimiter {
    /// Defaults: 100 r/s burst 200 for authenticated tokens; 10 r/s burst 20
    /// for unauthenticated IPs.
    pub fn default_cs() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            auth_rate: 100.0,
            auth_burst: 200.0,
            anon_rate: 10.0,
            anon_burst: 20.0,
        }
    }

    /// Override defaults; used by tests.
    pub fn new(auth_rate: f64, auth_burst: f64, anon_rate: f64, anon_burst: f64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            auth_rate,
            auth_burst,
            anon_rate,
            anon_burst,
        }
    }

    async fn try_consume(&self, key: &str, authed: bool) -> bool {
        let (rate, burst) = if authed {
            (self.auth_rate, self.auth_burst)
        } else {
            (self.anon_rate, self.anon_burst)
        };
        let mut map = self.inner.lock().await;
        let bucket = map.entry(key.to_owned()).or_insert_with(|| Bucket::new(burst));
        bucket.try_consume(rate, burst)
    }
}

/// Extract the bearer access token from `Authorization: Bearer ...`.
fn bearer_token(req: &Request<Body>) -> Option<String> {
    req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_owned())
}

/// SHA-256 of `token`, base64url-encoded (matches the access_token storage
/// hash so we don't fingerprint the same client twice across endpoints).
fn token_hash(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(h.finalize())
}

/// axum middleware. Authenticated tokens get a generous per-token bucket;
/// pre-auth paths get a tight per-IP bucket (falling back to a shared
/// "ip:unknown" bucket when ConnectInfo isn't attached — e.g. iroh transport,
/// which has no IP). On overflow returns 429 `M_LIMIT_EXCEEDED`.
pub async fn cs_rate_limit(
    State(limiter): State<CsRateLimiter>,
    addr: Option<Extension<ConnectInfo<SocketAddr>>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let (key, authed) = match bearer_token(&req) {
        Some(t) => (format!("tok:{}", token_hash(&t)), true),
        None => {
            let ip = addr
                .map(|Extension(ConnectInfo(a))| a.ip().to_string())
                .unwrap_or_else(|| "unknown".to_owned());
            (format!("ip:{ip}"), false)
        }
    };

    if !limiter.try_consume(&key, authed).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "errcode": "M_LIMIT_EXCEEDED",
                "error": "Too many requests",
                "retry_after_ms": 1000,
            })),
        )
            .into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authed_and_anon_have_separate_limits() {
        let rl = CsRateLimiter::new(1000.0, 5.0, 1.0, 2.0);
        // Anon is tighter: burst 2.
        assert!(rl.try_consume("ip:1.2.3.4", false).await);
        assert!(rl.try_consume("ip:1.2.3.4", false).await);
        assert!(!rl.try_consume("ip:1.2.3.4", false).await);
        // Same IP under a token gets the authed bucket: burst 5.
        for _ in 0..5 {
            assert!(rl.try_consume("tok:abc", true).await);
        }
        assert!(!rl.try_consume("tok:abc", true).await);
    }

    #[tokio::test]
    async fn tokens_refill() {
        let rl = CsRateLimiter::new(1000.0, 1.0, 1.0, 1.0);
        assert!(rl.try_consume("tok:a", true).await);
        assert!(!rl.try_consume("tok:a", true).await);
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert!(rl.try_consume("tok:a", true).await);
    }
}
