//! Per-origin token-bucket rate limiter (x2r.11).
//!
//! Defaults: 50 requests/sec/origin, burst 100.
//! Rejects with 429 `M_LIMIT_EXCEEDED` when the bucket is exhausted.
//!
//! The rate limiter must be applied **after** the X-Matrix auth middleware so
//! that `FederationOrigin` is available in extensions.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tokio::sync::Mutex;

use super::middleware::FederationOrigin;

// ---------------------------------------------------------------------------
// Token-bucket state per origin
// ---------------------------------------------------------------------------

struct Bucket {
    /// Current number of tokens (fractional).
    tokens: f64,
    /// Timestamp of last refill.
    last_refill: Instant,
}

impl Bucket {
    fn new(burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    /// Attempt to consume one token, refilling first based on elapsed time.
    ///
    /// Returns `true` if the request is allowed, `false` if the bucket is empty.
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

// ---------------------------------------------------------------------------
// Shared rate-limiter state
// ---------------------------------------------------------------------------

/// Per-origin token-bucket rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, Bucket>>>,
    /// Tokens refilled per second per origin.
    rate: f64,
    /// Maximum burst size (initial/maximum token count).
    burst: f64,
}

impl RateLimiter {
    /// Create a new rate limiter with the given rate and burst.
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            rate,
            burst,
        }
    }

    /// Create with defaults: 50 req/s, burst 100.
    pub fn default_federation() -> Self {
        Self::new(50.0, 100.0)
    }

    /// Attempt to consume one token for `origin`.
    pub async fn try_consume(&self, origin: &str) -> bool {
        let mut map = self.inner.lock().await;
        let bucket = map
            .entry(origin.to_owned())
            .or_insert_with(|| Bucket::new(self.burst));
        bucket.try_consume(self.rate, self.burst)
    }

    /// Periodically evict buckets that are full (to bound memory use).
    /// Call from a background task.
    pub async fn evict_full(&self) {
        let mut map = self.inner.lock().await;
        let burst = self.burst;
        map.retain(|_, bucket| {
            // Keep buckets that have been used recently (not yet refilled to burst).
            bucket.tokens < burst - 0.5
        });
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::default_federation()
    }
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// axum middleware that applies the per-origin rate limit.
///
/// Must run **after** [`super::middleware::verify_xmatrix`] so that
/// `FederationOrigin` is available.  Unauthenticated requests (no extension)
/// are rejected outright.
pub async fn rate_limit(
    axum::extract::State(limiter): axum::extract::State<RateLimiter>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let origin = match req.extensions().get::<FederationOrigin>() {
        Some(o) => o.server_name.clone(),
        None => {
            // No authenticated origin — this middleware should only run after auth.
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "errcode": "M_UNAUTHORIZED", "error": "Not authenticated" })),
            )
                .into_response();
        }
    };

    if !limiter.try_consume(&origin).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "errcode": "M_LIMIT_EXCEEDED",
                "error": "Too many requests from this origin",
                "retry_after_ms": 1000,
            })),
        )
            .into_response();
    }

    next.run(req).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bucket_allows_up_to_burst() {
        let rl = RateLimiter::new(1.0, 5.0);
        // Should allow 5 requests immediately (burst).
        for _ in 0..5 {
            assert!(rl.try_consume("server.example").await);
        }
        // 6th should be denied.
        assert!(!rl.try_consume("server.example").await);
    }

    #[tokio::test]
    async fn different_origins_independent() {
        let rl = RateLimiter::new(1.0, 2.0);
        assert!(rl.try_consume("a.example").await);
        assert!(rl.try_consume("a.example").await);
        assert!(!rl.try_consume("a.example").await);
        // b is independent.
        assert!(rl.try_consume("b.example").await);
    }

    #[tokio::test]
    async fn tokens_refill_over_time() {
        let rl = RateLimiter::new(1000.0, 1.0);
        // Drain.
        assert!(rl.try_consume("c.example").await);
        assert!(!rl.try_consume("c.example").await);
        // Sleep briefly to allow token refill at 1000/s.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert!(rl.try_consume("c.example").await);
    }
}
