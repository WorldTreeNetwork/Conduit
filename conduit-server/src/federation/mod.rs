//! Federation module (E08 outbound + E09 inbound).
//!
//! Provides:
//! - [`Client`]: high-level typed methods for every outbound SS-API endpoint.
//! - [`Queue`]: per-destination send queue with exponential backoff.
//! - [`discovery`]: server name → host:port resolution (well-known / SRV / DNS).
//! - [`auth`]: X-Matrix request signing.
//! - [`middleware`]: X-Matrix inbound signature verification (E09 x2r.1).
//! - [`pipeline`]: Incoming PDU processing pipeline (E09 x2r.3, x2r.4).
//! - [`rate_limit`]: Per-origin token-bucket rate limiter (E09 x2r.11).
//! - [`server`]: Inbound federation HTTP handlers + router (E09 x2r.2, x2r.5–x2r.10).
//!
//! ## Wiring into AppState
//!
//! ```ignore
//! use conduit_server::federation;
//!
//! let fed_client = Arc::new(federation::Client::new(
//!     http.clone(), resolver, Arc::clone(&remote_keys),
//!     Arc::clone(&server_key), Arc::clone(&server_name),
//! ));
//! let federation_queue = Arc::new(federation::Queue::new(Arc::clone(&fed_client)));
//! ```

pub mod auth;
pub mod client;
pub mod discovery;
pub mod middleware;
pub mod pipeline;
pub mod queue;
pub mod rate_limit;
pub mod server;
#[cfg(feature = "iroh")]
pub mod iroh_client;
#[cfg(feature = "iroh")]
pub mod iroh_server;

pub use client::{
    Client, DirectoryResponse, FederationError, MakeJoinResponse, SendJoinResponse,
    StateIdsResponse, StateResponse, TransactionResponse,
};
pub use queue::Queue;
pub use middleware::XMatrixMiddlewareState;
pub use rate_limit::RateLimiter;
pub use server::FedState;
pub use server::federation_router;

// ---------------------------------------------------------------------------
// Shared utility
// ---------------------------------------------------------------------------

/// Current time in Unix milliseconds.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
