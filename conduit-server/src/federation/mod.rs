//! Federation outbound client (E08).
//!
//! Provides:
//! - [`Client`]: high-level typed methods for every outbound SS-API endpoint.
//! - [`Queue`]: per-destination send queue with exponential backoff.
//! - [`discovery`]: server name → host:port resolution (well-known / SRV / DNS).
//! - [`auth`]: X-Matrix request signing.
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
pub mod queue;

pub use client::{
    Client, DirectoryResponse, FederationError, MakeJoinResponse, SendJoinResponse,
    StateIdsResponse, StateResponse, TransactionResponse,
};
pub use queue::Queue;

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
