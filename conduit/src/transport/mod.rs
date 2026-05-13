//! Transport abstraction.
//!
//! Matrix is canonically HTTPS, but we keep the transport pluggable.
//! HTTP is supplied by the host (see `conduit-server` for an axum
//! mount). An optional iroh-based P2P transport can be enabled with
//! `--features iroh` (adds roughly 30MB once linked).

#[cfg(feature = "iroh")]
pub mod iroh;

/// Marker trait for transports. Real wiring is host-specific; this
/// gives us a place to hang per-transport state.
pub trait Transport: Send + Sync + 'static {
    fn name(&self) -> &'static str;
}
