//! iroh-based peer-to-peer transport (feature `iroh`).
//!
//! Enabled with `--features iroh`. Currently a stub — when you wire
//! this up, add `iroh = { version = "...", optional = true }` to
//! `conduit/Cargo.toml`'s `[dependencies]`, change the feature
//! definition to `iroh = ["dep:iroh"]`, and replace this module's
//! body with real endpoint plumbing.
//!
//! See <https://docs.rs/iroh>.

use super::Transport;

/// Placeholder iroh transport.
pub struct IrohTransport {
    // TODO: hold an `iroh::Endpoint` here.
    _private: (),
}

impl IrohTransport {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for IrohTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for IrohTransport {
    fn name(&self) -> &'static str {
        "iroh"
    }
}
