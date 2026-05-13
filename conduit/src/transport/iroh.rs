//! iroh-based peer-to-peer transport (feature `iroh`).
//!
//! Enabled with `--features iroh`.  Binds a real `iroh::Endpoint` whose
//! identity is deterministically derived from the server's Ed25519 signing
//! key, so federation identity and transport identity are the same — no
//! confused-deputy.
//!
//! ALPN used on every stream: [`CONDUIT_FEDERATION_ALPN`].

use thiserror::Error;

use super::Transport;

// ---------------------------------------------------------------------------
// ALPN
// ---------------------------------------------------------------------------

/// Application-layer protocol identifier for Conduit federation over iroh.
/// All iroh streams carrying federation traffic use this ALPN.
pub const CONDUIT_FEDERATION_ALPN: &[u8] = b"conduit/federation/0";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum IrohError {
    #[error("failed to bind iroh endpoint: {0}")]
    Bind(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

// ---------------------------------------------------------------------------
// Key derivation (91r.3)
// ---------------------------------------------------------------------------

/// Derive an iroh [`SecretKey`][iroh::SecretKey] from the server signing key.
///
/// Uses the 32-byte Ed25519 seed from `server_key.signing_key` directly as
/// the iroh secret key bytes.  Both use Curve25519/Ed25519 arithmetic, so the
/// same 32 raw bytes produce a valid iroh key.  This makes the iroh `NodeId`
/// a deterministic function of the server signing key — the two identities
/// are permanently coupled.
pub fn derive_iroh_secret(server_key: &crate::keys::ServerKey) -> iroh::SecretKey {
    let seed: [u8; 32] = server_key.signing_key.to_bytes();
    iroh::SecretKey::from_bytes(&seed)
}

// ---------------------------------------------------------------------------
// Endpoint binding (91r.2)
// ---------------------------------------------------------------------------

/// Bind an iroh [`Endpoint`][iroh::Endpoint] whose identity is derived from
/// `server_key`.
///
/// The endpoint listens for incoming connections on
/// [`CONDUIT_FEDERATION_ALPN`].
pub async fn bind_endpoint(
    server_key: &crate::keys::ServerKey,
) -> Result<iroh::Endpoint, IrohError> {
    let secret = derive_iroh_secret(server_key);
    iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret)
        .alpns(vec![CONDUIT_FEDERATION_ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| IrohError::Bind(Box::new(e)))
}

// ---------------------------------------------------------------------------
// Transport marker
// ---------------------------------------------------------------------------

/// Live iroh transport — holds the bound endpoint.
pub struct IrohTransport {
    pub endpoint: iroh::Endpoint,
}

impl IrohTransport {
    pub fn new(endpoint: iroh::Endpoint) -> Self {
        Self { endpoint }
    }
}

impl Transport for IrohTransport {
    fn name(&self) -> &'static str {
        "iroh"
    }
}
