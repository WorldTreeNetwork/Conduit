//! Identity — who is this?
//!
//! Layer one of the IdentiKey split.  This module answers *who is
//! holding the key*, and nothing else.  A successful proof here is not
//! a grant: the caller mints a Biscuit ([`crate::agency`]) afterwards,
//! and only for an identity that is already linked to a local MXID.
//!
//! The on-ramp is identikey-protocol's challenge/response
//! (`identikey-auth`, Apache-2.0 OR BSD-2-Clause-Patent).  The verifier
//! issues an audience-bound, nonce-carrying [`Challenge`]; the claimant
//! signs it with a hardware- or software-held key; the verifier checks
//! the signature and burns the nonce.  identikey-core is **not** a
//! crate dependency — a host that wants it speaks OIDC to it as a
//! foreign OpenID Provider and asks the kernel to mint afterwards.
//!
//! ## Linking is not registration
//!
//! A verified fingerprint that no account has claimed **fails login**.
//! Linking happens in exactly two places: at registration, under the
//! registration policy the host already enforces, or through
//! [`bind_fingerprint`], which requires a capability grant for the
//! account being bound.  Without that rule the challenge endpoint would
//! be an open registration endpoint.

use std::sync::Mutex;

use identikey_auth::{
    verify_response, Challenge, ChallengeIssuer, InMemoryNonceStore, Response,
};
use thiserror::Error;

use crate::agency::Grant;
use crate::storage::Storage;

pub use identikey_auth::{Fingerprint, VerifyPolicy};

/// How long an issued challenge stays valid, in seconds.
pub const CHALLENGE_TTL_SECS: u64 = 120;

/// Clock skew tolerated when verifying a response, in seconds.
pub const CLOCK_SKEW_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("challenge response is malformed: {0}")]
    Malformed(String),

    #[error("challenge response did not verify: {0}")]
    NotVerified(String),

    #[error("no account is linked to that identity")]
    Unlinked,

    #[error("fingerprint is already linked to {0}")]
    AlreadyLinked(String),

    #[error("grant does not cover {0}")]
    NotYourAccount(String),

    #[error("storage error: {0}")]
    Storage(String),
}

type Result<T> = std::result::Result<T, IdentityError>;

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Issues and verifies identikey-auth challenges for one homeserver.
///
/// The audience is always the server name, so a response captured by
/// another verifier cannot be replayed here.
pub struct IdentityVerifier {
    server_name: String,
    policy: VerifyPolicy,
    issuer: ChallengeIssuer,
    nonces: Mutex<InMemoryNonceStore>,
}

impl std::fmt::Debug for IdentityVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityVerifier")
            .field("server_name", &self.server_name)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl IdentityVerifier {
    /// Build a verifier bound to `server_name` as its audience.
    ///
    /// `PqOptional` is the sane deployment default today: post-quantum
    /// signatures still verify when present, they are just not demanded.
    pub fn new(server_name: impl Into<String>, policy: VerifyPolicy) -> Self {
        let server_name = server_name.into();
        Self {
            issuer: ChallengeIssuer::new(server_name.clone(), CHALLENGE_TTL_SECS),
            server_name,
            policy,
            nonces: Mutex::new(InMemoryNonceStore::new()),
        }
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Issue a challenge.  `now` is Unix seconds.  The host serialises
    /// the returned bytes however its wire format prefers.
    pub fn issue_challenge(&self, now: u64) -> Vec<u8> {
        let mut nonces = self.nonces.lock().expect("nonce store poisoned");
        self.issuer.issue(&mut *nonces, now).to_bytes()
    }

    /// Verify a response and return the claimant's fingerprint.
    ///
    /// This proves possession of a key.  It says nothing about which
    /// account, if any, that key may act for.
    pub fn verify(&self, response_bytes: &[u8], now: u64) -> Result<String> {
        let response = Response::from_bytes(response_bytes)
            .map_err(|e| IdentityError::Malformed(e.to_string()))?;

        let mut nonces = self.nonces.lock().expect("nonce store poisoned");
        let verified = verify_response(
            &response,
            &self.server_name,
            now,
            CLOCK_SKEW_SECS,
            self.policy,
            &mut *nonces,
        )
        .map_err(|e| IdentityError::NotVerified(e.to_string()))?;

        Ok(verified.fingerprint.to_base58())
    }

    /// Verify a response and resolve it to a local MXID.
    ///
    /// Fails closed when the fingerprint is not linked: an unlinked
    /// identity never creates an account here.
    pub async fn login(
        &self,
        storage: &dyn Storage,
        response_bytes: &[u8],
        now: u64,
    ) -> Result<LoggedIn> {
        let fingerprint = self.verify(response_bytes, now)?;
        let user_id = storage
            .user_for_identikey(&fingerprint)
            .await
            .map_err(|e| IdentityError::Storage(e.to_string()))?
            .ok_or(IdentityError::Unlinked)?;
        Ok(LoggedIn {
            user_id,
            fingerprint,
        })
    }
}

/// The outcome of a successful identikey-auth login: an identity, not a
/// grant.  The caller mints the Biscuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedIn {
    pub user_id: String,
    pub fingerprint: String,
}

/// Parse challenge bytes (for hosts that need to inspect a challenge
/// they are about to hand out).
pub fn parse_challenge(bytes: &[u8]) -> Result<Challenge> {
    Challenge::from_bytes(bytes).map_err(|e| IdentityError::Malformed(e.to_string()))
}

// ---------------------------------------------------------------------------
// Linking
// ---------------------------------------------------------------------------

/// Link a fingerprint to an account at registration time.
///
/// The caller is responsible for having applied its registration policy
/// — this is the one path that may create a link without an existing
/// grant, because the account itself is being created.
pub async fn link_at_registration(
    storage: &dyn Storage,
    fingerprint: &str,
    user_id: &str,
) -> Result<()> {
    link(storage, fingerprint, user_id).await
}

/// Bind a fingerprint to an account that is already signed in.
///
/// Requires a capability grant for that same account, which is what
/// keeps the challenge endpoint from becoming open registration.
pub async fn bind_fingerprint(
    storage: &dyn Storage,
    grant: &Grant,
    fingerprint: &str,
    user_id: &str,
) -> Result<()> {
    if grant.user_id != user_id {
        return Err(IdentityError::NotYourAccount(user_id.to_owned()));
    }
    link(storage, fingerprint, user_id).await
}

async fn link(storage: &dyn Storage, fingerprint: &str, user_id: &str) -> Result<()> {
    if let Some(existing) = storage
        .user_for_identikey(fingerprint)
        .await
        .map_err(|e| IdentityError::Storage(e.to_string()))?
    {
        if existing != user_id {
            return Err(IdentityError::AlreadyLinked(existing));
        }
        return Ok(());
    }
    storage
        .link_identikey(fingerprint, user_id)
        .await
        .map_err(|e| IdentityError::Storage(e.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agency::{Minter, RootClaims, VerifyContext, RIGHT_CS};
    use crate::storage::MemoryStorage;
    use identikey_auth::{Signer as _, SoftwareSigner};

    const SERVER: &str = "example.com";
    const ALICE: &str = "@alice:example.com";
    const NOW: u64 = 1_760_000_000;

    fn verifier() -> IdentityVerifier {
        IdentityVerifier::new(SERVER, VerifyPolicy::PqOptional)
    }

    /// A claimant answering a challenge from `v`.
    fn respond(v: &IdentityVerifier, signer: &SoftwareSigner) -> Vec<u8> {
        let challenge_bytes = v.issue_challenge(NOW);
        let challenge = parse_challenge(&challenge_bytes).unwrap();
        signer.respond(&challenge).unwrap().to_bytes()
    }

    async fn storage_with_alice() -> MemoryStorage {
        let storage = MemoryStorage::default();
        storage.create_account(ALICE, None).await.unwrap();
        storage
    }

    #[tokio::test]
    async fn linked_fingerprint_logs_in_and_can_be_minted_for() {
        let storage = storage_with_alice().await;
        let v = verifier();
        let signer = SoftwareSigner::generate_ed25519();

        // Registration linked this identity.
        let fingerprint = signer.classical_public_key().fingerprint().to_base58();
        link_at_registration(&storage, &fingerprint, ALICE)
            .await
            .unwrap();

        let response = respond(&v, &signer);
        let logged_in = v.login(&storage, &response, NOW).await.unwrap();
        assert_eq!(logged_in.user_id, ALICE);

        // Identity proved; now — and only now — agency is minted.
        let minter = Minter::generate();
        let token = minter
            .mint_root(&RootClaims {
                user_id: &logged_in.user_id,
                device_id: "COND1",
                server_name: SERVER,
                epoch: 0,
                rights: &[RIGHT_CS],
                expires_at: None,
            })
            .unwrap();
        let grant = crate::agency::verify(
            &minter.public_key(),
            &token,
            &VerifyContext::cs(SERVER, NOW as i64, 0),
        )
        .unwrap();
        assert_eq!(grant.user_id, ALICE);
    }

    #[tokio::test]
    async fn unlinked_fingerprint_does_not_create_an_account() {
        let storage = MemoryStorage::default();
        let v = verifier();
        let signer = SoftwareSigner::generate_ed25519();

        let response = respond(&v, &signer);
        let err = v.login(&storage, &response, NOW).await.unwrap_err();
        assert!(matches!(err, IdentityError::Unlinked), "got {err:?}");

        // Crucially, nothing was created on the way out.
        let fingerprint = signer.classical_public_key().fingerprint().to_base58();
        assert!(storage
            .user_for_identikey(&fingerprint)
            .await
            .unwrap()
            .is_none());
        assert!(storage.get_account(ALICE).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn response_for_another_audience_fails_closed() {
        let storage = storage_with_alice().await;
        let ours = verifier();
        let theirs = IdentityVerifier::new("elsewhere.example", VerifyPolicy::PqOptional);
        let signer = SoftwareSigner::generate_ed25519();

        let fingerprint = signer.classical_public_key().fingerprint().to_base58();
        link_at_registration(&storage, &fingerprint, ALICE)
            .await
            .unwrap();

        // The claimant answers the *other* server's challenge.
        let response = respond(&theirs, &signer);
        let err = ours.login(&storage, &response, NOW).await.unwrap_err();
        assert!(matches!(err, IdentityError::NotVerified(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_replayed_response_is_rejected() {
        let storage = storage_with_alice().await;
        let v = verifier();
        let signer = SoftwareSigner::generate_ed25519();
        let fingerprint = signer.classical_public_key().fingerprint().to_base58();
        link_at_registration(&storage, &fingerprint, ALICE)
            .await
            .unwrap();

        let response = respond(&v, &signer);
        assert!(v.login(&storage, &response, NOW).await.is_ok());
        let err = v.login(&storage, &response, NOW).await.unwrap_err();
        assert!(matches!(err, IdentityError::NotVerified(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_tampered_response_is_rejected() {
        let storage = storage_with_alice().await;
        let v = verifier();
        let signer = SoftwareSigner::generate_ed25519();

        let mut response = respond(&v, &signer);
        let last = response.len() - 1;
        response[last] ^= 0xff;
        let err = v.login(&storage, &response, NOW).await.unwrap_err();
        assert!(
            matches!(
                err,
                IdentityError::NotVerified(_) | IdentityError::Malformed(_)
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn bind_requires_a_grant_for_that_account() {
        let storage = storage_with_alice().await;
        let minter = Minter::generate();
        let token = minter
            .mint_root(&RootClaims {
                user_id: "@bob:example.com",
                device_id: "COND2",
                server_name: SERVER,
                epoch: 0,
                rights: &[RIGHT_CS],
                expires_at: None,
            })
            .unwrap();
        let bobs_grant = crate::agency::verify(
            &minter.public_key(),
            &token,
            &VerifyContext::cs(SERVER, NOW as i64, 0),
        )
        .unwrap();

        // Bob cannot bind his key to Alice's account.
        let err = bind_fingerprint(&storage, &bobs_grant, "fp-of-bob", ALICE)
            .await
            .unwrap_err();
        assert!(matches!(err, IdentityError::NotYourAccount(_)), "got {err:?}");

        // …but he can bind it to his own.
        bind_fingerprint(&storage, &bobs_grant, "fp-of-bob", "@bob:example.com")
            .await
            .unwrap();
        assert_eq!(
            storage.user_for_identikey("fp-of-bob").await.unwrap(),
            Some("@bob:example.com".to_owned())
        );
    }

    #[tokio::test]
    async fn a_fingerprint_cannot_be_stolen_from_another_account() {
        let storage = storage_with_alice().await;
        link_at_registration(&storage, "fp-shared", ALICE)
            .await
            .unwrap();
        let err = link_at_registration(&storage, "fp-shared", "@bob:example.com")
            .await
            .unwrap_err();
        assert!(matches!(err, IdentityError::AlreadyLinked(_)), "got {err:?}");
    }
}
