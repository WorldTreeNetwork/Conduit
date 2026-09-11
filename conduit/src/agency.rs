//! Agency — capability tokens (Biscuits).
//!
//! Layer two of the IdentiKey split.  Identity answers *who is this*
//! ([`crate::identity`]); agency answers *what may this holder do*.  A
//! Biscuit is not a proof of identity, and an identity proof is not a
//! grant: the two never substitute for one another.
//!
//! Format follows identikey-protocol `identikey-capability-v1`.  The
//! authority block is signed by a homeserver **minter** key that is
//! distinct from the Matrix server signing key and from any user
//! identity key.  A root token asserts:
//!
//! ```text
//! user("@alice:example.com");
//! device("ABCDEF");
//! server("example.com");
//! epoch(3);
//! right("cs");
//! check if time($time), $time < 2026-09-11T00:00:00Z;
//! check if epoch($e), device_epoch($e);
//! ```
//!
//! The `device_epoch` fact is injected by the verifier from the device
//! row.  Bumping that row's epoch invalidates every token minted for
//! the device without a denylist — logout and device revocation keep
//! working.  Note that the two facts deliberately carry *different*
//! names: injecting `epoch(4)` alongside an authority `epoch(3)` would
//! simply add a fact and no check would fail.
//!
//! Attenuation is the delegation primitive.  A holder may append blocks
//! that add checks (a room subset, a shorter TTL); appended blocks
//! cannot widen rights, because the authorizer only ever sees facts
//! from the authority block and from itself.
//!
//! No HTTP types live here.  The host extracts the Bearer bytes and
//! calls [`verify`].

use std::collections::HashMap;

use biscuit_auth::builder::{fact, string, Term};
use biscuit_auth::{
    Algorithm, AuthorizerBuilder, Biscuit, BiscuitBuilder, BlockBuilder, KeyPair, PrivateKey,
    PublicKey,
};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Rights
// ---------------------------------------------------------------------------

/// The right a normal client-server session carries.
pub const RIGHT_CS: &str = "cs";

/// The right an administrative operation requires.  Root CS tokens do
/// not carry it, and no attenuation can add it.
pub const RIGHT_ADMIN: &str = "admin";

/// Optional prefix accepted (and never emitted) on the wire, so that a
/// deployment may tag tokens without breaking Matrix clients.
const WIRE_PREFIX: &str = "biscuit:";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum AgencyError {
    #[error("minter key must be exactly 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("token is not a valid biscuit: {0}")]
    Malformed(String),

    #[error("token does not carry the required authority facts")]
    MissingClaims,

    #[error("token was minted for server {token_server:?}, not {expected:?}")]
    WrongServer {
        token_server: String,
        expected: String,
    },

    #[error("token rejected: {0}")]
    Unauthorized(String),

    #[error("biscuit error: {0}")]
    Biscuit(String),
}

type Result<T> = std::result::Result<T, AgencyError>;

// ---------------------------------------------------------------------------
// Minter
// ---------------------------------------------------------------------------

/// The homeserver's Biscuit signing key.
///
/// Persist [`Minter::seed`] the same way the Matrix server signing key
/// is stored — it is a private key, so it cannot be "hashed at rest".
/// Rotating it invalidates every outstanding token, which is the global
/// form of an epoch bump.
pub struct Minter {
    keypair: KeyPair,
    seed: [u8; 32],
}

impl std::fmt::Debug for Minter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Minter")
            .field("public_key", &self.public_key_bytes())
            .finish_non_exhaustive()
    }
}

impl Minter {
    /// Generate a fresh minter key.  The caller persists [`Minter::seed`].
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        use rand_core::RngCore as _;
        rand_core::OsRng.fill_bytes(&mut seed);
        // A 32-byte Ed25519 seed is always a valid private key.
        Self::from_seed(&seed).expect("32-byte seed is a valid ed25519 key")
    }

    /// Rehydrate a minter from its persisted 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| AgencyError::InvalidKeyLength(seed.len()))?;
        let private = PrivateKey::from_bytes(&seed, Algorithm::Ed25519)
            .map_err(|e| AgencyError::Biscuit(e.to_string()))?;
        Ok(Self {
            keypair: KeyPair::from(&private),
            seed,
        })
    }

    /// The private seed, for persistence.  Handle like a signing key.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The public key verifiers need.
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public()
    }

    /// The public key as raw bytes, for storage next to the seed.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.keypair.public().to_bytes().to_vec()
    }

    /// Mint a root capability token.  The returned string is what a
    /// Matrix client sends back as `Authorization: Bearer <token>`.
    pub fn mint_root(&self, claims: &RootClaims<'_>) -> Result<String> {
        let mut builder: BiscuitBuilder = Biscuit::builder();

        builder = builder
            .fact(fact("user", &[string(claims.user_id)]))
            .and_then(|b| b.fact(fact("device", &[string(claims.device_id)])))
            .and_then(|b| b.fact(fact("server", &[string(claims.server_name)])))
            .and_then(|b| b.fact(fact("epoch", &[Term::Integer(claims.epoch)])))
            .map_err(|e| AgencyError::Biscuit(e.to_string()))?;

        for right in claims.rights {
            builder = builder
                .fact(fact("right", &[string(right)]))
                .map_err(|e| AgencyError::Biscuit(e.to_string()))?;
        }

        // The epoch check compares the authority fact against the
        // verifier-injected device row.  Distinct predicate names are
        // load-bearing: same-name facts would merely coexist.
        builder = builder
            .code("check if epoch($e), device_epoch($e);")
            .map_err(|e| AgencyError::Biscuit(e.to_string()))?;

        if let Some(expires_at) = claims.expires_at {
            let mut params = HashMap::new();
            params.insert("exp".to_owned(), Term::Date(expires_at.max(0) as u64));
            builder = builder
                .code_with_params(
                    "check if time($time), $time < {exp};",
                    params,
                    HashMap::new(),
                )
                .map_err(|e| AgencyError::Biscuit(e.to_string()))?;
        }

        let biscuit = builder
            .build(&self.keypair)
            .map_err(|e| AgencyError::Biscuit(e.to_string()))?;

        biscuit
            .to_base64()
            .map_err(|e| AgencyError::Biscuit(e.to_string()))
    }
}

/// The facts a freshly minted root token asserts.
#[derive(Debug, Clone)]
pub struct RootClaims<'a> {
    pub user_id: &'a str,
    pub device_id: &'a str,
    pub server_name: &'a str,
    /// The device row's current epoch.  Verification fails once the row
    /// moves past this value.
    pub epoch: i64,
    pub rights: &'a [&'a str],
    /// Unix seconds after which the token stops verifying.  `None`
    /// mints a token with no time check.
    pub expires_at: Option<i64>,
}

// ---------------------------------------------------------------------------
// Parsing and verification
// ---------------------------------------------------------------------------

/// The authority facts carried by a token, after signature verification
/// but *before* the Datalog checks have run.
///
/// The host needs these to look up the device row (and its epoch) that
/// [`VerifyContext`] requires — that lookup is I/O, so it cannot happen
/// inside the pure verify step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenClaims {
    pub user_id: String,
    pub device_id: String,
    pub server_name: String,
    pub epoch: i64,
}

/// Everything the verifier injects into the Datalog world.
#[derive(Debug, Clone)]
pub struct VerifyContext {
    /// Current time in Unix seconds.
    pub now: i64,
    /// The epoch stored on the device row right now.
    pub device_epoch: i64,
    /// This homeserver's name.
    pub server_name: String,
    /// The right this request needs, e.g. [`RIGHT_CS`].
    pub required_right: String,
    /// Room the request is scoped to, when it is scoped to one.
    pub room_id: Option<String>,
    /// Operation the request is scoped to, when it is scoped to one.
    pub operation: Option<String>,
}

impl VerifyContext {
    /// A context for an unscoped client-server request.
    pub fn cs(server_name: impl Into<String>, now: i64, device_epoch: i64) -> Self {
        Self {
            now,
            device_epoch,
            server_name: server_name.into(),
            required_right: RIGHT_CS.to_owned(),
            room_id: None,
            operation: None,
        }
    }

    /// Scope this context to a room and an operation.  Root tokens are
    /// unaffected; attenuated tokens bind their room / operation checks
    /// against these facts.
    pub fn scoped(mut self, room_id: impl Into<String>, operation: impl Into<String>) -> Self {
        self.room_id = Some(room_id.into());
        self.operation = Some(operation.into());
        self
    }

    /// Require a different right (e.g. [`RIGHT_ADMIN`]).
    pub fn requiring(mut self, right: impl Into<String>) -> Self {
        self.required_right = right.into();
        self
    }
}

/// A verified capability token.
///
/// Carries the parsed `Biscuit` so a later, narrower authorization can
/// inject `room` / `operation` facts without re-verifying the signature
/// chain — see [`Grant::authorize`].
#[derive(Debug, Clone)]
pub struct Grant {
    pub user_id: String,
    pub device_id: String,
    pub server_name: String,
    pub epoch: i64,
    biscuit: Biscuit,
}

impl Grant {
    /// The verified token itself.
    pub fn biscuit(&self) -> &Biscuit {
        &self.biscuit
    }

    /// Re-run authorization against a narrower context.  Cheap: the
    /// signature chain was already checked when the grant was built.
    pub fn authorize(&self, ctx: &VerifyContext) -> Result<()> {
        authorize_biscuit(&self.biscuit, ctx)
    }

    /// Append an attenuation block written in Datalog, returning a new
    /// wire token.  Appended blocks may only *narrow*: facts they add
    /// are invisible to the authorizer, so no block can grant a right
    /// the authority block did not.
    pub fn attenuate(&self, code: &str) -> Result<String> {
        let block = BlockBuilder::new()
            .code(code)
            .map_err(|e| AgencyError::Biscuit(e.to_string()))?;
        let appended = self
            .biscuit
            .append(block)
            .map_err(|e| AgencyError::Biscuit(e.to_string()))?;
        appended
            .to_base64()
            .map_err(|e| AgencyError::Biscuit(e.to_string()))
    }
}

/// Strip the optional `biscuit:` wire prefix.
fn strip_prefix(token: &str) -> &str {
    token.strip_prefix(WIRE_PREFIX).unwrap_or(token).trim()
}

/// Parse a wire token and verify its signature chain, returning the
/// authority facts.  Datalog checks have **not** run yet: a token that
/// parses is not yet authorized.
pub fn parse_claims(minter_public: &PublicKey, token: &str) -> Result<TokenClaims> {
    let biscuit = parse(minter_public, token)?;
    claims_of(&biscuit)
}

/// Verify a wire token end to end: signature chain, then Datalog
/// against the injected facts in `ctx`.
pub fn verify(minter_public: &PublicKey, token: &str, ctx: &VerifyContext) -> Result<Grant> {
    let biscuit = parse(minter_public, token)?;
    let claims = claims_of(&biscuit)?;

    if claims.server_name != ctx.server_name {
        return Err(AgencyError::WrongServer {
            token_server: claims.server_name,
            expected: ctx.server_name.clone(),
        });
    }

    authorize_biscuit(&biscuit, ctx)?;

    Ok(Grant {
        user_id: claims.user_id,
        device_id: claims.device_id,
        server_name: claims.server_name,
        epoch: claims.epoch,
        biscuit,
    })
}

/// Rehydrate a minter public key from stored bytes.
pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_bytes(bytes, Algorithm::Ed25519).map_err(|e| AgencyError::Biscuit(e.to_string()))
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn parse(minter_public: &PublicKey, token: &str) -> Result<Biscuit> {
    Biscuit::from_base64(strip_prefix(token), *minter_public)
        .map_err(|e| AgencyError::Malformed(e.to_string()))
}

fn claims_of(biscuit: &Biscuit) -> Result<TokenClaims> {
    let mut authorizer = AuthorizerBuilder::new()
        .build(biscuit)
        .map_err(|e| AgencyError::Biscuit(e.to_string()))?;

    // Only authority-block facts reach the authorizer's world, so an
    // appended block cannot forge a different user or epoch here.
    let rows: Vec<(String, String, String, i64)> = authorizer
        .query("claims($u, $d, $s, $e) <- user($u), device($d), server($s), epoch($e)")
        .map_err(|e| AgencyError::Biscuit(e.to_string()))?;

    let (user_id, device_id, server_name, epoch) =
        rows.into_iter().next().ok_or(AgencyError::MissingClaims)?;

    Ok(TokenClaims {
        user_id,
        device_id,
        server_name,
        epoch,
    })
}

fn authorize_biscuit(biscuit: &Biscuit, ctx: &VerifyContext) -> Result<()> {
    let mut builder = AuthorizerBuilder::new()
        .fact(fact("time", &[Term::Date(ctx.now.max(0) as u64)]))
        .and_then(|b| b.fact(fact("device_epoch", &[Term::Integer(ctx.device_epoch)])))
        .map_err(|e| AgencyError::Biscuit(e.to_string()))?;

    if let Some(room_id) = &ctx.room_id {
        builder = builder
            .fact(fact("room", &[string(room_id)]))
            .map_err(|e| AgencyError::Biscuit(e.to_string()))?;
    }
    if let Some(operation) = &ctx.operation {
        builder = builder
            .fact(fact("operation", &[string(operation)]))
            .map_err(|e| AgencyError::Biscuit(e.to_string()))?;
    }

    let mut params = HashMap::new();
    params.insert("right".to_owned(), string(&ctx.required_right));
    builder = builder
        .code_with_params("allow if right({right});", params, HashMap::new())
        .map_err(|e| AgencyError::Biscuit(e.to_string()))?;

    let mut authorizer = builder
        .build(biscuit)
        .map_err(|e| AgencyError::Biscuit(e.to_string()))?;

    authorizer
        .authorize()
        .map(|_| ())
        .map_err(|e| AgencyError::Unauthorized(e.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "example.com";
    const USER: &str = "@alice:example.com";
    const DEVICE: &str = "COND1234";
    const NOW: i64 = 1_760_000_000;

    fn claims(epoch: i64, expires_at: Option<i64>) -> RootClaims<'static> {
        RootClaims {
            user_id: USER,
            device_id: DEVICE,
            server_name: SERVER,
            epoch,
            rights: &[RIGHT_CS],
            expires_at,
        }
    }

    fn ctx(now: i64, device_epoch: i64) -> VerifyContext {
        VerifyContext::cs(SERVER, now, device_epoch)
    }

    // -----------------------------------------------------------------------
    // Epoch. Written first, per the advise note: the naive shape (inject
    // `epoch` under its own name) passes trivially, so this test is the
    // one that proves the check is real.
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_bump_revokes_the_token() {
        let minter = Minter::generate();
        let token = minter.mint_root(&claims(3, Some(NOW + 3600))).unwrap();

        // Same epoch: fine.
        verify(&minter.public_key(), &token, &ctx(NOW, 3)).expect("epoch 3 verifies");

        // Device logged out; the row moved to 4.  The old token dies
        // with no denylist involved.
        let err = verify(&minter.public_key(), &token, &ctx(NOW, 4)).unwrap_err();
        assert!(
            matches!(err, AgencyError::Unauthorized(_)),
            "expected unauthorized, got {err:?}"
        );
    }

    #[test]
    fn epoch_fact_alone_does_not_satisfy_the_check() {
        // Guards the trivial-pass shape: a token minted with no device
        // row to compare against must not authorize.  We simulate the
        // "no matching device_epoch" world by verifying at an epoch the
        // device never had.
        let minter = Minter::generate();
        let token = minter.mint_root(&claims(0, None)).unwrap();
        assert!(verify(&minter.public_key(), &token, &ctx(NOW, 1)).is_err());
        assert!(verify(&minter.public_key(), &token, &ctx(NOW, 0)).is_ok());
    }

    // -----------------------------------------------------------------------
    // Mint / verify round trip
    // -----------------------------------------------------------------------

    #[test]
    fn mint_and_verify_round_trip() {
        let minter = Minter::generate();
        let token = minter.mint_root(&claims(1, Some(NOW + 60))).unwrap();

        let grant = verify(&minter.public_key(), &token, &ctx(NOW, 1)).unwrap();
        assert_eq!(grant.user_id, USER);
        assert_eq!(grant.device_id, DEVICE);
        assert_eq!(grant.server_name, SERVER);
        assert_eq!(grant.epoch, 1);
    }

    #[test]
    fn wire_prefix_is_accepted() {
        let minter = Minter::generate();
        let token = minter.mint_root(&claims(1, None)).unwrap();
        let prefixed = format!("biscuit:{token}");
        assert!(verify(&minter.public_key(), &prefixed, &ctx(NOW, 1)).is_ok());
    }

    #[test]
    fn claims_are_readable_before_authorization() {
        let minter = Minter::generate();
        // An expired token still parses — the host needs the device id
        // to find the epoch row before it can authorize.
        let token = minter.mint_root(&claims(7, Some(NOW - 1))).unwrap();
        let parsed = parse_claims(&minter.public_key(), &token).unwrap();
        assert_eq!(parsed.user_id, USER);
        assert_eq!(parsed.device_id, DEVICE);
        assert_eq!(parsed.epoch, 7);
        assert!(verify(&minter.public_key(), &token, &ctx(NOW, 7)).is_err());
    }

    #[test]
    fn seed_round_trip_preserves_the_key() {
        let minter = Minter::generate();
        let token = minter.mint_root(&claims(1, None)).unwrap();
        let rehydrated = Minter::from_seed(minter.seed()).unwrap();
        assert_eq!(rehydrated.public_key_bytes(), minter.public_key_bytes());
        assert!(verify(&rehydrated.public_key(), &token, &ctx(NOW, 1)).is_ok());
    }

    #[test]
    fn short_seed_is_rejected() {
        let err = Minter::from_seed(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, AgencyError::InvalidKeyLength(16)));
    }

    // -----------------------------------------------------------------------
    // Expiry
    // -----------------------------------------------------------------------

    #[test]
    fn expired_token_is_rejected() {
        let minter = Minter::generate();
        let token = minter.mint_root(&claims(1, Some(NOW + 10))).unwrap();

        assert!(verify(&minter.public_key(), &token, &ctx(NOW, 1)).is_ok());
        let err = verify(&minter.public_key(), &token, &ctx(NOW + 11, 1)).unwrap_err();
        assert!(
            matches!(err, AgencyError::Unauthorized(_)),
            "expected unauthorized, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Forgery and cross-server confusion
    // -----------------------------------------------------------------------

    #[test]
    fn token_from_another_minter_is_rejected() {
        let mint_a = Minter::generate();
        let mint_b = Minter::generate();
        let token = mint_a.mint_root(&claims(1, None)).unwrap();

        let err = verify(&mint_b.public_key(), &token, &ctx(NOW, 1)).unwrap_err();
        assert!(matches!(err, AgencyError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn token_for_another_server_is_rejected() {
        let minter = Minter::generate();
        let other = RootClaims {
            server_name: "elsewhere.example",
            ..claims(1, None)
        };
        let token = minter.mint_root(&other).unwrap();

        let err = verify(&minter.public_key(), &token, &ctx(NOW, 1)).unwrap_err();
        assert!(matches!(err, AgencyError::WrongServer { .. }), "got {err:?}");
    }

    #[test]
    fn garbage_is_not_a_token() {
        let minter = Minter::generate();
        assert!(verify(&minter.public_key(), "not-a-biscuit", &ctx(NOW, 1)).is_err());
    }

    // -----------------------------------------------------------------------
    // Attenuation
    // -----------------------------------------------------------------------

    #[test]
    fn attenuation_cannot_add_admin() {
        let minter = Minter::generate();
        let token = minter.mint_root(&claims(1, None)).unwrap();
        let grant = verify(&minter.public_key(), &token, &ctx(NOW, 1)).unwrap();

        // The holder tries to promote itself.
        let widened = grant.attenuate(r#"right("admin");"#).unwrap();

        // The root token never had admin, and the appended fact is
        // invisible to the authorizer.
        let admin_ctx = ctx(NOW, 1).requiring(RIGHT_ADMIN);
        assert!(verify(&minter.public_key(), &token, &admin_ctx).is_err());
        assert!(verify(&minter.public_key(), &widened, &admin_ctx).is_err());

        // …and the attenuated token still works for what it did have.
        assert!(verify(&minter.public_key(), &widened, &ctx(NOW, 1)).is_ok());
    }

    #[test]
    fn attenuation_can_narrow_to_one_room() {
        let minter = Minter::generate();
        let token = minter.mint_root(&claims(1, None)).unwrap();
        let grant = verify(&minter.public_key(), &token, &ctx(NOW, 1)).unwrap();

        let room_only = grant
            .attenuate(r#"check if room("!kitchen:example.com");"#)
            .unwrap();

        let allowed = ctx(NOW, 1).scoped("!kitchen:example.com", "read");
        let denied = ctx(NOW, 1).scoped("!attic:example.com", "read");

        assert!(verify(&minter.public_key(), &room_only, &allowed).is_ok());
        assert!(verify(&minter.public_key(), &room_only, &denied).is_err());
        // The root token is unscoped and passes either way.
        assert!(verify(&minter.public_key(), &token, &denied).is_ok());
    }

    #[test]
    fn attenuation_can_shorten_the_ttl() {
        let minter = Minter::generate();
        let token = minter.mint_root(&claims(1, Some(NOW + 3600))).unwrap();
        let grant = verify(&minter.public_key(), &token, &ctx(NOW, 1)).unwrap();

        let short = grant
            .attenuate("check if time($time), $time < 2025-10-09T07:33:20Z;")
            .unwrap();
        // 2025-10-09T07:33:20Z is NOW - 31536000 (a year before NOW).
        assert!(verify(&minter.public_key(), &short, &ctx(NOW, 1)).is_err());
        assert!(verify(&minter.public_key(), &token, &ctx(NOW, 1)).is_ok());
    }

    #[test]
    fn grant_re_authorizes_without_reparsing() {
        let minter = Minter::generate();
        let token = minter.mint_root(&claims(1, None)).unwrap();
        let grant = verify(&minter.public_key(), &token, &ctx(NOW, 1)).unwrap();

        // The extractor verified once; a handler narrows later.
        grant
            .authorize(&ctx(NOW, 1).scoped("!room:example.com", "read"))
            .expect("root grant covers any room");
        assert!(grant.authorize(&ctx(NOW, 1).requiring(RIGHT_ADMIN)).is_err());
    }
}
