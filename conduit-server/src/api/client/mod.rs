//! Client-Server API handlers.
//!
//! Implements:
//!   POST /_matrix/client/v3/register
//!   GET  /_matrix/client/v3/login   (advertise flows)
//!   POST /_matrix/client/v3/login
//!   POST /_matrix/client/v3/logout
//!   GET  /_matrix/client/v3/account/whoami

pub mod account_data;
pub mod directory;
pub mod event_pipeline;
pub mod keys;
pub mod media;
pub mod presence;
pub mod probe;
pub mod rate_limit;
pub mod profile;
pub mod push;
pub mod receipts;
pub mod rooms;
pub mod sync;
pub mod typing;
pub mod uia;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{RwLock, broadcast};

pub use typing::TypingStore;
pub use presence::PresenceStore;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use conduit::agency::{self, Minter, RootClaims, VerifyContext, RIGHT_CS};
use conduit::identity::{IdentityVerifier, VerifyPolicy};
use conduit::keys::ServerKey;
use conduit::storage::Storage;

// ---------------------------------------------------------------------------
// AppState — imported from main.rs via a trait alias trick.
// We re-export a trait so main.rs can pass its AppState directly.
// ---------------------------------------------------------------------------

/// Minimal state surface that auth handlers need.
/// `main.rs` satisfies this by passing its concrete `AppState` which
/// implements `Clone` and holds `storage` + `server_name`.
/// Key type for the idempotency cache.
pub type TxnCacheKey = (String, String, String); // (user_id, device_id, txn_id)

pub trait AuthState: Clone + Send + Sync + 'static + conduit::room::RoomEventSender {
    fn storage(&self) -> &Arc<dyn Storage>;
    fn server_name(&self) -> &str;
    /// The server's signing key (ed25519).  Used by the event pipeline.
    fn server_key(&self) -> Arc<ServerKey>;
    /// Shared in-memory idempotency cache for `PUT /send/.../:txnId`.
    fn txn_cache(&self) -> &Arc<RwLock<HashMap<TxnCacheKey, String>>>;
    /// Broadcast sender for new stream positions.  `/sync` long-poll
    /// subscribes to this to wake up when new events arrive.
    fn events_tx(&self) -> &broadcast::Sender<i64>;
    /// Ephemeral in-memory typing store.
    fn typing_store(&self) -> &Arc<TypingStore>;
    /// Broadcast sender: emits room_id when typing state changes.
    fn typing_tx(&self) -> &broadcast::Sender<String>;
    /// Ephemeral in-memory presence store.
    fn presence_store(&self) -> &Arc<PresenceStore>;
    /// The Biscuit minter.  Capability tokens are signed with this key,
    /// which is deliberately not the Matrix server signing key.
    ///
    /// The default is an ephemeral, process-wide key: a host that does
    /// not persist one still works, but every restart invalidates every
    /// outstanding token.  `main.rs` overrides it with the stored key.
    fn minter(&self) -> Arc<Minter> {
        static EPHEMERAL: std::sync::OnceLock<Arc<Minter>> = std::sync::OnceLock::new();
        Arc::clone(EPHEMERAL.get_or_init(|| Arc::new(Minter::generate())))
    }

    /// The identikey-auth challenge verifier for this server name.
    ///
    /// Challenges are nonce-bound, so issuing and verifying must share
    /// one store.  The default keeps one per server name for the life
    /// of the process.
    fn identity_verifier(&self) -> Arc<IdentityVerifier> {
        static VERIFIERS: std::sync::OnceLock<
            std::sync::Mutex<HashMap<String, Arc<IdentityVerifier>>>,
        > = std::sync::OnceLock::new();
        let map = VERIFIERS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
        let mut map = map.lock().expect("verifier registry poisoned");
        Arc::clone(
            map.entry(self.server_name().to_owned())
                .or_insert_with(|| {
                    Arc::new(IdentityVerifier::new(
                        self.server_name(),
                        VerifyPolicy::PqOptional,
                    ))
                }),
        )
    }

    /// Optional outbound federation client (for cross-server CS-API paths
    /// like /sendToDevice and outbound device_list_update EDUs).
    /// Default `None` keeps tests that use a stub state working.
    fn federation_client(&self) -> Option<&Arc<crate::federation::Client>> {
        None
    }
    /// Optional outbound federation send queue.
    fn federation_queue(&self) -> Option<&Arc<crate::federation::Queue>> {
        None
    }
}

// ---------------------------------------------------------------------------
// MatrixError — standard Matrix JSON error response
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct MatrixError {
    pub errcode: &'static str,
    pub error: String,
}

impl MatrixError {
    fn new(errcode: &'static str, error: impl Into<String>) -> Self {
        Self { errcode, error: error.into() }
    }
    pub fn unknown_token() -> (StatusCode, Json<MatrixError>) {
        (StatusCode::UNAUTHORIZED, Json(Self::new("M_UNKNOWN_TOKEN", "Unrecognised access token")))
    }
    pub fn missing_token() -> (StatusCode, Json<MatrixError>) {
        (StatusCode::UNAUTHORIZED, Json(Self::new("M_MISSING_TOKEN", "Missing access token")))
    }
    pub fn forbidden(msg: impl Into<String>) -> (StatusCode, Json<MatrixError>) {
        (StatusCode::FORBIDDEN, Json(Self::new("M_FORBIDDEN", msg)))
    }
    pub fn user_in_use(user_id: &str) -> (StatusCode, Json<MatrixError>) {
        (StatusCode::BAD_REQUEST, Json(Self::new("M_USER_IN_USE", format!("User ID already taken: {user_id}"))))
    }
    pub fn invalid_username(msg: impl Into<String>) -> (StatusCode, Json<MatrixError>) {
        (StatusCode::BAD_REQUEST, Json(Self::new("M_INVALID_USERNAME", msg)))
    }
    pub fn bad_json(msg: impl Into<String>) -> (StatusCode, Json<MatrixError>) {
        (StatusCode::BAD_REQUEST, Json(Self::new("M_BAD_JSON", msg)))
    }
    pub fn unknown(msg: impl Into<String>) -> (StatusCode, Json<MatrixError>) {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(Self::new("M_UNKNOWN", msg)))
    }
    pub fn new_not_found(msg: impl Into<String>) -> (StatusCode, Json<MatrixError>) {
        (StatusCode::NOT_FOUND, Json(Self::new("M_NOT_FOUND", msg)))
    }
    /// Map a domain `conduit::Error` to the appropriate Matrix HTTP error.
    /// Preserves auth rejections as 403 M_FORBIDDEN instead of collapsing
    /// everything to 500 (conduit-29w / dbb0938 regression).
    pub fn from_conduit(e: conduit::Error) -> (StatusCode, Json<MatrixError>) {
        match e {
            conduit::Error::Forbidden(msg) => Self::forbidden(msg),
            conduit::Error::NotFound => Self::new_not_found("Not found"),
            other => Self::unknown(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

/// Generate a fresh opaque access token (32 random bytes, url-safe base64).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 hash of a raw token string → hex string stored in the DB.
///
/// Still used by the short-lived OpenID credential in `probe.rs`, which
/// is a bearer secret we compare, not a capability token.  It is no
/// longer the request-path source of truth for Matrix access tokens.
pub fn hash_token(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    hex::encode(digest)
}

/// How long a freshly minted client-server token stays valid.
///
/// The capability format requires a time check, so sessions are finite
/// rather than eternal.  Thirty days matches the common client
/// expectation of "stays logged in", and logging out early is an epoch
/// bump, not a wait.
pub const TOKEN_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// Mint a root capability token for a freshly authenticated session.
///
/// Identity has already been proven by the caller — password, an
/// identikey-auth response, or a verified foreign OIDC token.  This is
/// the agency half, and it is the only place a token is created.
pub async fn mint_access_token<S: AuthState>(
    state: &S,
    user_id: &str,
    device_id: &str,
) -> Result<String, String> {
    let epoch = state
        .storage()
        .device_epoch(user_id, device_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("device {device_id} does not exist"))?;

    state
        .minter()
        .mint_root(&RootClaims {
            user_id,
            device_id,
            server_name: state.server_name(),
            epoch,
            rights: &[RIGHT_CS],
            expires_at: Some(now_unix() + TOKEN_TTL_SECS),
        })
        .map_err(|e| e.to_string())
}

/// Current time in Unix seconds.
pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

// ---------------------------------------------------------------------------
// Password helpers (CPU-bound — run in spawn_blocking)
// ---------------------------------------------------------------------------

pub async fn hash_password(password: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

pub async fn verify_password(password: String, hash: String) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&hash).map_err(|e| e.to_string())?;
        Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
    })
    .await
    .map_err(|e| e.to_string())?
}

// ---------------------------------------------------------------------------
// AuthedUser extractor
// ---------------------------------------------------------------------------

/// Axum extractor that verifies a Bearer capability token and resolves
/// the owner.  Returns 401 on a missing, malformed, expired, or
/// epoch-stale token.
#[derive(Debug, Clone)]
pub struct AuthedUser {
    pub user_id: String,
    pub device_id: String,
    /// The verified capability token.
    ///
    /// Carried so a handler can authorize a narrower operation — a room,
    /// an op — without re-verifying the signature chain.  The in-process
    /// client (`add-in-process-client`) is the consumer that attenuates.
    pub grant: agency::Grant,
}

/// We cannot implement `FromRequestParts` with a generic `S: AuthState`
/// directly inside this file because the concrete `AppState` lives in
/// `main.rs` — instead we expose a free function that `main.rs` can use
/// to build an extractor layer, OR we implement it against the concrete
/// type by re-exporting a helper.
///
/// The cleanest approach: make `AuthedUser` extraction generic via a
/// helper function `extract_authed_user` that takes the storage + headers,
/// and have `main.rs` wire it via a closure / custom extractor.
///
/// Actually the simplest axum pattern is: implement `FromRequestParts<S>`
/// where `S: AuthState`.  axum 0.7 supports that.
#[async_trait]
impl<S: AuthState> FromRequestParts<S> for AuthedUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(&parts.headers)
            .ok_or_else(|| MatrixError::missing_token().into_response())?;

        let minter = state.minter();

        // Two steps, because the epoch the Datalog compares against
        // lives in the device row: read the signed claims first, then
        // fetch that row, then authorize.
        let claims = agency::parse_claims(&minter.public_key(), &token)
            .map_err(|_| MatrixError::unknown_token().into_response())?;

        let epoch = state
            .storage()
            .device_epoch(&claims.user_id, &claims.device_id)
            .await
            .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?
            // No device row means the device was deleted: fail closed.
            .ok_or_else(|| MatrixError::unknown_token().into_response())?;

        let ctx = VerifyContext::cs(state.server_name(), now_unix(), epoch);
        let grant = agency::verify(&minter.public_key(), &token, &ctx)
            .map_err(|_| MatrixError::unknown_token().into_response())?;

        Ok(AuthedUser {
            user_id: grant.user_id.clone(),
            device_id: grant.device_id.clone(),
            grant,
        })
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let val = headers.get("authorization")?.to_str().ok()?;
    val.strip_prefix("Bearer ").map(|s| s.to_owned())
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub device_id: Option<String>,
    pub initial_device_display_name: Option<String>,
    /// UIA auth block
    pub auth: Option<UiaAuthBlock>,
    /// Optional identikey-auth fingerprint (base58) to link to the new
    /// account, so a later challenge/response can log in as this user.
    #[serde(rename = "io.identikey.fingerprint")]
    pub identikey_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UiaAuthBlock {
    #[serde(rename = "type")]
    pub auth_type: String,
    pub session: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub access_token: String,
    pub device_id: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    #[serde(rename = "type")]
    pub login_type: String,
    pub identifier: Option<LoginIdentifier>,
    pub password: Option<String>,
    pub device_id: Option<String>,
    pub initial_device_display_name: Option<String>,
    /// For `io.identikey.auth`: url-safe base64 of the challenge
    /// response bytes.
    pub response: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginIdentifier {
    #[serde(rename = "type")]
    pub id_type: String,
    pub user: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user_id: String,
    pub access_token: String,
    pub device_id: String,
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/register
// ---------------------------------------------------------------------------

pub async fn register<S: AuthState>(
    State(state): State<S>,
    Json(body): Json<RegisterRequest>,
) -> Response {
    // UIA: require m.login.dummy stage completed.
    let auth = match &body.auth {
        Some(a) if a.auth_type == "m.login.dummy" => a,
        _ => {
            // Return 401 with flows to prompt client to complete UIA.
            let session_id = uia::new_session_id();
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "flows": [{ "stages": ["m.login.dummy"] }],
                    "params": {},
                    "session": session_id
                })),
            )
                .into_response();
        }
    };

    let localpart = match &body.username {
        Some(u) if !u.is_empty() => u.clone(),
        _ => {
            return MatrixError::invalid_username("username is required").into_response();
        }
    };

    // Validate localpart: only lowercase a-z, 0-9, -, _, .
    if !localpart.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return MatrixError::invalid_username("username contains invalid characters").into_response();
    }

    let user_id = format!("@{}:{}", localpart, state.server_name());

    // Hash password (or None for passwordless).
    let password_hash = match &body.password {
        Some(pw) if !pw.is_empty() => match hash_password(pw.clone()).await {
            Ok(h) => Some(h),
            Err(e) => return MatrixError::unknown(format!("password hashing failed: {e}")).into_response(),
        },
        _ => None,
    };

    // Create account.
    if let Err(e) = state.storage().create_account(&user_id, password_hash.as_deref()).await {
        let msg = e.to_string();
        if msg.contains("already exists") {
            return MatrixError::user_in_use(&user_id).into_response();
        }
        return MatrixError::unknown(msg).into_response();
    }

    // Device.
    let device_id = body.device_id.clone().unwrap_or_else(|| generate_device_id());
    let display_name = body.initial_device_display_name.as_deref();
    if let Err(e) = state.storage().upsert_device(&user_id, &device_id, display_name).await {
        return MatrixError::unknown(e.to_string()).into_response();
    }

    // Registration is also where an identikey-auth identity may be
    // linked: the account is being created here, so this is one of the
    // only two places a fingerprint may be bound to an MXID.
    if let Some(fingerprint) = body.identikey_fingerprint.as_deref() {
        if let Err(e) =
            conduit::identity::link_at_registration(state.storage().as_ref(), fingerprint, &user_id)
                .await
        {
            return MatrixError::forbidden(e.to_string()).into_response();
        }
    }

    // Agency: mint the capability token for the new session.
    let raw_token = match mint_access_token(&state, &user_id, &device_id).await {
        Ok(t) => t,
        Err(e) => return MatrixError::unknown(e).into_response(),
    };

    // Mark UIA session used (no-op for dummy, but keeps the pattern).
    if let Some(session) = &auth.session {
        uia::mark_session_used(session);
    }

    (
        StatusCode::OK,
        Json(RegisterResponse { user_id, access_token: raw_token, device_id }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /_matrix/client/v3/login  (advertise flows)
// ---------------------------------------------------------------------------

pub async fn get_login_flows() -> Json<serde_json::Value> {
    Json(json!({
        "flows": [
            { "type": "m.login.password" },
            { "type": IDENTIKEY_LOGIN_TYPE }
        ]
    }))
}

/// The login `type` for identikey-auth challenge/response.
pub const IDENTIKEY_LOGIN_TYPE: &str = "io.identikey.auth";

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/login
// ---------------------------------------------------------------------------

pub async fn login<S: AuthState>(
    State(state): State<S>,
    Json(body): Json<LoginRequest>,
) -> Response {
    if body.login_type == IDENTIKEY_LOGIN_TYPE {
        return identikey_login(state, body).await;
    }
    if body.login_type != "m.login.password" {
        return MatrixError::forbidden(format!("unsupported login type: {}", body.login_type))
            .into_response();
    }

    // Extract localpart from identifier.
    let localpart = match &body.identifier {
        Some(id) if id.id_type == "m.id.user" => match &id.user {
            Some(u) if !u.is_empty() => {
                // Strip leading @ if present (some clients send the full user_id here).
                u.trim_start_matches('@')
                 .split(':')
                 .next()
                 .unwrap_or(u)
                 .to_owned()
            }
            _ => return MatrixError::forbidden("missing user identifier").into_response(),
        },
        _ => return MatrixError::forbidden("identifier type must be m.id.user").into_response(),
    };

    let user_id = format!("@{}:{}", localpart, state.server_name());

    let password = match &body.password {
        Some(p) if !p.is_empty() => p.clone(),
        _ => return MatrixError::forbidden("password required").into_response(),
    };

    // Look up account.
    let account = match state.storage().get_account(&user_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return MatrixError::forbidden("unknown user or bad password").into_response(),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };

    // Check deactivated.
    if account.deactivated_at.is_some() {
        return MatrixError::forbidden("account deactivated").into_response();
    }

    // Verify password.
    let stored_hash = match account.password_hash {
        Some(h) => h,
        None => return MatrixError::forbidden("account has no password").into_response(),
    };

    match verify_password(password, stored_hash).await {
        Ok(true) => {}
        Ok(false) => return MatrixError::forbidden("unknown user or bad password").into_response(),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }

    // Issue device + token.
    let device_id = body.device_id.clone().unwrap_or_else(|| generate_device_id());
    let display_name = body.initial_device_display_name.as_deref();
    if let Err(e) = state.storage().upsert_device(&user_id, &device_id, display_name).await {
        return MatrixError::unknown(e.to_string()).into_response();
    }

    let raw_token = match mint_access_token(&state, &user_id, &device_id).await {
        Ok(t) => t,
        Err(e) => return MatrixError::unknown(e).into_response(),
    };

    (
        StatusCode::OK,
        Json(LoginResponse { user_id, access_token: raw_token, device_id }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/logout
// ---------------------------------------------------------------------------

/// Logging out advances the device's epoch.  Every capability token
/// minted for that device stops verifying on the next request, without
/// a denylist and without the server having stored the token bytes.
pub async fn logout<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
) -> Response {
    if let Err(e) = state
        .storage()
        .bump_device_epoch(&authed.user_id, &authed.device_id)
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

/// `POST /_matrix/client/v3/logout/all` — every device, one update.
pub async fn logout_all<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
) -> Response {
    if let Err(e) = state
        .storage()
        .bump_all_device_epochs(&authed.user_id)
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// identikey-auth on-ramp
// ---------------------------------------------------------------------------

/// `POST /_matrix/client/v3/login/identikey/challenge`
///
/// Hands out an audience-bound, nonce-carrying challenge.  Issuing one
/// is not a login and grants nothing: an unlinked identity that answers
/// it correctly is still refused.
pub async fn identikey_challenge<S: AuthState>(State(state): State<S>) -> Response {
    let bytes = state
        .identity_verifier()
        .issue_challenge(now_unix().max(0) as u64);

    (
        StatusCode::OK,
        Json(json!({
            "challenge": URL_SAFE_NO_PAD.encode(&bytes),
            "audience": state.server_name(),
        })),
    )
        .into_response()
}

/// The `io.identikey.auth` branch of `POST /login`.
async fn identikey_login<S: AuthState>(state: S, body: LoginRequest) -> Response {
    let Some(encoded) = body.response.as_deref() else {
        return MatrixError::forbidden("identikey login requires a challenge response")
            .into_response();
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded) else {
        return MatrixError::bad_json("response is not url-safe base64").into_response();
    };

    // Identity.  An unlinked fingerprint fails here rather than
    // creating an account — the challenge endpoint is not a
    // registration endpoint.
    let logged_in = match state
        .identity_verifier()
        .login(state.storage().as_ref(), &bytes, now_unix().max(0) as u64)
        .await
    {
        Ok(l) => l,
        Err(e) => return MatrixError::forbidden(e.to_string()).into_response(),
    };

    let account = match state.storage().get_account(&logged_in.user_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return MatrixError::forbidden("unknown user").into_response(),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    if account.deactivated_at.is_some() {
        return MatrixError::forbidden("account deactivated").into_response();
    }

    let device_id = body.device_id.clone().unwrap_or_else(generate_device_id);
    if let Err(e) = state
        .storage()
        .upsert_device(
            &logged_in.user_id,
            &device_id,
            body.initial_device_display_name.as_deref(),
        )
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }

    // Agency, minted exactly as the password on-ramp mints it.
    let raw_token = match mint_access_token(&state, &logged_in.user_id, &device_id).await {
        Ok(t) => t,
        Err(e) => return MatrixError::unknown(e).into_response(),
    };

    (
        StatusCode::OK,
        Json(LoginResponse {
            user_id: logged_in.user_id,
            access_token: raw_token,
            device_id,
        }),
    )
        .into_response()
}

/// `POST /_matrix/client/v3/account/identikey/bind`
///
/// Links a fingerprint to the *already authenticated* account.  The
/// grant is the authorization; there is no other way to create a link
/// after registration.
#[derive(Debug, Deserialize)]
pub struct BindRequest {
    pub response: String,
}

pub async fn identikey_bind<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<BindRequest>,
) -> Response {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(&body.response) else {
        return MatrixError::bad_json("response is not url-safe base64").into_response();
    };

    let fingerprint = match state
        .identity_verifier()
        .verify(&bytes, now_unix().max(0) as u64)
    {
        Ok(fp) => fp,
        Err(e) => return MatrixError::forbidden(e.to_string()).into_response(),
    };

    match conduit::identity::bind_fingerprint(
        state.storage().as_ref(),
        &authed.grant,
        &fingerprint,
        &authed.user_id,
    )
    .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "fingerprint": fingerprint }))).into_response(),
        Err(e) => MatrixError::forbidden(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /_matrix/client/v3/account/whoami
// ---------------------------------------------------------------------------

pub async fn whoami(authed: AuthedUser) -> Json<serde_json::Value> {
    Json(json!({
        "user_id": authed.user_id,
        "device_id": authed.device_id,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn generate_device_id() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("COND{}", URL_SAFE_NO_PAD.encode(bytes).to_uppercase())
}
