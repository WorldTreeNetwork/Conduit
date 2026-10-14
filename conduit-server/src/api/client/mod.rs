//! Client-Server API handlers.
//!
//! Implements:
//!   POST /_matrix/client/v3/register
//!   GET  /_matrix/client/v3/login   (advertise flows)
//!   POST /_matrix/client/v3/login
//!   POST /_matrix/client/v3/logout
//!   GET  /_matrix/client/v3/account/whoami

pub mod account;
pub mod account_config;
pub mod account_data;
pub mod appservice_ping;
pub mod auth_fallback;
pub mod devices;
pub mod device_lists;
pub mod directory;
pub mod registration;
pub mod session;
pub mod well_known;
pub mod event_pipeline;
pub mod filters;
pub mod key_identity;
pub mod keys;
pub mod knock;
pub mod media;
pub mod media_preview;
pub mod presence;
pub mod probe;
pub mod rate_limit;
pub mod profile;
pub mod push;
pub mod receipts;
pub mod room_directory;
pub mod room_content;
pub mod rooms;
pub mod safe_fetch;
pub mod sso;
pub mod standards;
pub mod sync;
pub mod thirdparty;
pub mod typing;
pub mod uia;
pub mod user_directory;

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
use identikey_oidc_client::OidcClient;

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
    /// Legacy host cache, retained for compatibility. Protocol idempotency uses Storage transactions.
    fn txn_cache(&self) -> &Arc<RwLock<HashMap<TxnCacheKey, String>>>;
    /// Broadcast sender for new stream positions.  `/sync` long-poll
    /// subscribes to this to wake up when new events arrive.
    fn events_tx(&self) -> &broadcast::Sender<i64>;
    /// Wake sync for durable non-room data without triggering room-event workers.
    fn sync_notify(&self) -> Arc<tokio::sync::Notify> {
        static DEFAULT: std::sync::OnceLock<Arc<tokio::sync::Notify>> = std::sync::OnceLock::new();
        Arc::clone(DEFAULT.get_or_init(|| Arc::new(tokio::sync::Notify::new())))
    }

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

    /// Configured identikey-core (or any OIDC) RP client. Default: none.
    fn oidc_client(&self) -> Option<Arc<OidcClient>> {
        None
    }

    /// Confidential-client knobs for Matrix SSO redirect. Default: none
    /// (JWT-in-hand `io.identikey.oidc` may still work).
    fn oidc_sso(&self) -> Option<Arc<sso::OidcSsoConfig>> {
        None
    }

    fn sso_sessions(&self) -> Arc<sso::SsoSessionStore> {
        static STORE: std::sync::OnceLock<Arc<sso::SsoSessionStore>> = std::sync::OnceLock::new();
        Arc::clone(STORE.get_or_init(|| Arc::new(sso::SsoSessionStore::new())))
    }

    fn login_tokens(&self) -> Arc<sso::LoginTokenStore> {
        static STORE: std::sync::OnceLock<Arc<sso::LoginTokenStore>> = std::sync::OnceLock::new();
        Arc::clone(STORE.get_or_init(|| Arc::new(sso::LoginTokenStore::new())))
    }

    /// Registered application services (exclusive namespaces, AS
    /// registration).  Default: none.
    fn registered_app_services(&self) -> Option<Arc<Vec<crate::app_service::AppService>>> {
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
            conduit::Error::UnsupportedRoomVersion(v) => (
                StatusCode::BAD_REQUEST,
                Json(Self::new(
                    "M_UNSUPPORTED_ROOM_VERSION",
                    format!("unsupported room version: {v}"),
                )),
            ),
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
        let token = extract_access_token(parts)
            .ok_or_else(|| MatrixError::missing_token().into_response())?;

        let grant = verify_access_token(state, &token).await?;

        session::guest_gate(state, parts, &grant.user_id).await?;
        session::touch(state, parts, &grant.user_id, &grant.device_id);

        Ok(AuthedUser {
            user_id: grant.user_id.clone(),
            device_id: grant.device_id.clone(),
            grant,
        })
    }
}

/// Verify a capability access token.
///
/// Failures are `401 M_UNKNOWN_TOKEN`.  `soft_logout` is `true` only
/// when the session itself is intact and merely the token's lifetime ran
/// out — the client may refresh or log in again with the same device.
/// A deleted device or a logged-out session (epoch moved on) is a hard
/// logout.
pub async fn verify_access_token<S: AuthState>(
    state: &S,
    token: &str,
) -> Result<agency::Grant, Response> {
    let minter = state.minter();

    // Two steps, because the epoch the Datalog compares against
    // lives in the device row: read the signed claims first, then
    // fetch that row, then authorize.
    let claims = agency::parse_claims(&minter.public_key(), token)
        .map_err(|_| MatrixError::unknown_token().into_response())?;

    let epoch = state
        .storage()
        .device_epoch(&claims.user_id, &claims.device_id)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?
        // No device row means the device was deleted: fail closed.
        .ok_or_else(|| session::unknown_token_response(false, "Unrecognised access token"))?;

    let ctx = VerifyContext::cs(state.server_name(), now_unix(), epoch);
    agency::verify(&minter.public_key(), token, &ctx).map_err(|_| {
        if claims.epoch == epoch && claims.server_name == state.server_name() {
            // Same live session, so the time check is what failed.
            session::unknown_token_response(true, "Access token has expired")
        } else {
            session::unknown_token_response(false, "Unrecognised access token")
        }
    })
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let val = headers.get("authorization")?.to_str().ok()?;
    val.strip_prefix("Bearer ").map(|s| s.to_owned())
}

/// The access token from `Authorization: Bearer`, or the deprecated
/// `access_token` query parameter (servers MUST support both).
pub fn extract_access_token(parts: &Parts) -> Option<String> {
    if let Some(t) = extract_bearer_token(&parts.headers) {
        return Some(t);
    }
    let query = parts.uri.query()?;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == "access_token")
        .map(|(_, v)| v.into_owned())
        .filter(|v| !v.is_empty())
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    #[serde(rename = "type")]
    pub login_type: String,
    pub identifier: Option<LoginIdentifier>,
    /// Deprecated top-level user field, still sent by older clients.
    pub user: Option<String>,
    pub password: Option<String>,
    pub device_id: Option<String>,
    pub initial_device_display_name: Option<String>,
    /// `true` when the client supports refresh tokens.
    #[serde(default)]
    pub refresh_token: bool,
    /// For `io.identikey.auth`: url-safe base64 of the challenge
    /// response bytes.
    pub response: Option<String>,
    /// For `io.identikey.oidc`: the OP ID/access token (JWT).
    pub token: Option<String>,
}

impl LoginRequest {
    fn options(&self) -> session::LoginOptions {
        session::LoginOptions {
            device_id: self.device_id.clone(),
            initial_device_display_name: self.initial_device_display_name.clone(),
            refresh_token: self.refresh_token,
        }
    }
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

/// Registration lives in [`registration`]; this keeps the long-standing
/// handler path for routers and tests.
pub async fn register<S: AuthState>(
    State(state): State<S>,
    query: Option<axum::extract::Query<registration::RegisterQuery>>,
    headers: HeaderMap,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let query = query.map(|q| q.0).unwrap_or_default();
    let body = body.map(|b| b.0).unwrap_or_else(|| json!({}));
    registration::register(state, query, headers, body).await
}

// ---------------------------------------------------------------------------
// GET /_matrix/client/v3/login  (advertise flows)
// ---------------------------------------------------------------------------

pub async fn get_login_flows<S: AuthState>(State(state): State<S>) -> Json<serde_json::Value> {
    let mut flows = vec![
        json!({ "type": "m.login.password" }),
        json!({ "type": IDENTIKEY_LOGIN_TYPE }),
    ];
    if state.oidc_client().is_some() {
        flows.push(json!({ "type": OIDC_LOGIN_TYPE }));
    }
    if state.oidc_client().is_some() && state.oidc_sso().is_some() {
        flows.push(json!({
            "type": "m.login.sso",
            "identity_providers": [{
                "id": sso::IDENTIKEY_IDP_ID,
                "name": "IdentiKey",
                "brand": "identikey",
            }],
        }));
    }
    // Tokens come from SSO and from POST /login/get_token.
    flows.push(json!({ "type": "m.login.token", "get_login_token": true }));
    Json(json!({ "flows": flows }))
}

/// The login `type` for identikey-auth challenge/response.
pub const IDENTIKEY_LOGIN_TYPE: &str = "io.identikey.auth";
/// The login `type` for a verified identikey-core (OIDC) ID token.
pub const OIDC_LOGIN_TYPE: &str = "io.identikey.oidc";

/// `403 M_USER_DEACTIVATED`.
pub fn user_deactivated() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"errcode": "M_USER_DEACTIVATED", "error": "This account has been deactivated"})),
    )
        .into_response()
}

/// Issue the login response for an authenticated user.
async fn login_response<S: AuthState>(state: &S, user_id: &str, body: &LoginRequest) -> Response {
    match session::issue_session(state, user_id, &body.options()).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(r) => r,
    }
}

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
    if body.login_type == OIDC_LOGIN_TYPE {
        return oidc_login(state, body).await;
    }
    if body.login_type == "m.login.token" {
        let Some(token) = body.token.as_deref() else {
            return MatrixError::forbidden("m.login.token requires a token").into_response();
        };
        return sso::token_login(state, token, body.options()).await;
    }
    if body.login_type != "m.login.password" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errcode": "M_UNKNOWN",
                "error": format!("unsupported login type: {}", body.login_type),
            })),
        )
            .into_response();
    }

    // Extract the localpart from the identifier (or the deprecated
    // top-level `user`).
    let raw_user = match &body.identifier {
        Some(id) if id.id_type == "m.id.user" => id.user.clone(),
        Some(_) => {
            return MatrixError::forbidden("unknown or unsupported identifier").into_response()
        }
        None => body.user.clone(),
    };
    let Some(raw_user) = raw_user.filter(|u| !u.is_empty()) else {
        return MatrixError::forbidden("missing user identifier").into_response();
    };
    let localpart = match raw_user.strip_prefix('@') {
        Some(full) => match full.split_once(':') {
            Some((local, server)) if server == state.server_name() => local.to_owned(),
            _ => return MatrixError::forbidden("unknown user or bad password").into_response(),
        },
        None => raw_user.clone(),
    }
    .to_lowercase();

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

    // Verify password.
    let stored_hash = match account.password_hash.clone() {
        Some(h) => h,
        None => return MatrixError::forbidden("unknown user or bad password").into_response(),
    };

    match verify_password(password, stored_hash).await {
        Ok(true) => {}
        Ok(false) => return MatrixError::forbidden("unknown user or bad password").into_response(),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }

    // Only after the password proved who is asking: deactivated.
    if account.deactivated_at.is_some() {
        return user_deactivated();
    }

    login_response(&state, &user_id, &body).await
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/logout
// ---------------------------------------------------------------------------

/// Logging out deletes the device (spec): its tokens, refresh tokens and
/// E2EE keys go with it, and every outstanding capability token for it
/// fails on the next request because its device row is gone.
pub async fn logout<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
) -> Response {
    match session::remove_devices(&state, &authed.user_id, std::slice::from_ref(&authed.device_id)).await {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(r) => r,
    }
}

/// `POST /_matrix/client/v3/logout/all` — every device of the user.
pub async fn logout_all<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
) -> Response {
    let devices = match session::device_ids_except(&state, &authed.user_id, None).await {
        Ok(d) => d,
        Err(r) => return r,
    };
    match session::remove_devices(&state, &authed.user_id, &devices).await {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(r) => r,
    }
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
        return user_deactivated();
    }

    // Agency, minted exactly as the password on-ramp mints it.
    login_response(&state, &logged_in.user_id, &body).await
}

/// The `io.identikey.oidc` branch of `POST /login`.
///
/// The host verifies the OP JWT; the kernel only sees `sub`. An
/// unlinked subject fails closed — same rule as identikey-auth.
async fn oidc_login<S: AuthState>(state: S, body: LoginRequest) -> Response {
    let Some(client) = state.oidc_client() else {
        return MatrixError::forbidden("oidc login is not configured").into_response();
    };
    let Some(token) = body.token.as_deref() else {
        return MatrixError::forbidden("oidc login requires a token").into_response();
    };
    let identity = match client
        .validate(token, now_unix().max(0) as u64)
        .await
    {
        Ok(id) => id,
        Err(e) => return MatrixError::forbidden(e.to_string()).into_response(),
    };
    let logged_in = match conduit::identity::login_oidc_subject(
        state.storage().as_ref(),
        &identity.subject,
    )
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
        return user_deactivated();
    }

    login_response(&state, &logged_in.user_id, &body).await
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
