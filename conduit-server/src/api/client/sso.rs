//! Matrix SSO against an identikey-core (or any OIDC) OpenID Provider.
//!
//! Browser path (Element):
//! 1. GET `/_matrix/client/v3/login/sso/redirect?redirectUrl=…`
//! 2. 302 to the OP `/authorize` (PKCE S256, state, nonce)
//! 3. GET `/_matrix/client/v3/login/identikey/callback?code&state`
//! 4. confidential `/token` exchange, ID-token verify (iss/aud/exp/nonce)
//! 5. 302 to `redirectUrl?loginToken=`
//! 6. POST `/login` `type: m.login.token`
//!
//! First login (verified sub, no existing link) creates a local account
//! and links it. Unverified `io.identikey.oidc_sub` on `/register` is
//! refused — that check lives next to registration, not here.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use tokio::sync::Mutex;
use url::Url;

use identikey_oidc_client::{self, AuthorizeRequest};
use sha2::Digest;

use super::{generate_device_id, mint_access_token, now_unix, AuthState, LoginResponse, MatrixError};

/// Identity-provider id advertised in `m.login.sso`.
pub const IDENTIKEY_IDP_ID: &str = "identikey";

const SESSION_TTL: Duration = Duration::from_secs(600);
const LOGIN_TOKEN_TTL: Duration = Duration::from_secs(120);

/// Confidential-client knobs for the browser SSO redirect.
#[derive(Debug, Clone)]
pub struct OidcSsoConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub allowlist: Vec<String>,
}

#[derive(Clone)]
struct PendingAuth {
    nonce: String,
    code_verifier: String,
    client_redirect: String,
    created: Instant,
}

/// One-shot OAuth `state` → PKCE/nonce/Element redirectUrl.
#[derive(Default)]
pub struct SsoSessionStore {
    inner: Mutex<HashMap<String, PendingAuth>>,
}

impl SsoSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    async fn insert(&self, state: String, pending: PendingAuth) {
        let mut map = self.inner.lock().await;
        map.retain(|_, v| v.created.elapsed() < SESSION_TTL);
        map.insert(state, pending);
    }

    async fn take(&self, state: &str) -> Option<PendingAuth> {
        let mut map = self.inner.lock().await;
        map.retain(|_, v| v.created.elapsed() < SESSION_TTL);
        map.remove(state)
    }
}

struct IssuedLogin {
    user_id: String,
    created: Instant,
}

/// One-shot `m.login.token` values handed to Element after the callback.
#[derive(Default)]
pub struct LoginTokenStore {
    inner: Mutex<HashMap<String, IssuedLogin>>,
}

impl LoginTokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn issue(&self, user_id: String) -> String {
        let token = super::generate_token();
        let mut map = self.inner.lock().await;
        map.retain(|_, v| v.created.elapsed() < LOGIN_TOKEN_TTL);
        map.insert(
            token.clone(),
            IssuedLogin {
                user_id,
                created: Instant::now(),
            },
        );
        token
    }

    pub async fn consume(&self, token: &str) -> Option<String> {
        let mut map = self.inner.lock().await;
        map.retain(|_, v| v.created.elapsed() < LOGIN_TOKEN_TTL);
        map.remove(token).map(|v| v.user_id)
    }
}

#[derive(Debug, Deserialize)]
pub struct SsoRedirectQuery {
    #[serde(rename = "redirectUrl")]
    pub redirect_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// `GET /_matrix/client/v3/login/sso/redirect`
pub async fn sso_redirect<S: AuthState>(
    State(state): State<S>,
    Query(query): Query<SsoRedirectQuery>,
) -> Response {
    start_sso(&state, query.redirect_url.as_deref()).await
}

/// `GET /_matrix/client/v3/login/sso/redirect/:idpId`
pub async fn sso_redirect_idp<S: AuthState>(
    State(state): State<S>,
    Path(idp_id): Path<String>,
    Query(query): Query<SsoRedirectQuery>,
) -> Response {
    if idp_id != IDENTIKEY_IDP_ID {
        return MatrixError::new_not_found(format!("unknown identity provider: {idp_id}"))
            .into_response();
    }
    start_sso(&state, query.redirect_url.as_deref()).await
}

async fn start_sso<S: AuthState>(state: &S, redirect_url: Option<&str>) -> Response {
    let Some(client) = state.oidc_client() else {
        return MatrixError::forbidden("oidc sso is not configured").into_response();
    };
    let Some(sso) = state.oidc_sso() else {
        return MatrixError::forbidden("oidc sso is not configured").into_response();
    };
    let Some(redirect_url) = redirect_url.filter(|s| !s.is_empty()) else {
        return MatrixError::bad_json("redirectUrl is required").into_response();
    };
    if !redirect_allowed(redirect_url, &sso.allowlist) {
        return MatrixError::forbidden("redirectUrl is not allowed").into_response();
    }

    let pkce = match identikey_oidc_client::generate_pkce() {
        Ok(p) => p,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let oauth_state = match identikey_oidc_client::generate_state() {
        Ok(s) => s,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let nonce = match identikey_oidc_client::generate_state() {
        Ok(s) => s,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };

    let authorize = match client.authorize_url(&AuthorizeRequest {
        client_id: sso.client_id.clone(),
        redirect_uri: sso.redirect_uri.clone(),
        state: oauth_state.clone(),
        nonce: nonce.clone(),
        code_challenge: pkce.challenge.clone(),
    }) {
        Ok(u) => u,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };

    state
        .sso_sessions()
        .insert(
            oauth_state,
            PendingAuth {
                nonce,
                code_verifier: pkce.verifier,
                client_redirect: redirect_url.to_owned(),
                created: Instant::now(),
            },
        )
        .await;

    (
        StatusCode::FOUND,
        [(axum::http::header::LOCATION, authorize)],
    )
        .into_response()
}

/// `GET /_matrix/client/v3/login/identikey/callback`
pub async fn identikey_callback<S: AuthState>(
    State(state): State<S>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    if let Some(err) = query.error.as_deref() {
        let desc = query.error_description.as_deref().unwrap_or("");
        return html_error(
            StatusCode::BAD_REQUEST,
            &format!("IdentiKey returned {err}: {desc}"),
        );
    }
    let Some(client) = state.oidc_client() else {
        return html_error(StatusCode::FORBIDDEN, "OIDC is not configured");
    };
    let Some(sso) = state.oidc_sso() else {
        return html_error(StatusCode::FORBIDDEN, "OIDC SSO is not configured");
    };
    let Some(code) = query.code.as_deref().filter(|s| !s.is_empty()) else {
        return html_error(StatusCode::BAD_REQUEST, "missing authorization code");
    };
    let Some(oauth_state) = query.state.as_deref().filter(|s| !s.is_empty()) else {
        return html_error(StatusCode::BAD_REQUEST, "missing state");
    };
    let Some(pending) = state.sso_sessions().take(oauth_state).await else {
        return html_error(StatusCode::BAD_REQUEST, "unknown or expired state");
    };

    let tokens = match client
        .exchange_authorization_code(
            &sso.client_id,
            &sso.client_secret,
            code,
            &sso.redirect_uri,
            &pending.code_verifier,
        )
        .await
    {
        Ok(t) => t,
        Err(e) => {
            return html_error(
                StatusCode::BAD_GATEWAY,
                &format!("token exchange failed: {e}"),
            )
        }
    };

    let identity = match client
        .validate_with_nonce(
            &tokens.id_token,
            now_unix().max(0) as u64,
            Some(&pending.nonce),
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            return html_error(StatusCode::FORBIDDEN, &format!("id token rejected: {e}"))
        }
    };

    let user_id = match provision_or_login(state.clone(), &identity.subject).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let login_token = state.login_tokens().issue(user_id).await;
    let dest = append_login_token(&pending.client_redirect, &login_token);
    (
        StatusCode::FOUND,
        [(axum::http::header::LOCATION, dest)],
    )
        .into_response()
}

/// Resolve a verified OIDC `sub` to an MXID. Linked subjects log in;
/// unlinked subjects get a new local account (this is the verified
/// first-login path — the JWT was already checked).
pub async fn provision_or_login<S: AuthState>(state: S, subject: &str) -> Result<String, Response> {
    match conduit::identity::login_oidc_subject(state.storage().as_ref(), subject).await {
        Ok(logged_in) => {
            if let Ok(Some(account)) = state.storage().get_account(&logged_in.user_id).await {
                if account.deactivated_at.is_some() {
                    return Err(html_error(StatusCode::FORBIDDEN, "account deactivated"));
                }
            }
            Ok(logged_in.user_id)
        }
        Err(conduit::identity::IdentityError::Unlinked) => create_oidc_account(&state, subject).await,
        Err(e) => Err(html_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
        )),
    }
}

async fn create_oidc_account<S: AuthState>(state: &S, subject: &str) -> Result<String, Response> {
    let mut localpart = localpart_for_sub(subject);
    for extra in 0u32..8 {
        if extra > 0 {
            localpart = format!("{localpart}{extra}");
        }
        if !valid_localpart(&localpart) {
            continue;
        }
        let user_id = format!("@{}:{}", localpart, state.server_name());
        match state.storage().create_account(&user_id, None).await {
            Ok(()) => {
                let key = conduit::identity::oidc_identity_key(subject);
                if let Err(e) = conduit::identity::link_at_registration(
                    state.storage().as_ref(),
                    &key,
                    &user_id,
                )
                .await
                {
                    return Err(html_error(StatusCode::FORBIDDEN, &e.to_string()));
                }
                return Ok(user_id);
            }
            Err(e) if e.to_string().contains("already exists") => continue,
            Err(e) => {
                return Err(html_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &e.to_string(),
                ))
            }
        }
    }
    Err(html_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "could not allocate a localpart for this identity",
    ))
}

fn localpart_for_sub(subject: &str) -> String {
    let digest = sha2::Sha256::digest(subject.as_bytes());
    format!("ik{}", hex::encode(&digest[..6]))
}

fn valid_localpart(localpart: &str) -> bool {
    !localpart.is_empty()
        && localpart
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// `m.login.token` — consume a one-shot token issued by the callback.
pub async fn token_login<S: AuthState>(state: S, token: &str) -> Response {
    let Some(user_id) = state.login_tokens().consume(token).await else {
        return MatrixError::forbidden("invalid or expired login token").into_response();
    };
    let account = match state.storage().get_account(&user_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return MatrixError::forbidden("unknown user").into_response(),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    if account.deactivated_at.is_some() {
        return MatrixError::forbidden("account deactivated").into_response();
    }
    let device_id = generate_device_id();
    if let Err(e) = state
        .storage()
        .upsert_device(&user_id, &device_id, None)
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    let raw_token = match mint_access_token(&state, &user_id, &device_id).await {
        Ok(t) => t,
        Err(e) => return MatrixError::unknown(e).into_response(),
    };
    (
        StatusCode::OK,
        Json(LoginResponse {
            user_id,
            access_token: raw_token,
            device_id,
        }),
    )
        .into_response()
}

pub fn redirect_allowed(url: &str, allowlist: &[String]) -> bool {
    if url.contains('\r') || url.contains('\n') {
        return false;
    }
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    match parsed.scheme() {
        "http" | "https" | "element" => {}
        _ => return false,
    }
    allowlist.iter().any(|prefix| url.starts_with(prefix.as_str()))
}

pub fn default_sso_allowlist() -> Vec<String> {
    vec![
        "http://127.0.0.1".into(),
        "http://localhost".into(),
        "https://app.element.io".into(),
        "element://".into(),
    ]
}

fn append_login_token(redirect: &str, token: &str) -> String {
    let mut url = match Url::parse(redirect) {
        Ok(u) => u,
        Err(_) => {
            let sep = if redirect.contains('?') { '&' } else { '?' };
            return format!("{redirect}{sep}loginToken={token}");
        }
    };
    url.query_pairs_mut().append_pair("loginToken", token);
    url.to_string()
}

fn html_error(status: StatusCode, message: &str) -> Response {
    let escaped = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    (
        status,
        [("content-type", "text/html; charset=utf-8")],
        format!("<html><body><h1>Sign-in failed</h1><p>{escaped}</p></body></html>"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_accepts_localhost_element() {
        let list = default_sso_allowlist();
        assert!(redirect_allowed("http://localhost:8080/", &list));
        assert!(redirect_allowed(
            "https://app.element.io/#/login",
            &list
        ));
        assert!(!redirect_allowed("https://evil.example/phish", &list));
        assert!(!redirect_allowed("javascript:alert(1)", &list));
    }

    #[test]
    fn login_token_is_appended() {
        let a = append_login_token("http://localhost:8080/", "abc");
        assert!(a.contains("loginToken=abc"));
        let b = append_login_token("http://localhost:8080/?x=1", "abc");
        assert!(b.contains("x=1"));
        assert!(b.contains("loginToken=abc"));
    }
}
