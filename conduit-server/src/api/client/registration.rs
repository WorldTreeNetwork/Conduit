//! Account registration (conduit-y99.18).
//!
//! <https://spec.matrix.org/v1.19/client-server-api/#account-registration>
//!
//!   POST /_matrix/client/v3/register[?kind=user|guest]
//!   GET  /_matrix/client/v3/register/available
//!   GET  /_matrix/client/v1/register/m.login.registration_token/validity
//!
//! Username problems (`M_INVALID_USERNAME`, `M_EXCLUSIVE`,
//! `M_USER_IN_USE`) are reported before User-Interactive Authentication,
//! as the spec requires.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value};

use super::account_config::AccountConfig;
use super::session::{issue_session, LoginOptions};
use super::{hash_password, now_unix, uia, AuthState, MatrixError};

/// Localpart grammar: <https://spec.matrix.org/v1.19/appendices/#user-identifiers>.
/// Purely numeric localparts are reserved for guest accounts.
pub fn validate_localpart(localpart: &str, server_name: &str) -> Result<(), String> {
    if localpart.is_empty() {
        return Err("username must not be empty".into());
    }
    if !localpart
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'=' | b'-' | b'/' | b'+'))
    {
        return Err("username may only contain a-z, 0-9, '.', '_', '=', '-', '/' and '+'".into());
    }
    if localpart.bytes().all(|b| b.is_ascii_digit()) {
        return Err("numeric usernames are reserved for guest accounts".into());
    }
    if format!("@{localpart}:{server_name}").len() > 255 {
        return Err("user ID would exceed 255 bytes".into());
    }
    Ok(())
}

/// Map a requested username onto a localpart: an optional leading `@`
/// and `:server` are accepted for this server, and letters are lowercased.
fn normalise_username(raw: &str, server_name: &str) -> Result<String, String> {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix('@') {
        s = rest;
        if let Some((local, server)) = s.split_once(':') {
            if server != server_name {
                return Err("username must be local to this server".into());
            }
            s = local;
        }
    }
    Ok(s.to_lowercase())
}

fn exclusive_owner<S: AuthState>(state: &S, user_id: &str) -> bool {
    state
        .registered_app_services()
        .map(|svcs| crate::app_service::exclusive_as_for_user(user_id, &svcs).is_some())
        .unwrap_or(false)
}

fn exclusive_error() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "errcode": "M_EXCLUSIVE",
            "error": "The desired user ID is in the exclusive namespace of an application service",
        })),
    )
        .into_response()
}

fn registration_disabled() -> Response {
    MatrixError::forbidden("Registration is not enabled on this homeserver").into_response()
}

fn missing_param(name: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"errcode": "M_MISSING_PARAM", "error": format!("{name} is required")})),
    )
        .into_response()
}

/// Check that `localpart` could be registered by an ordinary user now.
async fn check_available<S: AuthState>(state: &S, localpart: &str) -> Result<String, Response> {
    validate_localpart(localpart, state.server_name())
        .map_err(|e| MatrixError::invalid_username(e).into_response())?;
    let user_id = format!("@{}:{}", localpart, state.server_name());
    if exclusive_owner(state, &user_id) {
        return Err(exclusive_error());
    }
    match state.storage().get_account(&user_id).await {
        Ok(Some(_)) => Err(MatrixError::user_in_use(&user_id).into_response()),
        Ok(None) => Ok(user_id),
        Err(e) => Err(MatrixError::unknown(e.to_string()).into_response()),
    }
}

// ---------------------------------------------------------------------------
// GET /register/available
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AvailableQuery {
    pub username: Option<String>,
}

pub async fn available<S: AuthState>(
    State(state): State<S>,
    Query(q): Query<AvailableQuery>,
) -> Response {
    if !AccountConfig::get().allow_registration {
        return registration_disabled();
    }
    let Some(raw) = q.username.filter(|u| !u.is_empty()) else {
        return missing_param("username");
    };
    let localpart = match normalise_username(&raw, state.server_name()) {
        Ok(l) => l,
        Err(e) => return MatrixError::invalid_username(e).into_response(),
    };
    match check_available(&state, &localpart).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "available": true }))).into_response(),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------------------
// GET /register/m.login.registration_token/validity
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ValidityQuery {
    pub token: Option<String>,
}

pub async fn token_validity(Query(q): Query<ValidityQuery>) -> Response {
    let config = AccountConfig::get();
    if !config.allow_registration {
        return registration_disabled();
    }
    let Some(token) = q.token else {
        return missing_param("token");
    };
    (
        StatusCode::OK,
        Json(json!({ "valid": config.registration_token_valid(&token) })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /register
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct RegisterQuery {
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RegisterBody {
    auth: Option<Value>,
    /// `m.login.application_service` for AS registration (spec v1.17).
    #[serde(rename = "type")]
    login_type: Option<String>,
    username: Option<String>,
    password: Option<String>,
    device_id: Option<String>,
    initial_device_display_name: Option<String>,
    #[serde(default)]
    inhibit_login: bool,
    #[serde(default)]
    refresh_token: bool,
    guest_access_token: Option<String>,
    #[serde(rename = "io.identikey.fingerprint")]
    identikey_fingerprint: Option<String>,
    #[serde(rename = "io.identikey.oidc_sub")]
    oidc_sub: Option<String>,
    #[serde(rename = "io.identikey.oidc_token")]
    oidc_token: Option<String>,
}

fn registration_flows() -> Vec<Vec<&'static str>> {
    let base = if AccountConfig::get().registration_tokens.is_empty() {
        vec![uia::DUMMY]
    } else {
        vec![uia::REGISTRATION_TOKEN]
    };
    super::threepid_validation::registration_flows(base)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

pub async fn register<S: AuthState>(
    state: S,
    query: RegisterQuery,
    headers: HeaderMap,
    raw: Value,
) -> Response {
    let body: RegisterBody = match serde_json::from_value(raw) {
        Ok(b) => b,
        Err(e) => return MatrixError::bad_json(e.to_string()).into_response(),
    };
    match query.kind.as_deref().unwrap_or("user") {
        "guest" => register_guest(&state, body).await,
        "user" => register_user(&state, body, &headers).await,
        other => (
            StatusCode::BAD_REQUEST,
            Json(json!({"errcode": "M_INVALID_PARAM", "error": format!("unknown kind {other}")})),
        )
            .into_response(),
    }
}

async fn register_guest<S: AuthState>(state: &S, body: RegisterBody) -> Response {
    if !AccountConfig::get().allow_guest_access {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "errcode": "M_GUEST_ACCESS_FORBIDDEN",
                "error": "Guest access is disabled on this homeserver",
            })),
        )
            .into_response();
    }
    // Every parameter except initial_device_display_name is ignored.
    let mut user_id = None;
    for _ in 0..8 {
        let n: u64 = rand::thread_rng().gen_range(1_000_000_000..10_000_000_000);
        let candidate = format!("@{n}:{}", state.server_name());
        match state.storage().create_account(&candidate, None).await {
            Ok(()) => {
                user_id = Some(candidate);
                break;
            }
            Err(e) if e.to_string().contains("already exists") => continue,
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        }
    }
    let Some(user_id) = user_id else {
        return MatrixError::unknown("could not allocate a guest user ID").into_response();
    };
    if let Err(e) = state.storage().set_guest(&user_id, true).await {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    let opts = LoginOptions {
        device_id: None,
        initial_device_display_name: body.initial_device_display_name,
        refresh_token: false,
    };
    match issue_session(state, &user_id, &opts).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(r) => r,
    }
}

/// The application service whose `as_token` authorised this request.
fn calling_app_service<S: AuthState>(
    state: &S,
    headers: &HeaderMap,
) -> Option<crate::app_service::AppService> {
    let token = bearer(headers)?;
    state
        .registered_app_services()?
        .iter()
        .find(|s| s.as_token == token)
        .cloned()
}

async fn register_user<S: AuthState>(state: &S, body: RegisterBody, headers: &HeaderMap) -> Response {
    let server_name = state.server_name().to_owned();
    let appservice = calling_app_service(state, headers);
    // The application-service registration type needs a valid as_token.
    if body.login_type.as_deref() == Some(super::APPSERVICE_LOGIN_TYPE) && appservice.is_none() {
        let (errcode, error) = if bearer(headers).is_some() {
            ("M_UNKNOWN_TOKEN", "Unrecognised application service token")
        } else {
            ("M_MISSING_TOKEN", "m.login.application_service requires the as_token")
        };
        return (StatusCode::UNAUTHORIZED, Json(json!({"errcode": errcode, "error": error})))
            .into_response();
    }
    if appservice.is_none() && !AccountConfig::get().allow_registration {
        return registration_disabled();
    }

    // Guest upgrade: the guest keeps its user ID.
    let mut upgrading_guest = None;
    if let Some(token) = body.guest_access_token.as_deref() {
        let grant = match super::verify_access_token(state, token).await {
            Ok(g) => g,
            Err(r) => return r,
        };
        match state.storage().get_account(&grant.user_id).await {
            Ok(Some(a)) if a.is_guest => {}
            Ok(_) => return MatrixError::forbidden("guest_access_token is not a guest's").into_response(),
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        }
        let guest_local = grant
            .user_id
            .trim_start_matches('@')
            .split(':')
            .next()
            .unwrap_or_default()
            .to_owned();
        if let Some(requested) = body.username.as_deref() {
            match normalise_username(requested, &server_name) {
                Ok(l) if l == guest_local => {}
                _ => {
                    return MatrixError::invalid_username(
                        "username must be the guest's own localpart when upgrading",
                    )
                    .into_response()
                }
            }
        }
        upgrading_guest = Some(grant.user_id);
    }

    // Choose and check the user ID before any UIA, per spec.
    let user_id = if let Some(guest) = &upgrading_guest {
        guest.clone()
    } else if let Some(svc) = &appservice {
        let Some(requested) = body.username.as_deref().filter(|u| !u.is_empty()) else {
            return missing_param("username");
        };
        let localpart = match normalise_username(requested, &server_name) {
            Ok(l) => l,
            Err(e) => return MatrixError::invalid_username(e).into_response(),
        };
        if localpart.is_empty()
            || !localpart.bytes().all(|b| {
                matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'=' | b'-' | b'/' | b'+')
            })
        {
            return MatrixError::invalid_username("invalid username").into_response();
        }
        let user_id = format!("@{localpart}:{server_name}");
        if !crate::app_service::user_in_as_namespace(&user_id, svc) {
            return exclusive_error();
        }
        match state.storage().get_account(&user_id).await {
            Ok(Some(_)) => return MatrixError::user_in_use(&user_id).into_response(),
            Ok(None) => {}
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        }
        user_id
    } else if let Some(requested) = body.username.as_deref().filter(|u| !u.is_empty()) {
        let localpart = match normalise_username(requested, &server_name) {
            Ok(l) => l,
            Err(e) => return MatrixError::invalid_username(e).into_response(),
        };
        match check_available(state, &localpart).await {
            Ok(u) => u,
            Err(r) => return r,
        }
    } else {
        // No username: the server picks one.
        let mut picked = None;
        for _ in 0..8 {
            let suffix: String = (0..10)
                .map(|_| {
                    let c = rand::thread_rng().gen_range(0..36u8);
                    if c < 10 { (b'0' + c) as char } else { (b'a' + c - 10) as char }
                })
                .collect();
            if let Ok(u) = check_available(state, &format!("u{suffix}")).await {
                picked = Some(u);
                break;
            }
        }
        match picked {
            Some(u) => u,
            None => return MatrixError::unknown("could not allocate a user ID").into_response(),
        }
    };

    if body.oidc_sub.is_some() && body.oidc_token.is_none() {
        return MatrixError::forbidden(
            "io.identikey.oidc_sub is not accepted without a verified io.identikey.oidc_token",
        )
        .into_response();
    }

    // UIA (application services authenticate with their as_token).
    let proved = if appservice.is_none() {
        let req = uia::UiaRequest::new("POST /register", None, registration_flows());
        match uia::authenticate(state, req, body.auth.as_ref()).await {
            Ok(passed) => Some(passed),
            Err(r) => return r,
        }
    } else {
        None
    };

    let password_hash = match body.password.as_deref() {
        Some(pw) if !pw.is_empty() => match hash_password(pw.to_owned()).await {
            Ok(h) => Some(h),
            Err(e) => {
                return MatrixError::unknown(format!("password hashing failed: {e}")).into_response()
            }
        },
        _ => None,
    };

    if upgrading_guest.is_some() {
        if let Some(hash) = &password_hash {
            if let Err(e) = state.storage().set_password_hash(&user_id, hash).await {
                return MatrixError::unknown(e.to_string()).into_response();
            }
        }
        if let Err(e) = state.storage().set_guest(&user_id, false).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    } else if let Err(e) = state
        .storage()
        .create_account(&user_id, password_hash.as_deref())
        .await
    {
        let msg = e.to_string();
        if msg.contains("already exists") {
            // Registered while the client was completing UIA.
            return MatrixError::user_in_use(&user_id).into_response();
        }
        return MatrixError::unknown(msg).into_response();
    }

    // Identity links may only be written at registration (or by a later
    // authenticated bind).
    if let Some(fingerprint) = body.identikey_fingerprint.as_deref() {
        if let Err(e) =
            conduit::identity::link_at_registration(state.storage().as_ref(), fingerprint, &user_id)
                .await
        {
            return MatrixError::forbidden(e.to_string()).into_response();
        }
    }
    if let Some(token) = body.oidc_token.as_deref() {
        let Some(client) = state.oidc_client() else {
            return MatrixError::forbidden("oidc is not configured").into_response();
        };
        let identity = match client.validate(token, now_unix().max(0) as u64).await {
            Ok(id) => id,
            Err(e) => return MatrixError::forbidden(e.to_string()).into_response(),
        };
        if let Some(claimed) = body.oidc_sub.as_deref() {
            if claimed != identity.subject {
                return MatrixError::forbidden("io.identikey.oidc_sub does not match token")
                    .into_response();
            }
        }
        let key = conduit::identity::oidc_identity_key(&identity.subject);
        if let Err(e) =
            conduit::identity::link_at_registration(state.storage().as_ref(), &key, &user_id).await
        {
            return MatrixError::forbidden(e.to_string()).into_response();
        }
    }

    if let Some(passed) = &proved {
        if let Err(r) = super::threepid_validation::bind_registration(state, &user_id, passed).await {
            return r;
        }
    }

    if body.inhibit_login {
        return (StatusCode::OK, Json(json!({ "user_id": user_id }))).into_response();
    }
    let opts = LoginOptions {
        device_id: body.device_id,
        initial_device_display_name: body.initial_device_display_name,
        refresh_token: body.refresh_token,
    };
    match issue_session(state, &user_id, &opts).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(r) => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localpart_grammar() {
        assert!(validate_localpart("alice", "hs").is_ok());
        assert!(validate_localpart("a.b_c=d-e/f+g", "hs").is_ok());
        assert!(validate_localpart("Alice", "hs").is_err());
        assert!(validate_localpart("al ice", "hs").is_err());
        assert!(validate_localpart("", "hs").is_err());
        assert!(validate_localpart("12345", "hs").is_err());
        assert!(validate_localpart(&"a".repeat(260), "hs").is_err());
    }

    #[test]
    fn usernames_are_mapped_to_localparts() {
        assert_eq!(normalise_username("Alice", "hs").unwrap(), "alice");
        assert_eq!(normalise_username("@bob:hs", "hs").unwrap(), "bob");
        assert!(normalise_username("@bob:other", "hs").is_err());
    }
}
