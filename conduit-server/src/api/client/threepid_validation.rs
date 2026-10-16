//! Homeserver-validated third-party identifiers.
//!
//! With `CONDUIT_THREEPID_SINK` unset, every `requestToken` is
//! `403 M_THREEPID_DENIED` and add endpoints are `403 M_FORBIDDEN`
//! (`m.3pid_changes` disabled). When the sink is set, this server
//! validates email and phone numbers itself: it stores a session, posts
//! the token to the sink, and accepts `submitToken` only when the token
//! matches that session.

use std::time::Duration;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::account_config::AccountConfig;
use super::uia::{self, UiaPassed};
use super::{AuthState, AuthedUser, MatrixError};
use crate::identity_service::canonical_3pid;

const SECRET_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.=_-";

#[derive(Debug, Clone)]
pub struct ValidatedThreepid {
    pub medium: String,
    pub address: String,
    pub validated_at: i64,
}

fn denied() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "errcode": "M_THREEPID_DENIED",
            "error": "Third-party identifiers are not supported on this homeserver",
        })),
    )
        .into_response()
}

fn changes_disabled() -> Response {
    MatrixError::forbidden("Third-party identifier changes are disabled on this homeserver (m.3pid_changes)")
        .into_response()
}

fn err(status: StatusCode, code: &str, error: &str) -> Response {
    (status, Json(json!({"errcode": code, "error": error}))).into_response()
}

fn missing(name: &str) -> Response {
    err(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", &format!("{name} is required"))
}

fn invalid(error: &str) -> Response {
    err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", error)
}

fn configured() -> bool {
    AccountConfig::get().threepid_enabled()
}

fn valid_client_secret(secret: &str) -> bool {
    !secret.is_empty()
        && secret.len() <= 255
        && secret.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'=' | b'_' | b'-'))
}

fn random_token() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn random_sid() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| SECRET_ALPHABET[(*b as usize) % SECRET_ALPHABET.len()] as char).collect()
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// National numbers gain their country's calling code. A leading `+`
/// is already international.
fn msisdn_address(country: &str, phone: &str) -> Option<String> {
    let country = country.trim();
    if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let raw = phone.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with('+') {
        return canonical_3pid("msisdn", raw);
    }
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    let national = digits.trim_start_matches('0');
    if national.is_empty() {
        return None;
    }
    let cc = calling_code(country)?;
    canonical_3pid("msisdn", &format!("{cc}{national}"))
}

fn calling_code(country: &str) -> Option<&'static str> {
    Some(match country {
        "AU" => "61",
        "AT" => "43",
        "BE" => "32",
        "BR" => "55",
        "CA" => "1",
        "CH" => "41",
        "DE" => "49",
        "DK" => "45",
        "ES" => "34",
        "FI" => "358",
        "FR" => "33",
        "GB" => "44",
        "IE" => "353",
        "IN" => "91",
        "IT" => "39",
        "JP" => "81",
        "MX" => "52",
        "NL" => "31",
        "NO" => "47",
        "NZ" => "64",
        "PL" => "48",
        "PT" => "351",
        "SE" => "46",
        "US" => "1",
        _ => return None,
    })
}

fn submit_url(headers: &HeaderMap, medium: &str) -> String {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .filter(|h| !h.is_empty())
        .unwrap_or("localhost");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .filter(|p| *p == "http" || *p == "https")
        .unwrap_or("http");
    format!("{proto}://{host}/_matrix/client/v3/validate/{medium}/submitToken")
}

fn string_field<'a>(body: &'a Value, name: &str) -> Result<&'a str, Response> {
    match body.get(name) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s),
        Some(Value::Null) | None => Err(missing(name)),
        _ => Err(invalid(&format!("{name} must be a string"))),
    }
}

async fn deliver(sink: &str, body: &Value) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let response = client.post(sink).json(body).send().await.map_err(|e| e.to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("validation sink returned {}", response.status()))
    }
}

async fn request_token<S: AuthState>(
    state: &S,
    headers: &HeaderMap,
    body: Option<Json<Value>>,
    medium: &str,
    purpose: &str,
) -> Response {
    if !configured() {
        return denied();
    }
    let body = body.map(|Json(v)| v).unwrap_or(Value::Null);
    let client_secret = match string_field(&body, "client_secret") {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !valid_client_secret(client_secret) {
        return invalid("client_secret must match [0-9a-zA-Z.=_-] and be at most 255 characters");
    }
    let send_attempt = match body.get("send_attempt") {
        Some(Value::Number(n)) => match n.as_i64().and_then(|n| i32::try_from(n).ok()) {
            Some(n) => n,
            None => return invalid("send_attempt must be an integer"),
        },
        Some(_) => return invalid("send_attempt must be an integer"),
        None => return missing("send_attempt"),
    };
    if body.get("id_server").and_then(Value::as_str).is_some()
        && body.get("id_access_token").and_then(Value::as_str).is_none()
    {
        return missing("id_access_token");
    }
    let address = match medium {
        "email" => {
            let email = match string_field(&body, "email") {
                Ok(s) => s,
                Err(r) => return r,
            };
            match canonical_3pid("email", email) {
                Some(a) => a,
                None => return invalid("email address is not valid"),
            }
        }
        "msisdn" => {
            let country = match string_field(&body, "country") {
                Ok(s) => s,
                Err(r) => return r,
            };
            let phone = match string_field(&body, "phone_number") {
                Ok(s) => s,
                Err(r) => return r,
            };
            match msisdn_address(country, phone) {
                Some(a) => a,
                None => return invalid("phone number is not valid"),
            }
        }
        _ => return err(StatusCode::BAD_REQUEST, "M_THREEPID_MEDIUM_NOT_SUPPORTED", "unsupported medium"),
    };

    let storage = state.storage();
    let owner = match storage.account_threepid_owner(medium, &address).await {
        Ok(o) => o,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    match purpose {
        "register" | "add" if owner.is_some() => {
            return err(
                StatusCode::BAD_REQUEST,
                "M_THREEPID_IN_USE",
                "The specified address is already in use",
            );
        }
        "password" if owner.is_none() => {
            return err(
                StatusCode::BAD_REQUEST,
                "M_THREEPID_NOT_FOUND",
                "No account matches this third-party identifier",
            );
        }
        _ => {}
    }

    let existing = match storage.threepid_session_for_client(medium, &address, client_secret).await {
        Ok(s) => s,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let url = submit_url(headers, medium);
    if let Some(session) = existing {
        if send_attempt <= session.send_attempt {
            return (
                StatusCode::OK,
                Json(json!({"sid": session.sid, "submit_url": url})),
            )
                .into_response();
        }
        let token = random_token();
        let hash = token_hash(&token);
        if let Err(e) = deliver_token(medium, &address, purpose, &session.sid, send_attempt, &token).await {
            return MatrixError::unknown(e).into_response();
        }
        if let Err(e) = storage
            .retarget_threepid_session(&session.sid, purpose, send_attempt, &hash)
            .await
        {
            return MatrixError::unknown(e.to_string()).into_response();
        }
        return (StatusCode::OK, Json(json!({"sid": session.sid, "submit_url": url}))).into_response();
    }

    let sid = random_sid();
    let token = random_token();
    let hash = token_hash(&token);
    if let Err(e) = deliver_token(medium, &address, purpose, &sid, send_attempt, &token).await {
        return MatrixError::unknown(e).into_response();
    }
    let session = conduit::storage::ThreepidValidation {
        sid: sid.clone(),
        client_secret: client_secret.to_owned(),
        medium: medium.to_owned(),
        address,
        purpose: purpose.to_owned(),
        send_attempt,
        token_hash: hash,
        validated_at: None,
    };
    if let Err(e) = storage.insert_threepid_session(&session).await {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    (StatusCode::OK, Json(json!({"sid": sid, "submit_url": url}))).into_response()
}

async fn deliver_token(
    medium: &str,
    address: &str,
    purpose: &str,
    sid: &str,
    send_attempt: i32,
    token: &str,
) -> Result<(), String> {
    let Some(sink) = AccountConfig::get().threepid_sink.clone() else {
        return Err("validation sink is not configured".into());
    };
    deliver(
        &sink,
        &json!({
            "medium": medium,
            "address": address,
            "purpose": purpose,
            "sid": sid,
            "send_attempt": send_attempt,
            "token": token,
        }),
    )
    .await
}

macro_rules! request_route {
    ($name:ident, $medium:expr, $purpose:expr) => {
        pub async fn $name<S: AuthState>(
            State(state): State<S>,
            headers: HeaderMap,
            body: Option<Json<Value>>,
        ) -> Response {
            request_token(&state, &headers, body, $medium, $purpose).await
        }
    };
}

request_route!(register_email, "email", "register");
request_route!(register_msisdn, "msisdn", "register");
request_route!(password_email, "email", "password");
request_route!(password_msisdn, "msisdn", "password");
request_route!(add_email, "email", "add");
request_route!(add_msisdn, "msisdn", "add");

fn token_body(body: &Value) -> Result<(&str, &str, &str), Response> {
    let sid = match string_field(body, "sid") {
        Ok(s) => s,
        Err(r) => return Err(r),
    };
    let client_secret = match string_field(body, "client_secret") {
        Ok(s) => s,
        Err(r) => return Err(r),
    };
    let token = match string_field(body, "token") {
        Ok(s) => s,
        Err(r) => return Err(r),
    };
    Ok((sid, client_secret, token))
}

async fn accept_token<S: AuthState>(state: &S, sid: &str, client_secret: &str, token: &str) -> Response {
    if !configured() {
        return denied();
    }
    let storage = state.storage();
    let session = match storage.threepid_session(sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return invalid("unknown validation session"),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    if session.client_secret != client_secret || token_hash(token) != session.token_hash {
        return invalid("the validation token is not correct");
    }
    if session.validated_at.is_none() {
        if let Err(e) = storage.mark_threepid_validated(sid, now_ms()).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }
    (StatusCode::OK, Json(json!({"success": true}))).into_response()
}

pub async fn submit_token<S: AuthState>(
    State(state): State<S>,
    body: Option<Json<Value>>,
) -> Response {
    let body = body.map(|Json(v)| v).unwrap_or(Value::Null);
    let (sid, client_secret, token) = match token_body(&body) {
        Ok(t) => t,
        Err(r) => return r,
    };
    accept_token(&state, sid, client_secret, token).await
}

pub async fn submit_token_get<S: AuthState>(
    State(state): State<S>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let body = json!({
        "sid": query.get("sid"),
        "client_secret": query.get("client_secret"),
        "token": query.get("token"),
    });
    let (sid, client_secret, token) = match token_body(&body) {
        Ok(t) => t,
        Err(r) => return r,
    };
    accept_token(&state, sid, client_secret, token).await
}

async fn validated_add_session<S: AuthState>(
    state: &S,
    sid: &str,
    client_secret: &str,
) -> Result<conduit::storage::ThreepidValidation, Response> {
    let session = match state.storage().threepid_session(sid).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(err(StatusCode::FORBIDDEN, "M_THREEPID_AUTH_FAILED", "unknown validation session")),
        Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
    };
    if session.client_secret != client_secret || session.purpose != "add" || session.validated_at.is_none() {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_THREEPID_AUTH_FAILED",
            "the third-party identifier has not been validated",
        ));
    }
    Ok(session)
}

async fn store_for_user<S: AuthState>(
    state: &S,
    user_id: &str,
    session: &conduit::storage::ThreepidValidation,
) -> Response {
    let validated_at = session.validated_at.unwrap_or_else(now_ms);
    match state
        .storage()
        .add_account_threepid(user_id, &session.medium, &session.address, now_ms(), validated_at)
        .await
    {
        Ok(true) => (StatusCode::OK, Json(json!({}))).into_response(),
        Ok(false) => err(
            StatusCode::BAD_REQUEST,
            "M_THREEPID_IN_USE",
            "The specified address is already in use",
        ),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

pub async fn add<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    body: Option<Json<Value>>,
) -> Response {
    if !configured() {
        return changes_disabled();
    }
    let body = body.map(|Json(v)| v).unwrap_or(Value::Null);
    let sid = match string_field(&body, "sid") {
        Ok(s) => s.to_owned(),
        Err(r) => return r,
    };
    let client_secret = match string_field(&body, "client_secret") {
        Ok(s) => s.to_owned(),
        Err(r) => return r,
    };
    let flows = uia::account_flows(&state, &authed.user_id).await;
    let req = uia::UiaRequest::new("POST /account/3pid/add", Some(&authed.user_id), flows);
    if let Err(r) = uia::authenticate(&state, req, body.get("auth")).await {
        return r;
    }
    let session = match validated_add_session(&state, &sid, &client_secret).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    store_for_user(&state, &authed.user_id, &session).await
}

pub async fn add_legacy<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    body: Option<Json<Value>>,
) -> Response {
    if !configured() {
        return changes_disabled();
    }
    let body = body.map(|Json(v)| v).unwrap_or(Value::Null);
    let creds = body.get("three_pid_creds").cloned().unwrap_or(Value::Null);
    let sid = match string_field(&creds, "sid") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client_secret = match string_field(&creds, "client_secret") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let session = match validated_add_session(&state, sid, client_secret).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    store_for_user(&state, &authed.user_id, &session).await
}

/// `m.login.email.identity` / `m.login.msisdn` against a homeserver session.
pub async fn identity_stage<S: AuthState>(
    state: &S,
    operation: &str,
    medium: &str,
    creds: &Value,
) -> Result<(Option<String>, ValidatedThreepid), (&'static str, String)> {
    if !configured() {
        return Err(("M_THREEPID_DENIED", "third-party identifiers are not supported".into()));
    }
    let sid = creds
        .get("sid")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(("M_MISSING_PARAM", "sid is required".to_owned()))?;
    let client_secret = creds
        .get("client_secret")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(("M_MISSING_PARAM", "client_secret is required".to_owned()))?;
    let session = state
        .storage()
        .threepid_session(sid)
        .await
        .map_err(|e| ("M_UNKNOWN", e.to_string()))?
        .ok_or(("M_FORBIDDEN", "unknown validation session".to_owned()))?;
    if session.client_secret != client_secret
        || session.medium != medium
        || session.validated_at.is_none()
    {
        return Err(("M_FORBIDDEN", "the third-party identifier has not been validated".into()));
    }
    let expected = match operation {
        "POST /register" => "register",
        "POST /account/password" => "password",
        _ => return Err(("M_FORBIDDEN", "this operation does not accept a third-party identifier".into())),
    };
    if session.purpose != expected {
        return Err(("M_FORBIDDEN", "validation session is for a different request".into()));
    }
    let owner = state
        .storage()
        .account_threepid_owner(&session.medium, &session.address)
        .await
        .map_err(|e| ("M_UNKNOWN", e.to_string()))?;
    match expected {
        "register" if owner.is_some() => {
            return Err(("M_THREEPID_IN_USE", "The specified address is already in use".into()));
        }
        "password" => {
            if owner.is_none() {
                return Err((
                    "M_THREEPID_NOT_FOUND",
                    "No account matches this third-party identifier".into(),
                ));
            }
        }
        _ => {}
    }
    let proved = ValidatedThreepid {
        medium: session.medium,
        address: session.address,
        validated_at: session.validated_at.unwrap_or_else(now_ms),
    };
    let user_id = if expected == "password" { owner } else { None };
    Ok((user_id, proved))
}

/// Bind the 3PID a successful registration UIA proved, if it proved one.
pub async fn bind_registration<S: AuthState>(state: &S, user_id: &str, passed: &UiaPassed) -> Result<(), Response> {
    let Some(threepid) = &passed.threepid else {
        return Ok(());
    };
    match state
        .storage()
        .add_account_threepid(
            user_id,
            &threepid.medium,
            &threepid.address,
            now_ms(),
            threepid.validated_at,
        )
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(err(
            StatusCode::BAD_REQUEST,
            "M_THREEPID_IN_USE",
            "The specified address is already in use",
        )),
        Err(e) => Err(MatrixError::unknown(e.to_string()).into_response()),
    }
}

pub fn password_flows() -> Vec<Vec<&'static str>> {
    let mut flows = vec![vec![uia::PASSWORD]];
    if configured() {
        flows.push(vec![uia::EMAIL_IDENTITY]);
        flows.push(vec![uia::MSISDN]);
    }
    flows
}

pub fn registration_flows(base: Vec<&'static str>) -> Vec<Vec<&'static str>> {
    let mut flows = vec![base.clone()];
    if !configured() {
        return flows;
    }
    // Open registration can prove an email or a phone number by itself.
    // A registration token, when required, stays the first stage.
    if base == [uia::DUMMY] {
        flows.push(vec![uia::EMAIL_IDENTITY]);
        flows.push(vec![uia::MSISDN]);
    } else {
        let mut email = base.clone();
        email.push(uia::EMAIL_IDENTITY);
        let mut phone = base;
        phone.push(uia::MSISDN);
        flows.push(email);
        flows.push(phone);
    }
    flows
}
