//! Account management (conduit-y99.18), and the router for the whole
//! account & devices lane.
//!
//!   POST /_matrix/client/v3/account/password            (UIA)
//!   POST /_matrix/client/v3/account/deactivate          (UIA)
//!   GET  /_matrix/client/v3/account/3pid
//!   POST /_matrix/client/v3/account/3pid{,/add,/bind,/delete,/unbind}
//!   POST /_matrix/client/v3/{register,account/password,account/3pid}/{email,msisdn}/requestToken
//!   GET  /_matrix/client/v3/admin/whois/{userId}
//!
//! This server stores no third-party identifiers and has neither an
//! identity-server client nor outbound email/SMS, so `m.3pid_changes`
//! is disabled and the 3PID endpoints answer with the spec's errcodes
//! for that situation rather than 404.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use super::session::{device_ids_except, leave_all_rooms, remove_devices, MaybeAuthed};
use super::{hash_password, uia, AuthState, AuthedUser, MatrixError};

/// Every route owned by the account & devices lane.
pub fn router<S: AuthState>() -> Router<S> {
    use super::{auth_fallback, devices, registration, session, well_known};
    const V3: &str = "/_matrix/client/v3";
    Router::new()
        // Devices
        .route(&format!("{V3}/devices"), get(devices::list_devices::<S>))
        .route(
            &format!("{V3}/devices/:deviceId"),
            get(devices::get_device::<S>)
                .put(devices::update_device::<S>)
                .delete(devices::delete_device::<S>),
        )
        .route(&format!("{V3}/delete_devices"), post(devices::delete_devices::<S>))
        // Account
        .route(&format!("{V3}/account/password"), post(change_password::<S>))
        .route(&format!("{V3}/account/deactivate"), post(deactivate::<S>))
        .route(&format!("{V3}/account/3pid"), get(get_3pids::<S>).post(threepid_changes_disabled::<S>))
        .route(&format!("{V3}/account/3pid/add"), post(threepid_changes_disabled::<S>))
        .route(&format!("{V3}/account/3pid/bind"), post(super::third_party::account_bind::<S>))
        .route(&format!("{V3}/account/3pid/delete"), post(super::third_party::account_unbind::<S>))
        .route(&format!("{V3}/account/3pid/unbind"), post(super::third_party::account_unbind::<S>))
        .route(&format!("{V3}/account/3pid/email/requestToken"), post(threepid_denied))
        .route(&format!("{V3}/account/3pid/msisdn/requestToken"), post(threepid_denied))
        .route(&format!("{V3}/account/password/email/requestToken"), post(threepid_denied))
        .route(&format!("{V3}/account/password/msisdn/requestToken"), post(threepid_denied))
        .route(&format!("{V3}/register/email/requestToken"), post(threepid_denied))
        .route(&format!("{V3}/register/msisdn/requestToken"), post(threepid_denied))
        // Registration helpers
        .route(&format!("{V3}/register/available"), get(registration::available::<S>))
        .route(
            "/_matrix/client/v1/register/m.login.registration_token/validity",
            get(registration::token_validity),
        )
        // Sessions
        .route(&format!("{V3}/refresh"), post(session::refresh::<S>))
        .route("/_matrix/client/v1/login/get_token", post(session::get_login_token::<S>))
        // UIA fallback
        .route(
            &format!("{V3}/auth/:authType/fallback/web"),
            get(auth_fallback::fallback_page::<S>).post(auth_fallback::fallback_submit::<S>),
        )
        // Administration
        .route(&format!("{V3}/admin/whois/:userId"), get(whois::<S>))
        // Discovery
        .route("/.well-known/matrix/client", get(well_known::client::<S>))
        .route("/.well-known/matrix/server", get(well_known::server))
        .route("/.well-known/matrix/support", get(well_known::support::<S>))
}

fn missing_param(name: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"errcode": "M_MISSING_PARAM", "error": format!("{name} is required")})),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /account/password
// ---------------------------------------------------------------------------

pub async fn change_password<S: AuthState>(
    State(state): State<S>,
    MaybeAuthed(authed): MaybeAuthed,
    body: Option<Json<Value>>,
) -> Response {
    let body = body.map(|Json(v)| v).unwrap_or(Value::Null);
    let Some(new_password) = body.get("new_password").and_then(Value::as_str) else {
        return missing_param("new_password");
    };
    if new_password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"errcode": "M_WEAK_PASSWORD", "error": "password must not be empty"})),
        )
            .into_response();
    }
    let logout_devices = body
        .get("logout_devices")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    // With a token, the token names the user; without one the password
    // stage does.  Either way the account must already have a password:
    // passwordless (identikey/SSO) accounts advertise m.change_password
    // as disabled.
    if let Some(a) = &authed {
        match state.storage().get_account(&a.user_id).await {
            Ok(Some(acct)) if acct.password_hash.is_some() => {}
            Ok(_) => {
                return MatrixError::forbidden("Password changes are not enabled for this account")
                    .into_response()
            }
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        }
    }
    let req = uia::UiaRequest::new(
        "POST /account/password",
        authed.as_ref().map(|a| a.user_id.as_str()),
        vec![vec![uia::PASSWORD]],
    );
    let passed = match uia::authenticate(&state, req, body.get("auth")).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Some(user_id) = passed.user_id else {
        return MatrixError::forbidden("could not determine the account").into_response();
    };

    let hash = match hash_password(new_password.to_owned()).await {
        Ok(h) => h,
        Err(e) => return MatrixError::unknown(format!("password hashing failed: {e}")).into_response(),
    };
    if let Err(e) = state.storage().set_password_hash(&user_id, &hash).await {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    if logout_devices {
        // The requesting session survives; every other device goes.
        let keep = authed.as_ref().map(|a| a.device_id.as_str());
        let others = match device_ids_except(&state, &user_id, keep).await {
            Ok(d) => d,
            Err(r) => return r,
        };
        if let Err(r) = remove_devices(&state, &user_id, &others).await {
            return r;
        }
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// POST /account/deactivate
// ---------------------------------------------------------------------------

/// Deactivate an account: leave every room, remove every device (and so
/// every token and E2EE key), drop pushers and optionally erase profile
/// and account data.  Shared with the admin API.
pub async fn deactivate_user<S: AuthState>(state: &S, user_id: &str, erase: bool) -> Result<(), Response> {
    leave_all_rooms(state, user_id).await;
    let storage = state.storage();
    if let Ok(pushers) = storage.list_pushers(user_id).await {
        for p in pushers {
            let _ = storage.delete_pusher(user_id, &p.pushkey, &p.app_id).await;
        }
    }
    if erase {
        storage
            .erase_account(user_id)
            .await
            .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?;
    }
    storage
        .deactivate_account(user_id)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?;
    let devices = device_ids_except(state, user_id, None).await?;
    remove_devices(state, user_id, &devices).await
}

pub async fn deactivate<S: AuthState>(
    State(state): State<S>,
    MaybeAuthed(authed): MaybeAuthed,
    body: Option<Json<Value>>,
) -> Response {
    let body = body.map(|Json(v)| v).unwrap_or(Value::Null);
    let erase = body.get("erase").and_then(Value::as_bool).unwrap_or(false);
    let flows = match &authed {
        Some(a) => uia::account_flows(&state, &a.user_id).await,
        None => vec![vec![uia::PASSWORD]],
    };
    let req = uia::UiaRequest::new(
        "POST /account/deactivate",
        authed.as_ref().map(|a| a.user_id.as_str()),
        flows,
    );
    let passed = match uia::authenticate(&state, req, body.get("auth")).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Some(user_id) = passed.user_id else {
        return MatrixError::forbidden("could not determine the account").into_response();
    };
    if let Err(r) = deactivate_user(&state, &user_id, erase).await {
        return r;
    }
    // Unbind every identity-server binding made through this server
    // (conduit-y99.36); `success` when there is nothing to unbind.
    let id_server = body.get("id_server").and_then(Value::as_str);
    let result = super::third_party::unbind_all(&state, &user_id, id_server).await;
    (StatusCode::OK, Json(json!({ "id_server_unbind_result": result }))).into_response()
}

// ---------------------------------------------------------------------------
// Third-party identifiers
// ---------------------------------------------------------------------------

pub async fn get_3pids<S: AuthState>(_authed: AuthedUser) -> Response {
    (StatusCode::OK, Json(json!({ "threepids": [] }))).into_response()
}

pub async fn threepid_changes_disabled<S: AuthState>(_authed: AuthedUser) -> Response {
    MatrixError::forbidden("Third-party identifier changes are disabled on this homeserver (m.3pid_changes)")
        .into_response()
}

/// Validation-token requests: this server cannot send email or SMS and
/// does not delegate to an identity server.
pub async fn threepid_denied() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "errcode": "M_THREEPID_DENIED",
            "error": "Third-party identifiers are not supported on this homeserver",
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /admin/whois/{userId}
// ---------------------------------------------------------------------------

pub async fn whois<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(user_id): Path<String>,
) -> Response {
    let storage = state.storage();
    // Authorise before looking the target up (no user enumeration).
    if authed.user_id != user_id {
        match storage.get_account(&authed.user_id).await {
            Ok(Some(a)) if a.is_admin => {}
            Ok(_) => {
                return MatrixError::forbidden("Only server administrators may look up other users")
                    .into_response()
            }
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        }
    }
    let local_suffix = format!(":{}", state.server_name());
    if !user_id.starts_with('@') || !user_id.ends_with(&local_suffix) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"errcode": "M_INVALID_PARAM", "error": "Can only look up local users"})),
        )
            .into_response();
    }
    match storage.get_account(&user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return MatrixError::new_not_found("Unknown user").into_response(),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }
    let devices = match storage.list_devices_for_user(&user_id).await {
        Ok(d) => d,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let mut out = serde_json::Map::new();
    for d in devices {
        let mut connections = Vec::new();
        if d.last_seen_ts.is_some() || d.last_seen_ip.is_some() {
            let mut c = json!({});
            if let Some(ip) = &d.last_seen_ip {
                c["ip"] = json!(ip);
            }
            if let Some(ts) = d.last_seen_ts {
                c["last_seen"] = json!(ts);
            }
            if let Some(ua) = &d.last_seen_user_agent {
                c["user_agent"] = json!(ua);
            }
            connections.push(c);
        }
        out.insert(
            d.device_id.clone(),
            json!({ "sessions": [ { "connections": connections } ] }),
        );
    }
    (StatusCode::OK, Json(json!({ "user_id": user_id, "devices": out }))).into_response()
}
