//! Application service client-server API extensions (conduit-y99.35,
//! conduit-y99.18.1).
//!
//! <https://spec.matrix.org/v1.19/application-service-api/#client-server-api-extensions>
//!
//! * Identity assertion: an `as_token` is accepted wherever a user access
//!   token is ([`super::AuthedUser`]).  The request acts as `?user_id=`
//!   (default: the AS sender user), which must be the sender or a
//!   *registered* user in the AS's `users` namespaces (`403 M_FORBIDDEN`
//!   otherwise), and optionally as `?device_id=` (spec v1.17), which must be
//!   a device of that user (`400 M_UNKNOWN_DEVICE`).  Without a device ID
//!   the request is device-less.
//! * Timestamp massaging: `?ts=` on `PUT .../send/...` and
//!   `PUT .../state/...` sets `origin_server_ts` ([`ts_massaging`]).
//! * `m.login.application_service` login ([`login`]).
//! * Rate-limit exemption: see `rate_limit::CsRateLimiter::with_appservices`.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{request::Parts, HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::api::client::event_pipeline::ORIGIN_SERVER_TS;
use crate::app_service::{query_param, user_in_as_namespace, AppService};

use super::{AuthState, AuthedUser, LoginRequest, MatrixError};

/// The registered AS whose `as_token` is `token`, if any.
pub fn appservice_for_token<S: AuthState>(state: &S, token: &str) -> Option<Arc<AppService>> {
    state
        .registered_app_services()?
        .iter()
        .find(|s| s.as_token == token)
        .map(|s| Arc::new(s.clone()))
}

fn error(status: StatusCode, errcode: &str, message: &str) -> Response {
    (status, Json(json!({"errcode": errcode, "error": message}))).into_response()
}

/// Whether `user_id` is a local user ID (`@local:server_name`).
fn is_local(user_id: &str, server_name: &str) -> bool {
    user_id
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(':'))
        .is_some_and(|(local, server)| !local.is_empty() && server == server_name)
}

/// Resolve an AS-authenticated request to the user (and device) it acts as.
pub async fn assert_identity<S: AuthState>(
    state: &S,
    parts: &Parts,
    svc: Arc<AppService>,
) -> Result<AuthedUser, Response> {
    let server_name = state.server_name();
    let sender = svc.sender_user_id(server_name);
    let user_id = query_param(parts, "user_id").unwrap_or_else(|| sender.clone());
    if user_id != sender
        && !(is_local(&user_id, server_name) && user_in_as_namespace(&user_id, &svc))
    {
        return Err(error(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "Application service cannot masquerade as this user.",
        ));
    }
    let storage = state.storage();
    match storage.get_account(&user_id).await {
        Ok(Some(account)) if account.deactivated_at.is_some() => {
            return Err(super::user_deactivated());
        }
        Ok(Some(_)) => {}
        // The AS's own user exists implicitly.
        Ok(None) if user_id == sender => {
            if let Err(e) = storage.create_account(&user_id, None).await {
                if !e.to_string().contains("already exists") {
                    return Err(MatrixError::unknown(e.to_string()).into_response());
                }
            }
        }
        Ok(None) => {
            return Err(error(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                "Application service has not registered this user.",
            ));
        }
        Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
    }
    // Device masquerading (spec v1.17); the MSC3202 name is still accepted.
    let device_id = query_param(parts, "device_id")
        .or_else(|| query_param(parts, "org.matrix.msc3202.device_id"));
    let device_id = match device_id {
        None => String::new(),
        Some(device_id) => match storage.get_device(&user_id, &device_id).await {
            Ok(Some(_)) => device_id,
            Ok(None) => {
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    "M_UNKNOWN_DEVICE",
                    "The device does not belong to the asserted user.",
                ))
            }
            Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
        },
    };
    Ok(AuthedUser {
        user_id,
        device_id,
        grant: None,
        appservice: Some(svc),
    })
}

/// `400 M_EXCLUSIVE` when `authed` may not create `alias`: an application
/// service outside its own `aliases` namespaces, or anyone else inside a
/// namespace another application service holds exclusively.
pub fn alias_exclusivity_error<S: AuthState>(
    state: &S,
    authed: &AuthedUser,
    alias: &str,
) -> Option<Response> {
    let services = state.registered_app_services().unwrap_or_default();
    let owner = crate::app_service::exclusive_as_for_alias(alias, &services);
    let refused = match &authed.appservice {
        Some(svc) => {
            !svc.is_interested_in_alias(alias) || owner.is_some_and(|o| o.id != svc.id)
        }
        None => owner.is_some(),
    };
    refused.then(|| {
        error(
            StatusCode::BAD_REQUEST,
            "M_EXCLUSIVE",
            "This alias is reserved by an application service",
        )
    })
}

/// Whether the path is one of the two endpoints that honour `ts`.
fn ts_endpoint(method: &Method, path: &str) -> bool {
    if method != Method::PUT {
        return false;
    }
    let Some(rest) = path
        .strip_prefix("/_matrix/client/v3/rooms/")
        .or_else(|| path.strip_prefix("/_matrix/client/r0/rooms/"))
    else {
        return false;
    };
    let mut segments = rest.split('/');
    let _room = segments.next();
    matches!(segments.next(), Some("send") | Some("state"))
}

/// Largest `origin_server_ts` a canonical-JSON integer can carry.
const MAX_TS: u64 = (1 << 53) - 1;

/// `ts` timestamp massaging for application services (spec v1.3).
///
/// Only requests authenticated with an `as_token` may set it; it applies to
/// `PUT /rooms/{roomId}/send/...` and `PUT /rooms/{roomId}/state/...`, and
/// a value that is not a valid `origin_server_ts` is `400 M_INVALID_PARAM`.
pub async fn ts_massaging<S: AuthState>(
    State(state): State<S>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = req.into_parts();
    let ts = query_param(&parts, "ts");
    let is_as = super::extract_access_token(&parts)
        .is_some_and(|token| appservice_for_token(&state, &token).is_some());
    let req = Request::from_parts(parts, body);
    let Some(ts) = ts.filter(|_| is_as && ts_endpoint(req.method(), req.uri().path())) else {
        return next.run(req).await;
    };
    match ts.parse::<u64>() {
        Ok(ts) if ts <= MAX_TS => ORIGIN_SERVER_TS.scope(ts, next.run(req)).await,
        _ => error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "ts must be a non-negative integer millisecond timestamp",
        ),
    }
}

/// `POST /login` with `type: m.login.application_service`.
///
/// The `as_token` authenticates; the identifier names a registered user in
/// the AS's namespace.  An invalid token or unregistered user is
/// `403 M_FORBIDDEN`; a user outside the namespace is `403 M_EXCLUSIVE`.
pub async fn login<S: AuthState>(state: &S, headers: &HeaderMap, body: &LoginRequest) -> Response {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(svc) = token.and_then(|t| appservice_for_token(state, t)) else {
        return MatrixError::forbidden("m.login.application_service requires a valid as_token")
            .into_response();
    };
    let raw = match &body.identifier {
        Some(id) if id.id_type == "m.id.user" => id.user.clone(),
        Some(_) => return MatrixError::forbidden("unsupported identifier").into_response(),
        None => body.user.clone(),
    };
    let Some(raw) = raw.filter(|u| !u.is_empty()) else {
        return MatrixError::forbidden("missing user identifier").into_response();
    };
    let server_name = state.server_name();
    let user_id = if raw.starts_with('@') {
        raw
    } else {
        format!("@{}:{server_name}", raw.to_lowercase())
    };
    if user_id != svc.sender_user_id(server_name)
        && !(is_local(&user_id, server_name) && user_in_as_namespace(&user_id, &svc))
    {
        return error(
            StatusCode::FORBIDDEN,
            "M_EXCLUSIVE",
            "The user is outside the application service's namespace",
        );
    }
    match state.storage().get_account(&user_id).await {
        Ok(Some(account)) if account.deactivated_at.is_some() => return super::user_deactivated(),
        Ok(Some(_)) => {}
        Ok(None) => {
            return MatrixError::forbidden("Application service has not registered this user")
                .into_response()
        }
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }
    match super::session::issue_session(state, &user_id, &body.options()).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(r) => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_applies_only_to_send_and_state_puts() {
        assert!(ts_endpoint(&Method::PUT, "/_matrix/client/v3/rooms/!r:hs/send/m.room.message/1"));
        assert!(ts_endpoint(&Method::PUT, "/_matrix/client/v3/rooms/!r:hs/state/m.room.topic/"));
        assert!(ts_endpoint(&Method::PUT, "/_matrix/client/v3/rooms/!r:hs/state/m.room.topic"));
        assert!(!ts_endpoint(&Method::GET, "/_matrix/client/v3/rooms/!r:hs/state/m.room.topic"));
        assert!(!ts_endpoint(&Method::PUT, "/_matrix/client/v3/rooms/!r:hs/typing/@a:hs"));
        assert!(!ts_endpoint(&Method::PUT, "/_matrix/client/v3/profile/@a:hs/displayname"));
    }

    #[test]
    fn local_user_ids() {
        assert!(is_local("@a:hs.test", "hs.test"));
        assert!(!is_local("@a:other", "hs.test"));
        assert!(!is_local("@:hs.test", "hs.test"));
        assert!(!is_local("a:hs.test", "hs.test"));
    }
}
