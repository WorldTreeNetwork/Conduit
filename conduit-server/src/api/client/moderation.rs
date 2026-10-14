//! Account locking and suspension (Matrix v1.19 §Account moderation,
//! §Server administration; conduit-y99.43).
//!
//! GET/PUT /_matrix/client/v1/admin/lock/{userId}
//! GET/PUT /_matrix/client/v1/admin/suspend/{userId}
//!
//! Enforcement runs in the `AuthedUser` extractor ([`gate`]), so every
//! authenticated endpoint is covered without per-handler code:
//!
//! - **Locked**: `401 M_USER_LOCKED` with `soft_logout: true` on every
//!   authenticated endpoint except `POST /logout` and `POST /logout/all`.
//!   Tokens are not invalidated (spec SHOULD NOT), and login / refresh
//!   are refused the same way until the lock is lifted.
//! - **Suspended**: `403 M_USER_SUSPENDED` on the spec's recommended
//!   forbidden set — joining, knocking, inviting, sending messages and
//!   state, creating/upgrading rooms, changing the profile and redacting
//!   other users' events.  Reading, syncing, key backup, cross-signing,
//!   leaving, redacting one's own events, logout and deactivation stay
//!   available.

use axum::{
    extract::{Path, State},
    http::{request::Parts, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;

use super::{AuthState, MatrixError};
use crate::api::admin::AdminAuthed;

pub fn router<S: AuthState>() -> Router<S> {
    Router::new()
        .route(
            "/_matrix/client/v1/admin/lock/:userId",
            get(get_lock::<S>).put(put_lock::<S>),
        )
        .route(
            "/_matrix/client/v1/admin/suspend/:userId",
            get(get_suspend::<S>).put(put_suspend::<S>),
        )
}

/// `401 M_USER_LOCKED` with `soft_logout: true`.
pub fn user_locked() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "errcode": "M_USER_LOCKED",
            "error": "This account has been locked",
            "soft_logout": true,
        })),
    )
        .into_response()
}

/// `403 M_USER_SUSPENDED`.
pub fn user_suspended() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "errcode": "M_USER_SUSPENDED",
            "error": "You cannot perform this action while suspended.",
        })),
    )
        .into_response()
}

/// Whether a locked account may still call `method path` (logout only).
pub fn locked_may_call(method: &Method, path: &str) -> bool {
    method == Method::POST
        && matches!(
            path.trim_end_matches('/'),
            "/_matrix/client/v3/logout"
                | "/_matrix/client/v3/logout/all"
                | "/_matrix/client/r0/logout"
                | "/_matrix/client/r0/logout/all"
        )
}

/// What a suspended account's request amounts to.
#[derive(Debug, PartialEq, Eq)]
pub enum SuspendedCall {
    Allowed,
    Forbidden,
    /// A redaction: allowed only for the user's own event.
    Redaction { room_id: String, event_id: String },
}

/// Classify `method path` for a suspended account.
pub fn suspended_call(method: &Method, path: &str) -> SuspendedCall {
    let Some(rest) = path
        .strip_prefix("/_matrix/client/v3/")
        .or_else(|| path.strip_prefix("/_matrix/client/r0/"))
    else {
        return SuspendedCall::Allowed;
    };
    let segs: Vec<&str> = rest.trim_end_matches('/').split('/').collect();
    let forbidden = match (method.as_str(), segs.as_slice()) {
        ("POST", ["createRoom"]) => true,
        ("POST", ["join", _]) | ("POST", ["knock", _]) => true,
        ("POST", ["rooms", _, "join"]) | ("POST", ["rooms", _, "invite"]) => true,
        ("POST", ["rooms", _, "upgrade"]) => true,
        ("PUT", ["rooms", _, "send", _, _]) => true,
        ("PUT", ["rooms", _, "state", ..]) => true,
        ("PUT", ["profile", _, _]) | ("DELETE", ["profile", _, _]) => true,
        ("PUT", ["rooms", room, "redact", event, _]) => {
            return SuspendedCall::Redaction {
                room_id: percent_decode(room),
                event_id: percent_decode(event),
            }
        }
        _ => false,
    };
    if forbidden {
        SuspendedCall::Forbidden
    } else {
        SuspendedCall::Allowed
    }
}

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| s.to_owned())
}

/// Enforce lock and suspension for an authenticated request, then the
/// server-notices leave rule.  Called by the `AuthedUser` extractor.
pub async fn gate<S: AuthState>(state: &S, parts: &Parts, user_id: &str) -> Result<(), Response> {
    let moderation = state
        .storage()
        .account_moderation(user_id)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?;
    let path = parts.uri.path();
    if moderation.locked && !locked_may_call(&parts.method, path) {
        return Err(user_locked());
    }
    if moderation.suspended {
        match suspended_call(&parts.method, path) {
            SuspendedCall::Allowed => {}
            SuspendedCall::Forbidden => return Err(user_suspended()),
            SuspendedCall::Redaction { room_id, event_id } => {
                let own = match state.storage().get_event(&event_id).await {
                    Ok(Some(ev)) => ev.room_id == room_id && ev.sender == user_id,
                    // Unknown event: let the handler answer 404.
                    Ok(None) => true,
                    Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
                };
                if !own {
                    return Err(user_suspended());
                }
            }
        }
    }
    super::server_notices::leave_gate(state, parts, user_id).await
}

/// Refuse to issue new tokens to a locked account (login, refresh).
pub async fn refuse_if_locked<S: AuthState>(state: &S, user_id: &str) -> Result<(), Response> {
    match state.storage().account_moderation(user_id).await {
        Ok(m) if m.locked => Err(user_locked()),
        Ok(_) => Ok(()),
        Err(e) => Err(MatrixError::unknown(e.to_string()).into_response()),
    }
}

// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Action {
    Lock,
    Suspend,
}

impl Action {
    fn field(self) -> &'static str {
        match self {
            Action::Lock => "locked",
            Action::Suspend => "suspended",
        }
    }
}

fn invalid_param(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"errcode": "M_INVALID_PARAM", "error": msg})),
    )
        .into_response()
}

/// Shared validation, in spec order: the caller is already proven an
/// admin by [`AdminAuthed`] (authorisation before any account lookup),
/// then locality, existence, and the target not being an admin.
async fn target_checks<S: AuthState>(
    state: &S,
    admin: &AdminAuthed,
    target: &str,
    changing: bool,
) -> Result<(), Response> {
    let local = target
        .strip_prefix('@')
        .and_then(|s| s.split_once(':'))
        .is_some_and(|(local, server)| !local.is_empty() && server == state.server_name());
    if !local {
        return Err(invalid_param("User does not belong to the local server."));
    }
    if changing && target == admin.user_id {
        return Err(MatrixError::forbidden("You cannot change your own account moderation state")
            .into_response());
    }
    let account = match state.storage().get_account(target).await {
        Ok(Some(a)) if a.deactivated_at.is_none() => a,
        Ok(_) => return Err(MatrixError::new_not_found("User not found.").into_response()),
        Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
    };
    if account.is_admin && target != admin.user_id {
        return Err(MatrixError::forbidden("The target user is a server administrator").into_response());
    }
    Ok(())
}

async fn get_state<S: AuthState>(state: S, admin: AdminAuthed, target: String, action: Action) -> Response {
    if let Err(r) = target_checks(&state, &admin, &target, false).await {
        return r;
    }
    match state.storage().account_moderation(&target).await {
        Ok(m) => {
            let value = match action {
                Action::Lock => m.locked,
                Action::Suspend => m.suspended,
            };
            (StatusCode::OK, Json(json!({ action.field(): value }))).into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

async fn put_state<S: AuthState>(
    state: S,
    admin: AdminAuthed,
    target: String,
    action: Action,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let Some(value) = body
        .as_ref()
        .and_then(|b| b.get(action.field()))
        .and_then(serde_json::Value::as_bool)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errcode": "M_BAD_JSON",
                "error": format!("'{}' must be a boolean", action.field()),
            })),
        )
            .into_response();
    };
    if let Err(r) = target_checks(&state, &admin, &target, true).await {
        return r;
    }
    let storage = state.storage();
    let result = match action {
        Action::Lock => storage.set_account_locked(&target, value).await,
        Action::Suspend => storage.set_account_suspended(&target, value).await,
    };
    if let Err(e) = result {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    let _ = storage
        .append_audit_log(
            &admin.user_id,
            match action {
                Action::Lock => "lock_user",
                Action::Suspend => "suspend_user",
            },
            Some(&target),
            &json!({ action.field(): value }),
        )
        .await;
    (StatusCode::OK, Json(json!({ action.field(): value }))).into_response()
}

pub async fn get_lock<S: AuthState>(State(state): State<S>, admin: AdminAuthed, Path(user_id): Path<String>) -> Response {
    get_state(state, admin, user_id, Action::Lock).await
}

pub async fn put_lock<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Path(user_id): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    put_state(state, admin, user_id, Action::Lock, body).await
}

pub async fn get_suspend<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Path(user_id): Path<String>,
) -> Response {
    get_state(state, admin, user_id, Action::Suspend).await
}

pub async fn put_suspend<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Path(user_id): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    put_state(state, admin, user_id, Action::Suspend, body).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_accounts_may_only_log_out() {
        assert!(locked_may_call(&Method::POST, "/_matrix/client/v3/logout"));
        assert!(locked_may_call(&Method::POST, "/_matrix/client/v3/logout/all"));
        assert!(!locked_may_call(&Method::GET, "/_matrix/client/v3/sync"));
        assert!(!locked_may_call(&Method::GET, "/_matrix/client/v3/account/whoami"));
        assert!(!locked_may_call(&Method::GET, "/_matrix/client/v3/logout"));
    }

    #[test]
    fn suspension_forbids_the_recommended_set() {
        use SuspendedCall::*;
        let p = |m: Method, path: &str| suspended_call(&m, path);
        assert_eq!(p(Method::POST, "/_matrix/client/v3/createRoom"), Forbidden);
        assert_eq!(p(Method::POST, "/_matrix/client/v3/join/%23a%3Ahs"), Forbidden);
        assert_eq!(p(Method::POST, "/_matrix/client/v3/rooms/!r:hs/join"), Forbidden);
        assert_eq!(p(Method::POST, "/_matrix/client/v3/knock/!r:hs"), Forbidden);
        assert_eq!(p(Method::POST, "/_matrix/client/v3/rooms/!r:hs/invite"), Forbidden);
        assert_eq!(p(Method::PUT, "/_matrix/client/v3/rooms/!r:hs/send/m.room.message/1"), Forbidden);
        assert_eq!(p(Method::PUT, "/_matrix/client/v3/rooms/!r:hs/state/m.room.topic"), Forbidden);
        assert_eq!(p(Method::PUT, "/_matrix/client/v3/rooms/!r:hs/state/m.room.topic/"), Forbidden);
        assert_eq!(p(Method::PUT, "/_matrix/client/v3/profile/@u:hs/displayname"), Forbidden);
        assert_eq!(p(Method::DELETE, "/_matrix/client/v3/profile/@u:hs/m.tz"), Forbidden);
        assert_eq!(
            p(Method::PUT, "/_matrix/client/v3/rooms/!r:hs/redact/%24ev/t1"),
            Redaction { room_id: "!r:hs".into(), event_id: "$ev".into() }
        );
        for allowed in [
            (Method::GET, "/_matrix/client/v3/sync"),
            (Method::GET, "/_matrix/client/v3/rooms/!r:hs/messages"),
            (Method::POST, "/_matrix/client/v3/rooms/!r:hs/leave"),
            (Method::PUT, "/_matrix/client/v3/room_keys/keys"),
            (Method::POST, "/_matrix/client/v3/keys/signatures/upload"),
            (Method::POST, "/_matrix/client/v3/logout"),
            (Method::POST, "/_matrix/client/v3/account/deactivate"),
            (Method::GET, "/_matrix/client/v3/profile/@u:hs"),
        ] {
            assert_eq!(p(allowed.0, allowed.1), Allowed, "{}", allowed.1);
        }
    }
}
