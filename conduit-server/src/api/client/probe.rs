//! Lifecycle probe endpoints clients hit on login / startup (conduit-eck).
//!
//! - `GET  /_matrix/client/v3/capabilities`           feature advertisement
//! - `GET  /_matrix/client/v3/voip/turnServer`        TURN/STUN config (empty OK)
//! - `POST /_matrix/client/v3/user/{userId}/openid/request_token`  mint OIDC token
//!
//! The TURN endpoint returns an empty server list — a valid response for a
//! deployment without TURN. The OpenID endpoint mints a short-lived bearer
//! token via the existing access-token table; cross-server verification
//! (`/_matrix/federation/v1/openid/userinfo`) is tracked as a follow-up.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{AuthState, AuthedUser, MatrixError};

/// `GET /_matrix/client/v3/capabilities`
pub async fn capabilities<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
) -> Response {
    // Account capabilities reflect what this account can actually do
    // (conduit-y99.18): passwordless and guest accounts cannot change a
    // password, guests may only change their display name and cannot
    // mint login tokens, and no 3PIDs are supported.
    let (has_password, is_guest) = match state.storage().get_account(&authed.user_id).await {
        Ok(Some(a)) => (a.password_hash.is_some(), a.is_guest),
        Ok(None) => (false, false),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    (
        StatusCode::OK,
        Json(json!({
            "capabilities": {
                "m.change_password": { "enabled": has_password && !is_guest },
                // Guests may change only their display name (guest gate).
                "m.profile_fields": if is_guest {
                    json!({ "enabled": true, "allowed": ["displayname"] })
                } else {
                    json!({ "enabled": true })
                },
                "m.set_displayname":  { "enabled": true },
                "m.set_avatar_url":   { "enabled": !is_guest },
                "m.3pid_changes":     { "enabled": false },
                "m.get_login_token":  { "enabled": !is_guest },
                // Only versions the kernel can actually create and
                // validate (conduit-y99.28; more arrive with y99.23).
                "m.room_versions": {
                    "default": conduit::ROOM_VERSION,
                    "available": { conduit::ROOM_VERSION: "stable" }
                }
            }
        })),
    )
        .into_response()
}

/// `GET /_matrix/client/v3/voip/turnServer`
///
/// We don't run TURN/STUN. An empty `uris` array is a valid response and
/// tells Element to fall back to local-network ICE candidates only.
pub async fn turn_server<S: AuthState>(
    State(_state): State<S>,
    _authed: AuthedUser,
) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "username": "",
            "password": "",
            "uris": [],
            "ttl": 86400,
        })),
    )
        .into_response()
}

/// `POST /_matrix/client/v3/user/:userId/openid/request_token`
///
/// Mints a 1-hour bearer token bound to the requesting user. Element passes
/// this to widgets (e.g. Jitsi) for identity verification.
pub async fn openid_request_token<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(user_id): Path<String>,
    _body: Option<Json<serde_json::Value>>,
) -> Response {
    if user_id != authed.user_id {
        return MatrixError::forbidden("Can only request OpenID tokens for yourself")
            .into_response();
    }

    // Random 32-byte token, base64url-encoded.
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);

    // Persist hash → (user, device, expiry). Reuses the access_tokens table
    // since OpenID tokens are just bearer credentials with a short TTL.
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = URL_SAFE_NO_PAD.encode(hasher.finalize());

    let expires = Utc::now() + Duration::hours(1);
    if let Err(e) = state
        .storage()
        .insert_token(&token_hash, &authed.user_id, &authed.device_id, Some(expires))
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }

    (
        StatusCode::OK,
        Json(json!({
            "access_token": token,
            "token_type": "Bearer",
            "matrix_server_name": state.server_name(),
            "expires_in": 3600,
        })),
    )
        .into_response()
}
