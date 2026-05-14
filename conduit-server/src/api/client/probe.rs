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
    State(_state): State<S>,
    _authed: AuthedUser,
) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "capabilities": {
                "m.change_password": { "enabled": true },
                "m.set_displayname":  { "enabled": true },
                "m.set_avatar_url":   { "enabled": true },
                "m.3pid_changes":     { "enabled": false },
                "m.room_versions": {
                    "default": "11",
                    "available": {
                        "1":  "stable",
                        "2":  "stable",
                        "3":  "stable",
                        "4":  "stable",
                        "5":  "stable",
                        "6":  "stable",
                        "7":  "stable",
                        "8":  "stable",
                        "9":  "stable",
                        "10": "stable",
                        "11": "stable",
                    }
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
