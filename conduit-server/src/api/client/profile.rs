//! Profile handlers (1mo.1, 1mo.2).
//!
//! GET  /_matrix/client/v3/profile/:userId/displayname
//! PUT  /_matrix/client/v3/profile/:userId/displayname
//! GET  /_matrix/client/v3/profile/:userId/avatar_url
//! PUT  /_matrix/client/v3/profile/:userId/avatar_url
//! GET  /_matrix/client/v3/profile/:userId
//!
//! GET routes are unauthenticated (Matrix spec §11.1).
//! PUT routes require auth and the userId in the path must match the caller.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use super::{AuthState, AuthedUser, MatrixError};

// ---------------------------------------------------------------------------
// PUT /profile/:userId/displayname
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SetDisplaynameRequest {
    pub displayname: Option<String>,
}

pub async fn put_displayname<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(user_id): Path<String>,
    Json(body): Json<SetDisplaynameRequest>,
) -> Response {
    if authed.user_id != user_id {
        return MatrixError::forbidden("cannot set another user's display name").into_response();
    }
    if let Err(e) = state
        .storage()
        .set_displayname(&user_id, body.displayname.as_deref())
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// GET /profile/:userId/displayname  (unauthenticated)
// ---------------------------------------------------------------------------

pub async fn get_displayname<S: AuthState>(
    State(state): State<S>,
    Path(user_id): Path<String>,
) -> Response {
    match state.storage().get_account(&user_id).await {
        Ok(Some(acct)) => {
            let mut body = json!({});
            if let Some(dn) = acct.displayname {
                body["displayname"] = json!(dn);
            }
            (StatusCode::OK, Json(body)).into_response()
        }
        Ok(None) => MatrixError::new_not_found("user not found").into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /profile/:userId/avatar_url
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SetAvatarUrlRequest {
    pub avatar_url: Option<String>,
}

pub async fn put_avatar_url<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(user_id): Path<String>,
    Json(body): Json<SetAvatarUrlRequest>,
) -> Response {
    if authed.user_id != user_id {
        return MatrixError::forbidden("cannot set another user's avatar URL").into_response();
    }
    if let Err(e) = state
        .storage()
        .set_avatar_url(&user_id, body.avatar_url.as_deref())
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// GET /profile/:userId/avatar_url  (unauthenticated)
// ---------------------------------------------------------------------------

pub async fn get_avatar_url<S: AuthState>(
    State(state): State<S>,
    Path(user_id): Path<String>,
) -> Response {
    match state.storage().get_account(&user_id).await {
        Ok(Some(acct)) => {
            let mut body = json!({});
            if let Some(url) = acct.avatar_url {
                body["avatar_url"] = json!(url);
            }
            (StatusCode::OK, Json(body)).into_response()
        }
        Ok(None) => MatrixError::new_not_found("user not found").into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /profile/:userId  (unauthenticated — returns both fields)
// ---------------------------------------------------------------------------

pub async fn get_profile<S: AuthState>(
    State(state): State<S>,
    Path(user_id): Path<String>,
) -> Response {
    match state.storage().get_account(&user_id).await {
        Ok(Some(acct)) => {
            let mut body = json!({});
            if let Some(dn) = acct.displayname {
                body["displayname"] = json!(dn);
            }
            if let Some(url) = acct.avatar_url {
                body["avatar_url"] = json!(url);
            }
            (StatusCode::OK, Json(body)).into_response()
        }
        Ok(None) => MatrixError::new_not_found("user not found").into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}
