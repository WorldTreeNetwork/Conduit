//! Account data handlers (1mo.3, 1mo.4).
//!
//! GET /_matrix/client/v3/user/:userId/account_data/:type
//! PUT /_matrix/client/v3/user/:userId/account_data/:type
//! GET /_matrix/client/v3/user/:userId/rooms/:roomId/account_data/:type
//! PUT /_matrix/client/v3/user/:userId/rooms/:roomId/account_data/:type

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{Value, json};

use super::{AuthState, AuthedUser, MatrixError};

/// Account data types the server manages itself. Clients may read them
/// but setting them is `405 M_BAD_JSON` (v1.19 Client Config, server
/// behaviour; m.push_rules joined the list in v1.10).
pub const SERVER_MANAGED_TYPES: &[&str] = &["m.fully_read", "m.push_rules"];

fn reject_server_managed(event_type: &str) -> Option<Response> {
    SERVER_MANAGED_TYPES.contains(&event_type).then(|| {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(json!({
                "errcode": "M_BAD_JSON",
                "error": format!("Cannot set {event_type} through this API."),
            })),
        )
            .into_response()
    })
}

// ---------------------------------------------------------------------------
// PUT /user/:userId/account_data/:type
// ---------------------------------------------------------------------------

pub async fn put_account_data<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((user_id, event_type)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Response {
    if authed.user_id != user_id {
        return MatrixError::forbidden("cannot set another user's account data").into_response();
    }
    if let Some(rejection) = reject_server_managed(&event_type) {
        return rejection;
    }
    if let Err(e) = state
        .storage()
        .set_account_data(&user_id, None, &event_type, &body)
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    state.sync_notify().notify_waiters();
    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// GET /user/:userId/account_data/:type
// ---------------------------------------------------------------------------

pub async fn get_account_data<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((user_id, event_type)): Path<(String, String)>,
) -> Response {
    if authed.user_id != user_id {
        return MatrixError::forbidden("cannot read another user's account data").into_response();
    }
    match state.storage().get_account_data(&user_id, None, &event_type).await {
        Ok(Some(content)) => (StatusCode::OK, Json(content)).into_response(),
        Ok(None) => MatrixError::new_not_found("account data not found").into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /user/:userId/rooms/:roomId/account_data/:type
// ---------------------------------------------------------------------------

pub async fn put_room_account_data<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((user_id, room_id, event_type)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Response {
    if authed.user_id != user_id {
        return MatrixError::forbidden("cannot set another user's account data").into_response();
    }
    if let Some(rejection) = reject_server_managed(&event_type) {
        return rejection;
    }
    if let Err(e) = state
        .storage()
        .set_account_data(&user_id, Some(&room_id), &event_type, &body)
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    state.sync_notify().notify_waiters();
    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// GET /user/:userId/rooms/:roomId/account_data/:type
// ---------------------------------------------------------------------------

pub async fn get_room_account_data<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((user_id, room_id, event_type)): Path<(String, String, String)>,
) -> Response {
    if authed.user_id != user_id {
        return MatrixError::forbidden("cannot read another user's account data").into_response();
    }
    match state
        .storage()
        .get_account_data(&user_id, Some(&room_id), &event_type)
        .await
    {
        Ok(Some(content)) => (StatusCode::OK, Json(content)).into_response(),
        Ok(None) => MatrixError::new_not_found("account data not found").into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}
