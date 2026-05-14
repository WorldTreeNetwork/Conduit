//! Room directory CS-API (conduit-v0y).
//!
//! - `PUT    /_matrix/client/v3/directory/room/{alias}`  bind alias → room
//! - `GET    /_matrix/client/v3/directory/room/{alias}`  resolve alias
//! - `DELETE /_matrix/client/v3/directory/room/{alias}`  drop binding
//! - `GET    /_matrix/client/v3/rooms/{roomId}/aliases`  reverse lookup
//!
//! Local aliases only: aliases that don't end in our own server name
//! (e.g. `#irc:matrix.org`) are rejected by PUT — those bindings live
//! on the foreign server.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use super::{AuthState, AuthedUser, MatrixError};

#[derive(Debug, Deserialize)]
pub struct PutAliasBody {
    pub room_id: String,
}

/// `PUT /_matrix/client/v3/directory/room/:alias`
pub async fn put_alias<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(alias): Path<String>,
    Json(body): Json<PutAliasBody>,
) -> Response {
    if !alias_is_local(&alias, state.server_name()) {
        return MatrixError::bad_json("alias is not on this server").into_response();
    }
    if !alias.starts_with('#') {
        return MatrixError::bad_json("alias must start with '#'").into_response();
    }

    match state
        .storage()
        .upsert_alias(&alias, &body.room_id, &authed.user_id)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already in use") {
                (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "errcode": "M_UNKNOWN",
                        "error": "Room alias already in use",
                    })),
                )
                    .into_response()
            } else {
                MatrixError::unknown(msg).into_response()
            }
        }
    }
}

/// `GET /_matrix/client/v3/directory/room/:alias`
pub async fn get_alias<S: AuthState>(
    State(state): State<S>,
    Path(alias): Path<String>,
) -> Response {
    // Local resolve. Federation resolve (#room:other.server) is intentionally
    // out of scope here — the alias-to-room lookup over federation lands as
    // a separate follow-up; for now we 404 cross-server aliases.
    match state.storage().get_room_for_alias(&alias).await {
        Ok(Some(room_id)) => (
            StatusCode::OK,
            Json(json!({ "room_id": room_id, "servers": [state.server_name()] })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "errcode": "M_NOT_FOUND",
                "error": "Room alias not found",
            })),
        )
            .into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

/// `DELETE /_matrix/client/v3/directory/room/:alias`
pub async fn delete_alias<S: AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path(alias): Path<String>,
) -> Response {
    match state.storage().delete_alias(&alias).await {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

/// `GET /_matrix/client/v3/rooms/:roomId/aliases`
pub async fn list_room_aliases<S: AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path(room_id): Path<String>,
) -> Response {
    match state.storage().list_aliases_for_room(&room_id).await {
        Ok(aliases) => (StatusCode::OK, Json(json!({ "aliases": aliases }))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

/// Check that the alias's server-part matches our server.
fn alias_is_local(alias: &str, server_name: &str) -> bool {
    alias.split(':').nth(1) == Some(server_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_alias_recognized() {
        assert!(alias_is_local("#room:local", "local"));
        assert!(!alias_is_local("#room:other", "local"));
        assert!(!alias_is_local("no-colon", "local"));
    }
}
