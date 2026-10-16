//! Room directory CS-API (conduit-v0y).
//!
//! - `PUT    /_matrix/client/v3/directory/room/{alias}`  bind alias → room
//! - `GET    /_matrix/client/v3/directory/room/{alias}`  resolve alias
//! - `DELETE /_matrix/client/v3/directory/room/{alias}`  drop binding
//! - `GET    /_matrix/client/v3/rooms/{roomId}/aliases`  reverse lookup
//!
//! Local aliases only: aliases that don't end in our own server name
//! (e.g. `#irc:matrix.org`) are rejected by PUT — those bindings live
//! on the foreign server. GET resolves foreign aliases over federation
//! (`/_matrix/federation/v1/query/directory`).
//!
//! Malformed aliases are `400 M_INVALID_PARAM`. DELETE is allowed for
//! the alias's creator, a server admin, or a joined member with the
//! power to send `m.room.canonical_alias`; a missing alias is `404`.
//! The local alias list is visible to joined members, or anyone when
//! the room is `world_readable` (conduit-y99.20).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use conduit::auth::{current_state_map, history_visibility_of, may_send_state_event};
use conduit::state_events::{HistoryVisibility, Membership, parse_member};

use super::{AuthState, AuthedUser, MatrixError};

#[derive(Debug, Deserialize)]
pub struct PutAliasBody {
    pub room_id: String,
}

fn invalid_alias(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"errcode": "M_INVALID_PARAM", "error": msg})),
    )
        .into_response()
}

fn alias_not_found(alias: &str) -> Response {
    MatrixError::new_not_found(format!("Room alias {alias} not found")).into_response()
}

/// `#localpart:server` within 255 bytes, with a spec server name.
pub fn alias_is_valid(alias: &str) -> bool {
    conduit::identifiers::valid_room_alias(alias)
}

/// `PUT /_matrix/client/v3/directory/room/:alias`
pub async fn put_alias<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(alias): Path<String>,
    Json(body): Json<PutAliasBody>,
) -> Response {
    if !alias_is_valid(&alias) {
        return invalid_alias("Room alias invalid");
    }
    if !alias_is_local(&alias, state.server_name()) {
        return invalid_alias("Room alias must be on this server");
    }
    if let Some(refusal) = super::appservice_auth::alias_exclusivity_error(&state, &authed, &alias) {
        return refusal;
    }
    match state.storage().get_state_entry(&body.room_id, "m.room.create", "").await {
        Ok(Some(_)) => {}
        Ok(None) => return MatrixError::new_not_found("Room not found").into_response(),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
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
                        "error": format!("Room alias {alias} already exists."),
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
    if !alias_is_valid(&alias) {
        return invalid_alias("Room alias invalid");
    }
    if !alias_is_local(&alias, state.server_name()) {
        let server = alias.split_once(':').map(|(_, s)| s).unwrap_or_default();
        let Some(client) = state.federation_client() else {
            return alias_not_found(&alias);
        };
        return match client.query_directory(server, &alias).await {
            Ok(found) => (
                StatusCode::OK,
                Json(json!({"room_id": found.room_id, "servers": found.servers})),
            )
                .into_response(),
            Err(e) => {
                tracing::debug!(alias, error = %e, "remote alias lookup failed");
                alias_not_found(&alias)
            }
        };
    }
    match state.storage().get_room_for_alias(&alias).await {
        Ok(Some(room_id)) => (
            StatusCode::OK,
            Json(json!({ "room_id": room_id, "servers": [state.server_name()] })),
        )
            .into_response(),
        Ok(None) => alias_not_found(&alias),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

/// `DELETE /_matrix/client/v3/directory/room/:alias`
pub async fn delete_alias<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(alias): Path<String>,
) -> Response {
    if !alias_is_valid(&alias) {
        return invalid_alias("Room alias invalid");
    }
    let storage = state.storage();
    let room_id = match storage.get_room_for_alias(&alias).await {
        Ok(Some(room_id)) => room_id,
        Ok(None) => return alias_not_found(&alias),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let creator = match storage.alias_creator(&alias).await {
        Ok(c) => c,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let allowed = if creator.as_deref() == Some(authed.user_id.as_str()) {
        true
    } else {
        let is_admin = match storage.get_account(&authed.user_id).await {
            Ok(account) => account.is_some_and(|a| a.is_admin),
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        };
        is_admin
            || match current_state_map(storage.as_ref(), &room_id).await {
                Ok(room_state) => {
                    may_send_state_event(&room_state, &authed.user_id, "m.room.canonical_alias")
                }
                Err(e) => return MatrixError::from_conduit(e).into_response(),
            }
    };
    if !allowed {
        return MatrixError::forbidden(
            "You may only delete aliases you created, or those of rooms where you may set the canonical alias",
        )
        .into_response();
    }
    match storage.delete_alias(&alias).await {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

/// `GET /_matrix/client/v3/rooms/:roomId/aliases`
pub async fn list_room_aliases<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
) -> Response {
    let storage = state.storage();
    let room_state = match current_state_map(storage.as_ref(), &room_id).await {
        Ok(s) => s,
        Err(e) => return MatrixError::from_conduit(e).into_response(),
    };
    let joined = room_state
        .get(&("m.room.member".to_owned(), authed.user_id.clone()))
        .and_then(|e| parse_member(&e.content).ok())
        .is_some_and(|m| m.membership == Membership::Join);
    let world_readable = history_visibility_of(&room_state) == HistoryVisibility::WorldReadable;
    if !joined && !world_readable {
        return MatrixError::forbidden("You are not a member of the room.").into_response();
    }
    match storage.list_aliases_for_room(&room_id).await {
        Ok(aliases) => (StatusCode::OK, Json(json!({ "aliases": aliases }))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

/// Check that the alias's server-part matches our server.
fn alias_is_local(alias: &str, server_name: &str) -> bool {
    alias.split_once(':').map(|(_, server)| server) == Some(server_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_alias_recognized() {
        assert!(alias_is_local("#room:local", "local"));
        assert!(!alias_is_local("#room:other", "local"));
        assert!(!alias_is_local("no-colon", "local"));
        assert!(alias_is_local("#room:local:8448", "local:8448"));
    }

    #[test]
    fn alias_grammar() {
        assert!(alias_is_valid("#room:local"));
        assert!(!alias_is_valid("room:local"));
        assert!(!alias_is_valid("#:local"));
        assert!(!alias_is_valid("#room:"));
        assert!(!alias_is_valid("#room"));
    }
}
