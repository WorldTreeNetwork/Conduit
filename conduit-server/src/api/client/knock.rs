//! Client knocking (conduit-y99.20).
//!
//! `POST /_matrix/client/v3/knock/{roomIdOrAlias}`
//!
//! Sends `m.room.member` with `membership: knock` for the caller. The
//! room's auth rules decide (join rule `knock` / `knock_restricted`, not
//! banned, invited or joined); a refusal is `403 M_FORBIDDEN`. The knock
//! then shows in the knocker's `/sync` under `rooms.knock` with stripped
//! `knock_state`. A member with invite power accepts it by inviting the
//! knocker (who then joins), denies it by kicking, and the knocker can
//! rescind it with `/leave`.
//!
//! Only rooms this server participates in can be knocked on; federated
//! knocking (`make_knock` / `send_knock`) is a follow-up.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use super::event_pipeline::build_sign_and_persist;
use super::{AuthState, AuthedUser, MatrixError};

pub fn router<S: AuthState>() -> Router<S> {
    Router::new().route("/_matrix/client/v3/knock/:roomIdOrAlias", post(knock::<S>))
}

#[derive(Debug, Default, Deserialize)]
pub struct KnockBody {
    pub reason: Option<String>,
}

fn not_found(msg: &str) -> Response {
    MatrixError::new_not_found(msg).into_response()
}

/// Resolve `#alias:server` or `!room:server` to a room ID this server
/// knows, or a ready-made error response.
pub async fn resolve_local_room<S: AuthState>(state: &S, room_id_or_alias: &str) -> Result<String, Response> {
    let storage = state.storage();
    let room_id = if room_id_or_alias.starts_with('#') {
        match storage.get_room_for_alias(room_id_or_alias).await {
            Ok(Some(room_id)) => room_id,
            Ok(None) => return Err(not_found("Room alias not found")),
            Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
        }
    } else if room_id_or_alias.starts_with('!') {
        room_id_or_alias.to_owned()
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"errcode": "M_INVALID_PARAM", "error": "expected a room ID or alias"})),
        )
            .into_response());
    };
    match storage.get_state_entry(&room_id, "m.room.create", "").await {
        Ok(Some(_)) => Ok(room_id),
        Ok(None) => Err(not_found("That room does not appear to exist")),
        Err(e) => Err(MatrixError::unknown(e.to_string()).into_response()),
    }
}

pub async fn knock<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id_or_alias): Path<String>,
    Json(body): Json<KnockBody>,
) -> Response {
    let room_id = match resolve_local_room(&state, &room_id_or_alias).await {
        Ok(room_id) => room_id,
        Err(response) => return response,
    };

    let mut content = json!({"membership": "knock"});
    if let Some(reason) = body.reason.filter(|r| !r.is_empty()) {
        content["reason"] = json!(reason);
    }
    // Carry the knocker's profile so room members can see who knocked.
    if let Ok(Some(account)) = state.storage().get_account(&authed.user_id).await {
        if let Some(name) = account.displayname {
            content["displayname"] = json!(name);
        }
        if let Some(avatar) = account.avatar_url {
            content["avatar_url"] = json!(avatar);
        }
    }

    match build_sign_and_persist(
        &state,
        &authed.user_id,
        &room_id,
        "m.room.member",
        Some(&authed.user_id),
        content,
    )
    .await
    {
        Ok(_) => (StatusCode::OK, Json(json!({"room_id": room_id}))).into_response(),
        Err(error) => error.into_response(),
    }
}
