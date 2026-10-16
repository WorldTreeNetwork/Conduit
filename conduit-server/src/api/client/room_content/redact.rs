//! PUT /rooms/:roomId/redact/:eventId/:txnId (conduit-y99.19).
//!
//! The redaction is an ordinary `m.room.redaction` event authored through
//! the event pipeline; its effect is applied whenever the target is served
//! (see [`super::serve`]). Idempotency uses the persisted transactions
//! mechanism shared with `/send`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use serde_json::{json, Value};

use conduit::auth::StateMap;
use conduit::event::Event;

use crate::api::client::{AuthState, AuthedUser};

/// May `user_id` redact `target_id` in `room_id`?
///
/// Spec: anyone at or above the `m.room.redaction` event level may redact
/// their own events (the event pipeline's auth check enforces that level);
/// redacting another user's event additionally needs the room's `redact`
/// level, except that server administrators may redact events sent by
/// users on their own server.
///
/// Errors are `(status, Matrix error body)` so transaction replay can
/// persist them.
pub async fn authorize_redaction<S: AuthState>(
    state: &S,
    user_id: &str,
    room_id: &str,
    target_id: &str,
) -> Result<(), (StatusCode, Value)> {
    let storage = state.storage().as_ref();
    let failed = |e: conduit::Error| {
        (StatusCode::INTERNAL_SERVER_ERROR, json!({"errcode": "M_UNKNOWN", "error": e.to_string()}))
    };
    let target = match storage.get_event(target_id).await.map_err(failed)? {
        Some(event) if event.room_id == room_id => event,
        _ => return Err((StatusCode::NOT_FOUND, json!({"errcode": "M_NOT_FOUND", "error": "Event not found."}))),
    };
    if target.sender == user_id {
        return Ok(());
    }
    let room_state: StateMap<Event> = conduit::auth::current_state_map(storage, room_id)
        .await
        .map_err(failed)?;
    let power_levels = room_state.get(&("m.room.power_levels".to_owned(), String::new()));
    // Room version 12 creators have infinite power and are omitted from
    // `users`, so the numeric users_default is not their redact level.
    let level = conduit::auth::effective_user_level(user_id, &room_state);
    let required = power_levels
        .and_then(|event| conduit::state_events::parse_power_levels(&event.content).ok())
        .map(|content| content.redact)
        .unwrap_or(50);
    if level >= required {
        return Ok(());
    }
    let local_target = conduit::auth::server_of(&target.sender) == state.server_name();
    if local_target {
        let admin = storage
            .get_account(user_id)
            .await
            .map_err(failed)?
            .is_some_and(|account| account.is_admin);
        if admin {
            return Ok(());
        }
    }
    Err((
        StatusCode::FORBIDDEN,
        json!({"errcode": "M_FORBIDDEN", "error": "insufficient power level to redact another user's event"}),
    ))
}

pub async fn redact_event<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_id, txn_id)): Path<(String, String, String)>,
    request: axum::extract::Request,
) -> Response {
    let key = conduit::storage::TransactionKey::client(
        &authed.user_id,
        &authed.device_id,
        &["room_redact", &room_id, &event_id],
        &txn_id,
    );
    let mut replay = match crate::replay::Replay::start(state.storage().clone(), key.clone()).await {
        Ok(crate::replay::Start::Cached(response)) => return response,
        Ok(crate::replay::Start::Execute(replay)) => replay,
        Err(error) => return error,
    };
    let body = match replay.body(request).await {
        Ok(body) => body,
        Err(error) => return error,
    };
    let Some(body) = body.as_object() else {
        return replay
            .finish(StatusCode::BAD_REQUEST, json!({"errcode": "M_BAD_JSON", "error": "request body must be an object"}))
            .await;
    };
    let mut content = json!({"redacts": event_id});
    match body.get("reason") {
        None | Some(Value::Null) => {}
        Some(Value::String(reason)) => content["reason"] = json!(reason),
        Some(_) => {
            return replay
                .finish(StatusCode::BAD_REQUEST, json!({"errcode": "M_BAD_JSON", "error": "reason must be a string"}))
                .await
        }
    }
    if let Err((status, body)) = authorize_redaction(&state, &authed.user_id, &room_id, &event_id).await {
        return replay.finish(status, body).await;
    }
    match crate::api::client::event_pipeline::build_sign_and_persist_transaction(
        &state,
        &authed.user_id,
        &room_id,
        "m.room.redaction",
        content,
        &key,
    )
    .await
    {
        Ok(redaction_id) => replay.finish(StatusCode::OK, json!({"event_id": redaction_id})).await,
        Err((code, error)) => {
            replay
                .finish(code, serde_json::to_value(error.0).expect("Matrix error serializes"))
                .await
        }
    }
}
