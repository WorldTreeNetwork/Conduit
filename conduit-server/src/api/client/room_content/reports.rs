//! Reporting content (conduit-y99.19): events, rooms (v1.13) and users
//! (v1.14), retained in `content_reports` for server administrators, who
//! list them at `GET /_matrix/conduit/admin/v1/reports`.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::{json, Value};

use conduit::room_content::ContentReport;

use super::{not_found, storage_error, RoomAccess};
use crate::api::admin::{AdminAuthed, PaginationQuery};
use crate::api::client::{AuthState, AuthedUser, MatrixError};

/// Longest accepted reason, in bytes.
const MAX_REASON: usize = 4096;

/// `reason` from a report body: `Ok(None)` when absent and optional.
fn reason(body: &Value, required: bool) -> Result<Option<String>, Response> {
    if !body.is_object() {
        return Err(MatrixError::bad_json("request body must be an object").into_response());
    }
    match body.get("reason") {
        None | Some(Value::Null) if !required => Ok(None),
        Some(Value::String(reason)) if reason.len() <= MAX_REASON => Ok(Some(reason.clone())),
        Some(Value::String(_)) => {
            Err(MatrixError::bad_json(format!("reason is limited to {MAX_REASON} bytes")).into_response())
        }
        _ => Err(MatrixError::bad_json("reason is required and must be a string").into_response()),
    }
}

async fn store<S: AuthState>(state: &S, report: ContentReport) -> Response {
    match state.storage().insert_report(&report).await {
        Ok(id) => {
            tracing::info!(id, kind = %report.kind, reporter = %report.reporter, "content report received");
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => storage_error(e),
    }
}

fn report(kind: &str, reporter: &str) -> ContentReport {
    ContentReport {
        id: 0,
        kind: kind.into(),
        reporter: reporter.into(),
        room_id: None,
        event_id: None,
        target_user_id: None,
        reason: None,
        received_ts: Utc::now().timestamp_millis(),
    }
}

// POST /rooms/:roomId/report/:eventId — reporter must be joined (v1.8).
pub async fn report_event<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, event_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Response {
    let reason = match reason(&body, false) {
        Ok(reason) => reason,
        Err(response) => return response,
    };
    let storage = state.storage().as_ref();
    let access = match RoomAccess::load(storage, &room_id, &authed.user_id).await {
        Ok(access) => access,
        Err(e) => return storage_error(e),
    };
    // One 404 for "no such event" and "not joined", per the spec.
    if !access.is_joined() {
        return not_found("Event not found or you are not joined to the room.");
    }
    match storage.get_event(&event_id).await {
        Ok(Some(event)) if event.room_id == room_id => {}
        Ok(_) => return not_found("Event not found or you are not joined to the room."),
        Err(e) => return storage_error(e),
    }
    store(
        &state,
        ContentReport {
            room_id: Some(room_id),
            event_id: Some(event_id),
            reason,
            ..report("event", &authed.user_id)
        },
    )
    .await
}

// POST /rooms/:roomId/report — no membership requirement (v1.13).
pub async fn report_room<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let reason = match reason(&body, true) {
        Ok(reason) => reason,
        Err(response) => return response,
    };
    match state.storage().get_state_entry(&room_id, "m.room.create", "").await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found("Room not found."),
        Err(e) => return storage_error(e),
    }
    store(&state, ContentReport { room_id: Some(room_id), reason, ..report("room", &authed.user_id) }).await
}

// POST /users/:userId/report — no shared-room requirement (v1.14).
pub async fn report_user<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(user_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let reason = match reason(&body, true) {
        Ok(reason) => reason,
        Err(response) => return response,
    };
    // Local users must exist. Remote users cannot be checked without
    // federation, so their reports are accepted as submitted.
    if conduit::auth::server_of(&user_id) == state.server_name() {
        match state.storage().get_account(&user_id).await {
            Ok(Some(_)) => {}
            Ok(None) => return not_found("User not found."),
            Err(e) => return storage_error(e),
        }
    } else if !user_id.starts_with('@') || !user_id.contains(':') {
        return super::invalid_param("invalid user ID");
    }
    store(&state, ContentReport { target_user_id: Some(user_id), reason, ..report("user", &authed.user_id) })
        .await
}

// GET /_matrix/conduit/admin/v1/reports?from=&limit=
pub async fn list_reports<S: AuthState>(
    State(state): State<S>,
    _admin: AdminAuthed,
    Query(page): Query<PaginationQuery>,
) -> Response {
    let from = page.from.unwrap_or(0);
    let limit = page.limit.unwrap_or(100).clamp(1, 1000);
    match state.storage().list_reports(from, limit).await {
        Ok(reports) => {
            let next = (reports.len() as i64 == limit).then(|| reports.last().map(|r| r.id)).flatten();
            let mut body = json!({"reports": reports});
            if let Some(next) = next {
                body["next_from"] = json!(next);
            }
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => storage_error(e),
    }
}
