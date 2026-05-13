//! Receipt handler (1mo.6).
//!
//! POST /_matrix/client/v3/rooms/:roomId/receipt/:receiptType/:eventId
//!
//! Supported receipt types: `m.read`, `m.read.private`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::json;

use super::{AuthState, AuthedUser, MatrixError};

// ---------------------------------------------------------------------------
// POST /rooms/:roomId/receipt/:receiptType/:eventId
// ---------------------------------------------------------------------------

pub async fn post_receipt<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, receipt_type, event_id)): Path<(String, String, String)>,
) -> Response {
    // Only m.read and m.read.private are supported.
    if receipt_type != "m.read" && receipt_type != "m.read.private" {
        return MatrixError::bad_json(format!("unsupported receipt type: {receipt_type}"))
            .into_response();
    }

    let ts = Utc::now().timestamp_millis();

    if let Err(e) = state
        .storage()
        .set_receipt(&room_id, &authed.user_id, &receipt_type, &event_id, ts)
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }

    (StatusCode::OK, Json(json!({}))).into_response()
}
