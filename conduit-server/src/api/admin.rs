//! Admin API (E11 AD1–AD6).
//!
//! All endpoints under `/_matrix/conduit/admin/v1/...`.
//! Requires the caller to be authenticated AND have `is_admin = true`.
//!
//! Synapse uses `/_synapse/admin/v1/...`; we use our own prefix.

use std::sync::Arc;

use axum::{
    async_trait,
    extract::{FromRequestParts, Path, Query, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use conduit::storage::Storage;

use crate::api::client::{AuthState, AuthedUser, MatrixError, hash_password, hash_token, generate_token};

// ---------------------------------------------------------------------------
// AdminAuthed extractor (AD1)
// ---------------------------------------------------------------------------

/// Axum extractor that requires both a valid access token AND `is_admin = true`.
#[derive(Debug, Clone)]
pub struct AdminAuthed {
    pub user_id: String,
    pub device_id: String,
}

#[async_trait]
impl<S: AuthState> FromRequestParts<S> for AdminAuthed {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let authed = AuthedUser::from_request_parts(parts, state).await?;

        // Verify admin flag.
        let account = state.storage()
            .get_account(&authed.user_id)
            .await
            .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?
            .ok_or_else(|| MatrixError::unknown_token().into_response())?;

        if !account.is_admin {
            return Err(MatrixError::forbidden("admin access required").into_response());
        }

        Ok(AdminAuthed { user_id: authed.user_id, device_id: authed.device_id })
    }
}

// ---------------------------------------------------------------------------
// Pagination helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub from: Option<i64>,
    pub limit: Option<i64>,
}

// ---------------------------------------------------------------------------
// User management (AD2)
// ---------------------------------------------------------------------------

pub async fn list_users<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Query(q): Query<PaginationQuery>,
) -> Response {
    let from = q.from.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).min(500);

    match state.storage().list_accounts(from, limit).await {
        Ok(accounts) => {
            let users: Vec<Value> = accounts.iter().map(|a| json!({
                "user_id": a.user_id,
                "is_admin": a.is_admin,
                "deactivated": a.deactivated_at.is_some(),
                "created_at": a.created_at.timestamp_millis(),
                "displayname": a.displayname,
            })).collect();
            Json(json!({ "users": users, "next_token": from + users.len() as i64 })).into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

pub async fn get_user<S: AuthState>(
    State(state): State<S>,
    _admin: AdminAuthed,
    Path(user_id): Path<String>,
) -> Response {
    match state.storage().get_account(&user_id).await {
        Ok(Some(a)) => Json(json!({
            "user_id": a.user_id,
            "is_admin": a.is_admin,
            "deactivated": a.deactivated_at.is_some(),
            "created_at": a.created_at.timestamp_millis(),
            "displayname": a.displayname,
            "avatar_url": a.avatar_url,
        })).into_response(),
        Ok(None) => MatrixError::new_not_found("user not found").into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

pub async fn deactivate_user<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Path(user_id): Path<String>,
) -> Response {
    let storage = state.storage();

    match storage.deactivate_account(&user_id).await {
        Ok(_) => {}
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }

    let detail = json!({ "user_id": user_id });
    let _ = storage.append_audit_log(&admin.user_id, "deactivate_user", Some(&user_id), &detail).await;

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub new_password: String,
}

pub async fn reset_password<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Path(user_id): Path<String>,
    Json(body): Json<ResetPasswordRequest>,
) -> Response {
    let storage = state.storage();

    let hash = match hash_password(body.new_password).await {
        Ok(h) => h,
        Err(e) => return MatrixError::unknown(format!("password hashing failed: {e}")).into_response(),
    };

    match storage.set_password_hash(&user_id, &hash).await {
        Ok(_) => {}
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }

    let detail = json!({ "user_id": user_id });
    let _ = storage.append_audit_log(&admin.user_id, "reset_password", Some(&user_id), &detail).await;

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Debug, Deserialize)]
pub struct SetAdminRequest {
    pub is_admin: bool,
}

pub async fn set_admin<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Path(user_id): Path<String>,
    Json(body): Json<SetAdminRequest>,
) -> Response {
    let storage = state.storage();

    match storage.set_admin(&user_id, body.is_admin).await {
        Ok(_) => {}
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }

    let detail = json!({ "user_id": user_id, "is_admin": body.is_admin });
    let _ = storage.append_audit_log(&admin.user_id, "set_admin", Some(&user_id), &detail).await;

    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// Room management (AD3)
// ---------------------------------------------------------------------------

pub async fn list_rooms<S: AuthState>(
    State(state): State<S>,
    _admin: AdminAuthed,
    Query(q): Query<PaginationQuery>,
) -> Response {
    let from = q.from.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).min(500);

    match state.storage().list_rooms(from, limit).await {
        Ok(rooms) => {
            let total = rooms.len();
            Json(json!({ "rooms": rooms, "next_token": from + total as i64 })).into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

pub async fn purge_room<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Path(room_id): Path<String>,
) -> Response {
    let storage = state.storage();

    match storage.purge_room(&room_id).await {
        Ok(_) => {}
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }

    let detail = json!({ "room_id": room_id });
    let _ = storage.append_audit_log(&admin.user_id, "purge_room", Some(&room_id), &detail).await;

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Debug, Deserialize)]
pub struct LeaveUserRequest {
    pub user_id: String,
}

pub async fn leave_user<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Path(room_id): Path<String>,
    Json(body): Json<LeaveUserRequest>,
) -> Response {
    // We can't call into event_pipeline here easily without full AuthState threading,
    // so we use a simplified storage-level approach: insert a leave event.
    // For a complete implementation this would go through build_sign_and_persist.
    // For v0, we just log the audit entry and return success.
    // TODO: wire through event_pipeline for proper leave event.
    let storage = state.storage();
    let detail = json!({ "room_id": room_id, "user_id": body.user_id });
    let _ = storage.append_audit_log(&admin.user_id, "force_leave_user", Some(&room_id), &detail).await;

    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// Media management (AD4)
// ---------------------------------------------------------------------------

pub async fn list_media<S: AuthState>(
    State(state): State<S>,
    _admin: AdminAuthed,
    Query(q): Query<PaginationQuery>,
) -> Response {
    let from = q.from.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).min(500);

    match state.storage().list_media(from, limit).await {
        Ok(media) => {
            let items: Vec<Value> = media.iter().map(|m| json!({
                "media_id": m.media_id,
                "origin_server": m.origin_server,
                "content_type": m.content_type,
                "file_size": m.file_size,
                "uploaded_at": m.uploaded_at.timestamp_millis(),
                "uploader": m.uploader,
            })).collect();
            let total = items.len();
            Json(json!({ "media": items, "next_token": from + total as i64 })).into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

pub async fn delete_media<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Path(media_id): Path<String>,
) -> Response {
    let storage = state.storage();

    // We need server_name to locate the media. Assume local media by default.
    let server_name = state.server_name().to_owned();
    match storage.delete_media(&media_id, &server_name).await {
        Ok(_) => {}
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }

    let detail = json!({ "media_id": media_id });
    let _ = storage.append_audit_log(&admin.user_id, "delete_media", Some(&media_id), &detail).await;

    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// Federation management (AD5)
// ---------------------------------------------------------------------------

pub async fn list_federation_peers<S: AuthState>(
    State(state): State<S>,
    _admin: AdminAuthed,
) -> Response {
    // For v0 we return an empty list. The federation send queue in E08/E09
    // knows about destinations but doesn't expose a list via storage.
    // TODO: expose federation queue destinations from the queue module.
    Json(json!({ "peers": [] })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct DisableFederationRequest {
    pub destination: String,
}

pub async fn disable_federation<S: AuthState>(
    State(state): State<S>,
    admin: AdminAuthed,
    Json(body): Json<DisableFederationRequest>,
) -> Response {
    // For v0: log the audit entry. Actual federation blocking would require
    // a blocklist in the federation send queue.
    // TODO: wire federation destination blocklist.
    let storage = state.storage();
    let detail = json!({ "destination": body.destination });
    let _ = storage.append_audit_log(
        &admin.user_id, "disable_federation", Some(&body.destination), &detail
    ).await;

    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// Audit log (AD6)
// ---------------------------------------------------------------------------

pub async fn get_audit_log<S: AuthState>(
    State(state): State<S>,
    _admin: AdminAuthed,
    Query(q): Query<PaginationQuery>,
) -> Response {
    let from = q.from.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).min(500);

    match state.storage().list_audit_log(from, limit).await {
        Ok(entries) => {
            let items: Vec<Value> = entries.iter().map(|e| json!({
                "id": e.id,
                "admin_user": e.admin_user,
                "action": e.action,
                "target": e.target,
                "detail": e.detail,
                "ts": e.ts.timestamp_millis(),
            })).collect();
            let total = items.len();
            Json(json!({ "entries": items, "next_token": from + total as i64 })).into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}
