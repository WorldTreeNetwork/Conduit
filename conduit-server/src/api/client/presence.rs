//! Presence handlers (1mo.7).
//!
//! GET /_matrix/client/v3/presence/:userId/status
//! PUT /_matrix/client/v3/presence/:userId/status
//!
//! Presence is ephemeral (in-memory only, no DB table).
//! Local-only for v0; federation of presence EDUs is filed as a follow-up.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;

use super::{AuthState, AuthedUser, MatrixError};

// ---------------------------------------------------------------------------
// In-memory presence store
// ---------------------------------------------------------------------------

/// A single user's presence entry.
#[derive(Debug, Clone)]
pub struct PresenceEntry {
    pub presence: String,
    pub status_msg: Option<String>,
    pub last_changed_at: Instant,
}

impl PresenceEntry {
    fn new(presence: String, status_msg: Option<String>) -> Self {
        Self {
            presence,
            status_msg,
            last_changed_at: Instant::now(),
        }
    }

    /// Lazily decay to "offline" if last_changed_at is older than 5 minutes.
    pub fn effective_presence(&self) -> &str {
        const DECAY_SECS: u64 = 5 * 60;
        if self.last_changed_at.elapsed().as_secs() > DECAY_SECS {
            "offline"
        } else {
            &self.presence
        }
    }
}

/// Ephemeral presence state shared via `Arc` in `AppState`.
#[derive(Default)]
pub struct PresenceStore {
    inner: RwLock<HashMap<String, PresenceEntry>>,
}

impl PresenceStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub async fn set_presence(
        &self,
        user_id: &str,
        presence: String,
        status_msg: Option<String>,
    ) {
        let mut inner = self.inner.write().await;
        inner.insert(user_id.to_owned(), PresenceEntry::new(presence, status_msg));
    }

    pub async fn get_presence(&self, user_id: &str) -> Option<PresenceEntry> {
        let inner = self.inner.read().await;
        inner.get(user_id).cloned()
    }

    /// All known presence entries (for v0 /sync).
    pub async fn all_entries(&self) -> Vec<(String, PresenceEntry)> {
        let inner = self.inner.read().await;
        inner
            .iter()
            .map(|(uid, entry)| (uid.clone(), entry.clone()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SetPresenceRequest {
    pub presence: String,
    pub status_msg: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PresenceResponse {
    pub presence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_msg: Option<String>,
    pub last_active_ago: u64,
    pub currently_active: bool,
}

// ---------------------------------------------------------------------------
// PUT /presence/:userId/status
// ---------------------------------------------------------------------------

pub async fn put_presence<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(user_id): Path<String>,
    Json(body): Json<SetPresenceRequest>,
) -> Response {
    if authed.user_id != user_id {
        return MatrixError::forbidden("cannot set another user's presence").into_response();
    }

    let valid = matches!(
        body.presence.as_str(),
        "online" | "offline" | "unavailable"
    );
    if !valid {
        return MatrixError::bad_json(format!("invalid presence: {}", body.presence))
            .into_response();
    }

    state
        .presence_store()
        .set_presence(&user_id, body.presence, body.status_msg)
        .await;

    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// GET /presence/:userId/status
// ---------------------------------------------------------------------------

pub async fn get_presence<S: AuthState>(
    State(state): State<S>,
    Path(user_id): Path<String>,
) -> Response {
    match state.presence_store().get_presence(&user_id).await {
        None => MatrixError::new_not_found("no presence for user").into_response(),
        Some(entry) => {
            let last_active_ago = entry.last_changed_at.elapsed().as_millis() as u64;
            let effective = entry.effective_presence().to_owned();
            let currently_active = effective == "online";
            (
                StatusCode::OK,
                Json(PresenceResponse {
                    presence: effective,
                    status_msg: entry.status_msg,
                    last_active_ago,
                    currently_active,
                }),
            )
                .into_response()
        }
    }
}
