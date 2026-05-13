//! Typing notification handler (1mo.5).
//!
//! PUT /_matrix/client/v3/rooms/:roomId/typing/:userId
//!
//! Typing state is ephemeral (in-memory only, no DB table).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{RwLock, broadcast};

use super::{AuthState, AuthedUser, MatrixError};

// ---------------------------------------------------------------------------
// In-memory typing store
// ---------------------------------------------------------------------------

/// Ephemeral typing state. Shared via `Arc` in `AppState`.
#[derive(Default)]
pub struct TypingStore {
    /// (room_id, user_id) → expires_at
    inner: RwLock<HashMap<(String, String), Instant>>,
    // Broadcast sender is stored externally (see TypingStore::new).
}

impl TypingStore {
    pub fn new() -> (Arc<Self>, broadcast::Sender<String>) {
        let (tx, _) = broadcast::channel(256);
        (Arc::new(Self::default()), tx)
    }

    /// Set typing = true for `user_id` in `room_id` with a TTL.
    pub async fn set_typing(&self, room_id: &str, user_id: &str, timeout_ms: u64) {
        let expires_at = Instant::now()
            + std::time::Duration::from_millis(timeout_ms.min(30_000));
        let mut inner = self.inner.write().await;
        inner.insert((room_id.to_owned(), user_id.to_owned()), expires_at);
    }

    /// Clear typing for `user_id` in `room_id`.
    pub async fn clear_typing(&self, room_id: &str, user_id: &str) {
        let mut inner = self.inner.write().await;
        inner.remove(&(room_id.to_owned(), user_id.to_owned()));
    }

    /// Returns the list of user_ids currently typing in `room_id`,
    /// pruning expired entries lazily.
    pub async fn typers_in_room(&self, room_id: &str) -> Vec<String> {
        let now = Instant::now();
        let mut inner = self.inner.write().await;
        // Prune expired.
        inner.retain(|_, exp| *exp > now);
        inner
            .iter()
            .filter(|((r, _), _)| r == room_id)
            .map(|((_, u), _)| u.clone())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// PUT /rooms/:roomId/typing/:userId
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TypingRequest {
    pub typing: bool,
    /// Timeout in milliseconds. Default 10 000, clamped to 30 000.
    pub timeout: Option<u64>,
}

pub async fn put_typing<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((room_id, user_id)): Path<(String, String)>,
    Json(body): Json<TypingRequest>,
) -> Response {
    if authed.user_id != user_id {
        return MatrixError::forbidden("cannot set typing for another user").into_response();
    }

    let typing_store = state.typing_store();
    let typing_tx = state.typing_tx();

    if body.typing {
        let timeout_ms = body.timeout.unwrap_or(10_000);
        typing_store.set_typing(&room_id, &user_id, timeout_ms).await;
    } else {
        typing_store.clear_typing(&room_id, &user_id).await;
    }

    // Wake any /sync long-pollers for this room.
    let _ = typing_tx.send(room_id);

    (StatusCode::OK, Json(json!({}))).into_response()
}
