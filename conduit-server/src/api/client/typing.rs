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
use tokio::sync::{broadcast, watch, RwLock};

use super::{AuthState, AuthedUser, MatrixError};

// ---------------------------------------------------------------------------
// In-memory typing store
// ---------------------------------------------------------------------------

/// Ephemeral typing state. Shared via `Arc` in `AppState`.
pub struct TypingStore {
    inner: RwLock<TypingState>,
    changed: watch::Sender<i64>,
}

#[derive(Default)]
struct TypingState {
    users: HashMap<(String, String), Instant>,
    room_positions: HashMap<String, i64>,
    position: i64,
}

impl Default for TypingStore {
    fn default() -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            inner: RwLock::new(TypingState::default()),
            changed,
        }
    }
}

impl TypingStore {
    pub fn new() -> (Arc<Self>, broadcast::Sender<String>) {
        let (tx, _) = broadcast::channel(256);
        (Arc::new(Self::default()), tx)
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<i64> {
        self.changed.subscribe()
    }

    pub async fn set_typing(&self, room_id: &str, user_id: &str, timeout_ms: u64) {
        let expires_at = Instant::now() + std::time::Duration::from_millis(timeout_ms.min(30_000));
        let mut state = self.inner.write().await;
        state
            .users
            .insert((room_id.to_owned(), user_id.to_owned()), expires_at);
        state.position += 1;
        let position = state.position;
        state.room_positions.insert(room_id.to_owned(), position);
        self.changed.send_replace(position);
    }

    pub async fn clear_typing(&self, room_id: &str, user_id: &str) {
        let mut state = self.inner.write().await;
        if state
            .users
            .remove(&(room_id.to_owned(), user_id.to_owned()))
            .is_some()
        {
            state.position += 1;
            let position = state.position;
            state.room_positions.insert(room_id.to_owned(), position);
            self.changed.send_replace(position);
        }
    }

    /// Observe room revisions and expiry under the same lock. Empty user lists
    /// are retained as deltas so clients can clear stopped/expired typers.
    pub(crate) async fn snapshot(
        &self,
        since: Option<i64>,
    ) -> (i64, HashMap<String, Vec<String>>, Option<Instant>) {
        let mut state = self.inner.write().await;
        let now = Instant::now();
        let expired: std::collections::HashSet<_> = state
            .users
            .iter()
            .filter(|(_, expires)| **expires <= now)
            .map(|((room, _), _)| room.clone())
            .collect();
        state.users.retain(|_, expires| *expires > now);
        for room in &expired {
            state.position += 1;
            let position = state.position;
            state.room_positions.insert(room.clone(), position);
        }
        if !expired.is_empty() {
            self.changed.send_replace(state.position);
        }
        let mut rooms = HashMap::new();
        for (room, position) in &state.room_positions {
            if since.is_none_or(|since| *position > since) {
                let mut users: Vec<_> = state
                    .users
                    .keys()
                    .filter(|(room_id, _)| room_id == room)
                    .map(|(_, user)| user.clone())
                    .collect();
                users.sort();
                rooms.insert(room.clone(), users);
            }
        }
        let next_expiry = state.users.values().copied().min();
        (state.position, rooms, next_expiry)
    }

    pub async fn typers_in_room(&self, room_id: &str) -> Vec<String> {
        let (_, rooms, _) = self.snapshot(None).await;
        rooms.get(room_id).cloned().unwrap_or_default()
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
        typing_store
            .set_typing(&room_id, &user_id, timeout_ms)
            .await;
    } else {
        typing_store.clear_typing(&room_id, &user_id).await;
    }

    // Wake any /sync long-pollers for this room.
    let _ = typing_tx.send(room_id);

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expiry_is_a_clear_delta_and_snapshot_reads_do_not_advance_it() {
        let store = TypingStore::default();
        store.set_typing("!room:test", "@a:test", 0).await;
        let (position, rooms, expiry) = store.snapshot(Some(0)).await;
        assert_eq!(rooms.get("!room:test"), Some(&Vec::new()));
        assert!(expiry.is_none());
        let (next, rooms, _) = store.snapshot(Some(position)).await;
        assert_eq!(next, position);
        assert!(rooms.is_empty());
    }

    #[tokio::test]
    async fn clearing_one_user_preserves_the_other_typer() {
        let store = TypingStore::default();
        store.set_typing("!room:test", "@a:test", 10_000).await;
        store.set_typing("!room:test", "@b:test", 10_000).await;
        let (position, _, _) = store.snapshot(None).await;
        store.clear_typing("!room:test", "@a:test").await;
        let (next, rooms, _) = store.snapshot(Some(position)).await;
        assert!(next > position);
        assert_eq!(rooms["!room:test"], vec!["@b:test".to_owned()]);
    }
}
