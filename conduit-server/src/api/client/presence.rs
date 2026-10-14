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
use tokio::sync::{watch, RwLock};

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
    pub stream_position: i64,
    /// Profile values carried on `m.presence` after a profile change
    /// (spec "Events on Change of Profile Information", conduit-y99.38).
    pub displayname: Option<String>,
    pub avatar_url: Option<String>,
}

impl PresenceEntry {
    fn new(presence: String, status_msg: Option<String>) -> Self {
        Self {
            presence,
            status_msg,
            last_changed_at: Instant::now(),
            stream_position: 0,
            displayname: None,
            avatar_url: None,
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
pub struct PresenceStore {
    inner: RwLock<PresenceState>,
    changed: watch::Sender<i64>,
}

#[derive(Default)]
struct PresenceState {
    entries: HashMap<String, (i64, PresenceEntry)>,
    position: i64,
}

impl Default for PresenceStore {
    fn default() -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            inner: RwLock::new(PresenceState::default()),
            changed,
        }
    }
}

impl PresenceStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<i64> {
        self.changed.subscribe()
    }

    pub async fn set_presence(&self, user_id: &str, presence: String, status_msg: Option<String>) {
        let mut state = self.inner.write().await;
        state.position += 1;
        let position = state.position;
        let mut entry = PresenceEntry::new(presence, status_msg);
        entry.stream_position = position;
        if let Some((_, previous)) = state.entries.get(user_id) {
            entry.displayname = previous.displayname.clone();
            entry.avatar_url = previous.avatar_url.clone();
        }
        state.entries.insert(user_id.to_owned(), (position, entry));
        self.changed.send_replace(position);
    }

    /// Announce a profile change through presence: the user's current
    /// presence (online if none was recorded) with the new display name
    /// and avatar URL.
    pub async fn set_profile(&self, user_id: &str, displayname: Option<String>, avatar_url: Option<String>) {
        let mut state = self.inner.write().await;
        state.position += 1;
        let position = state.position;
        let mut entry = match state.entries.get(user_id) {
            Some((_, previous)) => previous.clone(),
            None => PresenceEntry::new("online".to_owned(), None),
        };
        entry.stream_position = position;
        entry.displayname = displayname;
        entry.avatar_url = avatar_url;
        state.entries.insert(user_id.to_owned(), (position, entry));
        self.changed.send_replace(position);
    }

    pub async fn get_presence(&self, user_id: &str) -> Option<PresenceEntry> {
        self.inner
            .read()
            .await
            .entries
            .get(user_id)
            .map(|(_, entry)| entry.clone())
    }

    pub(crate) async fn snapshot(
        &self,
        since: Option<i64>,
    ) -> (i64, Vec<(String, PresenceEntry)>, Option<Instant>) {
        let mut state = self.inner.write().await;
        let now = Instant::now();
        let expired: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, (_, entry))| {
                entry.presence != "offline"
                    && now.duration_since(entry.last_changed_at)
                        >= std::time::Duration::from_secs(300)
            })
            .map(|(user, _)| user.clone())
            .collect();
        for user in &expired {
            state.position += 1;
            let position = state.position;
            if let Some((pos, entry)) = state.entries.get_mut(user) {
                *pos = position;
                entry.stream_position = position;
                entry.presence = "offline".into();
            }
        }
        if !expired.is_empty() {
            self.changed.send_replace(state.position);
        }
        let mut entries: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, (pos, _))| since.is_none_or(|since| *pos > since))
            .map(|(user, (_, entry))| (user.clone(), entry.clone()))
            .collect();
        entries.sort_by_key(|(_, entry)| entry.stream_position);
        let next_expiry = state
            .entries
            .values()
            .filter(|(_, entry)| entry.presence != "offline")
            .map(|(_, entry)| entry.last_changed_at + std::time::Duration::from_secs(300))
            .min();
        (state.position, entries, next_expiry)
    }

    pub async fn all_entries(&self) -> Vec<(String, PresenceEntry)> {
        self.snapshot(None).await.1
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

    let valid = matches!(body.presence.as_str(), "online" | "offline" | "unavailable");
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
    authed: AuthedUser,
    Path(user_id): Path<String>,
) -> Response {
    if user_id != authed.user_id {
        let rooms = match state.storage().joined_rooms(&authed.user_id).await {
            Ok(rooms) => rooms,
            Err(error) => return MatrixError::unknown(error.to_string()).into_response(),
        };
        let mut visible = false;
        for room in rooms {
            match state
                .storage()
                .get_state_entry(&room, "m.room.member", &user_id)
                .await
            {
                Ok(Some(event)) if event.content["membership"] == "join" => {
                    visible = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => return MatrixError::unknown(error.to_string()).into_response(),
            }
        }
        if !visible {
            return MatrixError::forbidden("not allowed to see this user's presence")
                .into_response();
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn idle_decay_advances_once_and_preserves_last_activity() {
        let store = PresenceStore::default();
        store
            .set_presence("@a:test", "online".into(), Some("status".into()))
            .await;
        let (position, _, _) = store.snapshot(None).await;
        let last_active = Instant::now() - std::time::Duration::from_secs(301);
        store
            .inner
            .write()
            .await
            .entries
            .get_mut("@a:test")
            .unwrap()
            .1
            .last_changed_at = last_active;
        let (next, entries, expiry) = store.snapshot(Some(position)).await;
        assert!(next > position);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.presence, "offline");
        assert_eq!(entries[0].1.last_changed_at, last_active);
        assert_eq!(entries[0].1.status_msg.as_deref(), Some("status"));
        assert!(expiry.is_none());
        let (after, entries, _) = store.snapshot(Some(next)).await;
        assert_eq!(after, next);
        assert!(entries.is_empty());
    }
}
