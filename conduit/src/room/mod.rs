//! Rooms — the unit of conversation in Matrix.
//!
//! A room is a DAG of events replicated across all participating
//! homeservers. The current state of a room is computed by resolving
//! the DAG; see [`state_res`].
//!
//! Room methods encapsulate common room operations (create, join, leave,
//! invite, send) so handler code can focus on HTTP concerns.

pub mod state_res;

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::auth::StateMap;
use crate::event::Event;
use crate::Result;

// ---------------------------------------------------------------------------
// RoomEventSender — abstraction over the event pipeline
// ---------------------------------------------------------------------------

/// Trait for building, signing, auth-checking, and persisting a Matrix event.
///
/// Implemented by the application-layer state (e.g. conduit-server's
/// [`AuthState`]) which holds the signing keys, server name, and broadcast
/// channel for `/sync` notification.
#[async_trait::async_trait]
pub trait RoomEventSender: Send + Sync {
    /// Build, sign, auth-check, and persist one event.
    async fn send_event(
        &self,
        sender: &str,
        room_id: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: Value,
    ) -> Result<String>;
}

// ---------------------------------------------------------------------------
// Room identifier
// ---------------------------------------------------------------------------

/// A handle onto a room. Storage of the actual DAG lives in
/// [`crate::storage`]; this is a lightweight identifier + helpers.
#[derive(Debug, Clone)]
pub struct Room {
    pub room_id: String,
}

impl Room {
    pub fn new(room_id: impl Into<String>) -> Self {
        Self { room_id: room_id.into() }
    }

    // ------------------------------------------------------------------
    // Static constructor — create a brand-new room
    // ------------------------------------------------------------------

    /// Create a room, injecting the initial-state cascade:
    ///
    /// 1. `m.room.create`
    /// 2. `m.room.member` (creator joins)
    /// 3. `m.room.power_levels`
    /// 4. `m.room.join_rules`
    /// 5. `m.room.history_visibility`
    /// 6. Optional `m.room.name` / `m.room.topic`
    /// 7. `initial_state` entries supplied by the caller
    /// 8. Room aliases
    ///
    /// On success returns the new `Room`.
    pub async fn create(
        sender: &str,
        room_id: &str,
        room_version: &str,
        join_rule: &str,
        history_visibility: &str,
        body: &CreateRoomParams<'_>,
        sender_: &dyn RoomEventSender,
    ) -> Result<Room> {
        let sender = sender;
        let room_id = room_id;

        // 1. m.room.create
        let content = json!({
            "room_version": room_version,
            "creator": sender,
        });
        sender_.send_event(sender, room_id, "m.room.create", Some(""), content).await?;

        // 2. m.room.member — creator joins
        let content = json!({ "membership": "join" });
        sender_.send_event(sender, room_id, "m.room.member", Some(sender), content).await?;

        // 3. m.room.power_levels
        let mut users = serde_json::Map::new();
        users.insert(sender.to_owned(), json!(100));

        let default_pl = json!({
            "ban": 50,
            "kick": 50,
            "redact": 50,
            "invite": 50,
            "events_default": 0,
            "state_default": 50,
            "users_default": 0,
            "users": users,
            "events": {},
        });
        let pl_content = if let Some(override_pl) = &body.power_level_content_override {
            let mut base = default_pl;
            if let (Some(b), Some(o)) = (base.as_object_mut(), override_pl.as_object()) {
                for (k, v) in o {
                    b.insert(k.clone(), v.clone());
                }
            }
            base
        } else {
            default_pl
        };
        sender_.send_event(sender, room_id, "m.room.power_levels", Some(""), pl_content).await?;

        // 4. m.room.join_rules
        let content = json!({ "join_rule": join_rule });
        sender_.send_event(sender, room_id, "m.room.join_rules", Some(""), content).await?;

        // 5. m.room.history_visibility
        let content = json!({ "history_visibility": history_visibility });
        sender_.send_event(sender, room_id, "m.room.history_visibility", Some(""), content).await?;

        // 6. Optional name / topic
        if let Some(name) = body.name {
            let content = json!({ "name": name });
            sender_.send_event(sender, room_id, "m.room.name", Some(""), content).await?;
        }
        if let Some(topic) = body.topic {
            let content = json!({ "topic": topic });
            sender_.send_event(sender, room_id, "m.room.topic", Some(""), content).await?;
        }

        // 7. initial_state entries
        for ev in &body.initial_state {
            let sk = ev.state_key.as_deref().unwrap_or("");
            sender_.send_event(sender, room_id, &ev.event_type, Some(sk), ev.content.clone()).await?;
        }

        Ok(Room::new(room_id))
    }

    // ------------------------------------------------------------------
    // Membership operations
    // ------------------------------------------------------------------

    /// Join the room.
    pub async fn join(&self, user_id: &str, sender_: &dyn RoomEventSender) -> Result<String> {
        let content = json!({ "membership": "join" });
        sender_.send_event(user_id, &self.room_id, "m.room.member", Some(user_id), content).await
    }

    /// Leave the room.
    pub async fn leave(&self, user_id: &str, reason: Option<&str>, sender_: &dyn RoomEventSender) -> Result<String> {
        let mut content = json!({ "membership": "leave" });
        if let Some(r) = reason {
            content["reason"] = json!(r);
        }
        sender_.send_event(user_id, &self.room_id, "m.room.member", Some(user_id), content).await
    }

    /// Kick a user (set their membership to leave).
    pub async fn kick(&self, sender: &str, target_user_id: &str, reason: Option<&str>, sender_: &dyn RoomEventSender) -> Result<String> {
        let mut content = json!({ "membership": "leave" });
        if let Some(r) = reason {
            content["reason"] = json!(r);
        }
        sender_.send_event(sender, &self.room_id, "m.room.member", Some(target_user_id), content).await
    }

    /// Ban a user.
    pub async fn ban(&self, sender: &str, target_user_id: &str, reason: Option<&str>, sender_: &dyn RoomEventSender) -> Result<String> {
        let mut content = json!({ "membership": "ban" });
        if let Some(r) = reason {
            content["reason"] = json!(r);
        }
        sender_.send_event(sender, &self.room_id, "m.room.member", Some(target_user_id), content).await
    }

    /// Unban a user (set membership to leave).
    pub async fn unban(&self, sender: &str, target_user_id: &str, sender_: &dyn RoomEventSender) -> Result<String> {
        let content = json!({ "membership": "leave" });
        sender_.send_event(sender, &self.room_id, "m.room.member", Some(target_user_id), content).await
    }

    /// Invite a user.
    pub async fn invite(&self, sender: &str, target_user_id: &str, is_direct: bool, sender_: &dyn RoomEventSender) -> Result<String> {
        let content = json!({
            "membership": "invite",
            "is_direct": is_direct,
        });
        sender_.send_event(sender, &self.room_id, "m.room.member", Some(target_user_id), content).await
    }

    // ------------------------------------------------------------------
    // Event operations
    // ------------------------------------------------------------------

    /// Send a message event (no state_key).
    pub async fn send_event(
        &self,
        sender: &str,
        event_type: &str,
        content: Value,
        sender_: &dyn RoomEventSender,
    ) -> Result<String> {
        sender_.send_event(sender, &self.room_id, event_type, None, content).await
    }

    /// Send a state event.
    pub async fn send_state_event(
        &self,
        sender: &str,
        event_type: &str,
        state_key: &str,
        content: Value,
        sender_: &dyn RoomEventSender,
    ) -> Result<String> {
        sender_.send_event(sender, &self.room_id, event_type, Some(state_key), content).await
    }

    // ------------------------------------------------------------------
    // State query operations
    // ------------------------------------------------------------------

    /// All current-state events for this room, as a vec.
    pub async fn current_state_vec(&self, storage: &dyn crate::storage::Storage) -> Result<Vec<Event>> {
        storage.get_current_state(&self.room_id).await
    }

    /// All current-state events as a `StateMap`.
    pub async fn current_state_map(&self, storage: &dyn crate::storage::Storage) -> Result<StateMap<Event>> {
        let events = storage.get_current_state(&self.room_id).await?;
        let mut map = HashMap::new();
        for ev in events {
            let sk = ev.state_key.clone().unwrap_or_default();
            map.insert((ev.event_type.clone(), sk), ev);
        }
        Ok(map)
    }

    /// Get a single state entry.
    pub async fn get_state_entry(
        &self,
        event_type: &str,
        state_key: &str,
        storage: &dyn crate::storage::Storage,
    ) -> Result<Option<Event>> {
        storage.get_state_entry(&self.room_id, event_type, state_key).await
    }
}

// ---------------------------------------------------------------------------
// Request-type helpers (shared across handler and Room methods)
// ---------------------------------------------------------------------------

/// Parameters for room creation, lifted from the handler's request body
/// so `Room::create` does not depend on an HTTP-specific deserialization type.
#[derive(Debug, Default)]
pub struct CreateRoomParams<'a> {
    pub name: Option<&'a str>,
    pub topic: Option<&'a str>,
    pub initial_state: Vec<CreateRoomInitialState>,
    pub power_level_content_override: Option<Value>,
}

/// An initial state event supplied at room creation.
#[derive(Debug)]
pub struct CreateRoomInitialState {
    pub event_type: String,
    pub state_key: Option<String>,
    pub content: Value,
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Compute the current state of a room from a collection of state set snapshots.
///
/// `state_sets` — each element is a `(event_type, state_key) → Event` map
/// representing a branch tip.
///
/// `auth_chain` — the union of all auth-chain events (event_id → Event) for
/// all events in all state sets.
///
/// Returns `Ok(resolved_state)` or a [`state_res::StateResError`].
pub fn current_state(
    state_sets: Vec<StateMap<Event>>,
    auth_chain: HashMap<String, Event>,
) -> Result<StateMap<Event>, state_res::StateResError> {
    state_res::resolve(state_sets, auth_chain)
}

// ---------------------------------------------------------------------------
// Preset resolution helper
// ---------------------------------------------------------------------------

/// Resolve `(join_rule, history_visibility)` from a preset/visibility pair.
///
/// | preset                         | join_rule          | history_visibility |
/// |--------------------------------|--------------------|-------------------|
/// | `"public_chat"`                | `"public"`         | `"shared"`        |
/// | `"trusted_private_chat"`       | `"invite"`         | `"shared"`        |
/// | `"private_chat"`               | `"invite"`         | `"invited"`       |
/// | fallback + `"public"`          | `"public"`         | `"shared"`        |
/// | fallback + anything else       | `"invite"`         | `"invited"`       |
pub fn resolve_preset(preset: Option<&str>, visibility: Option<&str>) -> (&'static str, &'static str) {
    match preset {
        Some("public_chat") => ("public", "shared"),
        Some("trusted_private_chat") => ("invite", "shared"),
        Some("private_chat") => ("invite", "invited"),
        _ => match visibility {
            Some("public") => ("public", "shared"),
            _ => ("invite", "invited"),
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// A minimal in-memory event sender for testing.
    struct TestSender {
        storage: Arc<dyn Storage>,
        /// Track event_ids produced so tests can inspect them.
        events: Arc<RwLock<Vec<String>>>,
        /// Counter for generating unique event_ids.
        count: Arc<RwLock<u64>>,
    }

    impl TestSender {
        fn new(storage: Arc<dyn Storage>) -> Self {
            Self { storage, events: Arc::new(RwLock::new(Vec::new())), count: Arc::new(RwLock::new(0)) }
        }
    }

    #[async_trait::async_trait]
    impl RoomEventSender for TestSender {
        async fn send_event(
            &self,
            _sender: &str,
            room_id: &str,
            event_type: &str,
            state_key: Option<&str>,
            content: Value,
        ) -> Result<String> {
            // Build a minimal event with a deterministic dummy event_id.
            let mut count = self.count.write().await;
            *count += 1;
            let event_id = format!("${}_{}", event_type, count);
            let ev = Event {
                event_id: event_id.clone(),
                room_id: room_id.to_owned(),
                sender: _sender.to_owned(),
                event_type: event_type.to_owned(),
                content,
                state_key: state_key.map(|s| s.to_owned()),
                origin_server_ts: 0,
                auth_events: vec![],
                prev_events: vec![],
                hashes: json!({}),
                signatures: json!({}),
                depth: 0,
                unsigned: None,
            };

            self.storage.put_event(&ev).await?;

            // Update current state if it's a state event.
            if let Some(sk) = state_key {
                self.storage.set_state_entry(room_id, event_type, sk, &event_id).await?;
            }

            self.events.write().await.push(event_id.clone());
            Ok(event_id)
        }
    }

    fn test_storage() -> Arc<dyn Storage> {
        Arc::new(crate::storage::MemoryStorage::default())
    }

    #[tokio::test]
    async fn test_create_room() {
        let storage = test_storage();
        let sender = TestSender::new(storage.clone());

        let params = CreateRoomParams {
            name: Some("test room"),
            topic: Some("testing"),
            ..Default::default()
        };

        let room_id = "!test_room:localhost";
        let room = Room::create(
            "@alice:localhost",
            room_id,
            "11",
            "public",
            "shared",
            &params,
            &sender,
        )
        .await
        .expect("create should succeed");

        assert_eq!(room.room_id, room_id);

        // Verify the state was written.
        let create_ev = storage
            .get_state_entry(room_id, "m.room.create", "")
            .await
            .expect("get create")
            .expect("create event should exist");
        assert_eq!(create_ev.event_type, "m.room.create");
        assert_eq!(create_ev.content["creator"], "@alice:localhost");

        let member_ev = storage
            .get_state_entry(room_id, "m.room.member", "@alice:localhost")
            .await
            .expect("get member")
            .expect("member event should exist");
        assert_eq!(member_ev.content["membership"], "join");

        let name_ev = storage
            .get_state_entry(room_id, "m.room.name", "")
            .await
            .expect("get name")
            .expect("name event should exist");
        assert_eq!(name_ev.content["name"], "test room");

        let current = storage.get_current_state(room_id).await.expect("get current state");
        assert!(current.len() >= 6, "should have at least 6 state events, got {}", current.len());
    }

    #[tokio::test]
    async fn test_join_room() {
        let storage = test_storage();
        let sender = TestSender::new(storage.clone());
        let room_id = "!join_test:localhost";

        // Pre-create the room.
        Room::create("@owner:localhost", room_id, "11", "public", "shared", &CreateRoomParams::default(), &sender)
            .await
            .expect("create");

        let room = Room::new(room_id);
        let event_id = room.join("@bob:localhost", &sender).await.expect("join");

        // Verify the join was recorded.
        let member_ev = storage
            .get_state_entry(room_id, "m.room.member", "@bob:localhost")
            .await
            .expect("get member")
            .expect("member event should exist");
        assert_eq!(member_ev.content["membership"], "join");
        assert_eq!(member_ev.event_id, event_id);
    }

    #[tokio::test]
    async fn test_leave_room() {
        let storage = test_storage();
        let sender = TestSender::new(storage.clone());
        let room_id = "!leave_test:localhost";

        Room::create("@alice:localhost", room_id, "11", "public", "shared", &CreateRoomParams::default(), &sender)
            .await
            .expect("create");

        let room = Room::new(room_id);
        room.leave("@alice:localhost", None, &sender).await.expect("leave");

        let member_ev = storage
            .get_state_entry(room_id, "m.room.member", "@alice:localhost")
            .await
            .expect("get member")
            .expect("member event should exist");
        assert_eq!(member_ev.content["membership"], "leave");
    }

    #[tokio::test]
    async fn test_invite_room() {
        let storage = test_storage();
        let sender = TestSender::new(storage.clone());
        let room_id = "!invite_test:localhost";

        Room::create("@alice:localhost", room_id, "11", "invite", "invited", &CreateRoomParams::default(), &sender)
            .await
            .expect("create");

        let room = Room::new(room_id);
        room.invite("@alice:localhost", "@bob:localhost", false, &sender).await.expect("invite");

        let member_ev = storage
            .get_state_entry(room_id, "m.room.member", "@bob:localhost")
            .await
            .expect("get member")
            .expect("member event should exist");
        assert_eq!(member_ev.content["membership"], "invite");
        assert_eq!(member_ev.content["is_direct"], false);
    }

    #[tokio::test]
    async fn test_send_event() {
        let storage = test_storage();
        let sender = TestSender::new(storage.clone());
        let room_id = "!send_test:localhost";

        Room::create("@alice:localhost", room_id, "11", "public", "shared", &CreateRoomParams::default(), &sender)
            .await
            .expect("create");

        let room = Room::new(room_id);
        let msg_content = json!({ "body": "Hello!", "msgtype": "m.text" });
        let event_id = room
            .send_event("@alice:localhost", "m.room.message", msg_content.clone(), &sender)
            .await
            .expect("send");

        let ev = storage.get_event(&event_id).await.expect("get event").expect("event should exist");
        assert_eq!(ev.event_type, "m.room.message");
        assert_eq!(ev.content["body"], "Hello!");

        // Non-state events should not appear in current_state.
        let current = storage.get_current_state(room_id).await.expect("get current state");
        assert!(!current.iter().any(|e| e.event_type == "m.room.message"));
    }

    #[tokio::test]
    async fn test_send_state_event() {
        let storage = test_storage();
        let sender = TestSender::new(storage.clone());
        let room_id = "!state_test:localhost";

        Room::create("@alice:localhost", room_id, "11", "public", "shared", &CreateRoomParams::default(), &sender)
            .await
            .expect("create");

        let room = Room::new(room_id);
        let content = json!({ "topic": "A new topic" });
        room.send_state_event("@alice:localhost", "m.room.topic", "", content.clone(), &sender)
            .await
            .expect("send state");

        let stored = storage
            .get_state_entry(room_id, "m.room.topic", "")
            .await
            .expect("get state")
            .expect("state event should exist");
        assert_eq!(stored.content["topic"], "A new topic");
    }

    #[tokio::test]
    async fn test_kick_ban_unban() {
        let storage = test_storage();
        let sender = TestSender::new(storage.clone());
        let room_id = "!kbu_test:localhost";

        // Create room and have bob join.
        Room::create("@alice:localhost", room_id, "11", "public", "shared", &CreateRoomParams::default(), &sender)
            .await
            .expect("create");

        let room = Room::new(room_id);
        room.join("@bob:localhost", &sender).await.expect("bob join");
        room.join("@charlie:localhost", &sender).await.expect("charlie join");

        // Kick bob.
        room.kick("@alice:localhost", "@bob:localhost", Some("bye"), &sender)
            .await
            .expect("kick");
        let bob_member = storage
            .get_state_entry(room_id, "m.room.member", "@bob:localhost")
            .await
            .expect("get member")
            .expect("member should exist");
        assert_eq!(bob_member.content["membership"], "leave");

        // Ban charlie.
        room.ban("@alice:localhost", "@charlie:localhost", Some("spam"), &sender)
            .await
            .expect("ban");
        let charlie_member = storage
            .get_state_entry(room_id, "m.room.member", "@charlie:localhost")
            .await
            .expect("get member")
            .expect("member should exist");
        assert_eq!(charlie_member.content["membership"], "ban");

        // Unban charlie.
        room.unban("@alice:localhost", "@charlie:localhost", &sender)
            .await
            .expect("unban");
        let charlie_member = storage
            .get_state_entry(room_id, "m.room.member", "@charlie:localhost")
            .await
            .expect("get member")
            .expect("member should exist");
        assert_eq!(charlie_member.content["membership"], "leave");
    }

    #[tokio::test]
    async fn test_current_state_map() {
        let storage = test_storage();
        let sender = TestSender::new(storage.clone());
        let room_id = "!state_map_test:localhost";

        Room::create("@alice:localhost", room_id, "11", "public", "shared", &CreateRoomParams::default(), &sender)
            .await
            .expect("create");

        let room = Room::new(room_id);
        let state_map = room.current_state_map(&*storage).await.expect("current state map");

        // Should have at least create, member, power_levels, join_rules, history_visibility.
        assert!(state_map.contains_key(&("m.room.create".to_owned(), String::new())));
        assert!(state_map.contains_key(&("m.room.member".to_owned(), "@alice:localhost".to_owned())));
        assert!(state_map.contains_key(&("m.room.power_levels".to_owned(), String::new())));
        assert!(state_map.contains_key(&("m.room.join_rules".to_owned(), String::new())));
        assert!(state_map.contains_key(&("m.room.history_visibility".to_owned(), String::new())));
    }
}
