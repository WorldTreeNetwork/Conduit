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

    /// Map `alias` onto `room_id` before the canonical-alias event is sent.
    /// The default does nothing; the homeserver binds its directory.
    async fn bind_room_alias(&self, _creator: &str, _alias: &str, _room_id: &str) -> Result<()> {
        Ok(())
    }
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

    /// Create a room, applying events in the createRoom order:
    ///
    /// 1. `m.room.create` (first event; server overwrites `creator` and `room_version`)
    /// 2. creator `m.room.member` join
    /// 3. `m.room.power_levels` (override applied; v12 tombstone power above `state_default`)
    /// 4. `m.room.canonical_alias`, when an alias was requested
    /// 5. preset events: join rules, history visibility, guest access
    /// 6. `initial_state`, in the listed order
    /// 7. `name` and `topic`, which override `initial_state`
    ///
    /// Invites are the caller's step after this returns. On success returns the new `Room`.
    pub async fn create(
        sender: &str,
        room_id: &str,
        room_version: &str,
        join_rule: &str,
        history_visibility: &str,
        body: &CreateRoomParams<'_>,
        sender_: &dyn RoomEventSender,
    ) -> Result<Room> {
        crate::error::require_room_version(room_version)?;
        let sender = sender;
        let room_id = room_id;

        // 1. m.room.create
        let mut content = match &body.creation_content {
            Some(Value::Object(extra)) => Value::Object(extra.clone()),
            _ => json!({}),
        };
        content["room_version"] = json!(room_version);
        let version_num = crate::room_version::parse(room_version).unwrap_or(11);
        if version_num < 11 {
            content["creator"] = json!(sender);
        }
        if body.trusted_private_chat {
            merge_additional_creators(&mut content, sender, &body.invite);
        }
        let create_room_id = if version_num >= 12 { "" } else { room_id };
        let create_event_id = sender_
            .send_event(sender, create_room_id, "m.room.create", Some(""), content)
            .await?;
        let room_id_owned = if version_num >= 12 {
            crate::room_version::room_id_from_event_id(&create_event_id)
        } else {
            room_id.to_owned()
        };
        let room_id = room_id_owned.as_str();

        // 2. m.room.member — creator joins
        let content = json!({ "membership": "join" });
        sender_.send_event(sender, room_id, "m.room.member", Some(sender), content).await?;

        // 3. m.room.power_levels
        let mut users = serde_json::Map::new();
        if version_num < 12 {
            users.insert(sender.to_owned(), json!(100));
            if body.trusted_private_chat {
                for invitee in &body.invite {
                    if invitee != sender && crate::room_version::valid_user_id(invitee) {
                        users.insert(invitee.clone(), json!(100));
                    }
                }
            }
        }

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
        let mut pl_content = if let Some(override_pl) = &body.power_level_content_override {
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
        if version_num >= 12 {
            raise_tombstone_above_state_default(&mut pl_content);
        }
        sender_.send_event(sender, room_id, "m.room.power_levels", Some(""), pl_content).await?;

        // 4. Canonical alias, after the directory mapping exists.
        if let Some(alias) = &body.canonical_alias {
            sender_.bind_room_alias(sender, alias, room_id).await?;
            sender_
                .send_event(sender, room_id, "m.room.canonical_alias", Some(""), json!({ "alias": alias }))
                .await?;
        }

        // 5. Preset state. initial_state and name/topic come after, so they win.
        let content = json!({ "join_rule": join_rule });
        sender_.send_event(sender, room_id, "m.room.join_rules", Some(""), content).await?;
        let content = json!({ "history_visibility": history_visibility });
        sender_.send_event(sender, room_id, "m.room.history_visibility", Some(""), content).await?;
        if let Some(access) = &body.guest_access {
            sender_
                .send_event(sender, room_id, "m.room.guest_access", Some(""), json!({ "guest_access": access }))
                .await?;
        }

        // 6. initial_state, in listed order.
        for ev in &body.initial_state {
            let sk = ev.state_key.as_deref().unwrap_or("");
            sender_.send_event(sender, room_id, &ev.event_type, Some(sk), ev.content.clone()).await?;
        }

        // 7. name and topic override initial_state of the same type.
        if let Some(name) = body.name {
            sender_
                .send_event(sender, room_id, "m.room.name", Some(""), json!({ "name": name }))
                .await?;
        }
        if let Some(topic) = body.topic {
            sender_
                .send_event(sender, room_id, "m.room.topic", Some(""), topic_content(topic))
                .await?;
        }

        Ok(Room::new(room_id))
    }

    // ------------------------------------------------------------------
    // Membership operations
    // ------------------------------------------------------------------

    /// Join the room.
    pub async fn join(&self, user_id: &str, sender_: &dyn RoomEventSender) -> Result<String> {
        self.join_with_reason(user_id, None, sender_).await
    }

    /// Join the room, recording an optional `reason` on the member event.
    pub async fn join_with_reason(&self, user_id: &str, reason: Option<&str>, sender_: &dyn RoomEventSender) -> Result<String> {
        let mut content = json!({ "membership": "join" });
        if let Some(r) = reason {
            content["reason"] = json!(r);
        }
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
        self.unban_with_reason(sender, target_user_id, None, sender_).await
    }

    /// Unban a user, recording an optional `reason`.
    pub async fn unban_with_reason(&self, sender: &str, target_user_id: &str, reason: Option<&str>, sender_: &dyn RoomEventSender) -> Result<String> {
        let mut content = json!({ "membership": "leave" });
        if let Some(r) = reason {
            content["reason"] = json!(r);
        }
        sender_.send_event(sender, &self.room_id, "m.room.member", Some(target_user_id), content).await
    }

    /// Invite a user.
    pub async fn invite(&self, sender: &str, target_user_id: &str, is_direct: bool, sender_: &dyn RoomEventSender) -> Result<String> {
        self.invite_with_reason(sender, target_user_id, is_direct, None, sender_).await
    }

    /// Invite a user, recording an optional `reason`.
    pub async fn invite_with_reason(&self, sender: &str, target_user_id: &str, is_direct: bool, reason: Option<&str>, sender_: &dyn RoomEventSender) -> Result<String> {
        let mut content = json!({
            "membership": "invite",
            "is_direct": is_direct,
        });
        if let Some(r) = reason {
            content["reason"] = json!(r);
        }
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
    /// Extra `m.room.create` content (e.g. `type`, `m.federate`).
    /// `creator` and `room_version` are always set by the server.
    pub creation_content: Option<Value>,
    /// Preset `m.room.guest_access` value. Omitted when `None`.
    pub guest_access: Option<String>,
    /// Full room alias (`#local:server`) to bind and publish as canonical.
    pub canonical_alias: Option<String>,
    /// Users invited by the createRoom request. Trusted-private rooms
    /// copy them into creator power before any invite event is sent.
    pub invite: Vec<String>,
    /// `trusted_private_chat`: invitees share the creator's power.
    pub trusted_private_chat: bool,
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

/// Preset state from createRoom. History visibility is `shared` for every
/// defined preset. Guest access is `forbidden` only for `public_chat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomPreset {
    pub join_rule: &'static str,
    pub history_visibility: &'static str,
    pub guest_access: &'static str,
    pub trusted_private_chat: bool,
}

/// Resolve a createRoom preset. An omitted preset follows `visibility`:
/// `public` is `public_chat`, anything else (including omitted) is `private_chat`.
pub fn resolve_preset(preset: Option<&str>, visibility: Option<&str>) -> RoomPreset {
    match preset {
        Some("public_chat") => RoomPreset {
            join_rule: "public",
            history_visibility: "shared",
            guest_access: "forbidden",
            trusted_private_chat: false,
        },
        Some("trusted_private_chat") => RoomPreset {
            join_rule: "invite",
            history_visibility: "shared",
            guest_access: "can_join",
            trusted_private_chat: true,
        },
        Some("private_chat") => private_chat_preset(),
        _ => match visibility {
            Some("public") => RoomPreset {
                join_rule: "public",
                history_visibility: "shared",
                guest_access: "forbidden",
                trusted_private_chat: false,
            },
            _ => private_chat_preset(),
        },
    }
}

fn private_chat_preset() -> RoomPreset {
    RoomPreset {
        join_rule: "invite",
        history_visibility: "shared",
        guest_access: "can_join",
        trusted_private_chat: false,
    }
}

/// `trusted_private_chat` copies invitees into `additional_creators`.
fn merge_additional_creators(content: &mut Value, sender: &str, invite: &[String]) {
    let mut creators: Vec<String> = content
        .get("additional_creators")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|id| crate::room_version::valid_user_id(id))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    for invitee in invite {
        if invitee != sender
            && crate::room_version::valid_user_id(invitee)
            && !creators.iter().any(|existing| existing == invitee)
        {
            creators.push(invitee.clone());
        }
    }
    if !creators.is_empty() {
        content["additional_creators"] = json!(creators);
    }
}

/// Room versions 12+ require the tombstone event level to be strictly
/// above `state_default`. The spec's example is 150 when the default is 50.
fn raise_tombstone_above_state_default(content: &mut Value) {
    let Some(map) = content.as_object_mut() else { return };
    let state_default = map.get("state_default").and_then(Value::as_i64).unwrap_or(50);
    let events = map.entry("events").or_insert_with(|| json!({}));
    if !events.is_object() {
        *events = json!({});
    }
    let current = events.get("m.room.tombstone").and_then(Value::as_i64);
    if current.is_none_or(|level| level <= state_default) {
        events
            .as_object_mut()
            .expect("events object")
            .insert("m.room.tombstone".into(), json!(state_default.saturating_add(100)));
    }
}

fn topic_content(topic: &str) -> Value {
    json!({
        "topic": topic,
        "m.topic": { "m.text": [{ "body": topic, "mimetype": "text/plain" }] },
    })
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
            let stored_room = if room_id.is_empty() {
                crate::room_version::room_id_from_event_id(&event_id)
            } else {
                room_id.to_owned()
            };
            let ev = Event {
                event_id: event_id.clone(),
                pdu: crate::event::Pdu {
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
                    extensions: Default::default(),
                },
                unsigned: None,
            };

            self.storage.put_event(&ev).await?;

            // Update current state if it's a state event.
            if let Some(sk) = state_key {
                self.storage.set_state_entry(&stored_room, event_type, sk, &event_id).await?;
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
        assert!(create_ev.content.get("creator").is_none(), "v11 create has no creator field");

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
    async fn test_create_room_rejects_unknown_version() {
        let storage = test_storage();
        let sender = TestSender::new(storage.clone());
        let err = Room::create(
            "@alice:localhost",
            "!old:localhost",
            "13",
            "public",
            "shared",
            &CreateRoomParams::default(),
            &sender,
        )
        .await
        .expect_err("v13 must fail");
        assert!(matches!(err, crate::Error::UnsupportedRoomVersion(_)));

        let room = Room::create(
            "@alice:localhost",
            "!v1:localhost",
            "1",
            "public",
            "shared",
            &CreateRoomParams::default(),
            &sender,
        )
        .await
        .expect("v1 is supported");
        let create_ev = storage
            .get_state_entry(&room.room_id, "m.room.create", "")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(create_ev.content["creator"], "@alice:localhost");
        assert_eq!(create_ev.content["room_version"], "1");
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

    #[tokio::test]
    async fn create_room_event_order_matches_the_spec() {
        let storage = test_storage();
        let sender = TestSender::new(storage.clone());
        let room_id = "!order:localhost";
        let params = CreateRoomParams {
            name: Some("Final name"),
            topic: Some("Final topic"),
            canonical_alias: Some("#order:localhost".into()),
            guest_access: Some("can_join".into()),
            trusted_private_chat: true,
            invite: vec!["@bob:localhost".into(), "@carol:localhost".into()],
            creation_content: Some(json!({ "additional_creators": ["@carol:localhost"] })),
            initial_state: vec![
                CreateRoomInitialState {
                    event_type: "m.room.name".into(),
                    state_key: Some(String::new()),
                    content: json!({ "name": "Initial name" }),
                },
                CreateRoomInitialState {
                    event_type: "m.room.history_visibility".into(),
                    state_key: Some(String::new()),
                    content: json!({ "history_visibility": "world_readable" }),
                },
            ],
            power_level_content_override: Some(json!({ "state_default": 50 })),
        };
        let room = Room::create("@alice:localhost", room_id, "12", "invite", "shared", &params, &sender)
            .await
            .expect("create");
        let room_id = room.room_id.as_str();

        let ids = sender.events.read().await.clone();
        let mut types = Vec::new();
        for id in &ids {
            types.push(storage.get_event(id).await.unwrap().unwrap().event_type.clone());
        }
        assert_eq!(
            types,
            vec![
                "m.room.create",
                "m.room.member",
                "m.room.power_levels",
                "m.room.canonical_alias",
                "m.room.join_rules",
                "m.room.history_visibility",
                "m.room.guest_access",
                "m.room.name",
                "m.room.history_visibility",
                "m.room.name",
                "m.room.topic",
            ]
        );

        let create = storage.get_state_entry(room_id, "m.room.create", "").await.unwrap().unwrap();
        assert_eq!(create.room_id, "");
        let creators = create.content["additional_creators"].as_array().unwrap();
        assert_eq!(creators, &vec![json!("@carol:localhost"), json!("@bob:localhost")]);
        let name = storage.get_state_entry(room_id, "m.room.name", "").await.unwrap().unwrap();
        assert_eq!(name.content["name"], "Final name");
        let history = storage.get_state_entry(room_id, "m.room.history_visibility", "").await.unwrap().unwrap();
        assert_eq!(history.content["history_visibility"], "world_readable");
        let topic = storage.get_state_entry(room_id, "m.room.topic", "").await.unwrap().unwrap();
        assert_eq!(topic.content["m.topic"]["m.text"][0]["mimetype"], "text/plain");
        let power = storage.get_state_entry(room_id, "m.room.power_levels", "").await.unwrap().unwrap();
        assert!(power.content["users"].get("@alice:localhost").is_none());
        assert!(power.content["users"].get("@bob:localhost").is_none());
        assert!(power.content["events"]["m.room.tombstone"].as_i64().unwrap() > power.content["state_default"].as_i64().unwrap());

        let preset = resolve_preset(Some("private_chat"), None);
        assert_eq!(preset.history_visibility, "shared");
        assert_eq!(preset.guest_access, "can_join");
        assert_eq!(resolve_preset(None, Some("public")).guest_access, "forbidden");
        assert!(resolve_preset(Some("trusted_private_chat"), None).trusted_private_chat);
    }
}
