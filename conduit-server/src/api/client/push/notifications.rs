//! Push evaluation engine (conduit-y99.30, Matrix v1.19
//! #receiving-notifications).
//!
//! Every persisted event is evaluated exactly once, in stream order, for
//! each local user in its room except the sender. [`process_pending`]
//! advances a durable cursor and commits, atomically, the notifications the
//! rules produced and the push gateway deliveries they require. It is
//! idempotent and serialised in-process, so the push worker and `/sync`
//! (which must show a new event's count in the same response as the event)
//! can both call it.
//! A local sender's own event is recorded as a read mark for its thread
//! scope. Counts are derived from the stored notifications in
//! `notification_counts`.

use std::collections::HashMap;

use serde_json::Value;

use conduit::auth::{self, StateMap};
use conduit::event::Event;
use conduit::storage::{PushDelivery, PushNotification, PushReadMark, Storage};
use conduit::Result;

use super::rules::{self, EvalContext, Rule};

/// Serialises cursor processing within this process.
static PROCESS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const BATCH: i64 = 200;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn is_local(user_id: &str, server_name: &str) -> bool {
    user_id.rsplit_once(':').is_some_and(|(_, server)| server == server_name)
}

/// Room facts shared by every recipient of an event.
struct RoomFacts {
    joined: Vec<String>,
    display_names: HashMap<String, String>,
    power_levels: Option<Value>,
    auth_state: StateMap<Event>,
}

async fn room_facts(storage: &dyn Storage, room_id: &str) -> Result<RoomFacts> {
    let state = storage.get_current_state(room_id).await?;
    let mut facts = RoomFacts {
        joined: Vec::new(),
        display_names: HashMap::new(),
        power_levels: None,
        auth_state: StateMap::new(),
    };
    for event in state {
        match (event.event_type.as_str(), event.state_key.as_deref()) {
            ("m.room.member", Some(user)) => {
                if event.content.get("membership").and_then(Value::as_str) == Some("join") {
                    facts.joined.push(user.to_owned());
                }
                if let Some(name) = event.content.get("displayname").and_then(Value::as_str) {
                    facts.display_names.insert(user.to_owned(), name.to_owned());
                }
            }
            ("m.room.power_levels", Some("")) => {
                facts.power_levels = Some(event.content.clone());
                facts.auth_state.insert((event.event_type.clone(), String::new()), event);
            }
            ("m.room.create", Some("")) => {
                facts.auth_state.insert((event.event_type.clone(), String::new()), event);
            }
            _ => {}
        }
    }
    Ok(facts)
}

#[derive(Default)]
struct UserCache {
    rules: HashMap<String, Vec<Rule>>,
    ignored: HashMap<String, Vec<String>>,
    pushers: HashMap<String, Vec<conduit::storage::Pusher>>,
}

impl UserCache {
    async fn rules(&mut self, storage: &dyn Storage, user: &str) -> Result<&Vec<Rule>> {
        if !self.rules.contains_key(user) {
            let stored = storage.list_push_rules(user).await?;
            self.rules.insert(user.to_owned(), rules::ruleset(user, &stored));
        }
        Ok(&self.rules[user])
    }

    async fn ignores(&mut self, storage: &dyn Storage, user: &str, sender: &str) -> Result<bool> {
        if !self.ignored.contains_key(user) {
            let list = storage
                .get_account_data(user, None, "m.ignored_user_list")
                .await?
                .and_then(|c| c.get("ignored_users").and_then(Value::as_object).map(|m| m.keys().cloned().collect()))
                .unwrap_or_default();
            self.ignored.insert(user.to_owned(), list);
        }
        Ok(self.ignored[user].iter().any(|u| u == sender))
    }

    async fn pushers(&mut self, storage: &dyn Storage, user: &str) -> Result<&Vec<conduit::storage::Pusher>> {
        if !self.pushers.contains_key(user) {
            let pushers = storage.list_pushers(user).await?;
            self.pushers.insert(user.to_owned(), pushers);
        }
        Ok(&self.pushers[user])
    }
}

/// Evaluate every event after the push cursor. Returns the number of
/// events processed.
pub async fn process_pending(storage: &dyn Storage, server_name: &str) -> Result<usize> {
    let _guard = PROCESS_LOCK.lock().await;
    let mut cursor = storage.push_cursor().await?;
    let mut processed = 0;
    loop {
        let events = storage.events_since(cursor, BATCH).await?;
        if events.is_empty() {
            return Ok(processed);
        }
        let ids: Vec<String> = events.iter().map(|e| e.event_id.clone()).collect();
        let positions = storage.event_stream_positions(&ids).await?;
        let mut facts: HashMap<String, RoomFacts> = HashMap::new();
        let mut users = UserCache::default();
        let mut notifications = Vec::new();
        let mut read_marks = Vec::new();
        let mut deliveries = Vec::new();
        let mut next = cursor;
        for event in &events {
            let Some(&pos) = positions.get(&event.event_id) else { continue };
            next = next.max(pos);
            if !facts.contains_key(&event.room_id) {
                facts.insert(event.room_id.clone(), room_facts(storage, &event.room_id).await?);
            }
            evaluate_event(
                storage,
                server_name,
                event,
                pos,
                &facts[&event.room_id],
                &mut users,
                &mut notifications,
                &mut read_marks,
                &mut deliveries,
            )
            .await?;
            processed += 1;
        }
        if next == cursor {
            // Nothing addressable in this batch; avoid spinning.
            return Ok(processed);
        }
        storage.commit_push_batch(&notifications, &read_marks, &deliveries, next).await?;
        cursor = next;
    }
}

#[allow(clippy::too_many_arguments)]
async fn evaluate_event(
    storage: &dyn Storage,
    server_name: &str,
    event: &Event,
    pos: i64,
    facts: &RoomFacts,
    users: &mut UserCache,
    notifications: &mut Vec<PushNotification>,
    read_marks: &mut Vec<PushReadMark>,
    deliveries: &mut Vec<PushDelivery>,
) -> Result<()> {
    let thread_id = crate::api::client::receipts::thread_of(storage, event).await?;
    // The sender's own event marks its thread scope read for them.
    if is_local(&event.sender, server_name) {
        read_marks.push(PushReadMark {
            user_id: event.sender.clone(),
            room_id: event.room_id.clone(),
            scope: thread_id.clone().unwrap_or_else(|| "main".to_owned()),
            stream_pos: pos,
        });
    }
    let mut recipients: Vec<&str> = facts.joined.iter().map(String::as_str).collect();
    // An invitee is not joined yet but is the subject of .m.rule.invite_for_me.
    if event.event_type == "m.room.member"
        && event.content.get("membership").and_then(Value::as_str) == Some("invite")
    {
        if let Some(target) = event.state_key.as_deref() {
            if !recipients.contains(&target) {
                recipients.push(target);
            }
        }
    }
    recipients.retain(|u| *u != event.sender && is_local(u, server_name));
    if recipients.is_empty() {
        return Ok(());
    }
    let json = serde_json::to_value(event).map_err(|e| conduit::Error::InvalidEvent(e.to_string()))?;
    let sender_power_level = auth::effective_user_level(&event.sender, &facts.auth_state);
    let now = now_ms();
    for user in recipients {
        if users.ignores(storage, user, &event.sender).await? {
            continue;
        }
        let ctx = EvalContext {
            event: &json,
            user_id: user,
            display_name: facts.display_names.get(user).map(String::as_str),
            member_count: facts.joined.len() as u64,
            power_levels: facts.power_levels.as_ref(),
            sender_power_level,
        };
        let ruleset = users.rules(storage, user).await?;
        let Some(rule) = rules::evaluate(ruleset, &ctx) else { continue };
        let outcome = rules::outcome(&rule.actions);
        if !outcome.notify {
            continue;
        }
        let actions = Value::Array(rule.actions.clone());
        notifications.push(PushNotification {
            user_id: user.to_owned(),
            room_id: event.room_id.clone(),
            event_id: event.event_id.clone(),
            stream_pos: pos,
            thread_id: thread_id.clone(),
            actions: actions.clone(),
            highlight: outcome.highlight,
            ts: now,
        });
        for pusher in users.pushers(storage, user).await? {
            if pusher.kind != "http" {
                continue;
            }
            deliveries.push(PushDelivery {
                id: 0,
                user_id: user.to_owned(),
                app_id: pusher.app_id.clone(),
                pushkey: pusher.pushkey.clone(),
                room_id: event.room_id.clone(),
                event_id: event.event_id.clone(),
                actions: actions.clone(),
                attempts: 0,
                next_attempt_ms: now,
                created_ms: now,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locality() {
        assert!(is_local("@a:hs", "hs"));
        assert!(!is_local("@a:other", "hs"));
    }
}
