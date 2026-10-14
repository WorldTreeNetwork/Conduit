//! Serving room events to clients (conduit-y99.19).
//!
//! One place decides how a stored event looks to a particular user:
//!
//! - **Redactions** are applied at serve time from the event log: the
//!   target is pruned with the room-version algorithm
//!   ([`conduit::redaction::redact_event`]) and carries the redaction under
//!   `unsigned.redacted_because`.
//! - **Bundled aggregations** (`unsigned.m.relations`) for `m.thread`,
//!   `m.replace` and `m.reference`, computed from visible, unredacted
//!   children only.
//! - **Ignored users** (`m.ignored_user_list`): their non-state events are
//!   dropped; state events are always served.
//!
//! `/sync` and `/messages` keep their PDU-shaped values and call
//! [`Viewer::decorate_values`]; this module's endpoints use the client
//! format from [`Viewer::serve`].

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use conduit::event::Event;
use conduit::room_content::{
    client_event, is_valid_replacement, is_valid_thread_child, latest_edit, redaction_applies,
    redaction_target, relation,
};
use conduit::storage::Storage;

use super::now_ms;

/// The requesting user's view of room content.
pub struct Viewer<'a> {
    pub storage: &'a dyn Storage,
    pub user_id: &'a str,
    pub ignored: HashSet<String>,
}

/// Users named in `m.ignored_user_list` account data.
pub async fn ignored_users(storage: &dyn Storage, user_id: &str) -> conduit::Result<HashSet<String>> {
    Ok(storage
        .get_account_data(user_id, None, "m.ignored_user_list")
        .await?
        .and_then(|content| content.get("ignored_users").and_then(Value::as_object).cloned())
        .map(|users| users.keys().cloned().collect())
        .unwrap_or_default())
}

/// Should this event be withheld because its sender is ignored? State
/// events are never withheld (spec: "Servers must still send state events
/// sent by ignored users").
pub fn hidden_by_ignore(ignored: &HashSet<String>, event: &Event) -> bool {
    event.state_key.is_none() && ignored.contains(&event.sender)
}

impl<'a> Viewer<'a> {
    pub async fn load(storage: &'a dyn Storage, user_id: &'a str) -> conduit::Result<Self> {
        Ok(Self { storage, user_id, ignored: ignored_users(storage, user_id).await? })
    }

    pub fn hides(&self, event: &Event) -> bool {
        hidden_by_ignore(&self.ignored, event)
    }

    /// Drop events from ignored senders.
    pub fn without_ignored(&self, events: Vec<Event>) -> Vec<Event> {
        events.into_iter().filter(|event| !self.hides(event)).collect()
    }

    /// Effective redactions of `events`: target event ID → the redaction
    /// that applies to it (the earliest valid one).
    pub async fn redactions(&self, events: &[Event]) -> conduit::Result<HashMap<String, Event>> {
        let mut by_room: HashMap<&str, Vec<String>> = HashMap::new();
        for event in events {
            by_room.entry(event.room_id.as_str()).or_default().push(event.event_id.clone());
        }
        let targets: HashMap<&str, &Event> =
            events.iter().map(|event| (event.event_id.as_str(), event)).collect();
        let mut auth_cache: HashMap<String, Option<Event>> = HashMap::new();
        let mut applied: HashMap<String, Event> = HashMap::new();
        for (room_id, ids) in by_room {
            for redaction in self.storage.redactions_targeting(room_id, &ids).await? {
                let Some(target_id) = redaction_target(&redaction) else { continue };
                if applied.contains_key(target_id) {
                    continue;
                }
                let Some(target) = targets.get(target_id) else { continue };
                let (power_levels, creator) =
                    authorizing_power(self.storage, &redaction, &mut auth_cache).await?;
                if redaction_applies(&redaction, target, power_levels.as_ref(), creator.as_deref()) {
                    applied.insert(target_id.to_owned(), redaction);
                }
            }
        }
        Ok(applied)
    }

    /// Serve events in the client format, applying redactions and, when
    /// `bundle`, attaching `unsigned.m.relations`.
    pub async fn serve(&self, events: &[Event], bundle: bool) -> conduit::Result<Vec<Value>> {
        let redactions = self.redactions(events).await?;
        let bundles = if bundle {
            self.bundles(events, &redactions, true).await?
        } else {
            HashMap::new()
        };
        let now = now_ms();
        Ok(events
            .iter()
            .map(|event| {
                let mut value = match redactions.get(&event.event_id) {
                    Some(redaction) => {
                        let mut value = client_event(&conduit::redaction::redact_event(event), now);
                        value["unsigned"]["redacted_because"] = client_event(redaction, now);
                        value
                    }
                    None => client_event(event, now),
                };
                if let Some(relations) = bundles.get(&event.event_id) {
                    value["unsigned"]["m.relations"] = relations.clone();
                }
                value
            })
            .collect())
    }

    pub async fn serve_one(&self, event: &Event, bundle: bool) -> conduit::Result<Value> {
        Ok(self.serve(std::slice::from_ref(event), bundle).await?.remove(0))
    }

    /// Apply redactions (and optionally bundles) to PDU-shaped event values
    /// in place, keeping every other field. Values that are not events are
    /// left untouched.
    pub async fn decorate_values(&self, values: &mut [Value], bundle: bool) -> conduit::Result<()> {
        let events: Vec<Event> = values
            .iter()
            .filter_map(|value| serde_json::from_value(value.clone()).ok())
            .collect();
        if events.is_empty() {
            return Ok(());
        }
        let redactions = self.redactions(&events).await?;
        let bundles = if bundle {
            self.bundles(&events, &redactions, true).await?
        } else {
            HashMap::new()
        };
        let now = now_ms();
        for value in values.iter_mut() {
            let Ok(event) = serde_json::from_value::<Event>(value.clone()) else { continue };
            if event.event_type == "m.room.redaction" && value.get("redacts").is_none() {
                if let Some(target) = redaction_target(&event) {
                    value["redacts"] = json!(target);
                }
            }
            let redaction = redactions.get(&event.event_id);
            let relations = bundles.get(&event.event_id);
            if redaction.is_none() && relations.is_none() {
                continue;
            }
            if !value.get("unsigned").is_some_and(Value::is_object) {
                value["unsigned"] = json!({});
            }
            if let Some(redaction) = redaction {
                value["content"] = conduit::redaction::redact_event(&event).content;
                value["unsigned"]["redacted_because"] = client_event(redaction, now);
            }
            if let Some(relations) = relations {
                value["unsigned"]["m.relations"] = relations.clone();
            }
        }
        Ok(())
    }

    /// Visible, unredacted, non-ignored children of `parents`, grouped by
    /// parent ID and ordered by stream position.
    pub async fn children(
        &self,
        room_id: &str,
        parent_ids: &[String],
    ) -> conduit::Result<Vec<(i64, Event)>> {
        let rows = self.storage.relation_children(room_id, parent_ids).await?;
        if rows.is_empty() {
            return Ok(rows);
        }
        let positions: HashMap<String, i64> =
            rows.iter().map(|(position, event)| (event.event_id.clone(), *position)).collect();
        let events: Vec<Event> = rows.into_iter().map(|(_, event)| event).collect();
        let redacted = self.redactions(&events).await?;
        let events: Vec<Event> = events
            .into_iter()
            .filter(|event| !redacted.contains_key(&event.event_id) && !self.hides(event))
            .collect();
        let visible =
            conduit::auth::filter_visible_for_user(self.storage, room_id, self.user_id, events).await?;
        let mut rows: Vec<(i64, Event)> = visible
            .into_iter()
            .map(|event| (positions[&event.event_id], event))
            .collect();
        rows.sort_by_key(|(position, _)| *position);
        Ok(rows)
    }

    /// Bundled aggregations for each event (state and redacted events get
    /// none). `threads` is false for the `latest_event` of a thread, which
    /// carries only its own edits.
    async fn bundles(
        &self,
        events: &[Event],
        redactions: &HashMap<String, Event>,
        threads: bool,
    ) -> conduit::Result<HashMap<String, Value>> {
        let mut by_room: HashMap<&str, Vec<&Event>> = HashMap::new();
        for event in events {
            if event.state_key.is_none() && !redactions.contains_key(&event.event_id) {
                by_room.entry(event.room_id.as_str()).or_default().push(event);
            }
        }
        let mut out = HashMap::new();
        for (room_id, parents) in by_room {
            let ids: Vec<String> = parents.iter().map(|event| event.event_id.clone()).collect();
            let children = self.children(room_id, &ids).await?;
            if children.is_empty() {
                continue;
            }
            let mut latest_threads: Vec<Event> = Vec::new();
            let mut pending: Vec<(String, Value, Option<String>)> = Vec::new();
            for parent in parents {
                let mut relations = serde_json::Map::new();
                let edits: Vec<&Event> = children
                    .iter()
                    .map(|(_, child)| child)
                    .filter(|child| is_valid_replacement(parent, child))
                    .collect();
                if let Some(edit) = latest_edit(edits) {
                    relations.insert("m.replace".into(), client_event(edit, now_ms()));
                }
                let references: Vec<Value> = children
                    .iter()
                    .map(|(_, child)| child)
                    .filter(|child| {
                        relation(child).is_some_and(|(kind, id)| kind == "m.reference" && id == parent.event_id)
                    })
                    .map(|child| json!({"event_id": child.event_id}))
                    .collect();
                if !references.is_empty() {
                    relations.insert("m.reference".into(), json!({"chunk": references}));
                }
                let mut latest_thread_id = None;
                if threads {
                    let thread: Vec<&Event> = children
                        .iter()
                        .map(|(_, child)| child)
                        .filter(|child| is_valid_thread_child(parent, child))
                        .collect();
                    if let Some(latest) = thread.last() {
                        let participated = parent.sender == self.user_id
                            || thread.iter().any(|child| child.sender == self.user_id);
                        relations.insert(
                            "m.thread".into(),
                            json!({
                                "count": thread.len(),
                                "current_user_participated": participated,
                                "latest_event": Value::Null,
                            }),
                        );
                        latest_thread_id = Some(latest.event_id.clone());
                        latest_threads.push((*latest).clone());
                    }
                }
                if !relations.is_empty() {
                    pending.push((parent.event_id.clone(), Value::Object(relations), latest_thread_id));
                }
            }
            // Thread latest events, served with their own edit bundles.
            let served: HashMap<String, Value> = if latest_threads.is_empty() {
                HashMap::new()
            } else {
                let inner = Box::pin(self.bundles(&latest_threads, &HashMap::new(), false)).await?;
                latest_threads
                    .iter()
                    .map(|event| {
                        let mut value = client_event(event, now_ms());
                        if let Some(relations) = inner.get(&event.event_id) {
                            value["unsigned"]["m.relations"] = relations.clone();
                        }
                        (event.event_id.clone(), value)
                    })
                    .collect()
            };
            for (parent_id, mut relations, latest_thread_id) in pending {
                if let Some(latest) = latest_thread_id.and_then(|id| served.get(&id)) {
                    relations["m.thread"]["latest_event"] = latest.clone();
                }
                out.insert(parent_id, relations);
            }
        }
        Ok(out)
    }
}

/// The power levels and creator a redaction was authorized against, from
/// its `auth_events`.
async fn authorizing_power(
    storage: &dyn Storage,
    redaction: &Event,
    cache: &mut HashMap<String, Option<Event>>,
) -> conduit::Result<(Option<Event>, Option<String>)> {
    let mut power_levels = None;
    let mut creator = None;
    for id in &redaction.auth_events {
        if !cache.contains_key(id) {
            let event = storage.get_event(id).await?;
            cache.insert(id.clone(), event);
        }
        match cache.get(id).cloned().flatten() {
            Some(event) if event.event_type == "m.room.power_levels" => power_levels = Some(event),
            Some(event) if event.event_type == "m.room.create" => creator = Some(event.sender),
            _ => {}
        }
    }
    Ok((power_levels, creator))
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit::storage::MemoryStorage;

    fn event(id: &str, sender: &str, kind: &str, content: Value) -> Event {
        Event {
            event_id: id.into(),
            room_id: "!r:a.test".into(),
            sender: sender.into(),
            event_type: kind.into(),
            content,
            state_key: None,
            origin_server_ts: 10,
            auth_events: vec![],
            prev_events: vec![],
            hashes: json!({}),
            signatures: json!({}),
            depth: 1,
            unsigned: None,
        }
    }

    async fn room(storage: &MemoryStorage, events: &[Event]) {
        let mut create = event("$create", "@a:a.test", "m.room.create", json!({"room_version": "11"}));
        create.state_key = Some(String::new());
        let mut join = event("$join", "@a:a.test", "m.room.member", json!({"membership": "join"}));
        join.state_key = Some("@a:a.test".into());
        let mut history = event("$hv", "@a:a.test", "m.room.history_visibility", json!({"history_visibility": "shared"}));
        history.state_key = Some(String::new());
        for state in [&create, &join, &history] {
            storage.put_event(state).await.unwrap();
            storage
                .set_state_entry(&state.room_id, &state.event_type, state.state_key.as_deref().unwrap(), &state.event_id)
                .await
                .unwrap();
        }
        for event in events {
            storage.put_event(event).await.unwrap();
        }
    }

    #[tokio::test]
    async fn redacted_events_are_pruned_with_redacted_because() {
        let storage = MemoryStorage::default();
        let message = event("$m", "@a:a.test", "m.room.message", json!({"body": "secret", "msgtype": "m.text"}));
        let redaction = event("$x", "@a:a.test", "m.room.redaction", json!({"redacts": "$m", "reason": "oops"}));
        room(&storage, &[message.clone(), redaction]).await;
        let viewer = Viewer::load(&storage, "@a:a.test").await.unwrap();
        let served = viewer.serve_one(&message, true).await.unwrap();
        assert_eq!(served["content"], json!({}));
        assert_eq!(served["unsigned"]["redacted_because"]["event_id"], "$x");
        assert_eq!(served["unsigned"]["redacted_because"]["redacts"], "$m");

        let mut values = vec![serde_json::to_value(&message).unwrap()];
        viewer.decorate_values(&mut values, false).await.unwrap();
        assert_eq!(values[0]["content"], json!({}));
        assert!(values[0].get("hashes").is_some(), "decorate keeps PDU fields");
    }

    #[tokio::test]
    async fn remote_redaction_without_power_is_not_applied() {
        let storage = MemoryStorage::default();
        let message = event("$m", "@a:a.test", "m.room.message", json!({"body": "kept"}));
        let redaction = event("$x", "@evil:b.test", "m.room.redaction", json!({"redacts": "$m"}));
        room(&storage, &[message.clone(), redaction]).await;
        let viewer = Viewer::load(&storage, "@a:a.test").await.unwrap();
        assert_eq!(viewer.serve_one(&message, false).await.unwrap()["content"]["body"], "kept");
    }

    #[tokio::test]
    async fn bundles_edits_threads_and_references() {
        let storage = MemoryStorage::default();
        let root = event("$root", "@a:a.test", "m.room.message", json!({"body": "root"}));
        let mut edit1 = event("$e1", "@a:a.test", "m.room.message", json!({"m.new_content": {"body": "v1"}, "m.relates_to": {"rel_type": "m.replace", "event_id": "$root"}}));
        edit1.origin_server_ts = 20;
        let mut edit2 = event("$e2", "@a:a.test", "m.room.message", json!({"m.new_content": {"body": "v2"}, "m.relates_to": {"rel_type": "m.replace", "event_id": "$root"}}));
        edit2.origin_server_ts = 30;
        let forged = event("$e3", "@b:a.test", "m.room.message", json!({"m.new_content": {"body": "forged"}, "m.relates_to": {"rel_type": "m.replace", "event_id": "$root"}}));
        let reply = event("$t1", "@b:a.test", "m.room.message", json!({"body": "in thread", "m.relates_to": {"rel_type": "m.thread", "event_id": "$root"}}));
        let reference = event("$ref", "@a:a.test", "m.key.verification.done", json!({"m.relates_to": {"rel_type": "m.reference", "event_id": "$root"}}));
        room(&storage, &[root.clone(), edit1, edit2, forged, reply, reference]).await;
        let viewer = Viewer::load(&storage, "@a:a.test").await.unwrap();
        let served = viewer.serve_one(&root, true).await.unwrap();
        let relations = &served["unsigned"]["m.relations"];
        assert_eq!(relations["m.replace"]["event_id"], "$e2");
        assert_eq!(relations["m.thread"]["count"], 1);
        assert_eq!(relations["m.thread"]["current_user_participated"], true);
        assert_eq!(relations["m.thread"]["latest_event"]["event_id"], "$t1");
        assert_eq!(relations["m.reference"]["chunk"], json!([{"event_id": "$ref"}]));
        assert_eq!(served["content"]["body"], "root", "servers must not replace edited content");

        // An ignored thread participant disappears from the aggregation.
        let mut viewer = viewer;
        viewer.ignored.insert("@b:a.test".into());
        let served = viewer.serve_one(&root, true).await.unwrap();
        assert!(served["unsigned"]["m.relations"].get("m.thread").is_none());
    }

    #[test]
    fn ignored_state_events_are_still_served() {
        let ignored: HashSet<String> = ["@b:a.test".to_owned()].into();
        let message = event("$m", "@b:a.test", "m.room.message", json!({}));
        let mut topic = event("$t", "@b:a.test", "m.room.topic", json!({}));
        topic.state_key = Some(String::new());
        assert!(hidden_by_ignore(&ignored, &message));
        assert!(!hidden_by_ignore(&ignored, &topic));
    }
}
