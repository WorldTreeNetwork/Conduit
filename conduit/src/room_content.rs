//! Room content semantics shared by every host (conduit-y99.19).
//!
//! Pure predicates and shapes for serving room content to clients:
//! redaction validity, event relationships and their bundled
//! aggregations, the client event format, membership filters, space
//! child ordering and the naive search matcher used by non-SQL storage.
//! Hosts do the I/O; nothing here touches storage.
//!
//! Spec: <https://spec.matrix.org/v1.19/client-server-api/>

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::event::Event;

// ---------------------------------------------------------------------------
// Stored shapes
// ---------------------------------------------------------------------------

/// A report of an event, room or user, retained for server administrators.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentReport {
    /// Assigned by storage; ignored on insert.
    pub id: i64,
    /// `event`, `room` or `user`.
    pub kind: String,
    pub reporter: String,
    pub room_id: Option<String>,
    pub event_id: Option<String>,
    pub target_user_id: Option<String>,
    pub reason: Option<String>,
    pub received_ts: i64,
}

/// Which `POST /search` keys participate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchKeys {
    pub body: bool,
    pub name: bool,
    pub topic: bool,
}

impl SearchKeys {
    pub const ALL: SearchKeys = SearchKeys { body: true, name: true, topic: true };

    /// Parse the request `keys`; absent means all three. Unknown keys are
    /// rejected rather than silently searching nothing.
    pub fn parse(keys: Option<&[String]>) -> Result<Self, String> {
        let Some(keys) = keys else { return Ok(Self::ALL) };
        let mut selected = SearchKeys { body: false, name: false, topic: false };
        for key in keys {
            match key.as_str() {
                "content.body" => selected.body = true,
                "content.name" => selected.name = true,
                "content.topic" => selected.topic = true,
                other => return Err(format!("unsupported search key: {other}")),
            }
        }
        Ok(selected)
    }

    /// The searchable text of `event` under these keys. Each key belongs to
    /// the event type that defines it, so a message carrying a stray `name`
    /// field is not a room-name match.
    pub fn text<'a>(&self, event: &'a Event) -> Option<&'a str> {
        let field = match event.event_type.as_str() {
            "m.room.message" if self.body => "body",
            "m.room.name" if self.name => "name",
            "m.room.topic" if self.topic => "topic",
            _ => return None,
        };
        event.content.get(field).and_then(Value::as_str)
    }
}

/// A full-text match, before visibility filtering.
#[derive(Debug, Clone)]
pub struct SearchHit {
    pub rank: f64,
    pub position: i64,
    pub event: Event,
}

/// Lowercased word tokens of a search term or text.
pub fn search_tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Naive rank: every query token must prefix some word of `text`. The rank
/// is the fraction of words that matched, so short exact hits rank higher.
pub fn naive_rank(text: &str, query: &[String]) -> Option<f64> {
    if query.is_empty() {
        return None;
    }
    let words = search_tokens(text);
    if words.is_empty() {
        return None;
    }
    let mut matched = 0usize;
    for token in query {
        let hits = words.iter().filter(|word| word.starts_with(token.as_str())).count();
        if hits == 0 {
            return None;
        }
        matched += hits;
    }
    Some(matched as f64 / words.len() as f64)
}

// ---------------------------------------------------------------------------
// Client event format
// ---------------------------------------------------------------------------

/// The client-server representation of a room event: the federation-only
/// PDU fields (hashes, signatures, auth/prev events, depth) are dropped and
/// `unsigned.age` is computed at serve time.
///
/// For `m.room.redaction` the v11 `content.redacts` is mirrored at the top
/// level, as clients written against earlier room versions read it there.
pub fn client_event(event: &Event, now_ms: u64) -> Value {
    let mut value = json!({
        "content": event.content,
        "event_id": event.event_id,
        "origin_server_ts": event.origin_server_ts,
        "room_id": event.room_id,
        "sender": event.sender,
        "type": event.event_type,
    });
    if let Some(state_key) = &event.state_key {
        value["state_key"] = json!(state_key);
    }
    if event.event_type == "m.room.redaction" {
        if let Some(target) = redaction_target(event) {
            value["redacts"] = json!(target);
        }
    }
    let mut unsigned = match &event.unsigned {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    unsigned.insert("age".into(), json!(now_ms.saturating_sub(event.origin_server_ts)));
    value["unsigned"] = Value::Object(unsigned);
    value
}

// ---------------------------------------------------------------------------
// Redactions
// ---------------------------------------------------------------------------

/// The event a redaction targets (`content.redacts`, room v11).
pub fn redaction_target(event: &Event) -> Option<&str> {
    if event.event_type != "m.room.redaction" {
        return None;
    }
    event.content.get("redacts").and_then(Value::as_str)
}

/// Whether `redaction` takes effect on `target` (room v11 redaction rules).
///
/// A redaction applies when it is in the same room and either its sender's
/// server is the target sender's server, or its sender held the `redact`
/// power level in the power levels the redaction was authorized against.
/// `power_levels` is that event (from the redaction's `auth_events`);
/// `creator` covers rooms with no power-levels event.
pub fn redaction_applies(
    redaction: &Event,
    target: &Event,
    power_levels: Option<&Event>,
    creator: Option<&str>,
) -> bool {
    if redaction.room_id != target.room_id || redaction_target(redaction) != Some(&target.event_id)
    {
        return false;
    }
    if crate::auth::server_of(&redaction.sender) == crate::auth::server_of(&target.sender) {
        return true;
    }
    may_redact_others(&redaction.sender, power_levels, creator)
}

/// Does `user` hold the room's `redact` power level?
pub fn may_redact_others(user: &str, power_levels: Option<&Event>, creator: Option<&str>) -> bool {
    let level = crate::auth::user_power_level(user, power_levels, creator);
    let required = power_levels
        .and_then(|event| crate::state_events::parse_power_levels(&event.content).ok())
        .map(|content| content.redact)
        .unwrap_or(50);
    level >= required
}

// ---------------------------------------------------------------------------
// Relationships
// ---------------------------------------------------------------------------

/// `(rel_type, parent_event_id)` from a cleartext `m.relates_to`.
pub fn relation(event: &Event) -> Option<(&str, &str)> {
    let relates_to = event.content.get("m.relates_to")?;
    let rel_type = relates_to.get("rel_type")?.as_str()?;
    let parent = relates_to.get("event_id")?.as_str()?;
    Some((rel_type, parent))
}

/// Validity of an `m.replace` relationship
/// (spec: "Validity of replacement events").
pub fn is_valid_replacement(original: &Event, edit: &Event) -> bool {
    relation(edit).is_some_and(|(kind, parent)| kind == "m.replace" && parent == original.event_id)
        && original.room_id == edit.room_id
        && original.sender == edit.sender
        && original.event_type == edit.event_type
        && original.state_key.is_none()
        && edit.state_key.is_none()
        && relation(original).is_none_or(|(kind, _)| kind != "m.replace")
        && (edit.event_type == "m.room.encrypted"
            || edit.content.get("m.new_content").is_some_and(Value::is_object))
}

/// The most recent replacement: greatest `origin_server_ts`, ties broken by
/// the lexicographically largest event ID.
pub fn latest_edit<'a>(edits: impl IntoIterator<Item = &'a Event>) -> Option<&'a Event> {
    edits.into_iter().max_by(|a, b| {
        a.origin_server_ts
            .cmp(&b.origin_server_ts)
            .then_with(|| a.event_id.cmp(&b.event_id))
    })
}

/// A thread may only be rooted at an event that is not itself a relation.
pub fn is_valid_thread_child(root: &Event, child: &Event) -> bool {
    relation(child).is_some_and(|(kind, parent)| kind == "m.thread" && parent == root.event_id)
        && root.room_id == child.room_id
        && root.state_key.is_none()
        && relation(root).is_none()
}

// ---------------------------------------------------------------------------
// Membership listing
// ---------------------------------------------------------------------------

/// `GET /members` filtering. When both are given the spec makes them an
/// "or": the membership *is* `membership` or *is not* `not_membership`.
pub fn membership_selected(
    membership: &str,
    include: Option<&str>,
    exclude: Option<&str>,
) -> bool {
    match (include, exclude) {
        (None, None) => true,
        (Some(include), None) => membership == include,
        (None, Some(exclude)) => membership != exclude,
        (Some(include), Some(exclude)) => membership == include || membership != exclude,
    }
}

// ---------------------------------------------------------------------------
// Spaces
// ---------------------------------------------------------------------------

/// An `m.space.child` is valid only with a non-empty `via` array.
pub fn is_valid_space_child(event: &Event) -> bool {
    event.event_type == "m.space.child"
        && event.state_key.as_deref().is_some_and(|key| key.starts_with('!'))
        && event
            .content
            .get("via")
            .and_then(Value::as_array)
            .is_some_and(|via| !via.is_empty())
}

/// A child `order` is honoured only when it is at most 50 printable ASCII
/// characters (0x20–0x7E).
fn child_order(event: &Event) -> Option<&str> {
    event
        .content
        .get("order")
        .and_then(Value::as_str)
        .filter(|order| order.len() <= 50 && order.bytes().all(|b| (0x20..=0x7e).contains(&b)))
}

/// Ordering of space children: children with a valid `order` first, by
/// that string; then by `origin_server_ts`; then by room ID.
pub fn space_child_ordering(a: &Event, b: &Event) -> Ordering {
    match (child_order(a), child_order(b)) {
        (Some(x), Some(y)) => x.cmp(y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
    .then_with(|| a.origin_server_ts.cmp(&b.origin_server_ts))
    .then_with(|| a.state_key.cmp(&b.state_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: &str, sender: &str, kind: &str, content: Value) -> Event {
        Event {
            event_id: id.into(),
            pdu: crate::event::Pdu {
                room_id: "!r:a.test".into(),
                sender: sender.into(),
                event_type: kind.into(),
                content,
                state_key: None,
                origin_server_ts: 1_000,
                auth_events: vec![],
                prev_events: vec![],
                hashes: json!({}),
                signatures: json!({}),
                depth: 1,
                extensions: Default::default(),
            },
            unsigned: None,
        }
    }

    fn power_levels(users: Value) -> Event {
        let mut pl = event("$pl", "@admin:a.test", "m.room.power_levels", json!({"users": users, "redact": 50}));
        pl.state_key = Some(String::new());
        pl
    }

    #[test]
    fn client_format_drops_pdu_fields_and_mirrors_redacts() {
        let mut redaction = event("$r", "@a:a.test", "m.room.redaction", json!({"redacts": "$t"}));
        redaction.unsigned = Some(json!({"transaction_id": "x"}));
        let value = client_event(&redaction, 1_500);
        assert!(value.get("hashes").is_none() && value.get("auth_events").is_none());
        assert!(value.get("depth").is_none() && value.get("signatures").is_none());
        assert_eq!(value["redacts"], "$t");
        assert_eq!(value["unsigned"]["age"], 500);
        assert_eq!(value["unsigned"]["transaction_id"], "x");
        assert!(value.get("state_key").is_none());
    }

    #[test]
    fn redaction_applies_by_server_or_power() {
        let target = event("$t", "@victim:a.test", "m.room.message", json!({"body": "x"}));
        let same_server = event("$r1", "@other:a.test", "m.room.redaction", json!({"redacts": "$t"}));
        assert!(redaction_applies(&same_server, &target, None, None));

        let remote = event("$r2", "@mod:b.test", "m.room.redaction", json!({"redacts": "$t"}));
        assert!(!redaction_applies(&remote, &target, Some(&power_levels(json!({}))), None));
        let mod_pl = power_levels(json!({"@mod:b.test": 50}));
        assert!(redaction_applies(&remote, &target, Some(&mod_pl), None));

        let wrong_target = event("$r3", "@victim:a.test", "m.room.redaction", json!({"redacts": "$other"}));
        assert!(!redaction_applies(&wrong_target, &target, None, None));
        let mut other_room = same_server.clone();
        other_room.room_id = "!elsewhere:a.test".into();
        assert!(!redaction_applies(&other_room, &target, None, None));
    }

    #[test]
    fn replacement_validity_follows_the_spec_list() {
        let original = event("$o", "@a:a.test", "m.room.message", json!({"body": "x"}));
        let edit = |id: &str, sender: &str, content: Value| event(id, sender, "m.room.message", content);
        let good = edit("$e", "@a:a.test", json!({"m.new_content": {"body": "y"}, "m.relates_to": {"rel_type": "m.replace", "event_id": "$o"}}));
        assert!(is_valid_replacement(&original, &good));
        let other_sender = edit("$e2", "@b:a.test", good.content.clone());
        assert!(!is_valid_replacement(&original, &other_sender));
        let no_new_content = edit("$e3", "@a:a.test", json!({"m.relates_to": {"rel_type": "m.replace", "event_id": "$o"}}));
        assert!(!is_valid_replacement(&original, &no_new_content));
        let mut other_type = good.clone();
        other_type.event_type = "m.sticker".into();
        assert!(!is_valid_replacement(&original, &other_type));
        let mut state_original = original.clone();
        state_original.state_key = Some(String::new());
        assert!(!is_valid_replacement(&state_original, &good));
        let edit_of_edit = edit("$o2", "@a:a.test", json!({"m.relates_to": {"rel_type": "m.replace", "event_id": "$x"}, "m.new_content": {}}));
        let mut chained = good.clone();
        chained.content["m.relates_to"]["event_id"] = json!("$o2");
        assert!(!is_valid_replacement(&edit_of_edit, &chained));
    }

    #[test]
    fn latest_edit_breaks_timestamp_ties_by_event_id() {
        let mut a = event("$a", "@a:a.test", "m.room.message", json!({}));
        let mut b = event("$b", "@a:a.test", "m.room.message", json!({}));
        a.origin_server_ts = 5;
        b.origin_server_ts = 5;
        assert_eq!(latest_edit([&a, &b]).unwrap().event_id, "$b");
        a.origin_server_ts = 6;
        assert_eq!(latest_edit([&a, &b]).unwrap().event_id, "$a");
    }

    #[test]
    fn threads_cannot_root_on_relations() {
        let root = event("$root", "@a:a.test", "m.room.message", json!({}));
        let child = event("$c", "@b:a.test", "m.room.message", json!({"m.relates_to": {"rel_type": "m.thread", "event_id": "$root"}}));
        assert!(is_valid_thread_child(&root, &child));
        let nested_root = event("$root", "@a:a.test", "m.room.message", json!({"m.relates_to": {"rel_type": "m.thread", "event_id": "$x"}}));
        assert!(!is_valid_thread_child(&nested_root, &child));
    }

    #[test]
    fn membership_filters_combine_as_or() {
        assert!(membership_selected("join", None, None));
        assert!(membership_selected("join", Some("join"), None));
        assert!(!membership_selected("leave", Some("join"), None));
        assert!(!membership_selected("leave", None, Some("leave")));
        assert!(membership_selected("invite", Some("join"), Some("leave")));
        assert!(!membership_selected("leave", Some("join"), Some("leave")));
    }

    #[test]
    fn search_keys_and_naive_rank() {
        assert_eq!(SearchKeys::parse(None).unwrap(), SearchKeys::ALL);
        assert!(SearchKeys::parse(Some(&["content.nope".into()])).is_err());
        let only_name = SearchKeys::parse(Some(&["content.name".into()])).unwrap();
        let message = event("$m", "@a:a.test", "m.room.message", json!({"body": "Hello World", "name": "x"}));
        assert_eq!(only_name.text(&message), None);
        assert_eq!(SearchKeys::ALL.text(&message), Some("Hello World"));
        let query = search_tokens("WORLD hel");
        assert!(naive_rank("Hello World", &query).is_some());
        assert!(naive_rank("Hello there", &query).is_none());
        assert!(naive_rank("hi", &search_tokens("")).is_none());
    }

    #[test]
    fn space_children_need_via_and_sort_by_order() {
        let child = |room: &str, order: Option<&str>, ts: u64| {
            let mut ev = event(&format!("${room}"), "@a:a.test", "m.space.child", json!({"via": ["a.test"]}));
            if let Some(order) = order {
                ev.content["order"] = json!(order);
            }
            ev.state_key = Some(room.into());
            ev.origin_server_ts = ts;
            ev
        };
        let mut no_via = child("!x:a.test", None, 1);
        no_via.content = json!({"via": []});
        assert!(!is_valid_space_child(&no_via));
        let mut children = [child("!c:a.test", None, 1), child("!b:a.test", Some("b"), 9), child("!a:a.test", Some("a"), 9), child("!d:a.test", Some("\u{7f}"), 0)];
        assert!(children.iter().all(is_valid_space_child));
        children.sort_by(space_child_ordering);
        let order: Vec<_> = children.iter().map(|c| c.state_key.clone().unwrap()).collect();
        assert_eq!(order, ["!a:a.test", "!b:a.test", "!d:a.test", "!c:a.test"]);
    }
}
