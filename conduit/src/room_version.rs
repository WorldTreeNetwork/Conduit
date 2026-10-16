//! Per-version rules for Matrix room versions 1 through 12.
//!
//! <https://spec.matrix.org/v1.19/rooms/>
//!
//! Redaction, event IDs, and state resolution v1 live here so a test can call
//! them without HTTP. Authorization differences are applied by [`crate::auth`]
//! using [`version_of_content`].

use std::collections::HashMap;

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::{Map, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::canonical_json::{to_canonical_bytes, CanonicalJsonError};
use crate::event::{Event, Pdu};

/// Failure while deriving a reference-hash event id.
#[derive(Debug)]
pub enum EventIdError {
    Serialize(serde_json::Error),
    Canonical(CanonicalJsonError),
}

impl From<serde_json::Error> for EventIdError {
    fn from(error: serde_json::Error) -> Self {
        EventIdError::Serialize(error)
    }
}

impl From<CanonicalJsonError> for EventIdError {
    fn from(error: CanonicalJsonError) -> Self {
        EventIdError::Canonical(error)
    }
}

/// Room versions this homeserver creates and authorises.
pub const SUPPORTED: &[&str] = &[
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
];

/// `Some(n)` when `version` is a supported room version.
pub fn parse(version: &str) -> Option<u32> {
    SUPPORTED.iter().position(|v| *v == version).map(|i| (i as u32) + 1)
}

/// Spec default when `content.room_version` is absent: room version 1.
pub fn spec_default_when_absent(content: &Value) -> u32 {
    content
        .get("room_version")
        .and_then(Value::as_str)
        .and_then(parse)
        .unwrap_or(1)
}

/// Version written on an event. Omitted fields stay on the historical kernel
/// default (11) so fixtures that predate an explicit field keep their meaning.
/// [`spec_default_when_absent`] is the spec rule.
pub fn version_of_content(content: &Value) -> u32 {
    content
        .get("room_version")
        .and_then(Value::as_str)
        .and_then(parse)
        .unwrap_or(11)
}

pub fn version_of_event(event: &Event) -> u32 {
    version_of_content(&event.content)
}

/// Room version 12 selects no `m.room.create` auth event. The room id is that
/// event, so citing it is rejected.
pub fn cites_room_create(version: u32) -> bool {
    version < 12
}

/// Room id of a version-12 room: the create event's id with `!` instead of `$`.
pub fn room_id_from_event_id(event_id: &str) -> String {
    format!("!{}", event_id.trim_start_matches('$'))
}

/// Whether `id` is a Matrix user id of the form `@localpart:server`.
pub fn valid_user_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix('@') else {
        return false;
    };
    let Some((local, server)) = rest.split_once(':') else {
        return false;
    };
    !local.is_empty() && !server.is_empty()
}

/// Redact `pdu` with the algorithm for `version`.
pub fn redact_pdu(pdu: &Pdu, version: u32) -> Pdu {
    let mut redacted = pdu.clone();
    redacted.content = redact_content(&pdu.event_type, &pdu.content, version);
    if version >= 11 {
        redacted.extensions.clear();
    } else {
        redacted.extensions.retain(|key, _| {
            matches!(key.as_str(), "event_id" | "origin" | "membership" | "prev_state")
        });
    }
    redacted
}

fn redact_content(event_type: &str, content: &Value, version: u32) -> Value {
    if version >= 11 && event_type == "m.room.create" {
        return content.clone();
    }
    let mut redacted = Map::new();
    if let Some(map) = content.as_object() {
        for field in allowed_content_fields(event_type, version) {
            if let Some(value) = map.get(*field) {
                redacted.insert((*field).to_owned(), value.clone());
            }
        }
        if version >= 11 && event_type == "m.room.member" {
            if let Some(signed) = map
                .get("third_party_invite")
                .and_then(Value::as_object)
                .and_then(|invite| invite.get("signed"))
            {
                redacted.insert("third_party_invite".into(), serde_json::json!({"signed": signed}));
            }
        }
    }
    Value::Object(redacted)
}

fn allowed_content_fields(event_type: &str, version: u32) -> &'static [&'static str] {
    match event_type {
        "m.room.member" if version >= 9 => &["membership", "join_authorised_via_users_server"],
        "m.room.member" => &["membership"],
        "m.room.create" => &["creator"],
        "m.room.join_rules" if version >= 8 => &["join_rule", "allow"],
        "m.room.join_rules" => &["join_rule"],
        "m.room.power_levels" if version >= 11 => &[
            "ban",
            "events",
            "events_default",
            "invite",
            "kick",
            "redact",
            "state_default",
            "users",
            "users_default",
        ],
        "m.room.power_levels" => &[
            "ban",
            "events",
            "events_default",
            "kick",
            "redact",
            "state_default",
            "users",
            "users_default",
        ],
        "m.room.aliases" if version <= 5 => &["aliases"],
        "m.room.history_visibility" => &["history_visibility"],
        "m.room.redaction" if version >= 11 => &["redacts"],
        _ => &[],
    }
}

/// Reference-hash event id. Room versions 1 and 2 have no derived id.
pub fn event_id_for(pdu: &Pdu, version: u32) -> Result<Option<String>, EventIdError> {
    if version < 3 {
        return Ok(None);
    }
    let redacted = redact_pdu(pdu, version);
    let mut value = serde_json::to_value(&redacted)?;
    if let Some(map) = value.as_object_mut() {
        map.remove("signatures");
        map.remove("unsigned");
    }
    let canonical = to_canonical_bytes(&value)?;
    let digest = Sha256::digest(&canonical);
    let encoded = if version == 3 {
        STANDARD_NO_PAD.encode(digest)
    } else {
        URL_SAFE_NO_PAD.encode(digest)
    };
    Ok(Some(format!("${encoded}")))
}

/// Power-level content as the auth rules see it.
///
/// Versions 1–5 coerce integer strings and truncated floats. Versions 6–9
/// still accept an integer encoded as a string, and reject floats. Version
/// 10 rejects anything that is not a JSON integer.
pub fn power_levels_for_auth(content: &Value, version: u32) -> Value {
    if version < 6 {
        coerce_power_level_values(content)
    } else if version < 10 {
        coerce_integer_power_level_strings(content)
    } else {
        content.clone()
    }
}

/// Room versions 1–5 accept power-level numbers as strings or truncated floats.
pub fn coerce_power_level_values(content: &Value) -> Value {
    let Some(map) = content.as_object() else {
        return content.clone();
    };
    let mut out = map.clone();
    for key in ["ban", "events_default", "state_default", "users_default", "redact", "kick", "invite"] {
        if let Some(value) = out.get(key) {
            if let Some(n) = coerce_integer(value) {
                out.insert(key.to_owned(), Value::from(n));
            }
        }
    }
    for key in ["events", "notifications", "users"] {
        if let Some(Value::Object(inner)) = out.get(key).cloned() {
            let mut next = Map::new();
            for (name, value) in inner {
                if let Some(n) = coerce_integer(&value) {
                    next.insert(name, Value::from(n));
                } else {
                    next.insert(name, value);
                }
            }
            out.insert(key.to_owned(), Value::Object(next));
        }
    }
    Value::Object(out)
}

/// Room versions 6–9 keep the deprecated integer-as-string power levels.
/// Floats stay floats so a later integer parse rejects them.
pub fn coerce_integer_power_level_strings(content: &Value) -> Value {
    let Some(map) = content.as_object() else {
        return content.clone();
    };
    let mut out = map.clone();
    for key in ["ban", "events_default", "state_default", "users_default", "redact", "kick", "invite"] {
        if let Some(Value::String(text)) = out.get(key) {
            if let Some(n) = coerce_integer(&Value::String(text.clone())) {
                out.insert(key.to_owned(), Value::from(n));
            }
        }
    }
    for key in ["events", "notifications", "users"] {
        if let Some(Value::Object(inner)) = out.get(key).cloned() {
            let mut next = Map::new();
            for (name, value) in inner {
                if let Value::String(text) = &value {
                    if let Some(n) = coerce_integer(&Value::String(text.clone())) {
                        next.insert(name, Value::from(n));
                        continue;
                    }
                }
                next.insert(name, value);
            }
            out.insert(key.to_owned(), Value::Object(next));
        }
    }
    Value::Object(out)
}

fn coerce_integer(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Value::String(s) => {
            let trimmed = s.trim();
            let trimmed = trimmed.strip_prefix('+').unwrap_or(trimmed);
            trimmed.parse::<i64>().ok()
        }
        _ => None,
    }
}

/// `additional_creators` from a create event, when it is an array of strings.
pub fn additional_creators(content: &Value) -> Vec<String> {
    content
        .get("additional_creators")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// State resolution algorithm for room version 1.
///
/// Conflicted `m.room.power_levels`, then join rules, then members, are sorted
/// by ascending depth and descending SHA-1 of the event id. The first event is
/// applied; each later event is applied only while it passes auth. Other
/// conflicts take the highest depth and lowest SHA-1 that passes auth.
pub fn resolve_v1(
    state_sets: &[HashMap<(String, String), Event>],
    mut auth: impl FnMut(&Event, &HashMap<(String, String), Event>) -> bool,
) -> HashMap<(String, String), Event> {
    let mut keys = std::collections::BTreeSet::new();
    for set in state_sets {
        keys.extend(set.keys().cloned());
    }
    let mut resolved: HashMap<(String, String), Event> = HashMap::new();
    let mut conflicted: HashMap<(String, String), Vec<Event>> = HashMap::new();
    for key in keys {
        let mut distinct: Vec<Event> = Vec::new();
        for set in state_sets {
            if let Some(event) = set.get(&key) {
                if !distinct.iter().any(|have| have.event_id == event.event_id) {
                    distinct.push(event.clone());
                }
            }
        }
        if distinct.len() == 1 && state_sets.iter().all(|set| set.get(&key).map(|e| e.event_id.as_str()) == Some(distinct[0].event_id.as_str())) {
            resolved.insert(key, distinct.pop().expect("one"));
        } else if !distinct.is_empty() {
            conflicted.insert(key, distinct);
        }
    }

    fn sha1_desc(event_id: &str) -> [u8; 20] {
        let mut hasher = Sha1::new();
        hasher.update(event_id.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest);
        out
    }
    fn sort_key(event: &Event) -> (i64, std::cmp::Reverse<[u8; 20]>) {
        (event.depth, std::cmp::Reverse(sha1_desc(&event.event_id)))
    }

    for kind in ["m.room.power_levels", "m.room.join_rules", "m.room.member"] {
        let keys: Vec<_> = conflicted.keys().filter(|(t, _)| t == kind).cloned().collect();
        let mut events = Vec::new();
        for key in &keys {
            if let Some(group) = conflicted.remove(key) {
                events.extend(group);
            }
        }
        events.sort_by_key(sort_key);
        let mut iter = events.into_iter();
        if let Some(first) = iter.next() {
            let key = (first.event_type.clone(), first.state_key.clone().unwrap_or_default());
            resolved.insert(key, first);
            for event in iter {
                if !auth(&event, &resolved) {
                    break;
                }
                let key = (event.event_type.clone(), event.state_key.clone().unwrap_or_default());
                resolved.insert(key, event);
            }
        }
    }
    for (key, mut events) in conflicted {
        events.sort_by(|a, b| b.depth.cmp(&a.depth).then_with(|| sha1_desc(&a.event_id).cmp(&sha1_desc(&b.event_id))));
        if let Some(event) = events.into_iter().find(|event| auth(event, &resolved)) {
            resolved.insert(key, event);
        }
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn message() -> Pdu {
        let mut pdu = Pdu::new(
            "!r:example.org",
            "@a:example.org",
            "m.room.message",
            None,
            json!({"body": "hi", "msgtype": "m.text"}),
            5,
            vec!["$a".into()],
            vec!["$p".into()],
            3,
        );
        pdu.extensions.insert("origin".into(), json!("example.org"));
        pdu.extensions.insert("membership".into(), json!("join"));
        pdu.extensions.insert("prev_state".into(), json!([]));
        pdu.extensions.insert("org.example.x".into(), json!(1));
        pdu.hashes = json!({"sha256": "h"});
        pdu.signatures = json!({"example.org": {"ed25519:1": "s"}});
        pdu
    }

    #[test]
    fn supported_versions_are_one_through_twelve() {
        assert!(parse("1").is_some() && parse("12").is_some());
        assert!(parse("0").is_none() && parse("13").is_none() && parse("11 ").is_none());
    }

    #[test]
    fn absent_room_version_is_spec_default_one() {
        assert_eq!(spec_default_when_absent(&json!({})), 1);
        assert_eq!(spec_default_when_absent(&json!({"room_version": "12"})), 12);
        assert_eq!(version_of_content(&json!({})), 11);
    }

    #[test]
    fn v1_redaction_keeps_legacy_keys_and_only_creator() {
        let mut create = message();
        create.event_type = "m.room.create".into();
        create.content = json!({"creator": "@a:example.org", "room_version": "1", "extra": true});
        let redacted = redact_pdu(&create, 1);
        assert_eq!(redacted.content, json!({"creator": "@a:example.org"}));
        assert_eq!(redacted.extensions.get("origin").and_then(Value::as_str), Some("example.org"));
        assert!(redacted.extensions.contains_key("membership"));
        assert!(redacted.extensions.contains_key("prev_state"));
        assert!(!redacted.extensions.contains_key("org.example.x"));
    }

    /// Room version 2 uses the version 1 redaction keep-list: protected
    /// top-level keys stay, message content is emptied, and power levels
    /// omit `invite`. Aliases survive here and are removed from version 6.
    #[test]
    fn v2_redaction_keeps_the_v1_allow_list() {
        let mut original = message();
        original.extensions.insert("event_id".into(), json!("$evt:example.org"));
        let redacted = redact_pdu(&original, 2);
        assert_eq!(redacted.content, json!({}));
        assert_eq!(redacted.room_id, original.room_id);
        assert_eq!(redacted.sender, original.sender);
        assert_eq!(redacted.event_type, "m.room.message");
        assert!(redacted.state_key.is_none());
        assert_eq!(redacted.depth, original.depth);
        assert_eq!(redacted.origin_server_ts, original.origin_server_ts);
        assert_eq!(redacted.prev_events, original.prev_events);
        assert_eq!(redacted.auth_events, original.auth_events);
        assert_eq!(redacted.hashes, original.hashes);
        assert_eq!(redacted.signatures, original.signatures);
        assert_eq!(redacted.extensions.get("event_id").and_then(Value::as_str), Some("$evt:example.org"));
        assert_eq!(redacted.extensions.get("origin").and_then(Value::as_str), Some("example.org"));
        assert!(redacted.extensions.contains_key("membership"));
        assert!(redacted.extensions.contains_key("prev_state"));
        assert!(!redacted.extensions.contains_key("org.example.x"));

        let mut create = original.clone();
        create.event_type = "m.room.create".into();
        create.content = json!({"creator": "@a:example.org", "room_version": "2", "extra": true});
        assert_eq!(redact_pdu(&create, 2).content, json!({"creator": "@a:example.org"}));

        let mut member = original.clone();
        member.event_type = "m.room.member".into();
        member.content = json!({"membership": "join", "displayname": "A"});
        assert_eq!(redact_pdu(&member, 2).content, json!({"membership": "join"}));

        let mut rules = original.clone();
        rules.event_type = "m.room.join_rules".into();
        rules.content = json!({"join_rule": "public", "allow": []});
        assert_eq!(redact_pdu(&rules, 2).content, json!({"join_rule": "public"}));

        let mut levels = original.clone();
        levels.event_type = "m.room.power_levels".into();
        levels.content = json!({
            "ban": 50,
            "events": {"m.room.name": 50},
            "events_default": 0,
            "invite": 50,
            "kick": 50,
            "redact": 50,
            "state_default": 50,
            "users": {"@a:example.org": 100},
            "users_default": 0,
            "notifications": {"room": 50}
        });
        assert_eq!(
            redact_pdu(&levels, 2).content,
            json!({
                "ban": 50,
                "events": {"m.room.name": 50},
                "events_default": 0,
                "kick": 50,
                "redact": 50,
                "state_default": 50,
                "users": {"@a:example.org": 100},
                "users_default": 0
            })
        );

        let mut aliases = original.clone();
        aliases.event_type = "m.room.aliases".into();
        aliases.content = json!({"aliases": ["#a:example.org"], "note": "x"});
        assert_eq!(redact_pdu(&aliases, 2).content, json!({"aliases": ["#a:example.org"]}));
        assert!(redact_pdu(&aliases, 6).content.get("aliases").is_none());

        let mut history = original.clone();
        history.event_type = "m.room.history_visibility".into();
        history.content = json!({"history_visibility": "shared", "extra": 1});
        assert_eq!(redact_pdu(&history, 2).content, json!({"history_visibility": "shared"}));
    }

    /// Room version 3 keeps the version 1 redaction allow-list. Version 11
    /// keeps create extras and `invite`; version 6 drops aliases.
    #[test]
    fn v3_redaction_keeps_the_v1_allow_list() {
        let mut original = message();
        original.extensions.insert("event_id".into(), json!("$evt:example.org"));
        let redacted = redact_pdu(&original, 3);
        assert_eq!(redacted.content, json!({}));
        assert_eq!(redacted.extensions.get("event_id").and_then(Value::as_str), Some("$evt:example.org"));
        assert_eq!(redacted.extensions.get("origin").and_then(Value::as_str), Some("example.org"));
        assert!(redacted.extensions.contains_key("membership"));
        assert!(redacted.extensions.contains_key("prev_state"));
        assert!(!redacted.extensions.contains_key("org.example.x"));

        let mut create = original.clone();
        create.event_type = "m.room.create".into();
        create.content = json!({"creator": "@a:example.org", "room_version": "3", "extra": true});
        assert_eq!(redact_pdu(&create, 3).content, json!({"creator": "@a:example.org"}));
        assert!(redact_pdu(&create, 11).content.get("extra").is_some());

        let mut rules = original.clone();
        rules.event_type = "m.room.join_rules".into();
        rules.content = json!({"join_rule": "public", "allow": []});
        assert_eq!(redact_pdu(&rules, 3).content, json!({"join_rule": "public"}));

        let mut levels = original.clone();
        levels.event_type = "m.room.power_levels".into();
        levels.content = json!({"ban": 50, "invite": 50, "users": {}});
        assert!(redact_pdu(&levels, 3).content.get("invite").is_none());
        assert_eq!(redact_pdu(&levels, 11).content["invite"], 50);

        let mut aliases = original.clone();
        aliases.event_type = "m.room.aliases".into();
        aliases.content = json!({"aliases": ["#a:example.org"], "note": "x"});
        assert_eq!(redact_pdu(&aliases, 3).content, json!({"aliases": ["#a:example.org"]}));
        assert!(redact_pdu(&aliases, 6).content.get("aliases").is_none());
    }

    /// Room version 4 keeps the version 3 redaction allow-list, which is the
    /// version 1 list. Version 6 drops aliases. Version 11 keeps invite.
    #[test]
    fn v4_redaction_keeps_the_v3_allow_list() {
        let mut original = message();
        original.extensions.insert("event_id".into(), json!("$evt:example.org"));
        let redacted = redact_pdu(&original, 4);
        assert_eq!(redacted.content, json!({}));
        assert_eq!(redacted.extensions.get("event_id").and_then(Value::as_str), Some("$evt:example.org"));
        assert_eq!(redacted.extensions.get("origin").and_then(Value::as_str), Some("example.org"));
        assert!(redacted.extensions.contains_key("membership"));
        assert!(redacted.extensions.contains_key("prev_state"));
        assert!(!redacted.extensions.contains_key("org.example.x"));

        let mut create = original.clone();
        create.event_type = "m.room.create".into();
        create.content = json!({"creator": "@a:example.org", "room_version": "4", "extra": true});
        assert_eq!(redact_pdu(&create, 4).content, json!({"creator": "@a:example.org"}));
        assert!(redact_pdu(&create, 11).content.get("extra").is_some());

        let mut rules = original.clone();
        rules.event_type = "m.room.join_rules".into();
        rules.content = json!({"join_rule": "public", "allow": []});
        assert_eq!(redact_pdu(&rules, 4).content, json!({"join_rule": "public"}));

        let mut levels = original.clone();
        levels.event_type = "m.room.power_levels".into();
        levels.content = json!({"ban": 50, "invite": 50, "users": {}});
        assert!(redact_pdu(&levels, 4).content.get("invite").is_none());
        assert_eq!(redact_pdu(&levels, 11).content["invite"], 50);

        let mut aliases = original.clone();
        aliases.event_type = "m.room.aliases".into();
        aliases.content = json!({"aliases": ["#a:example.org"], "note": "x"});
        assert_eq!(redact_pdu(&aliases, 4).content, json!({"aliases": ["#a:example.org"]}));
        assert!(redact_pdu(&aliases, 6).content.get("aliases").is_none());
    }

    #[test]
    fn v6_redaction_drops_aliases_and_v11_drops_legacy_top_level_keys() {
        let mut aliases = message();
        aliases.event_type = "m.room.aliases".into();
        aliases.state_key = Some("example.org".into());
        aliases.content = json!({"aliases": ["#a:example.org"], "note": "x"});
        assert_eq!(redact_pdu(&aliases, 5).content["aliases"], json!(["#a:example.org"]));
        assert!(redact_pdu(&aliases, 6).content.get("aliases").is_none());

        let v11 = redact_pdu(&message(), 11);
        assert!(v11.extensions.is_empty());
        let mut create = message();
        create.event_type = "m.room.create".into();
        create.content = json!({"room_version": "11", "extra": 1});
        assert_eq!(redact_pdu(&create, 11).content["extra"], 1);
        let mut levels = message();
        levels.event_type = "m.room.power_levels".into();
        levels.content = json!({"invite": 50, "ban": 50, "users": {}});
        assert!(redact_pdu(&levels, 10).content.get("invite").is_none());
        assert_eq!(redact_pdu(&levels, 11).content["invite"], 50);
    }

    /// Room version 7 redacts with the v6 keep-list: legacy top-level keys
    /// stay, `invite` is stripped from power levels, and a knock membership
    /// keeps only `membership`. Version 11 drops those legacy keys.
    #[test]
    fn v7_redaction_keeps_the_v6_allow_list() {
        let original = message();
        let redacted = redact_pdu(&original, 7);
        assert_eq!(redacted.event_type, "m.room.message");
        assert_eq!(redacted.room_id, original.room_id);
        assert_eq!(redacted.sender, original.sender);
        assert_eq!(redacted.depth, original.depth);
        assert_eq!(redacted.origin_server_ts, original.origin_server_ts);
        assert_eq!(redacted.prev_events, original.prev_events);
        assert_eq!(redacted.auth_events, original.auth_events);
        assert_eq!(redacted.hashes, original.hashes);
        assert_eq!(redacted.signatures, original.signatures);
        assert_eq!(redacted.content, json!({}));
        assert_eq!(redacted.extensions.get("origin").and_then(Value::as_str), Some("example.org"));
        assert!(redacted.extensions.contains_key("membership"));
        assert!(redacted.extensions.contains_key("prev_state"));
        assert!(!redacted.extensions.contains_key("org.example.x"));
        assert!(!redact_pdu(&original, 11).extensions.contains_key("origin"));

        let mut knock = message();
        knock.event_type = "m.room.member".into();
        knock.state_key = Some("@a:example.org".into());
        knock.content = json!({"membership": "knock", "displayname": "A", "reason": "hi"});
        assert_eq!(redact_pdu(&knock, 7).content, json!({"membership": "knock"}));

        let mut levels = message();
        levels.event_type = "m.room.power_levels".into();
        levels.content = json!({"invite": 0, "ban": 50, "kick": 50, "events": {"m.room.message": 0}});
        let levels = redact_pdu(&levels, 7);
        assert!(levels.content.get("invite").is_none());
        assert_eq!(levels.content["ban"], 50);
        assert_eq!(levels.content["events"]["m.room.message"], 0);

        assert_eq!(
            event_id_for(&original, 7).unwrap(),
            event_id_for(&original, 6).unwrap(),
            "v7 redaction must not change the v6 reference hash"
        );
    }

    /// Room version 8 keeps `allow` on a redacted join-rules event. Version 7
    /// drops it. A member event still drops `join_authorised_via_users_server`.
    #[test]
    fn v8_redaction_keeps_join_rules_allow() {
        let mut rules = message();
        rules.event_type = "m.room.join_rules".into();
        rules.content = json!({
            "join_rule": "restricted",
            "allow": [{"type": "m.room_membership", "room_id": "!space:example.org"}],
            "extra": true
        });
        assert_eq!(redact_pdu(&rules, 7).content, json!({"join_rule": "restricted"}));
        assert_eq!(
            redact_pdu(&rules, 8).content,
            json!({
                "join_rule": "restricted",
                "allow": [{"type": "m.room_membership", "room_id": "!space:example.org"}]
            })
        );

        let mut member = message();
        member.event_type = "m.room.member".into();
        member.state_key = Some("@b:example.org".into());
        member.content = json!({
            "membership": "join",
            "join_authorised_via_users_server": "@a:example.org",
            "displayname": "B"
        });
        assert_eq!(redact_pdu(&member, 8).content, json!({"membership": "join"}));

        let mut levels = message();
        levels.event_type = "m.room.power_levels".into();
        levels.content = json!({"invite": 50, "ban": 50, "users": {}});
        assert!(redact_pdu(&levels, 8).content.get("invite").is_none());
        assert_eq!(redact_pdu(&levels, 8).content["ban"], 50);

        let mut aliases = message();
        aliases.event_type = "m.room.aliases".into();
        aliases.content = json!({"aliases": ["#a:example.org"]});
        assert!(redact_pdu(&aliases, 8).content.get("aliases").is_none());
    }

    /// Room version 9 keeps `join_authorised_via_users_server` on a redacted
    /// member event. Version 8 drops it. `invite` stays stripped, and a
    /// third-party invite is not kept until version 11.
    #[test]
    fn v9_redaction_keeps_the_authorising_user() {
        let mut member = message();
        member.event_type = "m.room.member".into();
        member.state_key = Some("@b:example.org".into());
        member.content = json!({
            "membership": "join",
            "join_authorised_via_users_server": "@a:example.org",
            "displayname": "B",
            "third_party_invite": {"signed": {"mxid": "@b:example.org", "token": "t"}}
        });
        assert_eq!(redact_pdu(&member, 8).content, json!({"membership": "join"}));
        assert_eq!(
            redact_pdu(&member, 9).content,
            json!({
                "membership": "join",
                "join_authorised_via_users_server": "@a:example.org"
            })
        );

        let mut levels = message();
        levels.event_type = "m.room.power_levels".into();
        levels.content = json!({"invite": 50, "ban": 50});
        assert!(redact_pdu(&levels, 9).content.get("invite").is_none());
        assert_eq!(redact_pdu(&levels, 9).content["ban"], 50);
    }

    #[test]
    fn event_ids_follow_the_version_encoding() {
        let pdu = message();
        assert!(event_id_for(&pdu, 1).unwrap().is_none());
        assert!(event_id_for(&pdu, 2).unwrap().is_none());
        let v3 = event_id_for(&pdu, 3).unwrap().unwrap();
        let v4 = event_id_for(&pdu, 4).unwrap().unwrap();
        let v11 = event_id_for(&pdu, 11).unwrap().unwrap();
        let v12 = event_id_for(&pdu, 12).unwrap().unwrap();
        assert!(v3.starts_with('$') && v4.starts_with('$'));
        assert!(!v3.contains('_') && !v3.contains('-'));
        assert_eq!(v11, v12, "v11 and v12 redact a message event the same way");
        assert_ne!(v4, v12, "v4 still protects origin, membership, and prev_state");
        assert_eq!(v12, crate::hashing::event_id(&pdu).unwrap());
        for version in 4..=10 {
            assert_eq!(
                event_id_for(&pdu, version).unwrap(),
                Some(v4.clone()),
                "room version {version} uses the v4 reference hash"
            );
        }
        let mut create = message();
        create.event_type = "m.room.create".into();
        create.room_id.clear();
        let wire = serde_json::to_value(&create).unwrap();
        assert!(wire.get("room_id").is_none(), "a v12 create omits room_id");
    }

    #[test]
    fn v3_and_v4_diverge_when_redaction_matches() {
        // A digest that uses only alphanumerics encodes the same in both
        // alphabets. Force a difference by checking the encoder the id uses:
        // re-encoding the decoded digest must round-trip only in its alphabet.
        let pdu = message();
        let v3 = event_id_for(&pdu, 3).unwrap().unwrap();
        let raw = STANDARD_NO_PAD.decode(&v3[1..]).unwrap();
        assert_eq!(v3, format!("${}", STANDARD_NO_PAD.encode(&raw)));
        let v4 = event_id_for(&pdu, 4).unwrap().unwrap();
        let raw4 = URL_SAFE_NO_PAD.decode(&v4[1..]).unwrap();
        assert_eq!(v4, format!("${}", URL_SAFE_NO_PAD.encode(&raw4)));
        assert_eq!(raw, raw4, "same redacted bytes; only the alphabet changes before v11 redaction");
    }

    #[test]
    fn legacy_power_levels_coerce_strings_and_truncate_floats() {
        let coerced = coerce_power_level_values(&json!({
            "ban": " 50 ",
            "users": {"@bob:example.org": 50.9, "@carol:example.org": "+7"},
            "events": {"m.room.name": "10"}
        }));
        assert_eq!(coerced["ban"], 50);
        assert_eq!(coerced["users"]["@bob:example.org"], 50);
        assert_eq!(coerced["users"]["@carol:example.org"], 7);
        assert_eq!(coerced["events"]["m.room.name"], 10);
    }

    fn ev(id: &str, kind: &str, key: &str, depth: i64, sender: &str) -> Event {
        Event::new(
            id,
            Pdu::new("!r:x", sender, kind, Some(key.into()), json!({}), 1, vec![], vec![], depth),
        )
    }

    #[test]
    fn state_resolution_v1_orders_power_levels_by_depth_then_sha1() {
        let low = ev("$low", "m.room.power_levels", "", 1, "@a:x");
        let high = ev("$high", "m.room.power_levels", "", 5, "@b:x");
        let mut left = HashMap::new();
        left.insert(("m.room.power_levels".into(), String::new()), low);
        let mut right = HashMap::new();
        right.insert(("m.room.power_levels".into(), String::new()), high);
        let mut checked = Vec::new();
        let resolved = resolve_v1(&[left, right], |event, _| {
            checked.push(event.event_id.clone());
            false
        });
        assert_eq!(checked, vec!["$high".to_owned()], "the deeper event is auth-checked second");
        assert_eq!(
            resolved[&("m.room.power_levels".into(), String::new())].event_id,
            "$low",
            "the shallower event was applied first and the deeper one was rejected"
        );
    }

    #[test]
    fn state_resolution_v1_stops_when_a_later_power_event_fails_auth() {
        let first = ev("$first", "m.room.power_levels", "", 1, "@a:x");
        let second = ev("$second", "m.room.power_levels", "", 2, "@b:x");
        let mut left = HashMap::new();
        left.insert(("m.room.power_levels".into(), String::new()), first);
        let mut right = HashMap::new();
        right.insert(("m.room.power_levels".into(), String::new()), second);
        let resolved = resolve_v1(&[left, right], |event, _| event.event_id == "$first");
        assert_eq!(resolved[&("m.room.power_levels".into(), String::new())].event_id, "$first");
    }

    #[test]
    fn room_id_replaces_the_event_id_sigil() {
        assert_eq!(
            room_id_from_event_id("$Rqnc-F-dvnEYJTyHq_iKxU2bZ1CI92-kuZq3a5lr5Zg"),
            "!Rqnc-F-dvnEYJTyHq_iKxU2bZ1CI92-kuZq3a5lr5Zg"
        );
    }
}
