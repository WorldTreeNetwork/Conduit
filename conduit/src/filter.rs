//! Matrix filters are validated independently of their HTTP/storage hosts.

use serde::{Deserialize, Deserializer};
use serde_json::Value;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Filter {
    pub event_fields: Option<Vec<String>>,
    pub event_format: EventFormat,
    pub presence: EventFilter,
    pub account_data: EventFilter,
    pub room: RoomFilter,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventFormat {
    #[default]
    Client,
    Federation,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct EventFilter {
    #[serde(deserialize_with = "positive_limit")]
    pub limit: Option<usize>,
    pub types: Option<Vec<String>>,
    pub not_types: Vec<String>,
    pub senders: Option<Vec<String>>,
    pub not_senders: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RoomEventFilter {
    #[serde(flatten)]
    pub events: EventFilter,
    pub rooms: Option<Vec<String>>,
    pub not_rooms: Vec<String>,
    pub contains_url: Option<bool>,
    pub lazy_load_members: bool,
    pub include_redundant_members: bool,
    pub unread_thread_notifications: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RoomFilter {
    pub rooms: Option<Vec<String>>,
    pub not_rooms: Vec<String>,
    pub include_leave: bool,
    pub timeline: RoomEventFilter,
    pub state: RoomEventFilter,
    pub ephemeral: RoomEventFilter,
    pub account_data: RoomEventFilter,
}

fn positive_limit<'de, D: Deserializer<'de>>(input: D) -> Result<Option<usize>, D::Error> {
    let value = usize::deserialize(input)?;
    if value == 0 {
        Err(serde::de::Error::custom("filter limits must be positive"))
    } else {
        Ok(Some(value))
    }
}

fn allowed(values: &Option<Vec<String>>, value: &str) -> bool {
    values
        .as_ref()
        .is_none_or(|items| items.iter().any(|item| item == value))
}

/// Match '*' only; regex metacharacters in event types remain literal.
pub fn type_matches(pattern: &str, value: &str) -> bool {
    let p: Vec<_> = pattern.chars().collect();
    let v: Vec<_> = value.chars().collect();
    let (mut i, mut j, mut star, mut checkpoint) = (0, 0, None, 0);
    while j < v.len() {
        if i < p.len() && p[i] == '*' {
            star = Some(i);
            i += 1;
            checkpoint = j;
        } else if i < p.len() && p[i] == v[j] {
            i += 1;
            j += 1;
        } else if let Some(s) = star {
            checkpoint += 1;
            j = checkpoint;
            i = s + 1;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
}

impl EventFilter {
    pub fn matches(&self, event: &Value) -> bool {
        let kind = event["type"].as_str().unwrap_or("");
        let sender = event["sender"].as_str().unwrap_or("");
        self.types
            .as_ref()
            .is_none_or(|types| types.iter().any(|pattern| type_matches(pattern, kind)))
            && !self
                .not_types
                .iter()
                .any(|pattern| type_matches(pattern, kind))
            && allowed(&self.senders, sender)
            && !self.not_senders.iter().any(|item| item == sender)
    }
}

impl RoomEventFilter {
    pub fn matches(&self, room: &str, event: &Value) -> bool {
        allowed(&self.rooms, room)
            && !self.not_rooms.iter().any(|item| item == room)
            && self.events.matches(event)
            && self
                .contains_url
                .is_none_or(|required| event["content"].get("url").is_some() == required)
    }
}

impl RoomFilter {
    pub fn allows(&self, room: &str) -> bool {
        allowed(&self.rooms, room) && !self.not_rooms.iter().any(|item| item == room)
    }
}

fn path_segments(path: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut escaped = false;
    for character in path.chars() {
        if escaped {
            parts.last_mut().unwrap().push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '.' {
            parts.push(String::new());
        } else {
            parts.last_mut().unwrap().push(character);
        }
    }
    if escaped {
        parts.last_mut().unwrap().push('\\');
    }
    parts
}

impl Filter {
    pub fn project(&self, event: Value) -> Value {
        let Some(fields) = &self.event_fields else {
            return event;
        };
        let mut projected = serde_json::json!({});
        for field in fields {
            let path = path_segments(field);
            let Some(value) = path.iter().try_fold(&event, |value, part| value.get(part)) else {
                continue;
            };
            let mut target = &mut projected;
            for part in &path[..path.len() - 1] {
                if !target.is_object() {
                    *target = serde_json::json!({});
                }
                let map = target.as_object_mut().unwrap();
                target = map.entry(part).or_insert_with(|| serde_json::json!({}));
            }
            if !target.is_object() {
                *target = serde_json::json!({});
            }
            target
                .as_object_mut()
                .unwrap()
                .insert(path.last().unwrap().clone(), value.clone());
        }
        projected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exclusions_and_empty_allowlists_have_distinct_meaning() {
        let rule: EventFilter =
            serde_json::from_value(json!({"types":["m.*"], "not_types":["m.room.member"]}))
                .unwrap();
        assert!(rule.matches(&json!({"type":"m.room.message"})));
        assert!(!rule.matches(&json!({"type":"m.room.member"})));
        let none: EventFilter = serde_json::from_value(json!({"types":[]})).unwrap();
        assert!(!none.matches(&json!({"type":"anything"})));
        assert!(type_matches("m.*.message", "m.room.message"));
        assert!(!type_matches("m.room.[x]", "m.room.x"));
    }

    #[test]
    fn field_projection_preserves_escaped_property_names() {
        let filter: Filter =
            serde_json::from_value(json!({"event_fields":["content.m\\.relates_to", "sender"]}))
                .unwrap();
        assert_eq!(filter.project(json!({"type":"m.test", "sender":"@a:test", "content":{"m.relates_to":{"event_id":"$x"}, "secret":"hidden"}})),
            json!({"sender":"@a:test", "content":{"m.relates_to":{"event_id":"$x"}}}));
    }

    #[test]
    fn malformed_and_nonpositive_limits_are_rejected() {
        for value in [
            json!({"presence":{"limit":0}}),
            json!({"room":{"state":{"limit":-1}}}),
            json!({"room":{"timeline":{"types":"m.*"}}}),
            json!({"event_format":"unknown"}),
        ] {
            assert!(serde_json::from_value::<Filter>(value).is_err());
        }
    }
}
