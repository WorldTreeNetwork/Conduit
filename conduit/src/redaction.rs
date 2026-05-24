//! v11 room redaction engine.
//!
//! Per the Matrix v11 spec (<https://spec.matrix.org/latest/rooms/v11/>):
//! A redacted event keeps only a fixed set of top-level fields plus
//! event-type-specific allowed content fields. All other fields are
//! stripped — most notably `signatures` (handled separately by the
//! signing module) and `unsigned.content`.

use serde_json::Value;

use crate::event::Event;

/// Redact an event per the v11 room version specification.
///
/// Returns a **new** `Event` with only the allowed fields retained:
///
/// **Always-kept top-level fields:**
/// `event_id`, `room_id`, `sender`, `origin_server_ts`, `type`,
/// `state_key`, `hashes`, `depth`, `prev_events`, `auth_events`,
/// `unsigned`.
///
/// Within `unsigned`, the `content` sub-field is stripped (but other
/// fields like `age`, `transaction_id`, `redacted_because`,
/// `prev_content`, `invite_room_state` are kept).
///
/// **Per-event-type content fields:** see [`allowed_content_fields`].
pub fn redact_event(event: &Event) -> Event {
    let mut redacted = event.clone();

    // Strip content to only the allowed fields for this event type.
    redacted.content = redact_content(&redacted.event_type, &redacted.content);

    // Strip `unsigned.content` if present.
    if let Some(unsigned_val) = redacted.unsigned.as_mut() {
        if let Some(map) = unsigned_val.as_object_mut() {
            map.remove("content");
            // If unsigned is now empty, set it to None (matching the
            // spirit of the spec: an empty object is fine to keep).
        }
    }

    redacted
}

/// Redact the `content` field of an event per its `event_type`.
///
/// For known event types (m.room.*) only the allowed fields are kept.
/// For unknown types, content becomes an empty object `{}`.
fn redact_content(event_type: &str, content: &Value) -> Value {
    let allowed = allowed_content_fields(event_type);
    if allowed.is_empty() {
        return serde_json::json!({});
    }

    let mut redacted = serde_json::Map::new();
    if let Some(map) = content.as_object() {
        for field in allowed {
            if let Some(val) = map.get(field) {
                redacted.insert(field.to_string(), val.clone());
            }
        }
    }
    Value::Object(redacted)
}

/// Return the list of allowed content field names for a given event type.
///
/// Used by both [`redact_content`] and tests.
pub fn allowed_content_fields(event_type: &str) -> Vec<&'static str> {
    match event_type {
        "m.room.create" => vec!["creator", "room_version", "predecessor"],
        "m.room.member" => vec![
            "membership",
            "displayname",
            "avatar_url",
            "is_direct",
            "reason",
        ],
        "m.room.power_levels" => vec![
            "ban",
            "kick",
            "redact",
            "invite",
            "events_default",
            "state_default",
            "users_default",
            "events",
            "users",
            "notifications",
        ],
        "m.room.join_rules" => vec!["join_rule", "allow"],
        "m.room.history_visibility" => vec!["history_visibility"],
        "m.room.name" => vec!["name"],
        "m.room.topic" => vec!["topic"],
        "m.room.avatar" => vec!["url"],
        "m.room.canonical_alias" => vec!["alias", "alt_aliases"],
        "m.room.encryption" => vec!["algorithm", "rotation_period_ms", "rotation_period_msgs"],
        "m.room.server_acl" => vec!["allow", "deny", "allow_ip_literals"],
        "m.room.tombstone" => vec!["body", "replacement_room"],
        "m.room.third_party_invite" => vec![
            "display_name",
            "key_validity_url",
            "public_key",
            "public_key_algorithm",
        ],
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a minimal event for redaction testing.
    fn make_event() -> Event {
        Event {
            event_id: "$test_event_id".to_string(),
            room_id: "!room:example.org".to_string(),
            sender: "@user:example.org".to_string(),
            event_type: "m.room.message".to_string(),
            content: json!({ "msgtype": "m.text", "body": "Hello" }),
            state_key: None,
            origin_server_ts: 1_000_000,
            auth_events: vec!["$auth1".to_string()],
            prev_events: vec!["$prev1".to_string()],
            hashes: json!({ "sha256": "AAAA" }),
            signatures: json!({}),
            depth: 42,
            unsigned: Some(json!({ "age": 100, "transaction_id": "txn1" })),
        }
    }

    /// Non-state events (m.room.message) should have their content redacted
    /// to `{}` while keeping all allowed top-level fields.
    #[test]
    fn redact_non_state_message() {
        let event = make_event();
        let redacted = redact_event(&event);

        // Content must be empty.
        assert_eq!(redacted.content, json!({}));

        // Top-level fields that must be preserved.
        assert_eq!(redacted.event_id, "$test_event_id");
        assert_eq!(redacted.room_id, "!room:example.org");
        assert_eq!(redacted.sender, "@user:example.org");
        assert_eq!(redacted.event_type, "m.room.message");
        assert_eq!(redacted.origin_server_ts, 1_000_000);
        assert_eq!(redacted.state_key, None);
        assert_eq!(redacted.hashes, json!({ "sha256": "AAAA" }));
        assert_eq!(redacted.depth, 42);
        assert_eq!(redacted.prev_events, vec!["$prev1".to_string()]);
        assert_eq!(redacted.auth_events, vec!["$auth1".to_string()]);

        // unsigned must be kept (but unsigned.content stripped — none in this case).
        assert_eq!(
            redacted.unsigned,
            Some(json!({ "age": 100, "transaction_id": "txn1" }))
        );
    }

    /// m.room.member must keep `membership`, `displayname`, `avatar_url`,
    /// `is_direct`, `reason` in content. Other fields are stripped.
    #[test]
    fn redact_member_keeps_allowed_fields() {
        let event = Event {
            event_type: "m.room.member".to_string(),
            content: json!({
                "membership": "join",
                "displayname": "Alice",
                "avatar_url": "mxc://example.org/abc123",
                "is_direct": true,
                "reason": "welcome",
                "extra_field": "should_be_stripped",
                "another_extra": 42,
            }),
            ..make_event()
        };
        let redacted = redact_event(&event);

        assert_eq!(
            redacted.content,
            json!({
                "membership": "join",
                "displayname": "Alice",
                "avatar_url": "mxc://example.org/abc123",
                "is_direct": true,
                "reason": "welcome",
            })
        );
        // Extra fields must be gone.
        assert!(redacted.content.get("extra_field").is_none());
        assert!(redacted.content.get("another_extra").is_none());
    }

    /// m.room.create must keep `creator` and `room_version` in content.
    #[test]
    fn redact_create_keeps_allowed_fields() {
        let event = Event {
            event_type: "m.room.create".to_string(),
            content: json!({
                "creator": "@admin:example.org",
                "room_version": "11",
                "predecessor": { "room_id": "!old:example.org", "event_id": "$old" },
                "extra": "should_be_stripped",
            }),
            ..make_event()
        };
        let redacted = redact_event(&event);

        assert_eq!(
            redacted.content,
            json!({
                "creator": "@admin:example.org",
                "room_version": "11",
                "predecessor": { "room_id": "!old:example.org", "event_id": "$old" },
            })
        );
        assert!(redacted.content.get("extra").is_none());
    }

    /// unsigned.content must be stripped.
    #[test]
    fn redact_strips_unsigned_content() {
        let event = Event {
            unsigned: Some(json!({
                "age": 42,
                "transaction_id": "txn-abc",
                "content": { "msgtype": "m.text", "body": "SHOULD_BE_REMOVED" },
                "redacted_because": { "event_id": "$redaction" },
            })),
            ..make_event()
        };
        let redacted = redact_event(&event);

        let unsigned = redacted.unsigned.expect("unsigned should be present");
        // age, transaction_id, redacted_because must be kept.
        assert_eq!(unsigned.get("age"), Some(&json!(42)));
        assert_eq!(unsigned.get("transaction_id"), Some(&json!("txn-abc")));
        assert_eq!(
            unsigned.get("redacted_because"),
            Some(&json!({ "event_id": "$redaction" }))
        );
        // unsigned.content must be gone.
        assert!(
            unsigned.get("content").is_none(),
            "unsigned.content must be stripped"
        );
    }

    /// Unknown event types must have content become empty object {}.
    #[test]
    fn redact_unknown_type_empties_content() {
        let event = Event {
            event_type: "com.example.custom".to_string(),
            content: json!({ "anything": "value", "nested": { "a": 1 } }),
            ..make_event()
        };
        let redacted = redact_event(&event);
        assert_eq!(redacted.content, json!({}));
    }

    /// event_type matching is by the full type string.
    #[test]
    fn allowed_fields_are_correct() {
        assert_eq!(
            allowed_content_fields("m.room.create"),
            vec!["creator", "room_version", "predecessor"]
        );
        assert_eq!(
            allowed_content_fields("m.room.member"),
            vec!["membership", "displayname", "avatar_url", "is_direct", "reason"]
        );
        assert_eq!(
            allowed_content_fields("m.room.power_levels"),
            vec![
                "ban", "kick", "redact", "invite", "events_default",
                "state_default", "users_default", "events", "users",
                "notifications"
            ]
        );
        assert_eq!(
            allowed_content_fields("m.room.join_rules"),
            vec!["join_rule", "allow"]
        );
        assert_eq!(
            allowed_content_fields("m.room.history_visibility"),
            vec!["history_visibility"]
        );
        assert_eq!(allowed_content_fields("m.room.name"), vec!["name"]);
        assert_eq!(allowed_content_fields("m.room.topic"), vec!["topic"]);
        assert_eq!(allowed_content_fields("m.room.avatar"), vec!["url"]);
        assert_eq!(
            allowed_content_fields("m.room.canonical_alias"),
            vec!["alias", "alt_aliases"]
        );
        assert_eq!(
            allowed_content_fields("m.room.encryption"),
            vec!["algorithm", "rotation_period_ms", "rotation_period_msgs"]
        );
        assert_eq!(
            allowed_content_fields("m.room.server_acl"),
            vec!["allow", "deny", "allow_ip_literals"]
        );
        assert_eq!(
            allowed_content_fields("m.room.tombstone"),
            vec!["body", "replacement_room"]
        );
        assert_eq!(
            allowed_content_fields("m.room.third_party_invite"),
            vec![
                "display_name",
                "key_validity_url",
                "public_key",
                "public_key_algorithm"
            ]
        );
        assert!(allowed_content_fields("m.room.message").is_empty());
        assert!(allowed_content_fields("com.example.unknown").is_empty());
    }

    /// Redacting modifies only content and unsigned.content;
    /// signatures and unsigned (non-content) must be preserved.
    #[test]
    fn redact_preserves_signatures() {
        let event = Event {
            signatures: json!({ "example.org": { "ed25519:k1": "SIG" } }),
            ..make_event()
        };
        let redacted = redact_event(&event);
        assert_eq!(
            redacted.signatures,
            json!({ "example.org": { "ed25519:k1": "SIG" } })
        );
    }
}
