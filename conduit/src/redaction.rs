//! Room version 11 redaction, including the signed third-party invite subset.
//!
//! <https://spec.matrix.org/v1.19/rooms/v11/#redactions>
//! Signing and reference hashing remove signatures separately. The derived
//! event ID remains local metadata; it is not part of the v11 PDU bytes.

use crate::event::Event;
use serde_json::Value;

/// Return a redacted copy, retaining essential fields and signatures.
/// All unsigned data is removed, including previous event content.
pub fn redact_event(event: &Event) -> Event {
    let mut redacted = event.clone();
    redacted.content = redact_content(&event.event_type, &event.content);
    redacted.unsigned = None;
    redacted
}

fn redact_content(event_type: &str, content: &Value) -> Value {
    // v11 protects the complete create content, including extension fields.
    if event_type == "m.room.create" {
        return content.clone();
    }
    let mut redacted = serde_json::Map::new();
    if let Some(map) = content.as_object() {
        for field in allowed_content_fields(event_type) {
            if let Some(value) = map.get(field) {
                redacted.insert(field.to_owned(), value.clone());
            }
        }
        if event_type == "m.room.member" {
            if let Some(signed) = map
                .get("third_party_invite")
                .and_then(Value::as_object)
                .and_then(|invite| invite.get("signed"))
            {
                redacted.insert(
                    "third_party_invite".into(),
                    serde_json::json!({"signed": signed}),
                );
            }
        }
    }
    Value::Object(redacted)
}

/// Flat content fields retained by v11 redaction.
/// Create events retain all content (no finite allowlist). Member events also
/// retain third_party_invite.signed through separate nested pruning.
pub fn allowed_content_fields(event_type: &str) -> Vec<&'static str> {
    match event_type {
        "m.room.member" => vec!["membership", "join_authorised_via_users_server"],
        "m.room.power_levels" => vec![
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
        "m.room.join_rules" => vec!["join_rule", "allow"],
        "m.room.history_visibility" => vec!["history_visibility"],
        "m.room.redaction" => vec!["redacts"],
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn malformed_nested_invites_do_not_leak_unprotected_fields() {
        for invite in [
            Value::Null,
            json!("invalid"),
            json!([]),
            json!({"display_name": "private"}),
        ] {
            assert_eq!(
                redact_content(
                    "m.room.member",
                    &json!({
                        "membership": "invite", "third_party_invite": invite,
                    })
                ),
                json!({"membership": "invite"})
            );
        }
    }

    #[test]
    fn pruning_does_not_mutate_original_content() {
        let original = json!({"membership": "join", "reason": "private"});
        assert_eq!(
            redact_content("m.room.member", &original),
            json!({"membership": "join"})
        );
        assert_eq!(original["reason"], "private");
    }
}
