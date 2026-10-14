//! Room version 11 redaction, including the signed third-party invite subset.
//!
//! <https://spec.matrix.org/v1.19/rooms/v11/#redactions>
//!
//! The v11 top-level keep-list is `event_id, type, room_id, sender,
//! state_key, content, hashes, signatures, depth, prev_events, auth_events,
//! origin_server_ts`. A [`Pdu`] never carries `event_id` (v3+ wire format),
//! so redaction keeps the typed fields and clears every extension —
//! including `origin`, `membership` and `prev_state`, which "are no longer
//! protected from redaction" in v11.

use crate::event::{Event, Pdu};
use serde_json::Value;

/// Return the v11 redaction of `pdu`: typed fields kept, content pruned,
/// extensions cleared. `hashes` and `signatures` are preserved.
pub fn redact(pdu: &Pdu) -> Pdu {
    let mut redacted = pdu.clone();
    redacted.content = redact_content(&pdu.event_type, &pdu.content);
    redacted.extensions.clear();
    redacted
}

/// Redact an event's PDU and drop all of its unsigned data, keeping its ID.
pub fn redact_event(event: &Event) -> Event {
    Event {
        event_id: event.event_id.clone(),
        pdu: redact(&event.pdu),
        unsigned: None,
    }
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

    #[test]
    fn redaction_clears_every_extension_including_v10_protected_keys() {
        let mut pdu = Pdu::new(
            "!r:x", "@a:x", "m.room.member", Some("@a:x".into()),
            json!({"membership": "join"}), 1, vec![], vec![], 1,
        );
        for key in ["origin", "membership", "prev_state", "age_ts", "outlier", "destinations", "org.x"] {
            pdu.extensions.insert(key.into(), json!("v"));
        }
        let redacted = redact(&pdu);
        assert!(redacted.extensions.is_empty());
        assert_eq!(redacted.hashes, pdu.hashes);
        assert_eq!(redacted.signatures, pdu.signatures);
    }
}
