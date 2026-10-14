//! Independent protocol vectors for Matrix v11.
//!
//! Rules: https://spec.matrix.org/v1.19/rooms/v11/#redactions and
//! https://spec.matrix.org/v1.19/server-server-api/#signing-events.
//! The constants below were generated with Python's JSON/SHA-256 and
//! OpenSSL 3.6 Ed25519, using the RFC 8032 test-1 seed. They do not use
//! Conduit's canonicalization, hashing, signing, or redaction code.

use conduit::event::Event;
use conduit::hashing::{content_hash, content_hash_matches, event_id};
use conduit::keys::{public_bytes, server_key_from_bytes};
use conduit::redaction::redact_event;
use conduit::signing::{sign_event, verify_event_and_hash, verify_event_signature};
use serde_json::{json, Value};

const CONTENT_HASH: &str = "G9c/FgXY1qHd5M2r5AI3RCAKzqggCtIQwIYBoKoAUY4";
const EVENT_ID: &str = "$3whi6BEjvwLUXlYehFXQrnNnSw86NcNNzmRRMroVRVc";
const SIGNATURE: &str =
    "6ndmxO0ci3v3v23HUmAz9JKbXko/YdcE4SII2TUoCsw48FgheO1sHu/qLxt2im5kYtdZFjktg58rtoSGvXVfDg";

fn message() -> Event {
    serde_json::from_value(json!({
        "event_id": "$local_metadata",
        "auth_events": ["$auth"],
        "content": {"body": "Hello, 世界", "msgtype": "m.text"},
        "depth": 2,
        "hashes": {"sha256": CONTENT_HASH},
        "origin_server_ts": 1700000000000_u64,
        "prev_events": ["$prev"],
        "room_id": "!room:example.org",
        "sender": "@alice:example.org",
        "signatures": {},
        "type": "m.room.message"
    }))
    .unwrap()
}

#[test]
fn hashes_match_independent_protocol_vector() {
    let event = message();
    assert_eq!(content_hash(&event).unwrap(), CONTENT_HASH);
    assert_eq!(event_id(&event).unwrap(), EVENT_ID);
}

#[test]
fn signature_matches_openssl_vector_and_verifies_external_signature() {
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let key = server_key_from_bytes("ed25519:vector", &seed).unwrap();
    let mut event = message();
    event.signatures = json!({"example.org": {"ed25519:vector": SIGNATURE}});
    verify_event_signature(&event, "example.org", &key.key_id, &public_bytes(&key)).unwrap();

    event.signatures = json!({});
    sign_event(&mut event, &key, "example.org").unwrap();
    assert_eq!(event.hashes["sha256"], CONTENT_HASH);
    assert_eq!(event.signatures["example.org"]["ed25519:vector"], SIGNATURE);
    event.event_id = event_id(&event).unwrap();
    assert_eq!(event.event_id, EVENT_ID);
    verify_event_signature(&event, "example.org", &key.key_id, &public_bytes(&key)).unwrap();
}

#[test]
fn content_hash_covers_message_payload_but_reference_hash_survives_redaction() {
    let original = message();
    let mut changed = original.clone();
    changed.content["body"] = json!("changed");
    assert_ne!(
        content_hash(&original).unwrap(),
        content_hash(&changed).unwrap()
    );
    assert_eq!(event_id(&original).unwrap(), event_id(&changed).unwrap());
    let redacted = redact_event(&original);
    assert_eq!(event_id(&original).unwrap(), event_id(&redacted).unwrap());
}

#[test]
fn hashes_ignore_local_id_and_ephemeral_metadata() {
    let original = message();
    let mut changed = original.clone();
    changed.event_id = "$different_local_metadata".into();
    changed.unsigned = Some(json!({"age": 999, "transaction_id": "txn"}));
    changed.signatures = json!({"another.example": {"ed25519:other": "ignored"}});
    assert_eq!(
        content_hash(&original).unwrap(),
        content_hash(&changed).unwrap()
    );
    assert_eq!(event_id(&original).unwrap(), event_id(&changed).unwrap());
}

fn redacted_content(event_type: &str, content: Value) -> Value {
    let mut event = message();
    event.event_type = event_type.into();
    event.content = content;
    redact_event(&event).content
}

#[test]
fn v11_redaction_retains_all_create_content_and_nested_invite_signature() {
    let create = json!({"room_version": "11", "m.federate": false,
        "predecessor": {"room_id": "!old:example.org", "event_id": "$old"},
        "com.example.extension": {"nested": true}});
    assert_eq!(redacted_content("m.room.create", create.clone()), create);

    let signed = json!({"mxid": "@alice:example.org", "token": "invite",
        "signatures": {"id.example": {"ed25519:key": "signature"}}});
    assert_eq!(
        redacted_content(
            "m.room.member",
            json!({
                "membership": "join", "join_authorised_via_users_server": "@bob:example.org",
                "displayname": "Alice", "avatar_url": "mxc://example.org/avatar",
                "reason": "private", "is_direct": true,
                "third_party_invite": {"display_name": "Alice", "signed": signed.clone()}
            })
        ),
        json!({"membership": "join", "join_authorised_via_users_server": "@bob:example.org",
        "third_party_invite": {"signed": signed}})
    );
}

#[test]
fn v11_redaction_protects_exact_protocol_content_fields() {
    let cases = [
        (
            "m.room.join_rules",
            json!({"join_rule": "restricted", "allow": []}),
            json!({"join_rule": "restricted", "allow": []}),
        ),
        (
            "m.room.power_levels",
            json!({"ban": 50, "events": {}, "events_default": 0,
            "invite": 50, "kick": 50, "redact": 50, "state_default": 50,
            "users": {}, "users_default": 0, "notifications": {"room": 50}}),
            json!({"ban": 50, "events": {}, "events_default": 0,
            "invite": 50, "kick": 50, "redact": 50, "state_default": 50,
            "users": {}, "users_default": 0}),
        ),
        (
            "m.room.history_visibility",
            json!({"history_visibility": "joined"}),
            json!({"history_visibility": "joined"}),
        ),
        (
            "m.room.redaction",
            json!({"redacts": "$target", "reason": "private"}),
            json!({"redacts": "$target"}),
        ),
    ];
    for (event_type, mut content, expected) in cases {
        content["com.example.extra"] = json!("discard");
        assert_eq!(
            redacted_content(event_type, content),
            expected,
            "{event_type}"
        );
    }
    for event_type in [
        "m.room.name",
        "m.room.topic",
        "m.room.avatar",
        "m.room.canonical_alias",
        "m.room.encryption",
        "m.room.server_acl",
        "m.room.tombstone",
        "m.room.third_party_invite",
        "com.example.custom",
    ] {
        assert_eq!(
            redacted_content(
                event_type,
                json!({"name": "private", "algorithm": "private"})
            ),
            json!({}),
            "{event_type}"
        );
    }
}

#[test]
fn redaction_removes_entire_unsigned_and_absent_optionals_stay_absent() {
    let mut event = message();
    let serialized = serde_json::to_value(&event).unwrap();
    assert!(serialized.get("state_key").is_none());
    assert!(serialized.get("unsigned").is_none());
    event.unsigned = Some(json!({"prev_content": {"body": "private"}, "age": 1}));
    assert!(redact_event(&event).unsigned.is_none());
    event.state_key = Some(String::new());
    assert_eq!(serde_json::to_value(&event).unwrap()["state_key"], "");
}

#[test]
fn incoming_hash_mismatch_redacts_content_after_signature_validation() {
    let key = conduit::keys::generate_server_key();
    let mut event = message();
    sign_event(&mut event, &key, "example.org").unwrap();
    let lookup = |server: &str, key_id: &str| {
        (server == "example.org" && key_id == key.key_id).then(|| public_bytes(&key))
    };
    assert_eq!(verify_event_and_hash(&event, lookup).unwrap(), event);
    event.content["body"] = json!("untrusted replacement");
    assert!(!content_hash_matches(&event).unwrap());
    let accepted = verify_event_and_hash(&event, lookup).unwrap();
    assert_eq!(accepted.content, json!({}));
    assert_eq!(accepted.hashes, event.hashes);
    assert_eq!(accepted.signatures, event.signatures);

    // Changing the signed hash fails signature validation before redaction.
    event.hashes["sha256"] = json!("forged");
    assert!(verify_event_and_hash(&event, lookup).is_err());
}

#[test]
fn content_hash_validation_accepts_padding_and_handles_invalid_hashes() {
    let mut event = message();
    assert!(content_hash_matches(&event).unwrap());
    event.hashes["sha256"] = json!(format!("{CONTENT_HASH}="));
    assert!(content_hash_matches(&event).unwrap());
    for hashes in [
        json!({}),
        json!({"sha256": "invalid!"}),
        json!({"sha256": 7}),
        json!(null),
    ] {
        event.hashes = hashes;
        assert!(!content_hash_matches(&event).unwrap());
    }
}
