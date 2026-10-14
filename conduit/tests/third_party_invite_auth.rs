//! Room v11 auth rules for third-party invites (conduit-y99.36):
//! `m.room.third_party_invite` needs the invite power level, and an
//! `m.room.member` invite carrying `third_party_invite.signed` must be
//! signed by a key of the matching `m.room.third_party_invite` event.

use std::collections::HashMap;

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use conduit::auth::{auth_event_keys, check_auth, StateMap};
use conduit::event::Event;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};

const ROOM: &str = "!room:hs.test";
const ALICE: &str = "@alice:hs.test";
const BOB: &str = "@bob:hs.test";
const CAROL: &str = "@carol:other.test";

fn event(sender: &str, ty: &str, state_key: Option<&str>, content: Value) -> Event {
    Event {
        event_id: format!("${ty}-{}", state_key.unwrap_or("")),
        pdu: conduit::event::Pdu {
            room_id: ROOM.into(),
            sender: sender.into(),
            event_type: ty.into(),
            content,
            state_key: state_key.map(str::to_owned),
            origin_server_ts: 1,
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

fn base_state() -> StateMap<Event> {
    let mut state: StateMap<Event> = HashMap::new();
    let mut put = |e: Event| {
        state.insert((e.event_type.clone(), e.state_key.clone().unwrap()), e);
    };
    put(event(ALICE, "m.room.create", Some(""), json!({"room_version": "11"})));
    put(event(ALICE, "m.room.member", Some(ALICE), json!({"membership": "join"})));
    put(event(BOB, "m.room.member", Some(BOB), json!({"membership": "join"})));
    put(event(ALICE, "m.room.join_rules", Some(""), json!({"join_rule": "invite"})));
    put(event(ALICE, "m.room.power_levels", Some(""), json!({"users": {ALICE: 100}, "invite": 50})));
    state
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// `signed` for `mxid`/`token`, signed by `signer` the way an identity
/// server does: canonical JSON of the object without `signatures`.
fn signed(mxid: &str, token: &str, signer: &SigningKey) -> Value {
    let unsigned = json!({"mxid": mxid, "token": token});
    let bytes = conduit::canonical_json::to_canonical_bytes(&unsigned).unwrap();
    let sig = STANDARD_NO_PAD.encode(signer.sign(&bytes).to_bytes());
    json!({"mxid": mxid, "token": token, "signatures": {"id.test": {"ed25519:0": sig}}})
}

fn tpi_event(sender: &str, public_key: &str) -> Event {
    event(
        sender,
        "m.room.third_party_invite",
        Some("tok"),
        json!({
            "display_name": "c...@e...",
            "key_validity_url": "https://id.test/_matrix/identity/v2/pubkey/isvalid",
            "public_key": "unrelatedAAAA",
            "public_keys": [{"public_key": public_key}],
        }),
    )
}

fn invite(sender: &str, signed: Value) -> Event {
    event(
        sender,
        "m.room.member",
        Some(CAROL),
        json!({"membership": "invite", "third_party_invite": {"display_name": "c...@e...", "signed": signed}}),
    )
}

fn with_tpi(public_key: &str) -> StateMap<Event> {
    let mut state = base_state();
    let tpi = tpi_event(ALICE, public_key);
    state.insert(("m.room.third_party_invite".into(), "tok".into()), tpi);
    state
}

#[test]
fn third_party_invite_event_needs_invite_power() {
    let state = base_state();
    let public = STANDARD_NO_PAD.encode(key().verifying_key().to_bytes());
    assert!(check_auth(&tpi_event(ALICE, &public), &state).is_ok());
    // bob has 0 < invite level 50.
    assert!(check_auth(&tpi_event(BOB, &public), &state).is_err());
}

#[test]
fn signed_member_invite_is_accepted_with_either_base64_alphabet() {
    let k = key();
    for public in [
        STANDARD_NO_PAD.encode(k.verifying_key().to_bytes()),
        URL_SAFE_NO_PAD.encode(k.verifying_key().to_bytes()),
    ] {
        let state = with_tpi(&public);
        let ev = invite(ALICE, signed(CAROL, "tok", &k));
        assert!(
            auth_event_keys(&ev).contains(&("m.room.third_party_invite".to_owned(), "tok".to_owned())),
            "the matching third-party invite is an auth event"
        );
        assert_eq!(check_auth(&ev, &state).map_err(|e| e.to_string()), Ok(()));
    }
}

#[test]
fn signed_member_invite_rejections() {
    let k = key();
    let public = STANDARD_NO_PAD.encode(k.verifying_key().to_bytes());
    let state = with_tpi(&public);
    // Wrong signer.
    let other = SigningKey::from_bytes(&[9u8; 32]);
    assert!(check_auth(&invite(ALICE, signed(CAROL, "tok", &other)), &state).is_err());
    // mxid does not match the state_key.
    assert!(check_auth(&invite(ALICE, signed("@mallory:other.test", "tok", &k)), &state).is_err());
    // Unknown token.
    assert!(check_auth(&invite(ALICE, signed(CAROL, "other", &k)), &state).is_err());
    // Sender is not the sender of the m.room.third_party_invite.
    assert!(check_auth(&invite(BOB, signed(CAROL, "tok", &k)), &state).is_err());
    // Missing signed / tampered body.
    assert!(check_auth(&invite(ALICE, json!(null)), &state).is_err());
    let mut tampered = signed(CAROL, "tok", &k);
    tampered["extra"] = json!(1);
    assert!(check_auth(&invite(ALICE, tampered), &state).is_err());
    // Banned target.
    let mut banned = with_tpi(&public);
    banned.insert(
        ("m.room.member".into(), CAROL.into()),
        event(ALICE, "m.room.member", Some(CAROL), json!({"membership": "ban"})),
    );
    assert!(check_auth(&invite(ALICE, signed(CAROL, "tok", &k)), &banned).is_err());
}
