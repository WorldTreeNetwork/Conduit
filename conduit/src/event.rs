//! Matrix room events: the wire PDU and the locally identified event.
//!
//! - [`Pdu`] is the room-version-11 federation format. It has no
//!   `event_id` (room v3+: "When events are sent over federation, the
//!   `event_id` field is no longer included") and keeps every unknown
//!   top-level key in [`Pdu::extensions`], so content hashes survive storage.
//! - [`Event`] is `{event_id, pdu, unsigned}`. The ID is always derived from
//!   the PDU's reference hash, never read from the wire. Client-facing and
//!   legacy snapshots serialise it in the flattened layout.
//! - [`WirePdu`] is the only type federation emitters accept. Its single
//!   constructor, [`WirePdu::checked`], re-derives the ID and content hash, so
//!   nothing reaches the wire without passing the integrity gate.
//!
//! <https://spec.matrix.org/v1.19/rooms/v11/#event-format>

use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A room-version-11 PDU exactly as it travels over federation.
///
/// `unsigned` is deliberately absent: it is unprotected local metadata and
/// lives on [`Event`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Pdu {
    /// Empty on a room-version-12 `m.room.create` event, which omits `room_id`.
    /// The room id is then the event id with `!` in place of `$`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub room_id: String,
    pub sender: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub content: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_key: Option<String>,
    pub origin_server_ts: u64,
    /// Event IDs of events required for this event to be valid.
    pub auth_events: Vec<String>,
    /// Event IDs of the most recent events in the room at the time this was sent.
    pub prev_events: Vec<String>,
    /// Content hashes of the PDU, e.g. `{ "sha256": "..." }`. Defaults to
    /// `{}` when deserialising an unsigned template (`make_join`).
    #[serde(default = "empty_object")]
    pub hashes: Value,
    /// Server signatures over the redacted PDU.
    #[serde(default = "empty_object")]
    pub signatures: Value,
    /// Topological ordering depth within the room DAG.
    pub depth: i64,
    /// Every other top-level key, verbatim. Covered by the content hash,
    /// cleared by v11 redaction.
    #[serde(flatten, default)]
    pub extensions: BTreeMap<String, Value>,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

impl Pdu {
    /// A Pdu template with empty hashes/signatures and no extensions.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        room_id: impl Into<String>,
        sender: impl Into<String>,
        event_type: impl Into<String>,
        state_key: Option<String>,
        content: Value,
        origin_server_ts: u64,
        auth_events: Vec<String>,
        prev_events: Vec<String>,
        depth: i64,
    ) -> Self {
        Pdu {
            room_id: room_id.into(),
            sender: sender.into(),
            event_type: event_type.into(),
            content,
            state_key,
            origin_server_ts,
            auth_events,
            prev_events,
            hashes: Value::Object(Default::default()),
            signatures: Value::Object(Default::default()),
            depth,
            extensions: BTreeMap::new(),
        }
    }
}

/// A room event with its locally derived ID.
///
/// Serialises in the legacy flattened layout (`event_id` beside the PDU
/// fields, plus `unsigned`). That layout is for client-facing snapshots and
/// read-only legacy storage; it never goes over federation.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Event {
    pub event_id: String,
    #[serde(flatten)]
    pub pdu: Pdu,
    /// Local, unprotected data (e.g. `age_ts`, `invite_room_state`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<Value>,
}

impl Event {
    pub fn new(event_id: impl Into<String>, pdu: Pdu) -> Self {
        Event { event_id: event_id.into(), pdu, unsigned: None }
    }

    pub fn with_unsigned(mut self, unsigned: Option<Value>) -> Self {
        self.unsigned = unsigned;
        self
    }
}

impl Deref for Event {
    type Target = Pdu;
    fn deref(&self) -> &Pdu {
        &self.pdu
    }
}

impl DerefMut for Event {
    fn deref_mut(&mut self) -> &mut Pdu {
        &mut self.pdu
    }
}

/// Servers that produced a valid, eligible signature on a received PDU.
pub type SignedBy = BTreeSet<String>;

/// Whether stored or queued bytes reproduce their saved event ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegrityClass {
    /// The reference hash equals the saved ID and the content hash matches.
    Verified,
    /// The ID matches but the content hash does not: lost extensions, or a
    /// copy that was redacted on receipt. Served only as its redaction.
    ContentMismatch,
    /// An accepted redaction replaced the content. Hashes and signatures are
    /// the originals. Served as the stored bytes, not re-redacted as v11.
    Redacted,
    /// The reference hash differs from the saved ID. Never served.
    IdMismatch,
}

impl IntegrityClass {
    pub fn as_str(self) -> &'static str {
        match self {
            IntegrityClass::Verified => "verified",
            IntegrityClass::ContentMismatch => "content_mismatch",
            IntegrityClass::Redacted => "redacted",
            IntegrityClass::IdMismatch => "id_mismatch",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "verified" => Some(IntegrityClass::Verified),
            "content_mismatch" => Some(IntegrityClass::ContentMismatch),
            "redacted" => Some(IntegrityClass::Redacted),
            "id_mismatch" => Some(IntegrityClass::IdMismatch),
            _ => None,
        }
    }
}

/// Classify `pdu` against the ID it is stored or queued under.
pub fn classify(saved_event_id: &str, pdu: &Pdu) -> IntegrityClass {
    match crate::hashing::event_id(pdu) {
        Ok(derived) if derived == saved_event_id => {
            if crate::hashing::content_hash_matches(pdu).unwrap_or(false) {
                IntegrityClass::Verified
            } else {
                IntegrityClass::ContentMismatch
            }
        }
        _ => IntegrityClass::IdMismatch,
    }
}

/// Extension that holds the signed room-version-1 or 2 JSON.
///
/// The PDU projection cannot represent tuple `auth_events`. Client responses
/// omit extensions, so the document stays off the client wire.
pub const LEGACY_EVENT_DOCUMENT: &str = "io.conduit.v1_event";

/// A PDU that may be put on the federation wire.
///
/// [`WirePdu::checked`] accepts a v11 reference hash. [`WirePdu::checked_for_version`]
/// accepts the id [`crate::room_version::event_id_for`] derives, which is
/// standard base64 in room version 3. A content-hash mismatch yields the v11
/// redaction; an ID mismatch yields nothing. Room versions 1 and 2 have no
/// derived id; [`WirePdu::stored_legacy`] serves the signed document, which
/// still carries `event_id` and tuple `auth_events`. Versions 3 and later
/// serialize the PDU alone.
#[derive(Debug, Clone, PartialEq)]
pub struct WirePdu {
    pdu: Pdu,
    event_id: String,
    /// Present for room versions 1 and 2. Serialization emits this document.
    legacy: Option<Value>,
}

impl Serialize for WirePdu {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.legacy {
            Some(document) => document.serialize(serializer),
            None => self.pdu.serialize(serializer),
        }
    }
}

impl WirePdu {
    fn bundle(event_id: impl Into<String>, pdu: Pdu) -> WirePdu {
        WirePdu { pdu, event_id: event_id.into(), legacy: None }
    }

    /// A room-version-1 or 2 document. `event_id` is `$opaque:server`, and
    /// `auth_events` / `prev_events` are tuples. Serialization is `document`.
    pub fn from_legacy_document(document: Value) -> Option<WirePdu> {
        let expected = document.get("event_id").and_then(Value::as_str)?.to_owned();
        let decoded = crate::wire::decode_v1_pdu(document.clone(), 0).ok()?;
        let event_id = decoded.explicit_event_id?;
        if event_id != expected {
            return None;
        }
        Some(WirePdu { pdu: decoded.pdu, event_id, legacy: Some(document) })
    }

    /// The signed document stored beside a room-version-1 or 2 PDU.
    pub fn stored_legacy(event_id: &str, pdu: Pdu) -> Option<WirePdu> {
        let raw = pdu.extensions.get(LEGACY_EVENT_DOCUMENT).and_then(Value::as_str)?;
        let document: Value = serde_json::from_str(raw).ok()?;
        let wire = Self::from_legacy_document(document)?;
        (wire.event_id() == event_id).then_some(wire)
    }

    pub fn checked(expected_event_id: &str, pdu: Pdu) -> Option<WirePdu> {
        Self::checked_with_class(expected_event_id, pdu).map(|(wire, _)| wire)
    }

    /// Like [`WirePdu::checked`], also returning the classification.
    pub fn checked_with_class(expected_event_id: &str, pdu: Pdu) -> Option<(WirePdu, IntegrityClass)> {
        match classify(expected_event_id, &pdu) {
            IntegrityClass::Verified => Some((Self::bundle(expected_event_id, pdu), IntegrityClass::Verified)),
            IntegrityClass::ContentMismatch => Some((
                Self::bundle(expected_event_id, crate::redaction::redact(&pdu)),
                IntegrityClass::ContentMismatch,
            )),
            IntegrityClass::Redacted => Some((Self::bundle(expected_event_id, pdu), IntegrityClass::Redacted)),
            IntegrityClass::IdMismatch => None,
        }
    }

    /// An authored PDU whose reference hash is the one `version` defines.
    ///
    /// Room version 3 uses standard base64. Versions 4 and later use URL-safe
    /// base64, with the version's own redaction. Versions 1 and 2 have no
    /// derived id.
    pub fn checked_for_version(version: u32, pdu: Pdu) -> Option<WirePdu> {
        let event_id = crate::room_version::event_id_for(&pdu, version).ok().flatten()?;
        if !crate::hashing::content_hash_matches(&pdu).unwrap_or(false) {
            return None;
        }
        Some(Self::bundle(event_id, pdu))
    }

    /// A PDU whose v11 reference hash still equals `expected_event_id`.
    ///
    /// Room versions 3–10 use [`WirePdu::retained_for_version`]: their
    /// reference hash keeps fields v11 redaction removes.
    pub fn retained(expected_event_id: &str, pdu: Pdu) -> Option<WirePdu> {
        Self::retained_for_version(11, expected_event_id, pdu)
    }

    /// A stored redaction whose reference hash for `version` still equals
    /// `expected_event_id`. The content hash no longer matches, and running
    /// a different version's redaction would drop fields this version still
    /// protects (for example `aliases` through version 5). Versions 1 and 2
    /// have no derived id; the stored bytes are the event.
    pub fn retained_for_version(version: u32, expected_event_id: &str, pdu: Pdu) -> Option<WirePdu> {
        if version < 3 {
            return Some(Self::bundle(expected_event_id, pdu));
        }
        match crate::room_version::event_id_for(&pdu, version) {
            Ok(Some(derived)) if derived == expected_event_id => Some(Self::bundle(expected_event_id, pdu)),
            _ => None,
        }
    }

    pub fn pdu(&self) -> &Pdu {
        &self.pdu
    }

    pub fn into_pdu(self) -> Pdu {
        self.pdu
    }

    /// The event id this PDU was admitted under.
    pub fn event_id(&self) -> String {
        self.event_id.clone()
    }
}

impl Deref for WirePdu {
    type Target = Pdu;
    fn deref(&self) -> &Pdu {
        &self.pdu
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pdu() -> Pdu {
        let mut pdu = Pdu::new(
            "!r:example.org", "@a:example.org", "m.room.message", None,
            json!({"body": "hi"}), 1, vec![], vec![], 1,
        );
        pdu.extensions.insert("org.example.extra".into(), json!({"k": 1}));
        pdu
    }

    #[test]
    fn event_serialises_flattened_with_extensions() {
        let event = Event::new("$x", pdu()).with_unsigned(Some(json!({"age_ts": 3})));
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["event_id"], "$x");
        assert_eq!(value["org.example.extra"], json!({"k": 1}));
        assert_eq!(value["unsigned"], json!({"age_ts": 3}));
        let back: Event = serde_json::from_value(value).unwrap();
        assert_eq!(back, event);
        assert!(!back.extensions.contains_key("event_id"));
        assert!(!back.extensions.contains_key("unsigned"));
    }

    #[test]
    fn wire_pdu_has_no_event_id_or_unsigned() {
        let pdu = pdu();
        let id = crate::hashing::event_id(&pdu).unwrap();
        // Unsigned PDU has no content hash, so it is classed as a content mismatch.
        let wire = WirePdu::checked(&id, pdu).expect("id matches");
        let value = serde_json::to_value(&wire).unwrap();
        assert!(value.get("event_id").is_none());
        assert!(value.get("unsigned").is_none());
        assert!(WirePdu::checked("$other", wire.into_pdu()).is_none());
    }

    #[test]
    fn redacted_room_version_5_keeps_aliases_under_its_own_event_id() {
        use crate::keys::generate_server_key;
        use crate::signing::sign_authored_for_version;

        let key = generate_server_key();
        let mut pdu = Pdu::new(
            "!r:example.org",
            "@a:example.org",
            "m.room.aliases",
            Some("example.org".into()),
            json!({"aliases": ["#kept:example.org"], "note": "drop-me"}),
            5,
            vec![],
            vec![],
            1,
        );
        pdu.extensions.insert("origin".into(), json!("example.org"));
        sign_authored_for_version(&mut pdu, 5, &key, "example.org").unwrap();
        let id = crate::room_version::event_id_for(&pdu, 5).unwrap().unwrap();
        assert_ne!(crate::hashing::event_id(&pdu).unwrap(), id);
        let pruned = crate::room_version::redact_pdu(&pdu, 5);
        assert_eq!(pruned.content["aliases"], json!(["#kept:example.org"]));
        assert!(pruned.content.get("note").is_none());
        assert!(WirePdu::retained(&id, pruned.clone()).is_none());
        let wire = WirePdu::retained_for_version(5, &id, pruned).expect("version 5 id");
        assert_eq!(wire.event_id(), id);
        assert_eq!(wire.pdu().content["aliases"], json!(["#kept:example.org"]));
    }

    #[test]
    fn legacy_wire_keeps_event_id_and_tuple_references() {
        let document = json!({
            "auth_events": [],
            "content": {"body": "hi"},
            "depth": 1,
            "event_id": "$abc:example.org",
            "hashes": {"sha256": "aaaa"},
            "origin": "example.org",
            "origin_server_ts": 1,
            "prev_events": [["$prev:example.org", {"sha256": "bbbb"}]],
            "room_id": "!r:example.org",
            "sender": "@a:example.org",
            "signatures": {"example.org": {"ed25519:0": "cccc"}},
            "type": "m.room.message"
        });
        let wire = WirePdu::from_legacy_document(document.clone()).expect("v1 document");
        let sent = serde_json::to_value(&wire).unwrap();
        assert_eq!(sent["event_id"], "$abc:example.org");
        assert!(sent["prev_events"][0].is_array());
        assert!(sent.get(LEGACY_EVENT_DOCUMENT).is_none());
        let mut stored = wire.pdu().clone();
        stored.extensions.insert(LEGACY_EVENT_DOCUMENT.into(), json!(document.to_string()));
        let again = WirePdu::stored_legacy("$abc:example.org", stored.clone()).expect("stored document");
        assert_eq!(serde_json::to_value(&again).unwrap()["event_id"], "$abc:example.org");
        assert!(WirePdu::stored_legacy("$other:example.org", stored).is_none());
    }
}
