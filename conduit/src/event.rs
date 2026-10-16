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

/// A PDU that may be put on the federation wire.
///
/// [`WirePdu::checked`] accepts a v11 reference hash. [`WirePdu::checked_for_version`]
/// accepts the id [`crate::room_version::event_id_for`] derives, which is
/// standard base64 in room version 3. A content-hash mismatch yields the v11
/// redaction; an ID mismatch yields nothing. The stored id is what emitters
/// put in the request path. Serialization is the PDU alone: room versions 3
/// and later do not carry `event_id` on the wire.
#[derive(Debug, Clone, PartialEq)]
pub struct WirePdu {
    pdu: Pdu,
    event_id: String,
}

impl Serialize for WirePdu {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.pdu.serialize(serializer)
    }
}

impl WirePdu {
    fn bundle(event_id: impl Into<String>, pdu: Pdu) -> WirePdu {
        WirePdu { pdu, event_id: event_id.into() }
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

    /// A PDU whose reference hash still equals `expected_event_id`.
    ///
    /// Used for a stored redaction: the content hash no longer matches, and
    /// running the v11 redaction again would drop fields an older room
    /// version still protects (for example `aliases` through version 5).
    pub fn retained(expected_event_id: &str, pdu: Pdu) -> Option<WirePdu> {
        match crate::hashing::event_id(&pdu) {
            Ok(derived) if derived == expected_event_id => Some(Self::bundle(expected_event_id, pdu)),
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
}
