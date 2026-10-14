//! Received-PDU decode: "is a valid event" for room version 11.
//!
//! Server-server API, "Checks performed on receipt of a PDU", step 1: an
//! event that does not comply with its room version's event format is
//! dropped. [`decode_pdu`] implements that check deterministically; every
//! failure is a typed [`PduDecodeError`] whose message never echoes a value
//! taken from the PDU.
//!
//! Steps, in order:
//! 1. Strip `unsigned` to the allow-list (`age`; plus `invite_room_state` and
//!    `knock_room_state` on `m.room.member`), as Synapse
//!    `_strip_unsigned_values` does. `age` becomes a local `age_ts`.
//! 2. Validate canonical JSON over the whole remaining object.
//! 3. Enforce the v11 format and limits (typed fields, list lengths, depth,
//!    65536-byte PDU, 255-byte identifiers, no U+0000 in key fields, no
//!    top-level `event_id`).
//! 4. Keep every other top-level key in [`Pdu::extensions`].
//! 5. Require that the decoded PDU re-encodes to exactly the received bytes.
//!
//! <https://spec.matrix.org/v1.19/rooms/v11/#event-format>
//! <https://spec.matrix.org/v1.19/client-server-api/#size-limits>

use serde_json::{Map, Value};
use thiserror::Error;

use crate::canonical_json::to_canonical_bytes;
use crate::event::Pdu;
use crate::signing::MAX_PDU_BYTES;

/// Largest legal `depth` (2^53 - 1), inclusive.
pub const MAX_DEPTH: i64 = 9_007_199_254_740_991;
/// v11: `auth_events` "Must contain less than or equal to 10 events".
pub const MAX_AUTH_EVENTS: usize = 10;
/// v11: `prev_events` "Must contain less than or equal to 20 events".
pub const MAX_PREV_EVENTS: usize = 20;
/// `sender`, `room_id`, `type` and `state_key`: at most 255 bytes of UTF-8.
pub const MAX_ID_BYTES: usize = 255;

/// Why a received PDU is not a valid v11 event. Messages use a fixed
/// vocabulary (variant, field name, numeric limits) and never echo values.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PduDecodeError {
    #[error("PDU is not a JSON object")]
    NotAnObject,
    #[error("PDU is not canonical JSON")]
    NonCanonical,
    #[error("PDU carries an explicit event_id, which room v11 does not allow")]
    ExplicitEventId,
    #[error("PDU field {0} is missing")]
    Missing(&'static str),
    #[error("PDU field {0} has the wrong type")]
    WrongType(&'static str),
    #[error("PDU state_key is null")]
    NullStateKey,
    #[error("PDU auth_events exceeds 10 entries")]
    TooManyAuthEvents,
    #[error("PDU prev_events exceeds 20 entries")]
    TooManyPrevEvents,
    #[error("PDU depth outside [0, 2^53-1]")]
    DepthOutOfRange,
    #[error("PDU exceeds 65536 bytes")]
    TooLarge,
    #[error("PDU field {0} exceeds 255 bytes")]
    FieldTooLong(&'static str),
    #[error("PDU field {0} contains U+0000")]
    NulInField(&'static str),
    #[error("PDU does not round-trip to identical canonical JSON")]
    NonRoundTrip,
}

/// A decoded PDU with its local, allow-listed unsigned data.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedPdu {
    pub pdu: Pdu,
    /// Allow-listed unsigned with `age` rewritten to `age_ts`.
    pub unsigned: Option<Value>,
}

const KNOWN: [&str; 11] = [
    "room_id", "sender", "type", "content", "state_key", "origin_server_ts",
    "auth_events", "prev_events", "hashes", "signatures", "depth",
];

fn string(map: &Map<String, Value>, field: &'static str) -> Result<String, PduDecodeError> {
    match map.get(field) {
        None => Err(PduDecodeError::Missing(field)),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(PduDecodeError::WrongType(field)),
    }
}

fn id_list(map: &Map<String, Value>, field: &'static str) -> Result<Vec<String>, PduDecodeError> {
    let Some(value) = map.get(field) else { return Err(PduDecodeError::Missing(field)) };
    let array = value.as_array().ok_or(PduDecodeError::WrongType(field))?;
    array
        .iter()
        .map(|v| {
            let id = v.as_str().ok_or(PduDecodeError::WrongType(field))?;
            if id.contains('\0') {
                return Err(PduDecodeError::NulInField(field));
            }
            Ok(id.to_owned())
        })
        .collect()
}

fn object(map: &Map<String, Value>, field: &'static str) -> Result<Value, PduDecodeError> {
    match map.get(field) {
        None => Err(PduDecodeError::Missing(field)),
        Some(v @ Value::Object(_)) => Ok(v.clone()),
        Some(_) => Err(PduDecodeError::WrongType(field)),
    }
}

fn check_id_field(value: &str, field: &'static str) -> Result<(), PduDecodeError> {
    if value.len() > MAX_ID_BYTES {
        return Err(PduDecodeError::FieldTooLong(field));
    }
    if value.contains('\0') {
        return Err(PduDecodeError::NulInField(field));
    }
    Ok(())
}

/// Filter remote `unsigned` to the allow-list. Returns the raw filtered
/// object (for size measurement) and the local form with `age` → `age_ts`.
fn allow_listed_unsigned(
    unsigned: Option<Value>,
    event_type: Option<&str>,
    received_ts: u64,
) -> (Option<Map<String, Value>>, Option<Value>) {
    let Some(unsigned) = unsigned else { return (None, None) };
    let Value::Object(map) = unsigned else { return (Some(Map::new()), None) };
    let member = event_type == Some("m.room.member");
    let raw: Map<String, Value> = map
        .into_iter()
        .filter(|(k, _)| k == "age" || (member && (k == "invite_room_state" || k == "knock_room_state")))
        .collect();
    let mut local = raw.clone();
    if let Some(age) = local.remove("age") {
        if let Some(age) = age.as_i64() {
            local.insert("age_ts".into(), Value::from(received_ts as i64 - age));
        }
    }
    let local = (!local.is_empty()).then_some(Value::Object(local));
    (Some(raw), local)
}

/// Decode and validate a received v11 PDU. `received_ts` (ms) converts
/// `unsigned.age` into a local `age_ts`.
pub fn decode_pdu(value: Value, received_ts: u64) -> Result<DecodedPdu, PduDecodeError> {
    let Value::Object(mut map) = value else { return Err(PduDecodeError::NotAnObject) };

    // 1. unsigned allow-list.
    let event_type_hint = map.get("type").and_then(Value::as_str).map(str::to_owned);
    let (raw_unsigned, local_unsigned) =
        allow_listed_unsigned(map.remove("unsigned"), event_type_hint.as_deref(), received_ts);

    // 2. canonical JSON over the whole remaining object (+ kept unsigned).
    let mut measured = map.clone();
    if let Some(raw) = &raw_unsigned {
        measured.insert("unsigned".into(), Value::Object(raw.clone()));
    }
    let measured_bytes = to_canonical_bytes(&measured).map_err(|_| PduDecodeError::NonCanonical)?;

    // 3. format and limits.
    if map.contains_key("event_id") {
        return Err(PduDecodeError::ExplicitEventId);
    }
    if measured_bytes.len() > MAX_PDU_BYTES {
        return Err(PduDecodeError::TooLarge);
    }
    let room_id = string(&map, "room_id")?;
    let sender = string(&map, "sender")?;
    let event_type = string(&map, "type")?;
    check_id_field(&room_id, "room_id")?;
    check_id_field(&sender, "sender")?;
    check_id_field(&event_type, "type")?;
    let state_key = match map.get("state_key") {
        None => None,
        Some(Value::Null) => return Err(PduDecodeError::NullStateKey),
        Some(Value::String(s)) => {
            check_id_field(s, "state_key")?;
            Some(s.clone())
        }
        Some(_) => return Err(PduDecodeError::WrongType("state_key")),
    };
    let content = object(&map, "content")?;
    let hashes = object(&map, "hashes")?;
    let signatures = object(&map, "signatures")?;
    let origin_server_ts = match map.get("origin_server_ts") {
        None => return Err(PduDecodeError::Missing("origin_server_ts")),
        Some(v) => v.as_u64().ok_or(PduDecodeError::WrongType("origin_server_ts"))?,
    };
    let depth = match map.get("depth") {
        None => return Err(PduDecodeError::Missing("depth")),
        Some(v) => v.as_i64().ok_or(PduDecodeError::WrongType("depth"))?,
    };
    if !(0..=MAX_DEPTH).contains(&depth) {
        return Err(PduDecodeError::DepthOutOfRange);
    }
    let auth_events = id_list(&map, "auth_events")?;
    let prev_events = id_list(&map, "prev_events")?;
    if auth_events.len() > MAX_AUTH_EVENTS {
        return Err(PduDecodeError::TooManyAuthEvents);
    }
    if prev_events.len() > MAX_PREV_EVENTS {
        return Err(PduDecodeError::TooManyPrevEvents);
    }

    // 4. extensions.
    let received = to_canonical_bytes(&map).map_err(|_| PduDecodeError::NonCanonical)?;
    for key in KNOWN {
        map.remove(key);
    }
    let pdu = Pdu {
        room_id, sender, event_type, content, state_key, origin_server_ts,
        auth_events, prev_events, hashes, signatures, depth,
        extensions: map.into_iter().collect(),
    };

    // 5. round-trip identity.
    let reencoded = to_canonical_bytes(&pdu).map_err(|_| PduDecodeError::NonRoundTrip)?;
    if reencoded != received {
        return Err(PduDecodeError::NonRoundTrip);
    }
    Ok(DecodedPdu { pdu, unsigned: local_unsigned })
}

// ---------------------------------------------------------------------------
// U+0000 helpers for storage sinks that cannot hold NUL
// ---------------------------------------------------------------------------

/// True when any string or object key inside `value` contains U+0000.
pub fn contains_nul(value: &Value) -> bool {
    match value {
        Value::String(s) => s.contains('\0'),
        Value::Array(items) => items.iter().any(contains_nul),
        Value::Object(map) => map.iter().any(|(k, v)| k.contains('\0') || contains_nul(v)),
        _ => false,
    }
}

/// A copy of `value` with U+0000 replaced by U+FFFD in every string and key.
/// For JSONB projections only; the authoritative bytes keep the NUL.
pub fn project_nul(value: &Value) -> Value {
    match value {
        Value::String(s) if s.contains('\0') => Value::String(s.replace('\0', "\u{FFFD}")),
        Value::Array(items) => Value::Array(items.iter().map(project_nul).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.replace('\0', "\u{FFFD}"), project_nul(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Drop every top-level unsigned value that contains U+0000 (unsigned is
/// unprotected: "Keys under `unsigned` can be modified by other servers").
pub fn strip_nul_unsigned(unsigned: Option<&Value>) -> Option<Value> {
    let map = unsigned?.as_object()?;
    let kept: Map<String, Value> = map
        .iter()
        .filter(|(k, v)| !k.contains('\0') && !contains_nul(v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    (!kept.is_empty()).then_some(Value::Object(kept))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base() -> Value {
        json!({
            "room_id": "!r:example.org", "sender": "@a:example.org", "type": "m.room.message",
            "content": {"body": "hi"}, "origin_server_ts": 5, "auth_events": [], "prev_events": [],
            "hashes": {"sha256": "x"}, "signatures": {}, "depth": 3,
        })
    }

    fn with(key: &str, value: Value) -> Value {
        let mut v = base();
        v[key] = value;
        v
    }

    #[test]
    fn decodes_extensions_and_unsigned_allow_list() {
        let mut v = with("org.example.ext", json!({"nested": [1, 2]}));
        v["unsigned"] = json!({"age": 10, "invite_room_state": [], "foo": 1});
        let decoded = decode_pdu(v, 100).unwrap();
        assert_eq!(decoded.pdu.extensions["org.example.ext"], json!({"nested": [1, 2]}));
        assert_eq!(decoded.unsigned, Some(json!({"age_ts": 90})));
        let mut m = with("type", json!("m.room.member"));
        m["state_key"] = json!("@a:example.org");
        m["unsigned"] = json!({"age": 1, "invite_room_state": [], "knock_room_state": [], "x": 1});
        let decoded = decode_pdu(m, 100).unwrap();
        assert_eq!(decoded.unsigned, Some(json!({"age_ts": 99, "invite_room_state": [], "knock_room_state": []})));
    }

    #[test]
    fn refuses_invalid_events() {
        let cases: Vec<(Value, PduDecodeError)> = vec![
            (with("event_id", json!("$x")), PduDecodeError::ExplicitEventId),
            (with("depth", json!(-1)), PduDecodeError::DepthOutOfRange),
            (with("depth", json!(MAX_DEPTH as u64 + 1)), PduDecodeError::NonCanonical),
            (with("depth", json!(1.5)), PduDecodeError::NonCanonical),
            (with("content", json!({"n": 9_007_199_254_740_992u64})), PduDecodeError::NonCanonical),
            (with("state_key", Value::Null), PduDecodeError::NullStateKey),
            (with("auth_events", json!(vec!["$a"; 11])), PduDecodeError::TooManyAuthEvents),
            (with("prev_events", json!(vec!["$a"; 21])), PduDecodeError::TooManyPrevEvents),
            (with("sender", json!(format!("@{}:xy", "é".repeat(126)))), PduDecodeError::FieldTooLong("sender")),
            (with("state_key", json!("a\u{0}b")), PduDecodeError::NulInField("state_key")),
            (with("prev_events", json!(["$a\u{0}"])), PduDecodeError::NulInField("prev_events")),
            (with("content", json!("not an object")), PduDecodeError::WrongType("content")),
        ];
        for (value, error) in cases {
            assert_eq!(decode_pdu(value, 0).unwrap_err(), error);
        }
    }

    #[test]
    fn depth_bounds_are_inclusive() {
        assert!(decode_pdu(with("depth", json!(0)), 0).is_ok());
        assert!(decode_pdu(with("depth", json!(MAX_DEPTH)), 0).is_ok());
    }

    #[test]
    fn field_byte_limits_count_bytes() {
        // 'é' is two bytes: 127 of them plus "@" ... ":x" lands exactly on 255/256.
        let at_limit = format!("@{}:x", "a".repeat(MAX_ID_BYTES - 3));
        assert_eq!(at_limit.len(), 255);
        assert!(decode_pdu(with("sender", json!(at_limit)), 0).is_ok());
        let over = format!("@{}:xy", "é".repeat(126));
        assert_eq!(over.len(), 256);
        assert!(decode_pdu(with("sender", json!(over)), 0).is_err());
        for field in ["room_id", "type", "state_key"] {
            assert!(decode_pdu(with(field, json!("é".repeat(127) + "a")), 0).is_ok(), "{field}");
            assert!(decode_pdu(with(field, json!("é".repeat(128))), 0).is_err(), "{field}");
        }
    }

    #[test]
    fn size_limit_is_inclusive_and_counts_unsigned() {
        let size = |v: &Value| to_canonical_bytes(v).unwrap().len();
        let mut v = with("content", json!({"body": ""}));
        let pad = MAX_PDU_BYTES - size(&v);
        v["content"]["body"] = json!("x".repeat(pad));
        assert_eq!(size(&v), MAX_PDU_BYTES);
        assert!(decode_pdu(v.clone(), 0).is_ok());
        v["content"]["body"] = json!("x".repeat(pad + 1));
        assert_eq!(decode_pdu(v.clone(), 0).unwrap_err(), PduDecodeError::TooLarge);
        v["content"]["body"] = json!("x".repeat(pad - 5));
        v["unsigned"] = json!({"age": 1});
        assert_eq!(decode_pdu(v, 0).unwrap_err(), PduDecodeError::TooLarge);
    }

    #[test]
    fn nul_in_content_is_accepted_and_preserved() {
        let decoded = decode_pdu(with("content", json!({"body": "a\u{0}b"})), 0).unwrap();
        assert_eq!(decoded.pdu.content["body"], "a\u{0}b");
        assert!(contains_nul(&decoded.pdu.content));
        assert_eq!(project_nul(&decoded.pdu.content)["body"], "a\u{FFFD}b");
    }

    #[test]
    fn messages_never_echo_values() {
        let secret = "SECRET\u{0}VALUE";
        let err = decode_pdu(with("state_key", json!(secret)), 0).unwrap_err();
        assert!(!err.to_string().contains("SECRET"));
    }
}
