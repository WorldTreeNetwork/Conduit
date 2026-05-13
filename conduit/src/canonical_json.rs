//! Canonical JSON serialization per the Matrix specification.
//!
//! See: <https://spec.matrix.org/latest/appendices/#canonical-json>
//!
//! Rules:
//! - UTF-8 encoding.
//! - Object keys sorted lexicographically by Unicode codepoint (raw byte
//!   order of UTF-8, which is the same as Rust `String` sort order).
//! - No insignificant whitespace outside string values.
//! - Numbers must be integers in the range `[-(2^53 - 1), 2^53 - 1]`.
//!   Fractions and out-of-range values are rejected.
//! - Strings use minimal RFC 8259 escaping: only `"`, `\`, and control
//!   characters U+0000–U+001F are escaped; all other Unicode (including
//!   non-ASCII) is emitted as literal UTF-8.

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

/// The maximum safe integer value: 2^53 - 1.
const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;
/// The minimum safe integer value: -(2^53 - 1).
const MIN_SAFE_INT: i64 = -9_007_199_254_740_991;

/// Errors that can occur during canonical JSON serialization.
#[derive(Debug, Error)]
pub enum CanonicalJsonError {
    /// A JSON number was fractional or outside the safe integer range
    /// `[-(2^53 - 1), 2^53 - 1]`.
    #[error("number out of safe integer range: {0}")]
    NumberOutOfRange(String),

    /// `serde_json` failed to convert the value to a `Value`.
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

/// Serialize `value` to canonical JSON bytes.
///
/// Keys in JSON objects are sorted lexicographically. Numbers must be
/// integers within `[-(2^53 - 1), 2^53 - 1]`; any other number returns
/// [`CanonicalJsonError::NumberOutOfRange`].
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalJsonError> {
    let json_value = serde_json::to_value(value)?;
    let mut buf = Vec::new();
    write_value(&json_value, &mut buf)?;
    Ok(buf)
}

/// Serialize `value` to a canonical JSON string.
///
/// This is a thin wrapper around [`to_canonical_bytes`] that interprets
/// the output as UTF-8 (which is always valid given the encoding rules).
pub fn to_canonical_string<T: Serialize>(value: &T) -> Result<String, CanonicalJsonError> {
    let bytes = to_canonical_bytes(value)?;
    // SAFETY: we only ever emit ASCII bytes or literal UTF-8 from the
    // original string values, so the output is always valid UTF-8.
    Ok(unsafe { String::from_utf8_unchecked(bytes) })
}

/// Recursively write a `Value` in canonical form into `buf`.
fn write_value(value: &Value, buf: &mut Vec<u8>) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null => buf.extend_from_slice(b"null"),
        Value::Bool(b) => {
            if *b {
                buf.extend_from_slice(b"true");
            } else {
                buf.extend_from_slice(b"false");
            }
        }
        Value::Number(n) => {
            // Must be an integer in the safe range.
            if let Some(i) = n.as_i64() {
                if i < MIN_SAFE_INT || i > MAX_SAFE_INT {
                    return Err(CanonicalJsonError::NumberOutOfRange(n.to_string()));
                }
                // Write the integer without any suffix or scientific notation.
                let s = i.to_string();
                buf.extend_from_slice(s.as_bytes());
            } else if let Some(u) = n.as_u64() {
                // u64 values that don't fit in i64 (i.e. > i64::MAX) are always
                // out of the safe integer range.
                if u > MAX_SAFE_INT as u64 {
                    return Err(CanonicalJsonError::NumberOutOfRange(n.to_string()));
                }
                let s = u.to_string();
                buf.extend_from_slice(s.as_bytes());
            } else {
                // Fractional or otherwise non-integer.
                return Err(CanonicalJsonError::NumberOutOfRange(n.to_string()));
            }
        }
        Value::String(s) => {
            write_string(s, buf);
        }
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_value(item, buf)?;
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            // Sort keys lexicographically (Rust String ordering == Unicode codepoint order).
            let mut pairs: Vec<(&String, &Value)> = map.iter().collect();
            pairs.sort_by(|(a, _), (b, _)| a.cmp(b));

            buf.push(b'{');
            for (i, (key, val)) in pairs.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_string(key, buf);
                buf.push(b':');
                write_value(val, buf)?;
            }
            buf.push(b'}');
        }
    }
    Ok(())
}

/// Write a JSON string value with minimal RFC 8259 escaping:
/// - `"` → `\"`
/// - `\` → `\\`
/// - U+0000–U+001F → `\uXXXX` (or short form where defined)
/// - Everything else (including non-ASCII UTF-8) is emitted verbatim.
fn write_string(s: &str, buf: &mut Vec<u8>) {
    buf.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => buf.extend_from_slice(b"\\\""),
            '\\' => buf.extend_from_slice(b"\\\\"),
            '\x08' => buf.extend_from_slice(b"\\b"),
            '\x09' => buf.extend_from_slice(b"\\t"),
            '\x0A' => buf.extend_from_slice(b"\\n"),
            '\x0C' => buf.extend_from_slice(b"\\f"),
            '\x0D' => buf.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                // Other control characters: \u00XX
                let code = c as u32;
                let hex = format!("\\u{:04x}", code);
                buf.extend_from_slice(hex.as_bytes());
            }
            c => {
                // Emit verbatim UTF-8 — no escaping for non-ASCII.
                let mut tmp = [0u8; 4];
                let encoded = c.encode_utf8(&mut tmp);
                buf.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    buf.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_object() {
        let v = json!({});
        assert_eq!(to_canonical_bytes(&v).unwrap(), b"{}");
    }

    #[test]
    fn keys_sorted() {
        // Keys "b" and "a" — should come out as a, b.
        let v = json!({ "b": 1, "a": 2 });
        assert_eq!(
            to_canonical_bytes(&v).unwrap(),
            b"{\"a\":2,\"b\":1}"
        );
    }

    #[test]
    fn nested_keys_sorted() {
        let v = json!({ "outer": { "y": 1, "x": 2 } });
        assert_eq!(
            to_canonical_bytes(&v).unwrap(),
            b"{\"outer\":{\"x\":2,\"y\":1}}"
        );
    }

    #[test]
    fn spec_example() {
        // Example from https://spec.matrix.org/latest/appendices/#canonical-json
        // The spec gives:
        //   { "b": "2", "a": 1 }  →  {"a":1,"b":"2"}
        let v = json!({ "b": "2", "a": 1 });
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            "{\"a\":1,\"b\":\"2\"}"
        );
    }

    #[test]
    fn out_of_range_integer() {
        // 2^53 is one past the max safe integer.
        let v = json!(9_007_199_254_740_992_i64);
        assert!(matches!(
            to_canonical_bytes(&v),
            Err(CanonicalJsonError::NumberOutOfRange(_))
        ));
    }

    #[test]
    fn min_out_of_range_integer() {
        // -(2^53) is one below the min safe integer.
        let v = Value::Number(serde_json::Number::from(-9_007_199_254_740_992_i64));
        assert!(matches!(
            to_canonical_bytes(&v),
            Err(CanonicalJsonError::NumberOutOfRange(_))
        ));
    }

    #[test]
    fn floating_point_rejected() {
        // serde_json represents 1.5 as a float Number.
        let v = json!(1.5_f64);
        assert!(matches!(
            to_canonical_bytes(&v),
            Err(CanonicalJsonError::NumberOutOfRange(_))
        ));
    }

    #[test]
    fn unicode_not_escaped() {
        // Non-ASCII UTF-8 must NOT be \uXXXX-escaped; bytes stay verbatim.
        let v = json!({ "msg": "héllo" });
        let result = to_canonical_string(&v).unwrap();
        assert_eq!(result, "{\"msg\":\"héllo\"}");
        // Verify the é is truly the raw UTF-8 bytes 0xC3 0xA9, not é.
        assert!(!result.contains("\\u"));
    }

    #[test]
    fn control_char_newline_escaped() {
        // \n (U+000A) must be escaped as \n.
        let v = json!({ "msg": "a\nb" });
        let result = to_canonical_string(&v).unwrap();
        assert_eq!(result, "{\"msg\":\"a\\nb\"}");
    }

    #[test]
    fn max_safe_integer_accepted() {
        let v = json!(9_007_199_254_740_991_i64);
        assert_eq!(to_canonical_string(&v).unwrap(), "9007199254740991");
    }

    #[test]
    fn min_safe_integer_accepted() {
        let v = json!(-9_007_199_254_740_991_i64);
        assert_eq!(to_canonical_string(&v).unwrap(), "-9007199254740991");
    }

    #[test]
    fn array_preserved_order() {
        // Array element order must not be changed.
        let v = json!([3, 1, 2]);
        assert_eq!(to_canonical_bytes(&v).unwrap(), b"[3,1,2]");
    }

    #[test]
    fn null_and_bool() {
        assert_eq!(to_canonical_bytes(&json!(null)).unwrap(), b"null");
        assert_eq!(to_canonical_bytes(&json!(true)).unwrap(), b"true");
        assert_eq!(to_canonical_bytes(&json!(false)).unwrap(), b"false");
    }

    #[test]
    fn backslash_and_quote_escaped() {
        let v = json!({"k": "a\"b\\c"});
        assert_eq!(
            to_canonical_string(&v).unwrap(),
            "{\"k\":\"a\\\"b\\\\c\"}"
        );
    }
}
