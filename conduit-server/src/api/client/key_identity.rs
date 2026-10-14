//! Authenticated E2EE key identities (conduit-y99.14).
//!
//! Every key object a client publishes names its owner (`user_id`,
//! `device_id`) and is signed per "Signing JSON". The homeserver must not
//! let one device publish keys that claim another identity, and must not hand
//! out device keys that are not self-signed by the device's own Ed25519 key.
//! Cross-signing keys must carry exactly one Ed25519 public key whose key ID
//! is that key, and self-/user-signing keys must be signed by the master key.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde_json::Value;

/// A spec error: `(HTTP status, errcode, message)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError {
    pub status: u16,
    pub errcode: &'static str,
    pub message: String,
}

impl KeyError {
    fn new(status: u16, errcode: &'static str, message: impl Into<String>) -> Self {
        Self { status, errcode, message: message.into() }
    }
    pub fn bad_json(message: impl Into<String>) -> Self {
        Self::new(400, "M_BAD_JSON", message)
    }
    pub fn invalid_param(message: impl Into<String>) -> Self {
        Self::new(400, "M_INVALID_PARAM", message)
    }
    pub fn invalid_signature(message: impl Into<String>) -> Self {
        Self::new(400, "M_INVALID_SIGNATURE", message)
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(403, "M_FORBIDDEN", message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, "M_NOT_FOUND", message)
    }
    pub fn into_response(self) -> axum::response::Response {
        use axum::response::IntoResponse;
        (
            axum::http::StatusCode::from_u16(self.status).unwrap_or(axum::http::StatusCode::BAD_REQUEST),
            axum::Json(serde_json::json!({"errcode": self.errcode, "error": self.message})),
        )
            .into_response()
    }
    pub fn to_json(&self) -> Value {
        serde_json::json!({"errcode": self.errcode, "error": self.message})
    }
}

/// The bytes covered by a JSON signature: canonical JSON without
/// `signatures` and `unsigned`.
pub fn signed_bytes(object: &Value) -> Option<Vec<u8>> {
    let mut stripped = object.as_object()?.clone();
    stripped.remove("signatures");
    stripped.remove("unsigned");
    conduit::canonical_json::to_canonical_bytes(&Value::Object(stripped)).ok()
}

/// Decode an unpadded-base64 Ed25519 public key.
pub fn decode_ed25519_public(key: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let bytes = STANDARD_NO_PAD.decode(key).ok()?;
    let array: [u8; 32] = bytes.as_slice().try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&array).ok()
}

/// Verify `signatures[user_id][key_id]` over `object` with `public_key`.
pub fn verify_signature(object: &Value, user_id: &str, key_id: &str, public_key: &str) -> bool {
    let Some(signature) = object["signatures"][user_id][key_id].as_str() else {
        return false;
    };
    let (Some(verifying), Some(bytes)) = (decode_ed25519_public(public_key), signed_bytes(object)) else {
        return false;
    };
    let Some(signature) = STANDARD_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|bytes| <[u8; 64]>::try_from(bytes.as_slice()).ok())
    else {
        return false;
    };
    verifying
        .verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&signature))
        .is_ok()
}

/// The device's own Ed25519 identity key, `keys["ed25519:<device_id>"]`.
pub fn device_ed25519(keys: &Value, device_id: &str) -> Option<String> {
    keys["keys"][format!("ed25519:{device_id}")]
        .as_str()
        .map(str::to_owned)
}

/// Validate a `DeviceKeys` upload for the authenticated `(user, device)`.
/// Returns the object to persist (client `unsigned` data removed).
pub fn validate_device_keys(keys: &Value, user: &str, device: &str) -> Result<Value, KeyError> {
    let object = keys
        .as_object()
        .ok_or_else(|| KeyError::bad_json("device_keys must be an object"))?;
    match object.get("user_id").and_then(Value::as_str) {
        Some(owner) if owner == user => {}
        Some(_) => return Err(KeyError::invalid_param("device_keys.user_id does not match the authenticated user")),
        None => return Err(KeyError::bad_json("device_keys.user_id is required")),
    }
    match object.get("device_id").and_then(Value::as_str) {
        Some(id) if id == device => {}
        Some(_) => return Err(KeyError::invalid_param("device_keys.device_id does not match the authenticated device")),
        None => return Err(KeyError::bad_json("device_keys.device_id is required")),
    }
    let algorithms_valid = object
        .get("algorithms")
        .and_then(Value::as_array)
        .is_some_and(|list| list.iter().all(Value::is_string));
    if !algorithms_valid {
        return Err(KeyError::bad_json("device_keys.algorithms must be a list of strings"));
    }
    let identity = object
        .get("keys")
        .and_then(Value::as_object)
        .ok_or_else(|| KeyError::bad_json("device_keys.keys must be an object"))?;
    for (name, value) in identity {
        let Some((algorithm, key_device)) = name.split_once(':') else {
            return Err(KeyError::bad_json(format!("identity key name {name} must be <algorithm>:<device_id>")));
        };
        if algorithm.is_empty() || !value.is_string() {
            return Err(KeyError::bad_json(format!("identity key {name} is malformed")));
        }
        if key_device != device {
            return Err(KeyError::invalid_param(format!("identity key {name} names another device")));
        }
    }
    let ed25519 = device_ed25519(keys, device)
        .ok_or_else(|| KeyError::bad_json(format!("device_keys.keys must include ed25519:{device}")))?;
    if decode_ed25519_public(&ed25519).is_none() {
        return Err(KeyError::bad_json("device Ed25519 key is not a valid public key"));
    }
    if !object.get("signatures").is_some_and(Value::is_object) {
        return Err(KeyError::bad_json("device_keys.signatures is required"));
    }
    if !verify_signature(keys, user, &format!("ed25519:{device}"), &ed25519) {
        return Err(KeyError::invalid_signature("device keys must be signed by the device's own Ed25519 key"));
    }
    let mut stored = object.clone();
    stored.remove("unsigned");
    Ok(Value::Object(stored))
}

/// Is this stored device-key object one we may serve for `(user, device)`?
pub fn device_keys_are_authentic(keys: &Value, user: &str, device: &str) -> bool {
    keys["user_id"] == user
        && keys["device_id"] == device
        && device_ed25519(keys, device)
            .is_some_and(|ed25519| verify_signature(keys, user, &format!("ed25519:{device}"), &ed25519))
}

/// Validate a one-time or fallback key entry (`<algorithm>:<key_id>`).
/// String keys are unsigned (`curve25519`); object keys must carry `key`
/// and `signatures`, and verify against the device key when it is known.
pub fn validate_one_time_key(
    name: &str,
    value: &Value,
    user: &str,
    device: &str,
    ed25519: Option<&str>,
) -> Result<String, KeyError> {
    let Some((algorithm, key_id)) = name.split_once(':') else {
        return Err(KeyError::bad_json(format!("key name {name} must be <algorithm>:<key_id>")));
    };
    if algorithm.is_empty() || key_id.is_empty() {
        return Err(KeyError::bad_json(format!("key name {name} must be <algorithm>:<key_id>")));
    }
    match value {
        Value::String(_) => {}
        Value::Object(object) => {
            if !object.get("key").is_some_and(Value::is_string) || !object.get("signatures").is_some_and(Value::is_object) {
                return Err(KeyError::bad_json(format!("signed key {name} requires key and signatures")));
            }
            if let Some(ed25519) = ed25519 {
                if !verify_signature(value, user, &format!("ed25519:{device}"), ed25519) {
                    return Err(KeyError::invalid_signature(format!("key {name} is not signed by this device")));
                }
            }
        }
        _ => return Err(KeyError::bad_json(format!("key {name} must be a string or a key object"))),
    }
    Ok(algorithm.to_owned())
}

/// A validated cross-signing key: its `ed25519:<public>` key ID and public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossSigningIdentity {
    pub key_id: String,
    pub public_key: String,
}

/// Validate a `CrossSigningKey` for `user` with the required `usage`.
pub fn validate_cross_signing_key(key: &Value, user: &str, usage: &str) -> Result<CrossSigningIdentity, KeyError> {
    let object = key
        .as_object()
        .ok_or_else(|| KeyError::bad_json(format!("{usage} key must be an object")))?;
    match object.get("user_id").and_then(Value::as_str) {
        Some(owner) if owner == user => {}
        Some(_) => return Err(KeyError::invalid_param(format!("{usage} key user_id does not match the authenticated user"))),
        None => return Err(KeyError::bad_json(format!("{usage} key user_id is required"))),
    }
    let usages = object
        .get("usage")
        .and_then(Value::as_array)
        .ok_or_else(|| KeyError::bad_json(format!("{usage} key usage is required")))?;
    if !usages.iter().any(|value| value == usage) {
        return Err(KeyError::invalid_param(format!("key usage must include {usage}")));
    }
    let keys = object
        .get("keys")
        .and_then(Value::as_object)
        .ok_or_else(|| KeyError::bad_json(format!("{usage} key keys is required")))?;
    if keys.len() != 1 {
        return Err(KeyError::invalid_param(format!("{usage} key must contain exactly one public key")));
    }
    let (key_id, public) = keys.iter().next().expect("one key");
    let public = public
        .as_str()
        .ok_or_else(|| KeyError::bad_json(format!("{usage} public key must be a string")))?;
    if key_id != &format!("ed25519:{public}") || decode_ed25519_public(public).is_none() {
        return Err(KeyError::invalid_param(format!("{usage} key ID must be ed25519:<its unpadded base64 public key>")));
    }
    if object.get("signatures").is_some_and(|value| !value.is_object()) {
        return Err(KeyError::bad_json(format!("{usage} key signatures must be an object")));
    }
    Ok(CrossSigningIdentity { key_id: key_id.clone(), public_key: public.to_owned() })
}

/// Public key of a stored cross-signing key, if well formed.
pub fn cross_signing_public(key: &Value) -> Option<String> {
    let keys = key["keys"].as_object()?;
    if keys.len() != 1 {
        return None;
    }
    keys.values().next()?.as_str().map(str::to_owned)
}

/// Do two key objects agree once signatures and unsigned data are ignored?
pub fn same_signed_content(left: &Value, right: &Value) -> bool {
    matches!((signed_bytes(left), signed_bytes(right)), (Some(a), Some(b)) if a == b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn key() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    fn public(key: &SigningKey) -> String {
        STANDARD_NO_PAD.encode(key.verifying_key().to_bytes())
    }

    fn sign(object: &mut Value, user: &str, key_id: &str, key: &SigningKey) {
        let bytes = signed_bytes(object).unwrap();
        let signature = STANDARD_NO_PAD.encode(key.sign(&bytes).to_bytes());
        object["signatures"][user][key_id] = json!(signature);
    }

    fn device_keys(user: &str, device: &str, key: &SigningKey) -> Value {
        let mut keys = json!({
            "user_id": user, "device_id": device,
            "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
            "keys": {format!("ed25519:{device}"): public(key), format!("curve25519:{device}"): "Y3VydmU"},
            "signatures": {}
        });
        sign(&mut keys, user, &format!("ed25519:{device}"), key);
        keys
    }

    #[test]
    fn device_keys_must_name_and_be_signed_by_the_authenticated_device() {
        let signing = key();
        let keys = device_keys("@a:x", "DEV", &signing);
        assert!(validate_device_keys(&keys, "@a:x", "DEV").is_ok());
        assert!(device_keys_are_authentic(&keys, "@a:x", "DEV"));
        assert_eq!(validate_device_keys(&keys, "@b:x", "DEV").unwrap_err().errcode, "M_INVALID_PARAM");
        assert_eq!(validate_device_keys(&keys, "@a:x", "OTHER").unwrap_err().errcode, "M_INVALID_PARAM");
        let mut tampered = keys.clone();
        tampered["algorithms"] = json!(["m.megolm.v1.aes-sha2"]);
        assert_eq!(validate_device_keys(&tampered, "@a:x", "DEV").unwrap_err().errcode, "M_INVALID_SIGNATURE");
        assert!(!device_keys_are_authentic(&tampered, "@a:x", "DEV"));
        let foreign = device_keys("@a:x", "DEV", &key());
        let mut swapped = foreign.clone();
        swapped["keys"]["ed25519:DEV"] = json!(public(&signing));
        assert_eq!(validate_device_keys(&swapped, "@a:x", "DEV").unwrap_err().errcode, "M_INVALID_SIGNATURE");
        let mut unsigned = keys.clone();
        unsigned["signatures"] = json!({});
        assert_eq!(validate_device_keys(&unsigned, "@a:x", "DEV").unwrap_err().errcode, "M_INVALID_SIGNATURE");
    }

    #[test]
    fn cross_signing_key_ids_must_be_their_public_key() {
        let master = key();
        let valid = json!({"user_id": "@a:x", "usage": ["master"], "keys": {format!("ed25519:{}", public(&master)): public(&master)}});
        assert_eq!(validate_cross_signing_key(&valid, "@a:x", "master").unwrap().public_key, public(&master));
        assert!(validate_cross_signing_key(&valid, "@a:x", "self_signing").is_err());
        assert!(validate_cross_signing_key(&valid, "@b:x", "master").is_err());
        let mismatched = json!({"user_id": "@a:x", "usage": ["master"], "keys": {"ed25519:other": public(&master)}});
        assert!(validate_cross_signing_key(&mismatched, "@a:x", "master").is_err());
        let two = json!({"user_id": "@a:x", "usage": ["master"], "keys": {format!("ed25519:{}", public(&master)): public(&master), "ed25519:x": "x"}});
        assert!(validate_cross_signing_key(&two, "@a:x", "master").is_err());
    }

    #[test]
    fn signed_one_time_keys_verify_against_the_device_key() {
        let signing = key();
        let mut otk = json!({"key": "b3Rr"});
        sign(&mut otk, "@a:x", "ed25519:DEV", &signing);
        let ed = public(&signing);
        assert_eq!(validate_one_time_key("signed_curve25519:AAA", &otk, "@a:x", "DEV", Some(&ed)).unwrap(), "signed_curve25519");
        assert!(validate_one_time_key("signed_curve25519:AAA", &otk, "@a:x", "DEV", Some(&public(&key()))).is_err());
        assert!(validate_one_time_key("nocolon", &json!("x"), "@a:x", "DEV", None).is_err());
        assert!(validate_one_time_key("curve25519:A", &json!(5), "@a:x", "DEV", None).is_err());
        assert!(validate_one_time_key("signed_curve25519:A", &json!({"key": "x"}), "@a:x", "DEV", None).is_err());
    }
}
