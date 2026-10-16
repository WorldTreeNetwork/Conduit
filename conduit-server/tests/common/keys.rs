//! Client-side E2EE key material for tests: device identity keys and
//! cross-signing keys signed per "Signing JSON" (conduit-y99.14).
#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

pub fn generate() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

pub fn public(key: &SigningKey) -> String {
    STANDARD_NO_PAD.encode(key.verifying_key().to_bytes())
}

/// Add `signatures[user][key_id]` over canonical JSON without
/// `signatures`/`unsigned`.
pub fn sign(object: &mut Value, user: &str, key_id: &str, key: &SigningKey) {
    let mut stripped = object.as_object().unwrap().clone();
    stripped.remove("signatures");
    stripped.remove("unsigned");
    let bytes = conduit::canonical_json::to_canonical_bytes(&Value::Object(stripped)).unwrap();
    let signature = STANDARD_NO_PAD.encode(key.sign(&bytes).to_bytes());
    if !object["signatures"].is_object() {
        object["signatures"] = json!({});
    }
    if !object["signatures"][user].is_object() {
        object["signatures"][user] = json!({});
    }
    object["signatures"][user][key_id] = json!(signature);
}

/// A device's identity: its Ed25519 signing key and self-signed `DeviceKeys`.
pub struct Device {
    pub user: String,
    pub device: String,
    pub key: SigningKey,
    pub keys: Value,
}

impl Device {
    pub fn new(user: &str, device: &str) -> Self {
        let key = generate();
        let mut keys = json!({
            "user_id": user,
            "device_id": device,
            "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
            "keys": {
                format!("curve25519:{device}"): STANDARD_NO_PAD.encode([7u8; 32]),
                format!("ed25519:{device}"): public(&key),
            },
        });
        sign(&mut keys, user, &format!("ed25519:{device}"), &key);
        Self { user: user.to_owned(), device: device.to_owned(), key, keys }
    }

    pub fn from_login(login: &Value) -> Self {
        Self::new(login["user_id"].as_str().unwrap(), login["device_id"].as_str().unwrap())
    }

    /// A `signed_curve25519` key object signed by this device.
    pub fn signed_key(&self, key: &str, fallback: bool) -> Value {
        let mut object = json!({"key": key});
        if fallback {
            object["fallback"] = json!(true);
        }
        sign(&mut object, &self.user, &format!("ed25519:{}", self.device), &self.key);
        object
    }
}

/// An unsigned `CrossSigningKey` for `usage`.
pub fn cross_signing_key(user: &str, usage: &str, key: &SigningKey) -> Value {
    json!({
        "user_id": user,
        "usage": [usage],
        "keys": {format!("ed25519:{}", public(key)): public(key)},
    })
}

/// A user's three cross-signing keys, self- and user-signing keys signed by
/// the master key.
pub struct CrossSigning {
    pub master: SigningKey,
    pub self_signing: SigningKey,
    pub user_signing: SigningKey,
    pub master_key: Value,
    pub self_signing_key: Value,
    pub user_signing_key: Value,
}

impl CrossSigning {
    pub fn new(user: &str) -> Self {
        let master = generate();
        let self_signing = generate();
        let user_signing = generate();
        let master_key = cross_signing_key(user, "master", &master);
        let master_id = format!("ed25519:{}", public(&master));
        let mut self_signing_key = cross_signing_key(user, "self_signing", &self_signing);
        sign(&mut self_signing_key, user, &master_id, &master);
        let mut user_signing_key = cross_signing_key(user, "user_signing", &user_signing);
        sign(&mut user_signing_key, user, &master_id, &master);
        Self { master, self_signing, user_signing, master_key, self_signing_key, user_signing_key }
    }

    /// A cross-signing identity whose master public key is an opaque identifier,
    /// so it can also be used as a device id.
    pub fn with_opaque_master(user: &str) -> Self {
        loop {
            let cross = Self::new(user);
            if conduit::identifiers::valid_opaque_identifier(&public(&cross.master)) {
                return cross;
            }
        }
    }

    pub fn upload_body(&self) -> Value {
        json!({
            "master_key": self.master_key,
            "self_signing_key": self.self_signing_key,
            "user_signing_key": self.user_signing_key,
        })
    }
}
