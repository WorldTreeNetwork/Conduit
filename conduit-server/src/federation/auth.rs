//! X-Matrix outgoing request authentication.
//!
//! Implements the signing algorithm described at:
//! <https://spec.matrix.org/latest/server-server-api/#request-authentication>
//!
//! ## Header format
//!
//! ```text
//! Authorization: X-Matrix origin="example.org",destination="other.org",key="ed25519:abc",sig="<unpadded-standard-base64>"
//! ```
//!
//! The `sig` field uses **unpadded standard base64** (not URL-safe), matching
//! the same encoding used for event signatures throughout the Matrix spec.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::Signer as _;
use serde::Serialize;
use serde_json::json;

use conduit::canonical_json::to_canonical_bytes;
use conduit::keys::ServerKey;

/// Produce the value of the `Authorization:` header for an outgoing
/// federation request.
///
/// ## Parameters
///
/// * `method`      — HTTP method in uppercase, e.g. `"GET"`, `"PUT"`.
/// * `uri`         — The request URI path + query, e.g.
///                   `"/_matrix/federation/v1/send/abc"`.
/// * `origin`      — Our server name.
/// * `destination` — The remote server name.
/// * `content`     — The request body, if any.  `None` for `GET` requests or
///                   requests with no body.
/// * `server_key`  — Our Ed25519 signing key.
///
/// ## Returns
///
/// The full `Authorization` header value, ready to set on the outgoing
/// request:
///
/// ```text
/// X-Matrix origin="...",destination="...",key="...",sig="..."
/// ```
pub fn sign_request<T: Serialize>(
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    content: Option<&T>,
    server_key: &ServerKey,
) -> String {
    // Build the object to be signed, per the spec:
    // {
    //   "method": "GET",
    //   "uri": "/_matrix/...",
    //   "origin": "example.org",
    //   "destination": "other.org",
    //   "content": <body | omitted>
    // }
    let mut obj = json!({
        "method": method,
        "uri": uri,
        "origin": origin,
        "destination": destination,
    });

    if let Some(body) = content {
        let body_value = serde_json::to_value(body)
            .expect("request body must be JSON-serializable");
        obj["content"] = body_value;
    }

    let canonical_bytes = to_canonical_bytes(&obj)
        .expect("request signing object must be canonical-JSON-serializable");

    let signature = server_key.signing_key.sign(&canonical_bytes);
    let sig_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());

    format!(
        r#"X-Matrix origin="{}",destination="{}",key="{}",sig="{}""#,
        origin, destination, server_key.key_id, sig_b64
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use base64::Engine as _;
    use conduit::keys::{generate_server_key, public_bytes};
    use ed25519_dalek::{Signature, VerifyingKey};

    /// Parse the Authorization header value and return (origin, destination, key_id, sig_b64).
    fn parse_xmatrix(header: &str) -> (String, String, String, String) {
        assert!(header.starts_with("X-Matrix "), "bad header prefix");
        let params = &header["X-Matrix ".len()..];
        let mut origin = String::new();
        let mut destination = String::new();
        let mut key = String::new();
        let mut sig = String::new();
        for part in params.split(',') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("origin=\"").and_then(|s| s.strip_suffix('"')) {
                origin = v.to_owned();
            } else if let Some(v) = part.strip_prefix("destination=\"").and_then(|s| s.strip_suffix('"')) {
                destination = v.to_owned();
            } else if let Some(v) = part.strip_prefix("key=\"").and_then(|s| s.strip_suffix('"')) {
                key = v.to_owned();
            } else if let Some(v) = part.strip_prefix("sig=\"").and_then(|s| s.strip_suffix('"')) {
                sig = v.to_owned();
            }
        }
        (origin, destination, key, sig)
    }

    #[test]
    fn xmatrix_signature_roundtrip() {
        let server_key = generate_server_key();
        let pub_bytes = public_bytes(&server_key);

        let header = sign_request::<serde_json::Value>(
            "GET",
            "/_matrix/federation/v1/version",
            "origin.example",
            "dest.example",
            None,
            &server_key,
        );

        let (origin, destination, key_id, sig_b64) = parse_xmatrix(&header);

        assert_eq!(origin, "origin.example");
        assert_eq!(destination, "dest.example");
        assert_eq!(key_id, server_key.key_id);

        // Reconstruct the signed bytes.
        let obj = json!({
            "method": "GET",
            "uri": "/_matrix/federation/v1/version",
            "origin": "origin.example",
            "destination": "dest.example",
        });
        let canonical = to_canonical_bytes(&obj).unwrap();

        // Verify signature.
        let sig_bytes = STANDARD_NO_PAD.decode(&sig_b64).expect("base64 decode sig");
        let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().expect("64 bytes");
        let signature = Signature::from_bytes(&sig_array);

        let pub_array: [u8; 32] = pub_bytes.as_slice().try_into().expect("32 bytes");
        let vk = VerifyingKey::from_bytes(&pub_array).expect("valid pubkey");
        vk.verify_strict(&canonical, &signature)
            .expect("signature must verify");
    }

    #[test]
    fn xmatrix_with_body() {
        let server_key = generate_server_key();
        let body = json!({ "pdus": [] });

        let header = sign_request(
            "PUT",
            "/_matrix/federation/v1/send/abc123",
            "my.server",
            "their.server",
            Some(&body),
            &server_key,
        );

        let (origin, destination, key_id, _sig_b64) = parse_xmatrix(&header);
        assert_eq!(origin, "my.server");
        assert_eq!(destination, "their.server");
        assert_eq!(key_id, server_key.key_id);
    }
}
