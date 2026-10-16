//! Homeserver side of Matrix v1.19 policy servers.
//!
//! When current state names a policy server that has a joined user, every
//! event except `m.room.policy` with an empty state key is signed by that
//! server before it is persisted. A refusal is returned to the client and
//! the event is not stored.

use axum::http::StatusCode;
use axum::Json;
use base64::{engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD}, Engine as _};
use serde_json::{json, Value};

use conduit::event::Event;
use conduit::signing::{server_of_user_id, verify_event_signature};

use super::client::FederationError;
use crate::api::client::{AuthState, MatrixError};

pub const POLICY_KEY_ID: &str = "ed25519:policy_server";

/// `via` and the `ed25519` public key when `content` is a usable
/// `m.room.policy`. Missing or empty required fields mean the room has
/// no policy server.
pub fn configured_policy(content: &Value) -> Option<(&str, &str)> {
    let via = content.get("via").and_then(Value::as_str).filter(|value| !value.is_empty())?;
    let public = content
        .get("public_keys")
        .and_then(|keys| keys.get("ed25519"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())?;
    Some((via, public))
}

fn exempt(event: &Event) -> bool {
    event.event_type == "m.room.policy" && event.state_key.as_deref() == Some("")
}

fn decode_key(encoded: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).or_else(|_| STANDARD_NO_PAD.decode(encoded)).ok()?;
    (bytes.len() == 32).then_some(bytes)
}

fn known_errcode(code: &str) -> &'static str {
    match code {
        "M_FORBIDDEN" => "M_FORBIDDEN",
        "M_BAD_JSON" => "M_BAD_JSON",
        "M_NOT_JSON" => "M_NOT_JSON",
        "M_NOT_FOUND" => "M_NOT_FOUND",
        "M_UNRECOGNIZED" => "M_UNRECOGNIZED",
        "M_LIMIT_EXCEEDED" => "M_LIMIT_EXCEEDED",
        _ => "M_UNKNOWN",
    }
}

fn remote_refusal(error: &FederationError) -> (StatusCode, Json<MatrixError>) {
    let FederationError::RemoteError { status, body } = error else {
        return MatrixError::unknown(format!("policy server request failed: {error}"));
    };
    let status = StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY);
    match serde_json::from_str::<Value>(body) {
        Ok(value) => {
            let errcode = known_errcode(value.get("errcode").and_then(Value::as_str).unwrap_or(""));
            let message = value.get("error").and_then(Value::as_str).unwrap_or("policy server refused the event");
            MatrixError::forwarded(status, errcode, message)
        }
        Err(_) => MatrixError::forwarded(status, "M_UNKNOWN", body.clone()),
    }
}

fn merge_signature(event: &mut Event, via: &str, body: &Value) -> bool {
    let Some(signature) = body.get(via).and_then(|entry| entry.get(POLICY_KEY_ID)).and_then(Value::as_str) else {
        return false;
    };
    if !event.signatures.is_object() {
        event.signatures = json!({});
    }
    let server = event
        .signatures
        .as_object_mut()
        .expect("signatures object")
        .entry(via.to_owned())
        .or_insert_with(|| json!({}));
    if !server.is_object() {
        *server = json!({});
    }
    server
        .as_object_mut()
        .expect("server signature object")
        .insert(POLICY_KEY_ID.to_owned(), json!(signature));
    true
}

/// Ask the room's policy server to sign `event` and attach
/// `ed25519:policy_server`. No-op when the room has no enabled policy server.
/// An error means the event must not be persisted.
pub async fn ensure_policy_signature<S: AuthState>(
    state: &S,
    event: &mut Event,
) -> Result<(), (StatusCode, Json<MatrixError>)> {
    if exempt(event) || event.room_id.is_empty() {
        return Ok(());
    }
    let storage = state.storage();
    let policy = match storage.get_state_entry(&event.room_id, "m.room.policy", "").await {
        Ok(Some(policy)) => policy,
        Ok(None) => return Ok(()),
        Err(error) => return Err(MatrixError::unknown(format!("storage error: {error}"))),
    };
    let Some((via, encoded_key)) = configured_policy(&policy.content) else {
        return Ok(());
    };
    let Some(public_key) = decode_key(encoded_key) else {
        return Ok(());
    };
    let joined = match storage.get_current_state(&event.room_id).await {
        Ok(events) => events.into_iter().any(|member| {
            member.event_type == "m.room.member"
                && member.content.get("membership").and_then(Value::as_str) == Some("join")
                && member.state_key.as_deref().and_then(server_of_user_id) == Some(via)
        }),
        Err(error) => return Err(MatrixError::unknown(format!("storage error: {error}"))),
    };
    if !joined {
        return Ok(());
    }
    let Some(client) = state.federation_client() else {
        return Err(MatrixError::forbidden("a policy server signature is required, but federation is disabled"));
    };
    let body = serde_json::to_value(&event.pdu).map_err(|error| MatrixError::unknown(format!("event encode failed: {error}")))?;
    let mut invalid = false;
    for _ in 0..2 {
        match client.sign_policy_event(via, &body).await {
            Ok(signed) => {
                if !merge_signature(event, via, &signed) {
                    invalid = true;
                    continue;
                }
                match verify_event_signature(&event.pdu, via, POLICY_KEY_ID, &public_key) {
                    Ok(()) => return Ok(()),
                    Err(_) => invalid = true,
                }
            }
            Err(error @ FederationError::RemoteError { .. }) => return Err(remote_refusal(&error)),
            Err(error) => return Err(MatrixError::unknown(format!("policy server request failed: {error}"))),
        }
    }
    let _ = invalid;
    Err(MatrixError::forbidden("policy server signature is missing or invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn policy_config_requires_via_and_ed25519() {
        assert!(configured_policy(&json!({})).is_none());
        assert!(configured_policy(&json!({"via": "policy.test"})).is_none());
        assert!(configured_policy(&json!({"via": "", "public_keys": {"ed25519": "abc"}})).is_none());
        assert_eq!(
            configured_policy(&json!({"via": "policy.test", "public_keys": {"ed25519": "abc"}})),
            Some(("policy.test", "abc"))
        );
    }
}
