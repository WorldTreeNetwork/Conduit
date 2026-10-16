//! Homeserver side of Matrix v1.19 policy servers.
//!
//! When current state names a policy server that has a joined user, every
//! event except `m.room.policy` with an empty state key is signed by that
//! server before it is persisted. A refusal is returned to the client and
//! the event is not stored. An event received over federation that still
//! lacks a valid `ed25519:policy_server` signature is stored as a soft failure.

use axum::http::StatusCode;
use axum::Json;
use base64::{engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD}, Engine as _};
use serde_json::{json, Value};

use std::sync::Arc;

use conduit::event::Event;
use conduit::signing::{server_of_user_id, verify_event_signature};
use conduit::storage::Storage;

use super::client::{Client, FederationError};
use crate::api::client::MatrixError;

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

struct EnabledPolicy {
    via: String,
    public_key: Vec<u8>,
}

/// The room's enabled policy server, or `None` when the state event is
/// absent, incomplete, or `via` has no joined user.
async fn enabled_policy(storage: &dyn Storage, room_id: &str) -> Result<Option<EnabledPolicy>, String> {
    if room_id.is_empty() {
        return Ok(None);
    }
    let policy = match storage.get_state_entry(room_id, "m.room.policy", "").await {
        Ok(Some(policy)) => policy,
        Ok(None) => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let Some((via, encoded_key)) = configured_policy(&policy.content) else {
        return Ok(None);
    };
    let Some(public_key) = decode_key(encoded_key) else {
        return Ok(None);
    };
    let via = via.to_owned();
    let joined = match storage.get_current_state(room_id).await {
        Ok(events) => events.into_iter().any(|member| {
            member.event_type == "m.room.member"
                && member.content.get("membership").and_then(Value::as_str) == Some("join")
                && member.state_key.as_deref().and_then(server_of_user_id) == Some(via.as_str())
        }),
        Err(error) => return Err(error.to_string()),
    };
    if !joined {
        return Ok(None);
    }
    Ok(Some(EnabledPolicy { via, public_key }))
}

enum AttachError {
    Remote(FederationError),
    Transport(FederationError),
    Invalid,
}

/// Ask twice. A refusal or a transport failure stops immediately. An
/// invalid signature is discarded and requested again. A valid signature
/// stays on `event`.
async fn attach_policy_signature(client: &Client, event: &mut Event, policy: &EnabledPolicy) -> Result<(), AttachError> {
    let body = serde_json::to_value(&event.pdu).map_err(|error| AttachError::Transport(FederationError::Parse(error.to_string())))?;
    for _ in 0..2 {
        match client.sign_policy_event(&policy.via, &body).await {
            Ok(signed) => {
                let saved = event.signatures.clone();
                if merge_signature(event, &policy.via, &signed)
                    && verify_event_signature(&event.pdu, &policy.via, POLICY_KEY_ID, &policy.public_key).is_ok()
                {
                    return Ok(());
                }
                event.signatures = saved;
            }
            Err(error @ FederationError::RemoteError { .. }) => return Err(AttachError::Remote(error)),
            Err(error) => return Err(AttachError::Transport(error)),
        }
    }
    Err(AttachError::Invalid)
}

/// Ask the room's policy server to sign `event` and attach
/// `ed25519:policy_server`. No-op when the room has no enabled policy server.
/// An error means the event must not be persisted.
pub async fn ensure_policy_signature(
    storage: &dyn Storage,
    client: Option<&Arc<Client>>,
    event: &mut Event,
) -> Result<(), (StatusCode, Json<MatrixError>)> {
    if exempt(event) {
        return Ok(());
    }
    let Some(policy) = enabled_policy(storage, &event.room_id)
        .await
        .map_err(|error| MatrixError::unknown(format!("storage error: {error}")))?
    else {
        return Ok(());
    };
    let Some(client) = client else {
        return Err(MatrixError::forbidden("a policy server signature is required, but federation is disabled"));
    };
    match attach_policy_signature(client, event, &policy).await {
        Ok(()) => Ok(()),
        Err(AttachError::Remote(error)) => Err(remote_refusal(&error)),
        Err(AttachError::Transport(error)) => Err(MatrixError::unknown(format!("policy server request failed: {error}"))),
        Err(AttachError::Invalid) => Err(MatrixError::forbidden("policy server signature is missing or invalid")),
    }
}

/// What a homeserver does with a PDU received over federation when the room
/// has an enabled policy server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Recommended for inclusion. A freshly checked signature may have been
    /// added to the event.
    Accept,
    /// Not recommended. Store it as a soft failure.
    SoftFail,
}

/// A valid `ed25519:policy_server` signature is enough. A missing or invalid
/// one is requested again. Refusal, an unreachable policy server, or a second
/// invalid signature is a soft failure. `m.room.policy` with an empty state
/// key is exempt.
pub async fn federated_policy_decision(
    storage: &dyn Storage,
    client: Option<&Client>,
    event: &mut Event,
) -> Result<PolicyDecision, String> {
    if exempt(event) {
        return Ok(PolicyDecision::Accept);
    }
    let Some(policy) = enabled_policy(storage, &event.room_id).await? else {
        return Ok(PolicyDecision::Accept);
    };
    if verify_event_signature(&event.pdu, &policy.via, POLICY_KEY_ID, &policy.public_key).is_ok() {
        return Ok(PolicyDecision::Accept);
    }
    let Some(client) = client else {
        return Ok(PolicyDecision::SoftFail);
    };
    match attach_policy_signature(client, event, &policy).await {
        Ok(()) => Ok(PolicyDecision::Accept),
        Err(AttachError::Remote(_) | AttachError::Transport(_) | AttachError::Invalid) => Ok(PolicyDecision::SoftFail),
    }
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
