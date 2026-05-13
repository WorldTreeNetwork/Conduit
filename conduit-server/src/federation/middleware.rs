//! X-Matrix inbound request authentication middleware (x2r.1).
//!
//! Implements the server-server request authentication described at:
//! <https://spec.matrix.org/latest/server-server-api/#request-authentication>
//!
//! ## How it works
//!
//! 1. Parse `Authorization: X-Matrix origin="...",destination="...",key="...",sig="..."`.
//! 2. Verify `destination` matches our `server_name` — else 401.
//! 3. Fetch origin's public key for `key_id` via `RemoteKeyCache::get_or_fetch`.
//! 4. Build canonical-JSON of `{method, uri, origin, destination, content?}`.
//! 5. Verify the Ed25519 signature with dalek.
//! 6. On success, insert `FederationOrigin` into request extensions and pass through.
//! 7. On failure, return `{"errcode":"M_UNAUTHORIZED","error":"..."}` 401.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::json;

use conduit::canonical_json::to_canonical_bytes;

use crate::RemoteKeyCache;

// ---------------------------------------------------------------------------
// Extension type injected by this middleware
// ---------------------------------------------------------------------------

/// Carries the verified origin server name through axum extensions.
#[derive(Clone, Debug)]
pub struct FederationOrigin {
    pub server_name: String,
}

// ---------------------------------------------------------------------------
// Middleware state
// ---------------------------------------------------------------------------

/// State passed to the middleware function.
#[derive(Clone)]
pub struct XMatrixMiddlewareState {
    pub server_name: Arc<str>,
    pub remote_keys: Arc<RemoteKeyCache>,
    pub http: reqwest::Client,
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "errcode": "M_UNAUTHORIZED", "error": msg })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Header parser
// ---------------------------------------------------------------------------

/// Parsed fields from `Authorization: X-Matrix ...`.
struct XMatrixAuth {
    origin: String,
    destination: String,
    key_id: String,
    sig_b64: String,
}

/// Parse the `X-Matrix` Authorization header value.
///
/// Format (per spec):
/// ```text
/// X-Matrix origin="example.org",destination="other.org",key="ed25519:abc",sig="..."
/// ```
fn parse_xmatrix_header(value: &str) -> Option<XMatrixAuth> {
    let rest = value.strip_prefix("X-Matrix ")?;
    let mut origin = None::<String>;
    let mut destination = None::<String>;
    let mut key_id = None::<String>;
    let mut sig_b64 = None::<String>;

    for part in rest.split(',') {
        let part = part.trim();
        if let Some(v) = extract_quoted(part, "origin") {
            origin = Some(v);
        } else if let Some(v) = extract_quoted(part, "destination") {
            destination = Some(v);
        } else if let Some(v) = extract_quoted(part, "key") {
            key_id = Some(v);
        } else if let Some(v) = extract_quoted(part, "sig") {
            sig_b64 = Some(v);
        }
    }

    Some(XMatrixAuth {
        origin: origin?,
        destination: destination?,
        key_id: key_id?,
        sig_b64: sig_b64?,
    })
}

fn extract_quoted(s: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=\"", key);
    let inner = s.strip_prefix(&prefix)?.strip_suffix('"')?;
    Some(inner.to_owned())
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// axum middleware that verifies the `X-Matrix` Authorization header on every
/// inbound federation request.
///
/// On success, inserts [`FederationOrigin`] into request extensions.
/// On failure, returns 401 with a Matrix-spec error body.
pub async fn verify_xmatrix(
    state: axum::extract::State<XMatrixMiddlewareState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // --- 1. Extract Authorization header ------------------------------------
    let auth_value = match req.headers().get("authorization") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => return unauthorized("Authorization header is not valid UTF-8"),
        },
        None => return unauthorized("Missing Authorization header"),
    };

    // --- 2. Parse X-Matrix fields -------------------------------------------
    let auth = match parse_xmatrix_header(&auth_value) {
        Some(a) => a,
        None => return unauthorized("Malformed X-Matrix Authorization header"),
    };

    // --- 3. Verify destination matches us -----------------------------------
    if auth.destination != &*state.server_name {
        return unauthorized("destination does not match this server");
    }

    // --- 4. Fetch origin's public key ---------------------------------------
    let pub_bytes = match state
        .remote_keys
        .get_or_fetch(&state.http, &auth.origin, &auth.key_id)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            return unauthorized(&format!("Cannot fetch key '{}' from '{}': {}", auth.key_id, auth.origin, e));
        }
    };

    // --- 5. Build canonical signing object ----------------------------------
    // Determine the method + uri from the request.
    // Use OriginalUri if present (axum's nest() strips the prefix from req.uri(),
    // but the Matrix spec requires signing the full original URI).
    let method = req.method().as_str().to_uppercase();
    let uri = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|ou| {
            ou.path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/")
                .to_owned()
        })
        .unwrap_or_else(|| {
            req.uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/")
                .to_owned()
        });

    // Extract and buffer the body so we can include `content` if present.
    // We need to read it here and re-insert it for the downstream handler.
    let content_type_is_json = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("application/json"))
        .unwrap_or(false);

    // Collect body bytes.
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return unauthorized("Failed to read request body"),
    };

    // Build the object to sign.
    let mut signing_obj = json!({
        "method": method,
        "uri": uri,
        "origin": auth.origin,
        "destination": auth.destination,
    });

    // Include content only if body is non-empty JSON.
    if content_type_is_json && !body_bytes.is_empty() {
        if let Ok(content) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            signing_obj["content"] = content;
        }
    }

    let canonical = match to_canonical_bytes(&signing_obj) {
        Ok(b) => b,
        Err(e) => return unauthorized(&format!("Failed to build canonical JSON: {e}")),
    };

    // --- 6. Decode sig + pubkey, verify -------------------------------------
    let sig_bytes = match STANDARD_NO_PAD.decode(&auth.sig_b64) {
        Ok(b) => b,
        Err(_) => return unauthorized("Cannot base64-decode signature"),
    };
    let sig_array: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return unauthorized("Signature must be 64 bytes"),
    };
    let signature = Signature::from_bytes(&sig_array);

    let pub_array: [u8; 32] = match pub_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return unauthorized("Public key must be 32 bytes"),
    };
    let verifying_key = match VerifyingKey::from_bytes(&pub_array) {
        Ok(k) => k,
        Err(_) => return unauthorized("Invalid Ed25519 public key"),
    };

    if verifying_key.verify_strict(&canonical, &signature).is_err() {
        return unauthorized("X-Matrix signature verification failed");
    }

    // --- 7. Reconstruct request, inject extension, pass through -------------
    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(FederationOrigin {
        server_name: auth.origin,
    });

    next.run(req).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xmatrix_roundtrip() {
        let header = r#"X-Matrix origin="a.org",destination="b.org",key="ed25519:k1",sig="AAAA""#;
        let parsed = parse_xmatrix_header(header).unwrap();
        assert_eq!(parsed.origin, "a.org");
        assert_eq!(parsed.destination, "b.org");
        assert_eq!(parsed.key_id, "ed25519:k1");
        assert_eq!(parsed.sig_b64, "AAAA");
    }

    #[test]
    fn parse_xmatrix_missing_field_returns_none() {
        // Missing sig
        let header = r#"X-Matrix origin="a.org",destination="b.org",key="ed25519:k1""#;
        assert!(parse_xmatrix_header(header).is_none());
    }

    #[test]
    fn parse_xmatrix_wrong_prefix_returns_none() {
        let header = r#"Bearer token"#;
        assert!(parse_xmatrix_header(header).is_none());
    }
}
