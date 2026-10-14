//! Client-Server API standards that apply across every endpoint
//! (conduit-y99.28, Matrix v1.19 #api-standards).
//!
//! - Unknown endpoints answer `404 M_UNRECOGNIZED`, known endpoints called
//!   with an unsupported method answer `405 M_UNRECOGNIZED`. axum's own
//!   404/405 have empty bodies; [`normalize_errors`] rewrites them.
//! - Every `429` carries a `Retry-After` header (SHOULD since v1.10),
//!   derived from the body's deprecated `retry_after_ms` when present.
//! - `GET /_matrix/client/v1/auth_metadata` answers `404 M_UNRECOGNIZED`:
//!   the OAuth 2.0 API is not supported, and authentication API discovery
//!   requires that answer (#authentication-api-discovery).
//! - `GET /_matrix/client/versions` advertises the spec versions served.
//! - Plain-text body rejections from axum extractors become `M_NOT_JSON`,
//!   `M_BAD_JSON` or `M_TOO_LARGE` JSON errors.

use axum::{
    body::Body,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};

use super::AuthState;

use conduit::api::client::SUPPORTED_VERSIONS;

/// Routes owned by this module.
pub fn router<S: AuthState>() -> Router<S> {
    Router::new()
        .route("/_matrix/client/versions", get(versions))
        .route("/_matrix/client/v1/auth_metadata", get(auth_metadata))
}

/// `GET /_matrix/client/versions`. Authentication is optional and no
/// unstable feature is advertised to anyone.
pub async fn versions() -> Json<Value> {
    Json(json!({ "versions": SUPPORTED_VERSIONS, "unstable_features": {} }))
}

/// `GET /_matrix/client/v1/auth_metadata`: OAuth 2.0 is unsupported.
pub async fn auth_metadata() -> Response {
    unrecognized(StatusCode::NOT_FOUND, "OAuth 2.0 API is not supported by this server")
}

fn unrecognized(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "errcode": "M_UNRECOGNIZED", "error": error }))).into_response()
}

fn is_json(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"))
}

/// Response middleware (`axum::middleware::map_response`) applied to the
/// whole application router.
pub async fn normalize_errors(response: Response) -> Response {
    let status = response.status();
    if (status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED)
        && !is_json(&response)
    {
        let allow = response.headers().get(header::ALLOW).cloned();
        let mut rewritten = if status == StatusCode::NOT_FOUND {
            unrecognized(status, "Unrecognized request")
        } else {
            unrecognized(status, "Method not allowed for this endpoint")
        };
        if let Some(allow) = allow {
            rewritten.headers_mut().insert(header::ALLOW, allow);
        }
        return rewritten;
    }
    // axum's body extractors reject with plain text; Matrix wants JSON
    // errors: unparsable or non-JSON bodies are M_NOT_JSON, JSON of the
    // wrong shape is M_BAD_JSON, oversized bodies M_TOO_LARGE.
    let rewrite = match status {
        StatusCode::BAD_REQUEST | StatusCode::UNSUPPORTED_MEDIA_TYPE => {
            Some((StatusCode::BAD_REQUEST, "M_NOT_JSON"))
        }
        StatusCode::UNPROCESSABLE_ENTITY => Some((StatusCode::BAD_REQUEST, "M_BAD_JSON")),
        StatusCode::PAYLOAD_TOO_LARGE => Some((StatusCode::PAYLOAD_TOO_LARGE, "M_TOO_LARGE")),
        _ => None,
    };
    if let Some((new_status, errcode)) = rewrite.filter(|_| !is_json(&response)) {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await.unwrap_or_default();
        let message = String::from_utf8_lossy(&bytes).trim().to_owned();
        return (new_status, Json(json!({ "errcode": errcode, "error": message }))).into_response();
    }
    if status == StatusCode::TOO_MANY_REQUESTS && !response.headers().contains_key(header::RETRY_AFTER) {
        let (mut parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 64 * 1024).await.unwrap_or_default();
        let millis = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|v| v.get("retry_after_ms").and_then(Value::as_u64))
            .unwrap_or(1000);
        parts.headers.insert(header::RETRY_AFTER, retry_after_header(millis));
        return Response::from_parts(parts, Body::from(bytes));
    }
    response
}

/// Whole seconds, rounded up, never zero.
pub fn retry_after_header(millis: u64) -> HeaderValue {
    HeaderValue::from(millis.div_ceil(1000).max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_404_and_405_become_m_unrecognized() {
        let not_found = normalize_errors(StatusCode::NOT_FOUND.into_response()).await;
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(not_found.into_body(), 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["errcode"], "M_UNRECOGNIZED");

        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET,HEAD"));
        let response = normalize_errors(response).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::ALLOW], "GET,HEAD");
        let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["errcode"], "M_UNRECOGNIZED");
    }

    #[tokio::test]
    async fn plain_text_body_rejections_become_matrix_errors() {
        for (status, expected_status, errcode) in [
            (StatusCode::BAD_REQUEST, 400, "M_NOT_JSON"),
            (StatusCode::UNSUPPORTED_MEDIA_TYPE, 400, "M_NOT_JSON"),
            (StatusCode::UNPROCESSABLE_ENTITY, 400, "M_BAD_JSON"),
            (StatusCode::PAYLOAD_TOO_LARGE, 413, "M_TOO_LARGE"),
        ] {
            let response = normalize_errors((status, "Failed to parse").into_response()).await;
            assert_eq!(response.status().as_u16(), expected_status);
            let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["errcode"], errcode);
            assert_eq!(body["error"], "Failed to parse");
        }
        // JSON 400s from handlers pass through.
        let response = (StatusCode::BAD_REQUEST, Json(json!({"errcode": "M_INVALID_PARAM"}))).into_response();
        let body = axum::body::to_bytes(normalize_errors(response).await.into_body(), 1024).await.unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["errcode"], "M_INVALID_PARAM");
    }

    #[tokio::test]
    async fn json_404_is_left_alone() {
        let response = (StatusCode::NOT_FOUND, Json(json!({"errcode": "M_NOT_FOUND"}))).into_response();
        let response = normalize_errors(response).await;
        let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["errcode"], "M_NOT_FOUND");
    }

    #[tokio::test]
    async fn rate_limited_responses_gain_retry_after() {
        let response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"errcode": "M_LIMIT_EXCEEDED", "retry_after_ms": 2500})),
        )
            .into_response();
        let response = normalize_errors(response).await;
        assert_eq!(response.headers()[header::RETRY_AFTER], "3");
        let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["retry_after_ms"], 2500);
    }

    #[test]
    fn versions_include_target_release() {
        assert!(SUPPORTED_VERSIONS.contains(&"v1.19"));
    }
}
