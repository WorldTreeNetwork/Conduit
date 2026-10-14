//! Application service ping (conduit-y99.20, spec v1.7+).
//!
//! `POST /_matrix/client/v1/appservice/{appserviceId}/ping`
//!
//! Authenticated with the AS's own `as_token`; the path ID must name
//! that same AS. The homeserver calls `POST {url}/_matrix/app/v1/ping`
//! with `Authorization: Bearer <hs_token>` and the caller's
//! `transaction_id`, and reports how long that took.
//!
//! Errors, per spec: `400 M_URL_NOT_SET` (registration `url: null`),
//! `403 M_FORBIDDEN` (not an AS token, or another AS's), `502
//! M_BAD_STATUS` with `status`/`body`, `502 M_CONNECTION_FAILED`, and
//! `504 M_CONNECTION_TIMEOUT`.

use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::app_service::AsState;

/// How long the homeserver waits for the AS to answer the ping.
pub const PING_TIMEOUT: Duration = Duration::from_secs(10);

pub fn router<S: AsState>() -> Router<S> {
    Router::new().route(
        "/_matrix/client/v1/appservice/:appserviceId/ping",
        post(ping::<S>),
    )
}

#[derive(Debug, Default, Deserialize)]
pub struct PingBody {
    pub transaction_id: Option<String>,
}

fn error(status: StatusCode, errcode: &str, msg: impl Into<String>) -> Response {
    (status, Json(json!({"errcode": errcode, "error": msg.into()}))).into_response()
}

fn http() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(PING_TIMEOUT)
            .build()
            .expect("reqwest client")
    })
}

pub async fn ping<S: AsState>(
    State(state): State<S>,
    headers: HeaderMap,
    Path(appservice_id): Path<String>,
    Json(body): Json<PingBody>,
) -> Response {
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return error(StatusCode::UNAUTHORIZED, "M_MISSING_TOKEN", "Missing access token");
    };
    let Some(service) = state.app_services().iter().find(|s| s.as_token == token) else {
        return error(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "Provided access token is not an application service's as_token",
        );
    };
    if service.id != appservice_id {
        return error(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "Provided access token is not the appservice's as_token",
        );
    }
    if service.url.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "M_URL_NOT_SET",
            "Application service doesn't have a URL configured",
        );
    }

    let mut ping = serde_json::Map::new();
    if let Some(txn) = body.transaction_id {
        ping.insert("transaction_id".into(), Value::String(txn));
    }
    let url = format!("{}/_matrix/app/v1/ping", service.url.trim_end_matches('/'));
    let started = Instant::now();
    let result = http()
        .post(&url)
        .bearer_auth(&service.hs_token)
        .json(&Value::Object(ping))
        .send()
        .await;
    match result {
        Ok(resp) if resp.status().is_success() => {
            let duration_ms = started.elapsed().as_millis() as u64;
            (StatusCode::OK, Json(json!({"duration_ms": duration_ms}))).into_response()
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "errcode": "M_BAD_STATUS",
                    "error": format!("Ping returned status {status}"),
                    "status": status,
                    "body": body,
                })),
            )
                .into_response()
        }
        Err(e) if e.is_timeout() => error(
            StatusCode::GATEWAY_TIMEOUT,
            "M_CONNECTION_TIMEOUT",
            "Connection to application service timed out",
        ),
        Err(e) => error(
            StatusCode::BAD_GATEWAY,
            "M_CONNECTION_FAILED",
            format!("Connection to application service failed: {e}"),
        ),
    }
}
