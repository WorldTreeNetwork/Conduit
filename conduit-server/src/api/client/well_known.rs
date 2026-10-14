//! Server discovery (conduit-y99.18).
//!
//! <https://spec.matrix.org/v1.19/client-server-api/#well-known-uris>
//!
//!   GET /.well-known/matrix/client   — always served; base URL from
//!       `CONDUIT_WELL_KNOWN_CLIENT_BASE_URL`, else the origin the request
//!       reached (it demonstrably serves the client-server API)
//!   GET /.well-known/matrix/server   — `CONDUIT_WELL_KNOWN_SERVER`, else
//!       404 (no delegation; peers use the server name directly)
//!   GET /.well-known/matrix/support  — configured contacts / support page,
//!       else the local server administrators, else 404
//!
//! CORS comes from the global layer (`Access-Control-Allow-Origin: *`).

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use super::account_config::AccountConfig;
use super::{AuthState, MatrixError};

fn is_local_host(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host);
    h == "localhost" || h.starts_with("127.") || host.starts_with("[::1]")
}

/// The origin a client used to reach us.
pub fn request_origin(headers: &HeaderMap) -> Option<String> {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())?
        .split(',')
        .next()?
        .trim()
        .to_owned();
    if host.is_empty() || host.contains('/') {
        return None;
    }
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|p| p.split(',').next().unwrap_or(p).trim().to_ascii_lowercase())
        .filter(|p| p == "http" || p == "https")
        .unwrap_or_else(|| if is_local_host(&host) { "http".into() } else { "https".into() });
    Some(format!("{proto}://{host}"))
}

pub async fn client<S: AuthState>(State(state): State<S>, headers: HeaderMap) -> Response {
    let config = AccountConfig::get();
    let base_url = config
        .client_base_url
        .clone()
        .or_else(|| request_origin(&headers))
        .unwrap_or_else(|| format!("https://{}", state.server_name()));
    let mut body = json!({ "m.homeserver": { "base_url": base_url } });
    if let Some(is) = &config.identity_server {
        body["m.identity_server"] = json!({ "base_url": is });
    }
    (StatusCode::OK, Json(body)).into_response()
}

pub async fn server() -> Response {
    match &AccountConfig::get().server_delegation {
        Some(delegated) => (StatusCode::OK, Json(json!({ "m.server": delegated }))).into_response(),
        None => MatrixError::new_not_found("No server delegation is configured").into_response(),
    }
}

pub async fn support<S: AuthState>(State(state): State<S>) -> Response {
    let config = AccountConfig::get();
    let contacts: Vec<Value> = match &config.support_contacts {
        Some(Value::Array(items)) => items.clone(),
        _ => match state.storage().list_admin_user_ids().await {
            Ok(admins) => admins
                .into_iter()
                .map(|id| json!({ "matrix_id": id, "role": "m.role.admin" }))
                .collect(),
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        },
    };
    if contacts.is_empty() && config.support_page.is_none() {
        return MatrixError::new_not_found("No support information is available").into_response();
    }
    let mut body = json!({});
    if !contacts.is_empty() {
        body["contacts"] = json!(contacts);
    }
    if let Some(page) = &config.support_page {
        body["support_page"] = json!(page);
    }
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn origin_from_host_and_proxy_headers() {
        assert_eq!(
            request_origin(&headers(&[("host", "127.0.0.1:8008")])).unwrap(),
            "http://127.0.0.1:8008"
        );
        assert_eq!(
            request_origin(&headers(&[("host", "matrix.example.org")])).unwrap(),
            "https://matrix.example.org"
        );
        assert_eq!(
            request_origin(&headers(&[
                ("host", "internal:8008"),
                ("x-forwarded-host", "chat.example.org"),
                ("x-forwarded-proto", "https"),
            ]))
            .unwrap(),
            "https://chat.example.org"
        );
        assert!(request_origin(&headers(&[("host", "evil/path")])).is_none());
    }
}
