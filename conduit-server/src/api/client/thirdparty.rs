//! Third-party networks (conduit-y99.20).
//!
//! - `GET /_matrix/client/v3/thirdparty/protocols`
//! - `GET /_matrix/client/v3/thirdparty/protocol/{protocol}`
//! - `GET /_matrix/client/v3/thirdparty/location/{protocol}?{fields}`
//! - `GET /_matrix/client/v3/thirdparty/user/{protocol}?{fields}`
//! - `GET /_matrix/client/v3/thirdparty/location?alias=`
//! - `GET /_matrix/client/v3/thirdparty/user?userid=`
//!
//! Everything is aggregated from the application services registered
//! with this homeserver, using the `protocols` list in their
//! registration and the AS API (`/_matrix/app/v1/thirdparty/...`,
//! authenticated with `Authorization: Bearer <hs_token>`). With no
//! bridges, `protocols` is `{}` and every lookup is `404 M_NOT_FOUND`,
//! which is what the spec answers when nothing was found.
//!
//! Each protocol instance gets an `instance_id` of
//! `{appservice_id}|{network_id}`, which `POST /publicRooms` accepts as
//! `third_party_instance_id`.

use std::time::Duration;

use axum::{
    extract::{Path, Query, RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Map, Value};

use super::room_directory::instance_id;
use super::{AuthState, AuthedUser, MatrixError};
use crate::app_service::{AppService, AsState};

pub fn router<S: AuthState + AsState>() -> Router<S> {
    Router::new()
        .route("/_matrix/client/v3/thirdparty/protocols", get(protocols::<S>))
        .route("/_matrix/client/v3/thirdparty/protocol/:protocol", get(protocol::<S>))
        .route("/_matrix/client/v3/thirdparty/location", get(location_by_alias::<S>))
        .route("/_matrix/client/v3/thirdparty/location/:protocol", get(location::<S>))
        .route("/_matrix/client/v3/thirdparty/user", get(user_by_id::<S>))
        .route("/_matrix/client/v3/thirdparty/user/:protocol", get(user::<S>))
}

/// One shared client for homeserver → AS lookups.
fn http() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client")
    })
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// `GET {as.url}/_matrix/app/v1/thirdparty/{path}` → JSON on 2xx.
async fn as_get(service: &AppService, path: &str) -> Option<Value> {
    if service.url.is_empty() {
        return None;
    }
    let url = format!("{}/_matrix/app/v1/thirdparty/{path}", service.url.trim_end_matches('/'));
    match http().get(&url).bearer_auth(&service.hs_token).send().await {
        Ok(resp) if resp.status().is_success() => resp.json().await.ok(),
        Ok(resp) => {
            tracing::debug!(as_id = service.id, status = resp.status().as_u16(), path, "AS thirdparty lookup miss");
            None
        }
        Err(e) => {
            tracing::warn!(as_id = service.id, error = %e, path, "AS thirdparty lookup failed");
            None
        }
    }
}

/// Merged protocol metadata for `name` across every AS that bridges it.
async fn protocol_metadata(services: &[AppService], name: &str) -> Option<Value> {
    let mut merged: Option<Map<String, Value>> = None;
    for service in services.iter().filter(|s| s.protocols.iter().any(|p| p == name)) {
        let Some(Value::Object(mut meta)) = as_get(service, &format!("protocol/{}", encode(name))).await
        else {
            continue;
        };
        let instances: Vec<Value> = meta
            .remove("instances")
            .and_then(|i| match i {
                Value::Array(a) => Some(a),
                _ => None,
            })
            .unwrap_or_default()
            .into_iter()
            .map(|mut instance| {
                if let Some(network) = instance["network_id"].as_str().map(str::to_owned) {
                    instance["instance_id"] = json!(instance_id(&service.id, &network));
                }
                instance
            })
            .collect();
        match merged.as_mut() {
            None => {
                meta.insert("instances".into(), Value::Array(instances));
                merged = Some(meta);
            }
            Some(existing) => {
                if let Some(Value::Array(all)) = existing.get_mut("instances") {
                    all.extend(instances);
                }
            }
        }
    }
    merged.map(Value::Object)
}

fn not_found(msg: &str) -> Response {
    MatrixError::new_not_found(msg).into_response()
}

fn missing_param(name: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"errcode": "M_MISSING_PARAM", "error": format!("missing query parameter: {name}")})),
    )
        .into_response()
}

/// Concatenate the array responses from `services`; `404` when empty.
async fn aggregate<'a>(
    services: impl Iterator<Item = &'a AppService>,
    path: &str,
    none_found: &str,
) -> Response {
    let mut results = Vec::new();
    for service in services {
        if let Some(Value::Array(items)) = as_get(service, path).await {
            results.extend(items);
        }
    }
    if results.is_empty() {
        not_found(none_found)
    } else {
        (StatusCode::OK, Json(Value::Array(results))).into_response()
    }
}

fn with_query(path: String, raw: Option<String>) -> String {
    match raw.filter(|q| !q.is_empty()) {
        Some(q) => format!("{path}?{q}"),
        None => path,
    }
}

/// `GET /thirdparty/protocols`
pub async fn protocols<S: AuthState + AsState>(State(state): State<S>, _authed: AuthedUser) -> Response {
    let services = state.app_services();
    let mut names: Vec<&String> = services.iter().flat_map(|s| s.protocols.iter()).collect();
    names.sort();
    names.dedup();
    let mut out = Map::new();
    for name in names {
        if let Some(meta) = protocol_metadata(services, name).await {
            out.insert(name.clone(), meta);
        }
    }
    (StatusCode::OK, Json(Value::Object(out))).into_response()
}

/// `GET /thirdparty/protocol/{protocol}`
pub async fn protocol<S: AuthState + AsState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path(name): Path<String>,
) -> Response {
    match protocol_metadata(state.app_services(), &name).await {
        Some(meta) => (StatusCode::OK, Json(meta)).into_response(),
        None => not_found("Protocol is unknown"),
    }
}

/// `GET /thirdparty/location/{protocol}`
pub async fn location<S: AuthState + AsState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path(name): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    let services = state.app_services();
    let path = with_query(format!("location/{}", encode(&name)), raw);
    aggregate(
        services.iter().filter(|s| s.protocols.contains(&name)),
        &path,
        "No portal rooms were found",
    )
    .await
}

/// `GET /thirdparty/user/{protocol}`
pub async fn user<S: AuthState + AsState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path(name): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    let services = state.app_services();
    let path = with_query(format!("user/{}", encode(&name)), raw);
    aggregate(
        services.iter().filter(|s| s.protocols.contains(&name)),
        &path,
        "The Matrix User ID was not found",
    )
    .await
}

/// `GET /thirdparty/location?alias=`
pub async fn location_by_alias<S: AuthState + AsState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(alias) = query.get("alias") else {
        return missing_param("alias");
    };
    let services = state.app_services();
    let path = format!("location?alias={}", encode(alias));
    aggregate(
        services
            .iter()
            .filter(|s| s.alias_namespaces.iter().any(|(_, re)| re.is_match(alias))),
        &path,
        "The Matrix room alias was not found",
    )
    .await
}

/// `GET /thirdparty/user?userid=`
pub async fn user_by_id<S: AuthState + AsState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(user_id) = query.get("userid") else {
        return missing_param("userid");
    };
    let services = state.app_services();
    let path = format!("user?userid={}", encode(user_id));
    aggregate(
        services
            .iter()
            .filter(|s| s.user_namespaces.iter().any(|(_, re)| re.is_match(user_id))),
        &path,
        "The Matrix User ID was not found",
    )
    .await
}
