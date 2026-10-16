//! Device management (conduit-y99.18).
//!
//! <https://spec.matrix.org/v1.19/client-server-api/#device-management>
//!
//!   GET    /_matrix/client/v3/devices
//!   GET    /_matrix/client/v3/devices/{deviceId}
//!   PUT    /_matrix/client/v3/devices/{deviceId}
//!   DELETE /_matrix/client/v3/devices/{deviceId}   (UIA)
//!   POST   /_matrix/client/v3/delete_devices        (UIA)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use conduit::storage::Device;

use super::session::remove_devices;
use super::{uia, AuthState, AuthedUser, MatrixError};

pub fn device_json(d: &Device) -> Value {
    let mut v = json!({ "device_id": d.device_id });
    if let Some(name) = &d.display_name {
        v["display_name"] = json!(name);
    }
    if let Some(ip) = &d.last_seen_ip {
        v["last_seen_ip"] = json!(ip);
    }
    if let Some(ts) = d.last_seen_ts {
        v["last_seen_ts"] = json!(ts);
    }
    v
}

fn not_found() -> Response {
    MatrixError::new_not_found("The current user has no device with the given ID").into_response()
}

pub async fn list_devices<S: AuthState>(State(state): State<S>, authed: AuthedUser) -> Response {
    match state.storage().list_devices_for_user(&authed.user_id).await {
        Ok(devices) => (
            StatusCode::OK,
            Json(json!({ "devices": devices.iter().map(device_json).collect::<Vec<_>>() })),
        )
            .into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

pub async fn get_device<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(device_id): Path<String>,
) -> Response {
    match state.storage().get_device(&authed.user_id, &device_id).await {
        Ok(Some(d)) => (StatusCode::OK, Json(device_json(&d))).into_response(),
        Ok(None) => not_found(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

pub async fn update_device<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(device_id): Path<String>,
    body: Option<Json<Value>>,
) -> Response {
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    if !body.is_object() {
        return MatrixError::bad_json("request body must be a JSON object").into_response();
    }
    let storage = state.storage();
    let existing = match storage.get_device(&authed.user_id, &device_id).await {
        Ok(Some(d)) => d,
        // Creating devices here is reserved to application services
        // (spec v1.17): `201` on creation (conduit-y99.18.1).
        Ok(None) if authed.appservice.is_some() => {
            let name = body.get("display_name").and_then(Value::as_str);
            if body.get("display_name").is_some_and(|v| !v.is_string()) {
                return MatrixError::bad_json("display_name must be a string").into_response();
            }
            return match storage.create_device_if_absent(&authed.user_id, &device_id, name).await {
                Ok(true) => {
                    super::session::notify_device_list_change(&state, &authed.user_id, Some(&device_id), &[]).await;
                    (StatusCode::CREATED, Json(json!({}))).into_response()
                }
                // Lost a race with a concurrent create: it exists now.
                Ok(false) => (StatusCode::OK, Json(json!({}))).into_response(),
                Err(e) => MatrixError::unknown(e.to_string()).into_response(),
            };
        }
        Ok(None) => return not_found(),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    match body.get("display_name") {
        // Absent: unchanged.
        None => {}
        Some(Value::String(name)) => {
            if existing.display_name.as_deref() != Some(name.as_str()) {
                if let Err(e) = storage
                    .set_device_display_name(&authed.user_id, &device_id, Some(name))
                    .await
                {
                    return MatrixError::unknown(e.to_string()).into_response();
                }
                // Display names are visible in /keys/query unsigned data.
                super::session::notify_device_list_change(&state, &authed.user_id, Some(&device_id), &[]).await;
            }
        }
        Some(_) => {
            return MatrixError::bad_json("display_name must be a string").into_response();
        }
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

pub async fn delete_device<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(device_id): Path<String>,
    body: Option<Json<Value>>,
) -> Response {
    // Application services delete devices without UIA (spec v1.17).
    if authed.appservice.is_none() {
        let auth = body.as_ref().and_then(|b| b.get("auth")).cloned();
        let flows = uia::account_flows(&state, &authed.user_id).await;
        let req = uia::UiaRequest::new(
            format!("DELETE /devices/{device_id}"),
            Some(&authed.user_id),
            flows,
        );
        if let Err(r) = uia::authenticate(&state, req, auth.as_ref()).await {
            return r;
        }
    }
    match remove_devices(&state, &authed.user_id, &[device_id]).await {
        // Deleting an already-deleted device is a success per spec.
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(r) => r,
    }
}

pub async fn delete_devices<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    body: Option<Json<Value>>,
) -> Response {
    let body = body.map(|Json(v)| v).unwrap_or(Value::Null);
    let devices: Vec<String> = match body.get("devices") {
        Some(Value::Array(items)) => {
            let mut ids = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(s) => ids.push(s.to_owned()),
                    None => {
                        return MatrixError::bad_json("devices must be an array of strings")
                            .into_response()
                    }
                }
            }
            ids
        }
        Some(_) => {
            return MatrixError::bad_json("devices must be an array of strings").into_response()
        }
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"errcode": "M_MISSING_PARAM", "error": "devices is required"})),
            )
                .into_response()
        }
    };
    if authed.appservice.is_none() {
        let flows = uia::account_flows(&state, &authed.user_id).await;
        let req = uia::UiaRequest::new("POST /delete_devices", Some(&authed.user_id), flows);
        if let Err(r) = uia::authenticate(&state, req, body.get("auth")).await {
            return r;
        }
    }
    match remove_devices(&state, &authed.user_id, &devices).await {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(r) => r,
    }
}
