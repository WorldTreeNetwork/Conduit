//! Sessions: issuing access/refresh tokens, `/refresh`, `/login/get_token`,
//! device removal, soft logout, last-seen tracking and the guest gate
//! (conduit-y99.18).
//!
//! Access tokens are Biscuit capability tokens bound to a device epoch
//! (see `conduit::agency`).  Revoking a device's tokens is an epoch bump
//! or a device deletion; refresh tokens are hashed rows bound to the same
//! epoch, so both revoke together.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts, State},
    http::{request::Parts, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use conduit::agency::{RootClaims, RIGHT_CS};

use super::account_config::AccountConfig;
use super::event_pipeline::RoomEventSenderWrapper;
use super::{
    generate_device_id, generate_token, hash_token, now_unix, uia, AuthState, AuthedUser,
    MatrixError, TOKEN_TTL_SECS,
};

// ---------------------------------------------------------------------------
// Issuing sessions
// ---------------------------------------------------------------------------

/// Device and token preferences shared by every login on-ramp.
#[derive(Debug, Clone, Default)]
pub struct LoginOptions {
    pub device_id: Option<String>,
    pub initial_device_display_name: Option<String>,
    pub refresh_token: bool,
}

/// Mint an access token for an existing device, expiring at `expires_at`.
pub async fn mint_with_expiry<S: AuthState>(
    state: &S,
    user_id: &str,
    device_id: &str,
    expires_at: i64,
) -> Result<String, String> {
    let epoch = state
        .storage()
        .device_epoch(user_id, device_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("device {device_id} does not exist"))?;
    state
        .minter()
        .mint_root(&RootClaims {
            user_id,
            device_id,
            server_name: state.server_name(),
            epoch,
            rights: &[RIGHT_CS],
            expires_at: Some(expires_at),
        })
        .map_err(|e| e.to_string())
}

/// True when `device_id` is this cross-signing key's public key or key ID.
fn cross_signing_key_id_is(key: &Value, device_id: &str) -> bool {
    let Some(keys) = key.get("keys").and_then(Value::as_object) else {
        return false;
    };
    let prefixed = format!("ed25519:{device_id}");
    keys.iter().any(|(id, value)| id == &prefixed || value.as_str() == Some(device_id))
}

/// Lifetime (ms) of access tokens issued alongside a refresh token.
/// Rounded up to whole seconds, the token's time-check resolution.
fn refreshable_lifetime_ms() -> i64 {
    let ms = AccountConfig::get().refresh_access_token_lifetime_ms;
    ((ms + 999) / 1000) * 1000
}

/// Unix seconds at which a token issued now with `lifetime_ms` expires,
/// rounded up so the token never lives shorter than advertised.
fn expiry_after_ms(lifetime_ms: i64) -> i64 {
    let now_ms = chrono::Utc::now().timestamp_millis();
    (now_ms + lifetime_ms + 999) / 1000
}

/// Issue a fresh access token (and refresh token when asked) for a
/// device, creating it when it does not exist.
///
/// Per spec, a client that supplies the ID of an existing device
/// invalidates every access and refresh token previously bound to it —
/// the device's epoch advances.  The device itself (and its E2EE keys)
/// survives, which is what soft-logout re-login relies on.
pub async fn issue_session<S: AuthState>(
    state: &S,
    user_id: &str,
    opts: &LoginOptions,
) -> Result<Value, Response> {
    // A locked account gets no new tokens (spec account locking).
    super::moderation::refuse_if_locked(state, user_id).await?;
    let storage = state.storage();
    let device_id = opts
        .device_id
        .clone()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(generate_device_id);
    // The client-supplied device ID shares a namespace with cross-signing
    // key IDs. A match is 403 M_FORBIDDEN and must not create the device.
    if opts.device_id.as_deref().is_some_and(|id| !id.is_empty()) {
        let keys = storage
            .get_cross_signing_keys(user_id)
            .await
            .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?;
        if keys.values().any(|key| cross_signing_key_id_is(key, &device_id)) {
            return Err(MatrixError::forbidden(
                "device_id must not be the same as a cross-signing key ID",
            )
            .into_response());
        }
    }
    let created = storage
        .create_device_if_absent(user_id, &device_id, opts.initial_device_display_name.as_deref())
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?;
    if !created {
        storage
            .bump_device_epoch(user_id, &device_id)
            .await
            .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?;
    }
    if created {
        notify_device_list_change(state, user_id, &[]).await;
    }

    let mut body = json!({ "user_id": user_id, "device_id": device_id });
    if opts.refresh_token {
        let lifetime = refreshable_lifetime_ms();
        let access = mint_with_expiry(state, user_id, &device_id, expiry_after_ms(lifetime))
            .await
            .map_err(|e| MatrixError::unknown(e).into_response())?;
        let refresh = new_refresh_token(state, user_id, &device_id, None).await?;
        body["access_token"] = json!(access);
        body["refresh_token"] = json!(refresh);
        body["expires_in_ms"] = json!(lifetime);
    } else {
        let access = mint_with_expiry(state, user_id, &device_id, now_unix() + TOKEN_TTL_SECS)
            .await
            .map_err(|e| MatrixError::unknown(e).into_response())?;
        body["access_token"] = json!(access);
        body["expires_in_ms"] = json!(TOKEN_TTL_SECS * 1000);
    }
    Ok(body)
}

async fn new_refresh_token<S: AuthState>(
    state: &S,
    user_id: &str,
    device_id: &str,
    parent_hash: Option<&str>,
) -> Result<String, Response> {
    let epoch = state
        .storage()
        .device_epoch(user_id, device_id)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?
        .ok_or_else(|| unknown_token_response(false, "device no longer exists"))?;
    let raw = format!("cr_{}", generate_token());
    state
        .storage()
        .insert_refresh_token(&hash_token(&raw), user_id, device_id, epoch, parent_hash)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?;
    Ok(raw)
}

/// `401 M_UNKNOWN_TOKEN`, with `soft_logout` when the session may be
/// resumed (refresh or re-login with the same device).
pub fn unknown_token_response(soft_logout: bool, error: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "errcode": "M_UNKNOWN_TOKEN",
            "error": error,
            "soft_logout": soft_logout,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/refresh
// ---------------------------------------------------------------------------

pub async fn refresh<S: AuthState>(State(state): State<S>, body: Option<Json<Value>>) -> Response {
    let Some(raw) = body
        .as_ref()
        .and_then(|b| b.get("refresh_token"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"errcode": "M_MISSING_PARAM", "error": "refresh_token is required"})),
        )
            .into_response();
    };
    let storage = state.storage();
    let hash = hash_token(raw);
    let record = match storage.get_refresh_token(&hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return unknown_token_response(false, "Unknown refresh token"),
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let epoch = match storage.device_epoch(&record.user_id, &record.device_id).await {
        Ok(e) => e,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    if epoch != Some(record.epoch) {
        let _ = storage.delete_refresh_token(&hash).await;
        return unknown_token_response(false, "Refresh token has been revoked");
    }
    // Locked accounts cannot obtain a new access token until unlocked.
    if let Err(r) = super::moderation::refuse_if_locked(&state, &record.user_id).await {
        return r;
    }
    // Using this token proves the client stored it, so the token it was
    // issued in exchange for is revoked now; tokens previously issued in
    // exchange for this one were evidently lost and are revoked as well.
    if let Some(parent) = &record.parent_hash {
        if let Err(e) = storage.delete_refresh_token(parent).await {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }
    if let Err(e) = storage.delete_refresh_token_children(&hash).await {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    let lifetime = refreshable_lifetime_ms();
    let access = match mint_with_expiry(
        &state,
        &record.user_id,
        &record.device_id,
        expiry_after_ms(lifetime),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => return MatrixError::unknown(e).into_response(),
    };
    let new_refresh =
        match new_refresh_token(&state, &record.user_id, &record.device_id, Some(&hash)).await {
            Ok(t) => t,
            Err(r) => return r,
        };
    (
        StatusCode::OK,
        Json(json!({
            "access_token": access,
            "refresh_token": new_refresh,
            "expires_in_ms": lifetime,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v1/login/get_token
// ---------------------------------------------------------------------------

pub const LOGIN_TOKEN_LIFETIME_MS: i64 = 120_000;

pub async fn get_login_token<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    body: Option<Json<Value>>,
) -> Response {
    let flows = uia::account_flows(&state, &authed.user_id).await;
    let req = uia::UiaRequest::new("POST /login/get_token", Some(&authed.user_id), flows);
    if let Err(r) = uia::authenticate(&state, req, body.as_ref().and_then(|b| b.get("auth"))).await {
        return r;
    }
    let token = state.login_tokens().issue(authed.user_id.clone()).await;
    (
        StatusCode::OK,
        Json(json!({ "login_token": token, "expires_in_ms": LOGIN_TOKEN_LIFETIME_MS })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Optional authentication
// ---------------------------------------------------------------------------

/// An access token when one was presented (and then it must be valid),
/// `None` when the request carries none.  For endpoints such as
/// `/account/password` whose security block allows `{}`.
#[derive(Debug, Clone)]
pub struct MaybeAuthed(pub Option<AuthedUser>);

#[async_trait]
impl<S: AuthState> FromRequestParts<S> for MaybeAuthed {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if super::extract_access_token(parts).is_none() {
            return Ok(MaybeAuthed(None));
        }
        AuthedUser::from_request_parts(parts, state)
            .await
            .map(|a| MaybeAuthed(Some(a)))
    }
}

// ---------------------------------------------------------------------------
// Device removal
// ---------------------------------------------------------------------------

/// Delete devices and everything bound to them, then announce the
/// device-list change locally (sync `device_lists.changed`) and to
/// remote servers sharing a room (`m.device_list_update` with
/// `deleted: true`).
pub async fn remove_devices<S: AuthState>(
    state: &S,
    user_id: &str,
    device_ids: &[String],
) -> Result<(), Response> {
    let mut removed = Vec::new();
    for device_id in device_ids {
        match state.storage().delete_device(user_id, device_id).await {
            Ok(true) => removed.push(device_id.clone()),
            Ok(false) => {}
            Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
        }
    }
    if !removed.is_empty() {
        notify_device_list_change(state, user_id, &removed).await;
    }
    Ok(())
}

/// Record a device-list change for `user_id` and federate it.  `deleted`
/// names devices that no longer exist; an empty slice announces a new
/// or changed device without keys.
pub async fn notify_device_list_change<S: AuthState>(
    state: &S,
    user_id: &str,
    deleted: &[String],
) {
    let stream_id = state
        .storage()
        .record_device_list_change(user_id)
        .await
        .unwrap_or(0);
    state.sync_notify().notify_waiters();

    let Some(queue) = state.federation_queue().cloned() else {
        return;
    };
    if deleted.is_empty() {
        return;
    }
    let storage = state.storage().clone();
    let server_name = state.server_name().to_owned();
    let user_id = user_id.to_owned();
    let deleted = deleted.to_vec();
    tokio::spawn(async move {
        let servers =
            super::keys::remote_servers_sharing_room_with(&storage, &server_name, &user_id).await;
        for device_id in deleted {
            let edu = json!({
                "edu_type": "m.device_list_update",
                "content": {
                    "user_id": user_id,
                    "device_id": device_id,
                    "stream_id": stream_id,
                    "prev_id": [],
                    "deleted": true,
                },
            });
            for dest in &servers {
                queue.enqueue(dest, vec![], vec![edu.clone()]).await;
            }
        }
    });
}

/// Every device of `user_id`, except `keep`.
pub async fn device_ids_except<S: AuthState>(
    state: &S,
    user_id: &str,
    keep: Option<&str>,
) -> Result<Vec<String>, Response> {
    Ok(state
        .storage()
        .list_devices_for_user(user_id)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?
        .into_iter()
        .map(|d| d.device_id)
        .filter(|d| Some(d.as_str()) != keep)
        .collect())
}

/// Leave every room the user is joined to, invited to or knocking on.
pub async fn leave_all_rooms<S: AuthState>(state: &S, user_id: &str) {
    let memberships = match state.storage().current_memberships(user_id).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(user_id, error = %e, "deactivation: membership lookup failed");
            return;
        }
    };
    for event in memberships {
        let membership = event.content.get("membership").and_then(Value::as_str);
        if !matches!(membership, Some("join" | "invite" | "knock")) {
            continue;
        }
        let room = conduit::room::Room::new(&event.room_id);
        if let Err(e) = room.leave(user_id, None, &RoomEventSenderWrapper(state)).await {
            tracing::warn!(user_id, room_id = %event.room_id, error = %e, "deactivation: leave failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Post-authentication hooks (called by the AuthedUser extractor)
// ---------------------------------------------------------------------------

const TOUCH_INTERVAL: Duration = Duration::from_secs(60);

fn should_touch(user_id: &str, device_id: &str) -> bool {
    static LAST: Mutex<Option<HashMap<(String, String), Instant>>> = Mutex::new(None);
    let mut guard = LAST.lock().unwrap_or_else(|p| p.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let key = (user_id.to_owned(), device_id.to_owned());
    match map.get(&key) {
        Some(at) if at.elapsed() < TOUCH_INTERVAL => false,
        _ => {
            if map.len() > 100_000 {
                map.retain(|_, at| at.elapsed() < TOUCH_INTERVAL);
            }
            map.insert(key, Instant::now());
            true
        }
    }
}

fn client_ip(parts: &Parts) -> Option<String> {
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    // Behind a local reverse proxy the peer is loopback; trust its
    // X-Forwarded-For then (display data only, never authorization).
    if peer.map(|ip| ip.is_loopback()).unwrap_or(false) {
        if let Some(forwarded) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
        {
            return Some(forwarded.to_string());
        }
    }
    peer.map(|ip| ip.to_string())
}

/// Record last-seen data (throttled, off the request path).
pub fn touch<S: AuthState>(state: &S, parts: &Parts, user_id: &str, device_id: &str) {
    if !should_touch(user_id, device_id) {
        return;
    }
    let storage = state.storage().clone();
    let ip = client_ip(parts);
    let ua = parts
        .headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect::<String>());
    let user_id = user_id.to_owned();
    let device_id = device_id.to_owned();
    let now_ms = chrono::Utc::now().timestamp_millis();
    tokio::spawn(async move {
        if let Err(e) = storage
            .touch_device(&user_id, &device_id, now_ms, ip.as_deref(), ua.as_deref())
            .await
        {
            tracing::debug!(error = %e, "last-seen update failed");
        }
    });
}

/// Guest localparts are purely numeric, and ordinary registration may not
/// claim one, so only those users pay for the account lookup.
pub fn may_be_guest(user_id: &str) -> bool {
    user_id
        .strip_prefix('@')
        .and_then(|s| s.split(':').next())
        .map(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Endpoints a guest may call: the spec's guest-access list plus the
/// read-mostly housekeeping clients perform around `/sync` (logout,
/// capabilities, filters, typing, receipts, presence, account data).
const GUEST_ALLOWED: &[(&str, &str)] = &[
    // Retrieving events (spec).
    ("GET", "client/v3/rooms/*/state"),
    ("GET", "client/v3/rooms/*/state/*"),
    ("GET", "client/v3/rooms/*/state/*/*"),
    ("GET", "client/v3/rooms/*/context/*"),
    ("GET", "client/v3/rooms/*/event/*"),
    ("GET", "client/v3/rooms/*/messages"),
    ("GET", "client/v3/rooms/*/members"),
    ("GET", "client/v3/rooms/*/initialSync"),
    ("GET", "client/v3/sync"),
    ("GET", "client/v3/events"),
    ("GET", "client/v1/media/download/*/*"),
    ("GET", "client/v1/media/download/*/*/*"),
    ("GET", "client/v1/media/thumbnail/*/*"),
    // Sending events (spec).
    ("POST", "client/v3/rooms/*/join"),
    ("POST", "client/v3/join/*"),
    ("POST", "client/v3/rooms/*/leave"),
    ("PUT", "client/v3/rooms/*/send/*/*"),
    ("PUT", "client/v3/rooms/*/state/*"),
    ("PUT", "client/v3/rooms/*/state/*/*"),
    ("PUT", "client/v3/sendToDevice/*/*"),
    // Account maintenance (spec).
    ("PUT", "client/v3/profile/*/displayname"),
    ("DELETE", "client/v3/profile/*/displayname"),
    ("GET", "client/v3/devices"),
    ("GET", "client/v3/devices/*"),
    ("PUT", "client/v3/devices/*"),
    ("GET", "client/v3/account/whoami"),
    // End-to-end encryption (spec).
    ("POST", "client/v3/keys/upload"),
    ("POST", "client/v3/keys/query"),
    ("POST", "client/v3/keys/claim"),
    // Housekeeping around sync (server choice).
    ("POST", "client/v3/logout"),
    ("POST", "client/v3/logout/all"),
    ("GET", "client/v3/capabilities"),
    ("GET", "client/v3/joined_rooms"),
    ("GET", "client/v3/rooms/*/joined_members"),
    ("GET", "client/v3/profile/*"),
    ("GET", "client/v3/profile/*/*"),
    ("POST", "client/v3/user/*/filter"),
    ("GET", "client/v3/user/*/filter/*"),
    ("PUT", "client/v3/rooms/*/typing/*"),
    ("POST", "client/v3/rooms/*/receipt/*/*"),
    ("POST", "client/v3/rooms/*/read_markers"),
    ("GET", "client/v3/keys/changes"),
    ("GET", "client/v3/presence/*/status"),
    ("PUT", "client/v3/presence/*/status"),
    ("GET", "client/v3/pushrules/"),
    ("GET", "client/v3/user/*/account_data/*"),
    ("PUT", "client/v3/user/*/account_data/*"),
    ("GET", "client/v3/user/*/rooms/*/account_data/*"),
    ("PUT", "client/v3/user/*/rooms/*/account_data/*"),
    ("GET", "client/v3/voip/turnServer"),
];

/// Whether a guest may call `method path`.
pub fn guest_may_call(method: &Method, path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/_matrix/") else {
        return false;
    };
    let segments: Vec<&str> = rest.split('/').collect();
    GUEST_ALLOWED.iter().any(|(m, pattern)| {
        if *m != method.as_str() {
            return false;
        }
        let pat: Vec<&str> = pattern.split('/').collect();
        pat.len() == segments.len()
            && pat
                .iter()
                .zip(&segments)
                .all(|(p, s)| *p == "*" || p == s)
    })
}

fn guest_forbidden(msg: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"errcode": "M_GUEST_ACCESS_FORBIDDEN", "error": msg})),
    )
        .into_response()
}

/// The room a guest join request targets, if this is a join.
fn guest_join_target(method: &Method, path: &str) -> Option<String> {
    if method != Method::POST {
        return None;
    }
    let rest = path.strip_prefix("/_matrix/client/v3/")?;
    let segs: Vec<&str> = rest.split('/').collect();
    match segs.as_slice() {
        ["join", target] => Some(percent_decode(target)),
        ["rooms", room, "join"] => Some(percent_decode(room)),
        _ => None,
    }
}

/// Enforce guest restrictions.  Called after the token verified.
pub async fn guest_gate<S: AuthState>(
    state: &S,
    parts: &Parts,
    user_id: &str,
) -> Result<(), Response> {
    if !may_be_guest(user_id) {
        return Ok(());
    }
    let is_guest = match state.storage().get_account(user_id).await {
        Ok(Some(a)) => a.is_guest,
        Ok(None) => false,
        Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
    };
    if !is_guest {
        return Ok(());
    }
    let path = parts.uri.path();
    if !guest_may_call(&parts.method, path) {
        return Err(guest_forbidden("Guest access is not allowed for this endpoint"));
    }
    if let Some(target) = guest_join_target(&parts.method, path) {
        let room_id = if target.starts_with('#') {
            match state.storage().get_room_for_alias(&target).await {
                Ok(Some(r)) => r,
                // Unknown alias: let the join handler produce its error.
                _ => return Ok(()),
            }
        } else {
            target
        };
        let allowed = match state
            .storage()
            .get_state_entry(&room_id, "m.room.guest_access", "")
            .await
        {
            Ok(Some(ev)) => ev.content.get("guest_access").and_then(Value::as_str) == Some("can_join"),
            Ok(None) => false,
            Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
        };
        if !allowed {
            return Err(guest_forbidden("Guest access is not enabled for this room"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_detection_is_numeric_localparts_only() {
        assert!(may_be_guest("@12345:hs"));
        assert!(!may_be_guest("@alice:hs"));
        assert!(!may_be_guest("@123a:hs"));
        assert!(!may_be_guest("@:hs"));
    }

    #[test]
    fn guest_allowlist_matches_spec_endpoints() {
        assert!(guest_may_call(&Method::GET, "/_matrix/client/v3/sync"));
        assert!(guest_may_call(&Method::PUT, "/_matrix/client/v3/rooms/!r:hs/send/m.room.message/1"));
        assert!(guest_may_call(&Method::POST, "/_matrix/client/v3/join/%23a%3Ahs"));
        assert!(guest_may_call(&Method::GET, "/_matrix/client/v3/account/whoami"));
        assert!(guest_may_call(&Method::POST, "/_matrix/client/v3/keys/upload"));
        assert!(!guest_may_call(&Method::POST, "/_matrix/client/v3/createRoom"));
        assert!(!guest_may_call(&Method::DELETE, "/_matrix/client/v3/devices/X"));
        assert!(!guest_may_call(&Method::POST, "/_matrix/client/v3/account/password"));
        assert!(!guest_may_call(&Method::PUT, "/_matrix/client/v3/profile/@g:hs/avatar_url"));
        assert!(!guest_may_call(&Method::POST, "/_matrix/client/v1/login/get_token"));
    }

    #[test]
    fn join_targets_are_decoded() {
        assert_eq!(
            guest_join_target(&Method::POST, "/_matrix/client/v3/join/%21room%3Ahs").as_deref(),
            Some("!room:hs")
        );
        assert_eq!(
            guest_join_target(&Method::POST, "/_matrix/client/v3/rooms/!r:hs/join").as_deref(),
            Some("!r:hs")
        );
        assert!(guest_join_target(&Method::GET, "/_matrix/client/v3/join/x").is_none());
        assert_eq!(percent_decode("%2"), "%2");
        assert_eq!(percent_decode("a%20b"), "a b");
    }
}
