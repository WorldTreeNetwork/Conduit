//! Profiles (Matrix v1.19 §Profiles; conduit-y99.38, conduit-y99.25).
//!
//! GET    /_matrix/client/v3/profile/{userId}
//! GET    /_matrix/client/v3/profile/{userId}/{keyName}
//! PUT    /_matrix/client/v3/profile/{userId}/{keyName}
//! DELETE /_matrix/client/v3/profile/{userId}/{keyName}
//!
//! `displayname` and `avatar_url` live on the account; `m.tz` and
//! namespaced custom keys are extended fields (v1.16).  The whole profile
//! must stay under 64 KiB (`M_PROFILE_TOO_LARGE`), keys under 255 bytes
//! (`M_KEY_TOO_LARGE`).
//!
//! Lookups are open by default, which satisfies the MUST (shared,
//! public and world-readable rooms) trivially.  With
//! `CONDUIT_PROFILE_LOOKUP=restricted` the server answers only those
//! required cases and denies the rest with `403 M_FORBIDDEN`, unknown
//! users included (no enumeration).
//!
//! A display name or avatar change is propagated as an updated
//! `m.room.member` join event in every joined room and as an
//! `m.presence` update carrying the new values.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Map, Value};

use super::event_pipeline::build_sign_and_persist;
use super::session::MaybeAuthed;
use super::{AuthState, AuthedUser, MatrixError};

/// The whole-profile size limit (spec: MUST be under 64 KiB).
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;
/// The maximum profile key length in bytes (spec `M_KEY_TOO_LARGE`).
pub const MAX_KEY_BYTES: usize = 255;

pub fn router<S: AuthState>() -> Router<S> {
    Router::new()
        .route("/_matrix/client/v3/profile/:userId", get(get_profile::<S>))
        .route(
            "/_matrix/client/v3/profile/:userId/:keyName",
            get(get_field::<S>).put(put_field::<S>).delete(delete_field::<S>),
        )
}

fn error(status: StatusCode, errcode: &str, msg: &str) -> Response {
    (status, Json(json!({"errcode": errcode, "error": msg}))).into_response()
}

/// Whether `key` is a profile key name the spec allows:
/// `avatar_url`, `displayname`, `m.tz`, or a namespaced identifier
/// (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`).
pub fn valid_key_name(key: &str) -> bool {
    if matches!(key, "avatar_url" | "displayname" | "m.tz") {
        return true;
    }
    let parts: Vec<&str> = key.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|p| {
            let mut chars = p.chars();
            matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
                && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// Validate a value for a well-known key.  Custom keys accept any JSON.
pub fn validate_value(key: &str, value: &Value) -> Result<(), &'static str> {
    match key {
        "displayname" => match value {
            Value::String(_) | Value::Null => Ok(()),
            _ => Err("displayname must be a string"),
        },
        "avatar_url" => match value {
            Value::String(s) if s.is_empty() || s.starts_with("mxc://") => Ok(()),
            Value::Null => Ok(()),
            _ => Err("avatar_url must be an mxc:// URI"),
        },
        "m.tz" => match value {
            Value::String(_) => Ok(()),
            _ => Err("m.tz must be a string time zone identifier"),
        },
        _ => Ok(()),
    }
}

/// The serialised size of a full profile object.
pub fn profile_size(profile: &Map<String, Value>) -> usize {
    serde_json::to_vec(profile).map(|v| v.len()).unwrap_or(usize::MAX)
}

/// The full profile of a local user, or `None` when no such account.
async fn load_profile<S: AuthState>(state: &S, user_id: &str) -> Result<Option<Map<String, Value>>, Response> {
    let account = match state.storage().get_account(user_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return Ok(None),
        Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
    };
    if account.deactivated_at.is_some() {
        return Ok(None);
    }
    let fields: BTreeMap<String, Value> = state
        .storage()
        .profile_fields(user_id)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?;
    let mut profile: Map<String, Value> = fields.into_iter().collect();
    if let Some(dn) = account.displayname {
        profile.insert("displayname".into(), json!(dn));
    }
    if let Some(url) = account.avatar_url {
        profile.insert("avatar_url".into(), json!(url));
    }
    Ok(Some(profile))
}

// ---------------------------------------------------------------------------
// Lookup visibility
// ---------------------------------------------------------------------------

fn lookup_restricted() -> bool {
    static MODE: OnceLock<bool> = OnceLock::new();
    *MODE.get_or_init(|| {
        std::env::var("CONDUIT_PROFILE_LOOKUP")
            .map(|v| v.eq_ignore_ascii_case("restricted"))
            .unwrap_or(false)
    })
}

/// Whether `requester` may look up `target` under the spec minimum:
/// the target is the requester, shares a room with them, or is joined
/// to a room with a `public` join rule or `world_readable` history.
pub async fn may_lookup<S: AuthState>(state: &S, requester: Option<&str>, target: &str) -> Result<bool, Response> {
    if requester == Some(target) {
        return Ok(true);
    }
    let storage = state.storage();
    let unknown = |e: conduit::Error| MatrixError::unknown(e.to_string()).into_response();
    let target_rooms = storage.joined_rooms(target).await.map_err(unknown)?;
    if let Some(requester) = requester {
        let mine = storage.joined_rooms(requester).await.map_err(unknown)?;
        if target_rooms.iter().any(|r| mine.contains(r)) {
            return Ok(true);
        }
    }
    for room in &target_rooms {
        let public = storage
            .get_state_entry(room, "m.room.join_rules", "")
            .await
            .map_err(unknown)?
            .is_some_and(|e| e.content.get("join_rule").and_then(Value::as_str) == Some("public"));
        let world_readable = storage
            .get_state_entry(room, "m.room.history_visibility", "")
            .await
            .map_err(unknown)?
            .is_some_and(|e| {
                e.content.get("history_visibility").and_then(Value::as_str) == Some("world_readable")
            });
        if public || world_readable {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Resolve a lookup: the profile, or the spec error response.
async fn lookup<S: AuthState>(state: &S, requester: Option<&str>, target: &str) -> Result<Map<String, Value>, Response> {
    if lookup_restricted() && !may_lookup(state, requester, target).await? {
        // Unknown users get the same 403 (spec RECOMMENDED when lookups
        // are restricted), so the answer does not enumerate accounts.
        return Err(error(StatusCode::FORBIDDEN, "M_FORBIDDEN", "Profile lookup is not permitted"));
    }
    match load_profile(state, target).await? {
        Some(p) => Ok(p),
        None => match remote_profile(state, target).await? {
            Some(p) => Ok(p),
            None => Err(MatrixError::new_not_found("Profile not found").into_response()),
        },
    }
}

/// Profile of a user on another server, via `GET /query/profile`.
/// `Ok(None)` means this server should answer as if the user is unknown:
/// they are local, federation is off, or the remote server returned 404.
async fn remote_profile<S: AuthState>(
    state: &S,
    user_id: &str,
) -> Result<Option<Map<String, Value>>, Response> {
    let Some(dest) = conduit::signing::server_of_user_id(user_id) else {
        return Ok(None);
    };
    if dest == state.server_name() || std::env::var("CONDUIT_FEDERATION").ok().as_deref() == Some("0") {
        return Ok(None);
    }
    let Some(client) = state.federation_client() else {
        return Ok(None);
    };
    match client.query_profile(dest, user_id, None).await {
        Ok(value) => {
            let Some(object) = value.as_object() else {
                return Err(MatrixError::unknown("remote profile was not a JSON object").into_response());
            };
            let profile = object
                .iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            Ok(Some(profile))
        }
        Err(crate::federation::FederationError::RemoteError { status: 404, .. }) => Ok(None),
        Err(crate::federation::FederationError::RemoteError { status: 403, .. }) => {
            Err(error(StatusCode::FORBIDDEN, "M_FORBIDDEN", "Profile lookup was denied by the remote server"))
        }
        Err(error) => Err(MatrixError::unknown(error.to_string()).into_response()),
    }
}

// ---------------------------------------------------------------------------
// GET /profile/{userId}
// ---------------------------------------------------------------------------

pub async fn get_profile<S: AuthState>(
    State(state): State<S>,
    MaybeAuthed(authed): MaybeAuthed,
    Path(user_id): Path<String>,
) -> Response {
    let requester = authed.as_ref().map(|a| a.user_id.as_str());
    match lookup(&state, requester, &user_id).await {
        Ok(profile) => (StatusCode::OK, Json(Value::Object(profile))).into_response(),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------------------
// GET /profile/{userId}/{keyName}
// ---------------------------------------------------------------------------

pub async fn get_field<S: AuthState>(
    State(state): State<S>,
    MaybeAuthed(authed): MaybeAuthed,
    Path((user_id, key)): Path<(String, String)>,
) -> Response {
    let requester = authed.as_ref().map(|a| a.user_id.as_str());
    let profile = match lookup(&state, requester, &user_id).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    match profile.get(&key) {
        Some(value) => (StatusCode::OK, Json(json!({ key: value }))).into_response(),
        None => MatrixError::new_not_found("Profile field not found").into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /profile/{userId}/{keyName}
// ---------------------------------------------------------------------------

pub async fn put_field<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((user_id, key)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if key.len() > MAX_KEY_BYTES {
        return error(StatusCode::BAD_REQUEST, "M_KEY_TOO_LARGE", "Profile key exceeds 255 bytes");
    }
    if !valid_key_name(&key) {
        return error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "Invalid profile key");
    }
    let body: Value = match serde_json::from_slice(&body) {
        Ok(Value::Object(o)) => Value::Object(o),
        _ => return MatrixError::bad_json("Request body must be a JSON object").into_response(),
    };
    let Some(value) = body.get(&key).cloned() else {
        return error(
            StatusCode::BAD_REQUEST,
            "M_MISSING_PARAM",
            &format!("Request body is missing the '{key}' property"),
        );
    };
    if authed.user_id != user_id {
        return MatrixError::forbidden("Cannot change another user's profile").into_response();
    }
    if let Err(msg) = validate_value(&key, &value) {
        return MatrixError::bad_json(msg).into_response();
    }
    set_field(&state, &user_id, &key, Some(value)).await
}

// ---------------------------------------------------------------------------
// DELETE /profile/{userId}/{keyName}
// ---------------------------------------------------------------------------

pub async fn delete_field<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((user_id, key)): Path<(String, String)>,
) -> Response {
    if key.len() > MAX_KEY_BYTES {
        return error(StatusCode::BAD_REQUEST, "M_KEY_TOO_LARGE", "Profile key exceeds 255 bytes");
    }
    if !valid_key_name(&key) {
        return error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "Invalid profile key");
    }
    if authed.user_id != user_id {
        return MatrixError::forbidden("Cannot change another user's profile").into_response();
    }
    set_field(&state, &user_id, &key, None).await
}

/// Store or remove one field, enforcing the 64 KiB limit and
/// propagating display name / avatar changes.
async fn set_field<S: AuthState>(state: &S, user_id: &str, key: &str, value: Option<Value>) -> Response {
    let mut profile = match load_profile(state, user_id).await {
        Ok(Some(p)) => p,
        Ok(None) => return MatrixError::new_not_found("User not found").into_response(),
        Err(r) => return r,
    };
    // displayname/avatar_url are nullable account columns: null clears.
    let effective = match (key, &value) {
        ("displayname" | "avatar_url", Some(Value::Null)) => None,
        _ => value.clone(),
    };
    let before = profile.clone();
    match &effective {
        Some(v) => {
            profile.insert(key.to_owned(), v.clone());
        }
        None => {
            profile.remove(key);
        }
    }
    if effective.is_some() && profile_size(&profile) > MAX_PROFILE_BYTES {
        return error(
            StatusCode::BAD_REQUEST,
            "M_PROFILE_TOO_LARGE",
            "The profile would exceed its maximum size of 64 KiB",
        );
    }
    let storage = state.storage();
    let stored = match key {
        "displayname" => storage.set_displayname(user_id, effective.as_ref().and_then(Value::as_str)).await,
        "avatar_url" => storage.set_avatar_url(user_id, effective.as_ref().and_then(Value::as_str)).await,
        _ => storage.set_profile_field(user_id, key, effective.as_ref()).await,
    };
    if let Err(e) = stored {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    if matches!(key, "displayname" | "avatar_url") && before.get(key) != profile.get(key) {
        propagate(state, user_id, &profile).await;
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

/// Send an updated `m.room.member` join event into every joined room and
/// announce the change through presence (spec "Events on Change of
/// Profile Information").
pub async fn propagate<S: AuthState>(state: &S, user_id: &str, profile: &Map<String, Value>) {
    let displayname = profile.get("displayname").and_then(Value::as_str).map(str::to_owned);
    let avatar_url = profile.get("avatar_url").and_then(Value::as_str).map(str::to_owned);
    let rooms = match state.storage().joined_rooms(user_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(user_id, error = %e, "profile propagation: joined rooms lookup failed");
            Vec::new()
        }
    };
    for room_id in rooms {
        let current = match state.storage().get_state_entry(&room_id, "m.room.member", user_id).await {
            Ok(Some(ev)) => ev.pdu.content,
            _ => continue,
        };
        let content = member_content_with_profile(&current, displayname.as_deref(), avatar_url.as_deref());
        if content == current {
            continue;
        }
        if let Err((_, e)) =
            build_sign_and_persist(state, user_id, &room_id, "m.room.member", Some(user_id), content).await
        {
            tracing::warn!(user_id, room_id, error = %e.0.error, "profile propagation: member update failed");
        }
    }
    state.presence_store().set_profile(user_id, displayname, avatar_url).await;
}

/// A join member content carrying the given profile values; other keys
/// of the current content (e.g. `reason`, `is_direct`) are dropped except
/// those that describe the member rather than the transition.
pub fn member_content_with_profile(current: &Value, displayname: Option<&str>, avatar_url: Option<&str>) -> Value {
    let mut content = Map::new();
    content.insert("membership".into(), json!("join"));
    if let Some(Value::Object(old)) = Some(current) {
        for keep in ["join_authorised_via_users_server"] {
            if let Some(v) = old.get(keep) {
                content.insert(keep.into(), v.clone());
            }
        }
    }
    if let Some(dn) = displayname {
        content.insert("displayname".into(), json!(dn));
    }
    if let Some(url) = avatar_url {
        content.insert("avatar_url".into(), json!(url));
    }
    Value::Object(content)
}

/// A local user's own join event that names no profile gets the
/// account's display name and avatar URL, so clients need no extra
/// profile round trip (spec: servers should include them).
pub async fn with_join_profile<S: AuthState>(
    state: &S,
    sender: &str,
    event_type: &str,
    state_key: Option<&str>,
    mut content: Value,
) -> Value {
    if event_type != "m.room.member"
        || state_key != Some(sender)
        || content.get("membership").and_then(Value::as_str) != Some("join")
        || content.get("displayname").is_some()
        || content.get("avatar_url").is_some()
        || !sender.ends_with(&format!(":{}", state.server_name()))
    {
        return content;
    }
    if let Ok(Some(account)) = state.storage().get_account(sender).await {
        if let Some(obj) = content.as_object_mut() {
            if let Some(dn) = account.displayname {
                obj.insert("displayname".into(), json!(dn));
            }
            if let Some(url) = account.avatar_url {
                obj.insert("avatar_url".into(), json!(url));
            }
        }
    }
    content
}

// ---------------------------------------------------------------------------
// Named handlers kept for existing routers and tests.
// ---------------------------------------------------------------------------

pub async fn get_displayname<S: AuthState>(
    state: State<S>,
    authed: MaybeAuthed,
    Path(user_id): Path<String>,
) -> Response {
    get_field(state, authed, Path((user_id, "displayname".to_owned()))).await
}

pub async fn get_avatar_url<S: AuthState>(
    state: State<S>,
    authed: MaybeAuthed,
    Path(user_id): Path<String>,
) -> Response {
    get_field(state, authed, Path((user_id, "avatar_url".to_owned()))).await
}

pub async fn put_displayname<S: AuthState>(
    state: State<S>,
    authed: AuthedUser,
    Path(user_id): Path<String>,
    body: Bytes,
) -> Response {
    put_field(state, authed, Path((user_id, "displayname".to_owned())), body).await
}

pub async fn put_avatar_url<S: AuthState>(
    state: State<S>,
    authed: AuthedUser,
    Path(user_id): Path<String>,
    body: Bytes,
) -> Response {
    put_field(state, authed, Path((user_id, "avatar_url".to_owned())), body).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_follow_the_spec_grammar() {
        for ok in ["displayname", "avatar_url", "m.tz", "m.example_field", "com.example.pronouns", "a.b1_c"] {
            assert!(valid_key_name(ok), "{ok}");
        }
        for bad in ["", "tz", "M.tz", "m.", ".m", "m..x", "1a.b", "com.Example", "com.ex-ample", "m.tz "] {
            assert!(!valid_key_name(bad), "{bad}");
        }
    }

    #[test]
    fn well_known_values_are_typed() {
        assert!(validate_value("displayname", &json!("Alice")).is_ok());
        assert!(validate_value("displayname", &json!(5)).is_err());
        assert!(validate_value("avatar_url", &json!("mxc://hs/abc")).is_ok());
        assert!(validate_value("avatar_url", &json!("https://x/y.png")).is_err());
        assert!(validate_value("m.tz", &json!("Europe/London")).is_ok());
        assert!(validate_value("m.tz", &json!(null)).is_err());
        assert!(validate_value("com.example.any", &json!({"nested": [1, null]})).is_ok());
    }

    #[test]
    fn size_counts_the_whole_serialised_profile() {
        let mut p = Map::new();
        p.insert("displayname".into(), json!("a"));
        assert_eq!(profile_size(&p), r#"{"displayname":"a"}"#.len());
    }

    #[test]
    fn member_content_carries_new_profile_and_drops_transition_keys() {
        let current = json!({"membership": "join", "displayname": "old", "reason": "hi", "is_direct": true});
        let next = member_content_with_profile(&current, Some("new"), None);
        assert_eq!(next, json!({"membership": "join", "displayname": "new"}));
    }
}
