//! Application Service support (E11 AS1–AS7).
//!
//! Loads AS registration files from a directory, enforces namespaces,
//! handles AS-authenticated CS-API calls, ghost user auto-creation,
//! and the AS transaction pusher.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

use conduit::storage::Storage;

// ---------------------------------------------------------------------------
// Registration YAML shape (AS1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AsRegistration {
    pub id: String,
    /// `null` (or absent) means the AS has no URL: the homeserver never
    /// pushes to it, and `/appservice/{id}/ping` answers `M_URL_NOT_SET`.
    #[serde(default, deserialize_with = "null_as_empty")]
    pub url: String,
    pub as_token: String,
    pub hs_token: String,
    pub sender_localpart: String,
    #[serde(default)]
    pub rate_limited: bool,
    #[serde(default)]
    pub namespaces: AsNamespaces,
    /// Third-party protocols the AS bridges (`GET /thirdparty/protocols`).
    #[serde(default)]
    pub protocols: Vec<String>,
    /// Whether the AS wants ephemeral data (typing, receipts, presence) in
    /// its transactions (spec v1.13).  The MSC2409 key is accepted as an
    /// alias for registrations written before stabilisation.
    #[serde(default, alias = "de.sorunome.msc2409.push_ephemeral")]
    pub receive_ephemeral: bool,
}

fn null_as_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AsNamespaces {
    #[serde(default)]
    pub users: Vec<AsNamespaceEntry>,
    #[serde(default)]
    pub aliases: Vec<AsNamespaceEntry>,
    #[serde(default)]
    pub rooms: Vec<AsNamespaceEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AsNamespaceEntry {
    pub exclusive: bool,
    pub regex: String,
}

/// A loaded + compiled Application Service registration.
#[derive(Debug, Clone)]
pub struct AppService {
    pub id: String,
    pub url: String,
    /// Raw `as_token` for inbound CS-API calls (Bearer <as_token>).
    pub as_token: String,
    /// `hs_token` used as `?access_token` when pushing to the AS.
    pub hs_token: String,
    pub sender_localpart: String,
    pub rate_limited: bool,
    /// Compiled namespace regexes.
    pub user_namespaces: Vec<(bool, Regex)>,
    pub alias_namespaces: Vec<(bool, Regex)>,
    pub room_namespaces: Vec<(bool, Regex)>,
    /// Third-party protocols this AS bridges (registration `protocols`).
    pub protocols: Vec<String>,
    /// Push ephemeral data in transactions (registration `receive_ephemeral`).
    pub receive_ephemeral: bool,
}

impl AppService {
    /// The AS's own user, `@{sender_localpart}:{server_name}`.
    pub fn sender_user_id(&self, server_name: &str) -> String {
        format!("@{}:{}", self.sender_localpart, server_name)
    }

    /// Whether `user_id` is the AS sender or lies in its `users`
    /// namespaces (exclusive or not).
    pub fn is_interested_in_user(&self, user_id: &str, server_name: &str) -> bool {
        user_id == self.sender_user_id(server_name) || user_in_as_namespace(user_id, self)
    }

    /// Whether `room_id` lies in the AS's `rooms` namespaces.
    pub fn is_interested_in_room_id(&self, room_id: &str) -> bool {
        self.room_namespaces.iter().any(|(_, re)| re.is_match(room_id))
    }

    /// Whether `alias` lies in the AS's `aliases` namespaces.
    pub fn is_interested_in_alias(&self, alias: &str) -> bool {
        self.alias_namespaces.iter().any(|(_, re)| re.is_match(alias))
    }
}

// ---------------------------------------------------------------------------
// AS loading (AS1)
// ---------------------------------------------------------------------------

/// Load all AS registration YAML files from the given directory.
/// Silently skips unparseable files (logs warning).
pub fn load_app_services(dir: &str) -> Vec<AppService> {
    let path = Path::new(dir);
    if !path.exists() {
        info!(dir, "AS registrations directory does not exist; no app services loaded");
        return vec![];
    }

    let mut services = Vec::new();
    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(err) => {
            warn!(dir, error = %err, "failed to read AS registrations directory");
            return vec![];
        }
    };

    for entry in entries.flatten() {
        let file_path = entry.path();
        if file_path.extension().and_then(|e| e.to_str()) != Some("yaml")
            && file_path.extension().and_then(|e| e.to_str()) != Some("yml")
        {
            continue;
        }

        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(err) => {
                warn!(path = ?file_path, error = %err, "failed to read AS registration file");
                continue;
            }
        };

        let reg: AsRegistration = match serde_yaml::from_str(&content) {
            Ok(r) => r,
            Err(err) => {
                warn!(path = ?file_path, error = %err, "failed to parse AS registration YAML");
                continue;
            }
        };

        match compile_registration(reg) {
            Ok(svc) => {
                info!(id = svc.id, "loaded application service registration");
                services.push(svc);
            }
            Err(err) => {
                warn!(path = ?file_path, error = %err, "invalid AS registration");
            }
        }
    }

    services
}

fn compile_registration(reg: AsRegistration) -> Result<AppService, String> {
    let compile = |entries: &[AsNamespaceEntry]| -> Result<Vec<(bool, Regex)>, String> {
        entries.iter().map(|e| {
            Regex::new(&e.regex)
                .map(|re| (e.exclusive, re))
                .map_err(|err| format!("invalid regex '{}': {err}", e.regex))
        }).collect()
    };

    Ok(AppService {
        id: reg.id,
        url: reg.url,
        as_token: reg.as_token,
        hs_token: reg.hs_token,
        sender_localpart: reg.sender_localpart,
        rate_limited: reg.rate_limited,
        user_namespaces: compile(&reg.namespaces.users)?,
        alias_namespaces: compile(&reg.namespaces.aliases)?,
        room_namespaces: compile(&reg.namespaces.rooms)?,
        protocols: reg.protocols,
        receive_ephemeral: reg.receive_ephemeral,
    })
}

// ---------------------------------------------------------------------------
// Namespace checks (AS2)
// ---------------------------------------------------------------------------

/// Returns the AS that exclusively owns this user_id, if any.
pub fn exclusive_as_for_user<'a>(
    user_id: &str,
    services: &'a [AppService],
) -> Option<&'a AppService> {
    for svc in services {
        for (exclusive, re) in &svc.user_namespaces {
            if *exclusive && re.is_match(user_id) {
                return Some(svc);
            }
        }
    }
    None
}

/// Returns the AS that exclusively owns this alias, if any.
pub fn exclusive_as_for_alias<'a>(
    alias: &str,
    services: &'a [AppService],
) -> Option<&'a AppService> {
    for svc in services {
        for (exclusive, re) in &svc.alias_namespaces {
            if *exclusive && re.is_match(alias) {
                return Some(svc);
            }
        }
    }
    None
}

/// Check whether the given user_id falls within the AS's user namespace.
pub fn user_in_as_namespace(user_id: &str, svc: &AppService) -> bool {
    svc.user_namespaces.iter().any(|(_, re)| re.is_match(user_id))
}

// ---------------------------------------------------------------------------
// Existence queries (AS6, conduit-dhd)
// ---------------------------------------------------------------------------

/// Return the AS whose user namespace matches `user_id`, exclusive or not.
pub fn as_for_user<'a>(user_id: &str, services: &'a [AppService]) -> Option<&'a AppService> {
    services
        .iter()
        .find(|s| s.user_namespaces.iter().any(|(_, re)| re.is_match(user_id)))
}

/// Return the AS whose alias namespace matches `alias`, exclusive or not.
pub fn as_for_alias<'a>(alias: &str, services: &'a [AppService]) -> Option<&'a AppService> {
    services
        .iter()
        .find(|s| s.alias_namespaces.iter().any(|(_, re)| re.is_match(alias)))
}

/// Ask the matching AS whether it owns `user_id` by calling
/// `GET {as.url}/_matrix/app/v1/users/{userId}` with
/// `Authorization: Bearer {hs_token}` (legacy `/users/{userId}` fallback).
/// Returns true on 2xx; false on 4xx/5xx, network error, or no matching AS.
///
/// The AS is expected to call back to the HS to create the user account if
/// needed, so callers should re-check storage after this returns true.
///
/// **Perf / abuse follow-up (conduit-c3u):** no negative cache today, so
/// repeated misses amplify into AS HTTP traffic. Add a short-TTL LRU keyed
/// on `(svc.id, user_id)` to absorb that.
pub async fn query_as_user(
    http: &reqwest::Client,
    services: &[AppService],
    user_id: &str,
) -> bool {
    let Some(svc) = as_for_user(user_id, services) else {
        return false;
    };
    let path = format!("users/{}", urlencode_path(user_id));
    query_as(http, svc, &path).await
}

/// Ask the matching AS whether it owns `alias`
/// (`GET /_matrix/app/v1/rooms/{roomAlias}`, legacy `/rooms/{roomAlias}`).
pub async fn query_as_alias(
    http: &reqwest::Client,
    services: &[AppService],
    alias: &str,
) -> bool {
    let Some(svc) = as_for_alias(alias, services) else {
        return false;
    };
    let path = format!("rooms/{}", urlencode_path(alias));
    query_as(http, svc, &path).await
}

/// How many times a user/alias query is attempted on a network error or
/// 5xx ("the homeserver should retry several times before timing out").
const QUERY_ATTEMPTS: usize = 3;

async fn query_as(http: &reqwest::Client, svc: &AppService, path: &str) -> bool {
    if svc.url.is_empty() {
        return false;
    }
    for attempt in 0..QUERY_ATTEMPTS {
        match as_request(http, svc, reqwest::Method::GET, path, None).await {
            Ok(status) if (200..300).contains(&status) => return true,
            Ok(status) if status < 500 => {
                tracing::debug!(as_id = svc.id, status, path, "AS query miss");
                return false;
            }
            Ok(status) => warn!(as_id = svc.id, status, path, attempt, "AS query failed"),
            Err(e) => warn!(as_id = svc.id, error = %e, path, attempt, "AS query failed"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(200 << attempt)).await;
    }
    false
}

/// Send one homeserver -> AS request, authorised with
/// `Authorization: Bearer {hs_token}` (spec v1.4+; no query token).
///
/// `path` is relative to `/_matrix/app/v1/`.  If the AS does not know the
/// route (404, or 405 `M_UNRECOGNIZED`), the legacy unprefixed route is
/// tried with the `access_token` query parameter the legacy spec used
/// (spec: legacy routes).  The current route is always tried first, so an
/// upgraded AS is picked up on the next request.  Returns the final HTTP
/// status.
pub async fn as_request(
    http: &reqwest::Client,
    svc: &AppService,
    method: reqwest::Method,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<u16, reqwest::Error> {
    let base = svc.url.trim_end_matches('/');
    let send = |url: String, legacy: bool| {
        let mut req = http
            .request(method.clone(), url)
            .bearer_auth(&svc.hs_token)
            .timeout(std::time::Duration::from_secs(30));
        if legacy {
            req = req.query(&[("access_token", svc.hs_token.as_str())]);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        req.send()
    };
    let status = send(format!("{base}/_matrix/app/v1/{path}"), false).await?.status().as_u16();
    if status == 404 || status == 405 {
        let legacy = send(format!("{base}/{path}"), true).await?.status().as_u16();
        if (200..300).contains(&legacy) {
            tracing::info!(as_id = svc.id, path, "AS answered on its legacy route");
        }
        return Ok(legacy);
    }
    Ok(status)
}

/// Percent-encode a path segment for URL safety.
fn urlencode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            other => {
                out.push('%');
                out.push_str(&format!("{other:02X}"));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// AS authentication extractor (AS3)
// ---------------------------------------------------------------------------

/// Extracted when a request carries a valid AS `as_token` Bearer.
#[derive(Debug, Clone)]
pub struct AsAuthed {
    /// The authenticated application service.
    pub service: Arc<AppService>,
    /// The `?user_id=` impersonation target (if provided).
    pub acting_as: Option<String>,
}

/// Trait for state types that carry the AS list.
pub trait AsState: Clone + Send + Sync + 'static {
    fn app_services(&self) -> &Arc<Vec<AppService>>;
    fn storage(&self) -> &Arc<dyn Storage>;
}

/// Ensure a ghost account exists for a user the AS is acting-as (conduit-5vr).
///
/// If `get_account` returns None, this calls `create_account(user_id, None)`
/// — a minimal, password-less account owned by the AS via its namespace
/// regex.  Idempotent: a race that loses the create is silently ignored.
pub async fn ensure_ghost_account(storage: &Arc<dyn Storage>, user_id: &str) {
    match storage.get_account(user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            if let Err(e) = storage.create_account(user_id, None).await {
                // Race or duplicate — log and move on.
                tracing::debug!(user_id, error = %e, "AS ghost create_account skipped");
            } else {
                tracing::info!(user_id, "AS ghost user auto-created");
            }
        }
        Err(e) => tracing::warn!(user_id, error = %e, "AS ghost lookup failed"),
    }
}

/// A decoded query-string parameter (`None` when absent or empty).
pub fn query_param(parts: &Parts, name: &str) -> Option<String> {
    let query = parts.uri.query()?;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .filter(|v| !v.is_empty())
}

#[async_trait]
impl<S: AsState> FromRequestParts<S> for AsAuthed {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract Bearer token from Authorization header.
        let token = parts.headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_owned())
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, Json(json!({
                    "errcode": "M_MISSING_TOKEN",
                    "error": "Missing access token"
                }))).into_response()
            })?;

        // Match against configured AS tokens.
        let services = state.app_services();
        let svc = services.iter().find(|s| s.as_token == token)
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, Json(json!({
                    "errcode": "M_UNKNOWN_TOKEN",
                    "error": "Unrecognised access token"
                }))).into_response()
            })?;

        // Extract ?user_id= query param if present.
        let acting_as = query_param(parts, "user_id");

        // Validate that user_id falls within AS's user namespace.
        if let Some(ref uid) = acting_as {
            if !user_in_as_namespace(uid, svc) {
                return Err((StatusCode::FORBIDDEN, Json(json!({
                    "errcode": "M_FORBIDDEN",
                    "error": "user_id is outside the AS's user namespace"
                }))).into_response());
            }
            // Auto-create ghost account on first use (conduit-5vr / AS4).
            ensure_ghost_account(state.storage(), uid).await;
        }

        Ok(AsAuthed {
            service: Arc::new(svc.clone()),
            acting_as,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_svc(url: &str, ns: &str) -> AppService {
        AppService {
            id: "test".to_owned(),
            url: url.to_owned(),
            as_token: "ast".to_owned(),
            hs_token: "hst".to_owned(),
            sender_localpart: "bot".to_owned(),
            rate_limited: false,
            user_namespaces: vec![(true, Regex::new(ns).unwrap())],
            alias_namespaces: vec![(true, Regex::new(ns).unwrap())],
            room_namespaces: vec![],
            protocols: vec![],
            receive_ephemeral: false,
        }
    }

    /// Mock AS that returns the given status for `GET /_matrix/app/v1/users/:userId`.
    async fn mock_as(status: u16) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{routing::get, Router};
        let app = Router::new().route(
            "/_matrix/app/v1/users/:user_id",
            get(move || async move {
                axum::http::StatusCode::from_u16(status).unwrap()
            }),
        )
        .route(
            "/_matrix/app/v1/rooms/:alias",
            get(move || async move {
                axum::http::StatusCode::from_u16(status).unwrap()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (url, handle)
    }

    #[tokio::test]
    async fn query_as_user_returns_true_on_200() {
        let (url, _h) = mock_as(200).await;
        let svc = build_svc(&url, r"^@bot_.*:localhost$");
        let http = reqwest::Client::new();
        let services = vec![svc];
        assert!(query_as_user(&http, &services, "@bot_alice:localhost").await);
    }

    #[tokio::test]
    async fn query_as_user_returns_false_on_404() {
        let (url, _h) = mock_as(404).await;
        let svc = build_svc(&url, r"^@bot_.*:localhost$");
        let http = reqwest::Client::new();
        let services = vec![svc];
        assert!(!query_as_user(&http, &services, "@bot_alice:localhost").await);
    }

    #[tokio::test]
    async fn query_as_user_returns_false_when_no_namespace_match() {
        let (url, _h) = mock_as(200).await;
        // Namespace doesn't cover @human:localhost.
        let svc = build_svc(&url, r"^@bot_.*:localhost$");
        let http = reqwest::Client::new();
        let services = vec![svc];
        assert!(!query_as_user(&http, &services, "@human:localhost").await);
    }

    /// Records `(path, authorization, query)` of every request; answers 200
    /// only on the legacy unprefixed route and only with the legacy query
    /// token, 404 elsewhere.
    async fn legacy_only_as() -> (String, Arc<std::sync::Mutex<Vec<(String, Option<String>, Option<String>)>>>) {
        use axum::{extract::Request, Router};
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let app = Router::new().fallback(move |req: Request| {
            let log = Arc::clone(&log);
            async move {
                let path = req.uri().path().to_owned();
                let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_owned);
                let query = req.uri().query().map(str::to_owned);
                log.lock().unwrap().push((path.clone(), auth, query.clone()));
                if path.starts_with("/users/") && query.as_deref() == Some("access_token=hst") {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (url, seen)
    }

    #[tokio::test]
    async fn queries_use_bearer_first_then_fall_back_to_legacy_routes() {
        let (url, seen) = legacy_only_as().await;
        let services = vec![build_svc(&url, r"^@bot_.*:localhost$")];
        let http = reqwest::Client::new();
        assert!(query_as_user(&http, &services, "@bot_a:localhost").await);
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2, "{seen:?}");
        // Current route: Bearer only, no query-string token.
        assert_eq!(seen[0].0, "/_matrix/app/v1/users/%40bot_a%3Alocalhost");
        assert_eq!(seen[0].1.as_deref(), Some("Bearer hst"));
        assert_eq!(seen[0].2, None);
        // Legacy route: unprefixed, with the legacy query token.
        assert_eq!(seen[1].0, "/users/%40bot_a%3Alocalhost");
        assert_eq!(seen[1].2.as_deref(), Some("access_token=hst"));
    }

    #[tokio::test]
    async fn query_as_alias_returns_true_on_200() {
        let (url, _h) = mock_as(200).await;
        let svc = build_svc(&url, r"^#bridge_.*:localhost$");
        let http = reqwest::Client::new();
        let services = vec![svc];
        assert!(query_as_alias(&http, &services, "#bridge_irc:localhost").await);
    }

    #[tokio::test]
    async fn ensure_ghost_account_creates_when_absent() {
        use conduit::storage::MemoryStorage;
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::default());
        assert!(storage.get_account("@ghost:localhost").await.unwrap().is_none());
        ensure_ghost_account(&storage, "@ghost:localhost").await;
        let acct = storage.get_account("@ghost:localhost").await.unwrap().unwrap();
        assert_eq!(acct.user_id, "@ghost:localhost");
        assert!(acct.password_hash.is_none());
        assert!(!acct.is_admin);
    }

    #[tokio::test]
    async fn ensure_ghost_account_is_idempotent() {
        use conduit::storage::MemoryStorage;
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::default());
        ensure_ghost_account(&storage, "@ghost:localhost").await;
        // Second call must not panic or duplicate.
        ensure_ghost_account(&storage, "@ghost:localhost").await;
        let acct = storage.get_account("@ghost:localhost").await.unwrap().unwrap();
        assert_eq!(acct.user_id, "@ghost:localhost");
    }
}

