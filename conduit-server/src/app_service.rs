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
use tokio::sync::Mutex;
use tracing::{info, warn};

use conduit::storage::Storage;

// ---------------------------------------------------------------------------
// Registration YAML shape (AS1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AsRegistration {
    pub id: String,
    pub url: String,
    pub as_token: String,
    pub hs_token: String,
    pub sender_localpart: String,
    #[serde(default)]
    pub rate_limited: bool,
    #[serde(default)]
    pub namespaces: AsNamespaces,
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
        let acting_as = parts.uri.query()
            .and_then(|q| {
                // Simple extraction without a full query parser.
                q.split('&')
                    .find(|p| p.starts_with("user_id="))
                    .map(|p| p["user_id=".len()..].to_owned())
            });

        // Validate that user_id falls within AS's user namespace.
        if let Some(ref uid) = acting_as {
            if !user_in_as_namespace(uid, svc) {
                return Err((StatusCode::FORBIDDEN, Json(json!({
                    "errcode": "M_FORBIDDEN",
                    "error": "user_id is outside the AS's user namespace"
                }))).into_response());
            }
        }

        Ok(AsAuthed {
            service: Arc::new(svc.clone()),
            acting_as,
        })
    }
}

// ---------------------------------------------------------------------------
// AS transaction pusher (AS5, AS7)
// ---------------------------------------------------------------------------

/// Per-AS outbound transaction queue entry.
#[derive(Debug, Clone)]
pub struct AsQueueEntry {
    pub event_json: serde_json::Value,
}

/// Per-AS queue: a list of pending events to deliver.
#[derive(Debug, Default)]
pub struct AsQueue {
    pub entries: Mutex<Vec<AsQueueEntry>>,
    pub next_txn_id: Mutex<u64>,
}

impl AsQueue {
    pub async fn push(&self, entry: AsQueueEntry) {
        self.entries.lock().await.push(entry);
    }

    pub async fn drain(&self) -> (u64, Vec<AsQueueEntry>) {
        let mut id = self.next_txn_id.lock().await;
        *id += 1;
        let txn_id = *id;
        let entries = std::mem::take(&mut *self.entries.lock().await);
        (txn_id, entries)
    }
}

/// Collection of per-AS queues, keyed by AS id.
pub struct AsQueues {
    pub queues: std::collections::HashMap<String, Arc<AsQueue>>,
}

impl AsQueues {
    pub fn new(services: &[AppService]) -> Self {
        let queues = services.iter()
            .map(|s| (s.id.clone(), Arc::new(AsQueue::default())))
            .collect();
        Self { queues }
    }
}

/// Spawn the AS transaction pusher workers. One task per AS.
pub fn spawn_as_workers(
    services: Arc<Vec<AppService>>,
    queues: Arc<AsQueues>,
    http: reqwest::Client,
    mut events_rx: tokio::sync::broadcast::Receiver<i64>,
    storage: Arc<dyn Storage>,
) {
    // Spawn a single dispatcher task that fans events to each AS queue.
    let services_clone = Arc::clone(&services);
    let queues_clone = Arc::clone(&queues);
    let storage_clone = Arc::clone(&storage);

    tokio::spawn(async move {
        loop {
            let stream_pos = match events_rx.recv().await {
                Ok(pos) => pos,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!(missed = n, "AS worker lagged behind event broadcast");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };

            // Fetch the event.
            let events = match storage_clone.events_since(stream_pos - 1, 1).await {
                Ok(evs) => evs,
                Err(e) => {
                    warn!(error = %e, "AS worker: events_since failed");
                    continue;
                }
            };

            let event = match events.into_iter().next() {
                Some(e) => e,
                None => continue,
            };

            let event_json = match serde_json::to_value(&event) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Check which ASes care about this event.
            let room_id = &event.room_id;
            let sender = &event.sender;

            for svc in services_clone.iter() {
                let relevant = svc.user_namespaces.iter().any(|(_, re)| re.is_match(sender))
                    || svc.alias_namespaces.iter().any(|(_, re)| re.is_match(room_id))
                    || svc.room_namespaces.iter().any(|(_, re)| re.is_match(room_id));

                if !relevant {
                    continue;
                }

                if let Some(queue) = queues_clone.queues.get(&svc.id) {
                    queue.push(AsQueueEntry { event_json: event_json.clone() }).await;
                }
            }
        }
    });

    // Spawn a flush task per AS.
    for svc in services.iter() {
        let svc_id = svc.id.clone();
        let svc_url = svc.url.clone();
        let hs_token = svc.hs_token.clone();
        let queue = match queues.queues.get(&svc_id) {
            Some(q) => Arc::clone(q),
            None => continue,
        };
        let http_clone = http.clone();

        tokio::spawn(async move {
            // Flush every 500ms.
            let interval = std::time::Duration::from_millis(500);
            loop {
                tokio::time::sleep(interval).await;

                let (txn_id, entries) = queue.drain().await;
                if entries.is_empty() {
                    continue;
                }

                let events: Vec<_> = entries.into_iter().map(|e| e.event_json).collect();
                let body = serde_json::json!({ "events": events });
                let url = format!(
                    "{}/_matrix/app/v1/transactions/{}?access_token={}",
                    svc_url.trim_end_matches('/'),
                    txn_id,
                    hs_token
                );

                let resp = http_clone.put(&url).json(&body).send().await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        tracing::debug!(as_id = svc_id, txn_id, events = events.len() as i64, "AS transaction delivered");
                        // Note: events variable is moved; we logged its len already via events.len() before moving.
                    }
                    Ok(r) => {
                        warn!(as_id = svc_id, status = r.status().as_u16(), "AS transaction rejected");
                    }
                    Err(e) => {
                        warn!(as_id = svc_id, error = %e, "AS transaction delivery failed");
                    }
                }
            }
        });
    }
}
