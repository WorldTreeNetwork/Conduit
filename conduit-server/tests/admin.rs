//! Integration tests for E11 Admin API (AD1–AD6).
//!
//! Covers:
//!   - dd8.14 AD1: admin role flag (non-admin rejected, AdminAuthed extractor)
//!   - dd8.15 AD2: user management (list, deactivate, reset password, promote)
//!   - dd8.16 AD3: room management (list rooms, purge)
//!   - dd8.17 AD4: media management (list)
//!   - dd8.18 AD5: federation peers (stub endpoint)
//!   - dd8.19 AD6: audit log records admin actions
//!
//! # Running
//! ```
//! DATABASE_URL=postgresql://postgres@localhost/conduit \
//!     cargo test --workspace --tests
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::{delete, get, post, put},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::{RwLock, broadcast};
use tower::util::ServiceExt as _;

use conduit::keys::ServerKey;
use conduit::storage::Storage;
use conduit_server::{
    PostgresStorage,
    api::client::{self as auth, AuthState, TxnCacheKey, TypingStore, PresenceStore},
    api::admin as admin_api,
};

// ---------------------------------------------------------------------------
// Simple percent-encode for characters that must be encoded in URL path segments.
// ---------------------------------------------------------------------------
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            // unreserved characters per RFC 3986 — pass through
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{:02X}", b);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// TempDb
// ---------------------------------------------------------------------------

struct TempDb {
    admin_url: String,
    db_name: String,
    pool: PgPool,
}

impl TempDb {
    async fn new() -> Self {
        let admin_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres@localhost/postgres".to_owned());

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let tid = format!("{:?}", std::thread::current().id())
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();
        let db_name = format!("conduit_test_admin_{}_{}", tid, nanos).to_lowercase();

        let admin_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&admin_url)
            .await
            .expect("connect to admin postgres");

        sqlx::query(&format!("CREATE DATABASE {db_name}"))
            .execute(&admin_pool)
            .await
            .unwrap_or_else(|e| panic!("CREATE DATABASE {db_name}: {e}"));
        admin_pool.close().await;

        let test_url = replace_db_in_url(&admin_url, &db_name);
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&test_url)
            .await
            .unwrap_or_else(|e| panic!("connect to {db_name}: {e}"));

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .unwrap_or_else(|e| panic!("migrations on {db_name}: {e}"));

        TempDb { admin_url, db_name, pool }
    }

    fn storage(&self) -> Arc<dyn Storage> {
        PostgresStorage::new(self.pool.clone()).into_arc()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::process::Command::new("psql")
            .args([
                &self.admin_url,
                "-c",
                &format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.db_name),
            ])
            .output();
    }
}

fn replace_db_in_url(url: &str, new_db: &str) -> String {
    let url = url.trim_end_matches('/');
    if let Some(pos) = url.rfind('/') {
        format!("{}/{}", &url[..pos], new_db)
    } else {
        format!("{}/{}", url, new_db)
    }
}

// ---------------------------------------------------------------------------
// TestState
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TestState {
    storage: Arc<dyn Storage>,
    server_name: Arc<str>,
    server_key: Arc<ServerKey>,
    txn_cache: Arc<RwLock<HashMap<TxnCacheKey, String>>>,
    events_tx: broadcast::Sender<i64>,
    typing_store: Arc<TypingStore>,
    typing_tx: broadcast::Sender<String>,
    presence_store: Arc<PresenceStore>,
}

impl AuthState for TestState {
    fn storage(&self) -> &Arc<dyn Storage> { &self.storage }
    fn server_name(&self) -> &str { &self.server_name }
    fn server_key(&self) -> Arc<ServerKey> { Arc::clone(&self.server_key) }
    fn txn_cache(&self) -> &Arc<RwLock<HashMap<TxnCacheKey, String>>> { &self.txn_cache }
    fn events_tx(&self) -> &broadcast::Sender<i64> { &self.events_tx }
    fn typing_store(&self) -> &Arc<TypingStore> { &self.typing_store }
    fn typing_tx(&self) -> &broadcast::Sender<String> { &self.typing_tx }
    fn presence_store(&self) -> &Arc<PresenceStore> { &self.presence_store }
}

fn make_state(storage: Arc<dyn Storage>) -> TestState {
    let (events_tx, _) = broadcast::channel(256);
    let (typing_store, typing_tx) = TypingStore::new();
    let presence_store = PresenceStore::new();
    TestState {
        storage,
        server_name: "localhost".into(),
        server_key: Arc::new(conduit::keys::generate_server_key()),
        txn_cache: Arc::new(RwLock::new(HashMap::new())),
        events_tx,
        typing_store,
        typing_tx,
        presence_store,
    }
}

fn build_router(state: TestState) -> Router {
    Router::new()
        .route("/_matrix/client/v3/register", post(auth::register::<TestState>))
        .route("/_matrix/client/v3/login",
            get(auth::get_login_flows).post(auth::login::<TestState>))
        .route("/_matrix/client/v3/logout", post(auth::logout::<TestState>))
        // Admin endpoints
        .route("/_matrix/conduit/admin/v1/users",
            get(admin_api::list_users::<TestState>))
        .route("/_matrix/conduit/admin/v1/users/:userId",
            get(admin_api::get_user::<TestState>))
        .route("/_matrix/conduit/admin/v1/users/:userId/deactivate",
            post(admin_api::deactivate_user::<TestState>))
        .route("/_matrix/conduit/admin/v1/users/:userId/reset_password",
            post(admin_api::reset_password::<TestState>))
        .route("/_matrix/conduit/admin/v1/users/:userId/admin",
            post(admin_api::set_admin::<TestState>))
        .route("/_matrix/conduit/admin/v1/rooms",
            get(admin_api::list_rooms::<TestState>))
        .route("/_matrix/conduit/admin/v1/rooms/:roomId/purge",
            post(admin_api::purge_room::<TestState>))
        .route("/_matrix/conduit/admin/v1/media",
            get(admin_api::list_media::<TestState>))
        .route("/_matrix/conduit/admin/v1/federation/peers",
            get(admin_api::list_federation_peers::<TestState>))
        .route("/_matrix/conduit/admin/v1/federation/disable",
            post(admin_api::disable_federation::<TestState>))
        .route("/_matrix/conduit/admin/v1/audit",
            get(admin_api::get_audit_log::<TestState>))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn do_register(app: &Router, username: &str, password: &str) -> Value {
    let body = json!({
        "username": username,
        "password": password,
        "auth": { "type": "m.login.dummy" }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/register")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register failed for {username}");
    json_body(resp).await
}

async fn authed_get(app: &Router, uri: &str, token: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

async fn authed_post(app: &Router, uri: &str, token: &str, body: Value) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

/// Promote a user to admin directly via storage (bypass API since you need an
/// existing admin to call the API endpoint).
async fn promote_to_admin(storage: &Arc<dyn Storage>, user_id: &str) {
    storage.set_admin(user_id, true).await.unwrap();
}

// ---------------------------------------------------------------------------
// Test: non_admin_rejected (dd8.14 AD1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_admin_rejected() {
    let db = TempDb::new().await;
    let storage = db.storage();
    let app = build_router(make_state(Arc::clone(&storage)));

    let body = do_register(&app, "alice", "pass").await;
    let token = body["access_token"].as_str().unwrap();

    // Non-admin calling an admin endpoint → 403 Forbidden.
    let resp = authed_get(&app, "/_matrix/conduit/admin/v1/users", token).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = json_body(resp).await;
    assert_eq!(body["errcode"].as_str().unwrap(), "M_FORBIDDEN");
}

// ---------------------------------------------------------------------------
// Test: admin_can_list_users (dd8.15 AD2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_can_list_users() {
    let db = TempDb::new().await;
    let storage = db.storage();
    let app = build_router(make_state(Arc::clone(&storage)));

    let a = do_register(&app, "admin_user", "pass").await;
    let admin_token = a["access_token"].as_str().unwrap().to_owned();
    let admin_uid = a["user_id"].as_str().unwrap().to_owned();

    let _ = do_register(&app, "normal_user", "pass").await;

    // Promote admin_user to admin.
    promote_to_admin(&storage, &admin_uid).await;

    let resp = authed_get(&app, "/_matrix/conduit/admin/v1/users", &admin_token).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = json_body(resp).await;
    let users = body["users"].as_array().unwrap();
    assert!(users.len() >= 2, "should list both users");

    let admin_entry = users.iter().find(|u| u["user_id"].as_str() == Some(&admin_uid));
    assert!(admin_entry.is_some());
    assert!(admin_entry.unwrap()["is_admin"].as_bool().unwrap());
}

// ---------------------------------------------------------------------------
// Test: admin_can_deactivate (dd8.15 AD2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_can_deactivate() {
    let db = TempDb::new().await;
    let storage = db.storage();
    let app = build_router(make_state(Arc::clone(&storage)));

    let a = do_register(&app, "adm", "pass").await;
    let admin_token = a["access_token"].as_str().unwrap().to_owned();
    let admin_uid = a["user_id"].as_str().unwrap().to_owned();

    let v = do_register(&app, "victim", "pass").await;
    let victim_uid = v["user_id"].as_str().unwrap().to_owned();

    promote_to_admin(&storage, &admin_uid).await;

    // Deactivate victim.
    let uri = format!("/_matrix/conduit/admin/v1/users/{}/deactivate",
        pct_encode(&victim_uid));
    let resp = authed_post(&app, &uri, &admin_token, json!({})).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Check via get_user — deactivated=true.
    let get_uri = format!("/_matrix/conduit/admin/v1/users/{}", pct_encode(&victim_uid));
    let resp = authed_get(&app, &get_uri, &admin_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["deactivated"].as_bool().unwrap(), "victim should be deactivated");
}

// ---------------------------------------------------------------------------
// Test: audit_log_records (dd8.19 AD6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn audit_log_records_admin_actions() {
    let db = TempDb::new().await;
    let storage = db.storage();
    let app = build_router(make_state(Arc::clone(&storage)));

    let a = do_register(&app, "logger_admin", "pass").await;
    let admin_token = a["access_token"].as_str().unwrap().to_owned();
    let admin_uid = a["user_id"].as_str().unwrap().to_owned();

    let v = do_register(&app, "target_user", "pass").await;
    let target_uid = v["user_id"].as_str().unwrap().to_owned();

    promote_to_admin(&storage, &admin_uid).await;

    // Perform a deactivate action.
    let uri = format!("/_matrix/conduit/admin/v1/users/{}/deactivate",
        pct_encode(&target_uid));
    let resp = authed_post(&app, &uri, &admin_token, json!({})).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Fetch audit log.
    let resp = authed_get(&app, "/_matrix/conduit/admin/v1/audit", &admin_token).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = json_body(resp).await;
    let entries = body["entries"].as_array().unwrap();
    assert!(!entries.is_empty(), "audit log should have at least one entry");

    // Most recent entry should be the deactivate action.
    let entry = entries.iter().find(|e| e["action"].as_str() == Some("deactivate_user"));
    assert!(entry.is_some(), "deactivate_user should appear in audit log");
    let entry = entry.unwrap();
    assert_eq!(entry["admin_user"].as_str().unwrap(), admin_uid);
    assert_eq!(entry["target"].as_str().unwrap(), target_uid);
}

// ---------------------------------------------------------------------------
// Test: admin_can_reset_password (dd8.15 AD2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_can_reset_password() {
    let db = TempDb::new().await;
    let storage = db.storage();
    let app = build_router(make_state(Arc::clone(&storage)));

    let a = do_register(&app, "admin_pwd", "pass").await;
    let admin_token = a["access_token"].as_str().unwrap().to_owned();
    let admin_uid = a["user_id"].as_str().unwrap().to_owned();

    let v = do_register(&app, "user_to_reset", "oldpass").await;
    let victim_uid = v["user_id"].as_str().unwrap().to_owned();

    promote_to_admin(&storage, &admin_uid).await;

    // Reset password.
    let uri = format!("/_matrix/conduit/admin/v1/users/{}/reset_password",
        pct_encode(&victim_uid));
    let resp = authed_post(
        &app, &uri, &admin_token,
        json!({ "new_password": "newpass123" }),
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Audit log should have the reset_password entry.
    let resp = authed_get(&app, "/_matrix/conduit/admin/v1/audit", &admin_token).await;
    let body = json_body(resp).await;
    let entries = body["entries"].as_array().unwrap();
    let entry = entries.iter().find(|e| e["action"].as_str() == Some("reset_password"));
    assert!(entry.is_some(), "reset_password should appear in audit log");
}

// ---------------------------------------------------------------------------
// Test: admin_can_list_rooms (dd8.16 AD3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_can_list_rooms() {
    let db = TempDb::new().await;
    let storage = db.storage();
    let app = build_router(make_state(Arc::clone(&storage)));

    let a = do_register(&app, "room_admin", "pass").await;
    let admin_token = a["access_token"].as_str().unwrap().to_owned();
    let admin_uid = a["user_id"].as_str().unwrap().to_owned();

    promote_to_admin(&storage, &admin_uid).await;

    // Initially no rooms.
    let resp = authed_get(&app, "/_matrix/conduit/admin/v1/rooms", &admin_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["rooms"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Test: admin_can_list_media (dd8.17 AD4)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_can_list_media() {
    let db = TempDb::new().await;
    let storage = db.storage();
    let app = build_router(make_state(Arc::clone(&storage)));

    let a = do_register(&app, "media_admin", "pass").await;
    let admin_token = a["access_token"].as_str().unwrap().to_owned();
    let admin_uid = a["user_id"].as_str().unwrap().to_owned();

    promote_to_admin(&storage, &admin_uid).await;

    // List media — initially empty.
    let resp = authed_get(&app, "/_matrix/conduit/admin/v1/media", &admin_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["media"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Test: federation peers stub (dd8.18 AD5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_federation_peers_stub() {
    let db = TempDb::new().await;
    let storage = db.storage();
    let app = build_router(make_state(Arc::clone(&storage)));

    let a = do_register(&app, "fed_admin", "pass").await;
    let admin_token = a["access_token"].as_str().unwrap().to_owned();
    let admin_uid = a["user_id"].as_str().unwrap().to_owned();

    promote_to_admin(&storage, &admin_uid).await;

    // GET federation peers — v0 stub returns empty list.
    let resp = authed_get(&app, "/_matrix/conduit/admin/v1/federation/peers", &admin_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["peers"].as_array().unwrap().len(), 0);

    // POST disable federation — v0 stub logs audit and returns OK.
    let resp = authed_post(
        &app,
        "/_matrix/conduit/admin/v1/federation/disable",
        &admin_token,
        json!({ "destination": "evil.server.example.com" }),
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Test: set_admin promote/demote (dd8.15 AD2, dd8.14 AD1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_can_promote_and_demote() {
    let db = TempDb::new().await;
    let storage = db.storage();
    let app = build_router(make_state(Arc::clone(&storage)));

    let a = do_register(&app, "super_admin", "pass").await;
    let admin_token = a["access_token"].as_str().unwrap().to_owned();
    let admin_uid = a["user_id"].as_str().unwrap().to_owned();

    let n = do_register(&app, "new_user", "pass").await;
    let new_uid = n["user_id"].as_str().unwrap().to_owned();

    promote_to_admin(&storage, &admin_uid).await;

    // Promote new_user.
    let uri = format!("/_matrix/conduit/admin/v1/users/{}/admin", pct_encode(&new_uid));
    let resp = authed_post(&app, &uri, &admin_token, json!({ "is_admin": true })).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify via get_user.
    let get_uri = format!("/_matrix/conduit/admin/v1/users/{}", pct_encode(&new_uid));
    let resp = authed_get(&app, &get_uri, &admin_token).await;
    let body = json_body(resp).await;
    assert!(body["is_admin"].as_bool().unwrap(), "new_user should now be admin");

    // Demote new_user.
    let resp = authed_post(&app, &uri, &admin_token, json!({ "is_admin": false })).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = authed_get(&app, &get_uri, &admin_token).await;
    let body = json_body(resp).await;
    assert!(!body["is_admin"].as_bool().unwrap(), "new_user should now be non-admin");
}
