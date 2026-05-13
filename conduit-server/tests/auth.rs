//! Integration tests for Matrix auth endpoints.
//!
//! Each test creates an ephemeral Postgres DB via `TempDb`, builds the full
//! axum router (same as `main.rs`), and hits endpoints via
//! `tower::ServiceExt::oneshot`.
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
    body::Body,
    http::{Request, StatusCode},
    Router,
    routing::{get, post},
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::RwLock;
use tower::util::ServiceExt as _;

use conduit::keys::ServerKey;
use conduit::storage::Storage;
use conduit_server::{
    PostgresStorage,
    api::client::{self as auth, AuthState, TxnCacheKey},
};

// ---------------------------------------------------------------------------
// TempDb (copy of the fixture from storage_pg.rs)
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
        let db_name = format!("conduit_test_auth_{}_{}", tid, nanos).to_lowercase();

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
// Minimal AppState for tests
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TestState {
    storage: Arc<dyn Storage>,
    server_name: Arc<str>,
    server_key: Arc<ServerKey>,
    txn_cache: Arc<RwLock<HashMap<TxnCacheKey, String>>>,
}

impl AuthState for TestState {
    fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
    fn server_name(&self) -> &str {
        &self.server_name
    }
    fn server_key(&self) -> Arc<ServerKey> {
        Arc::clone(&self.server_key)
    }
    fn txn_cache(&self) -> &Arc<RwLock<HashMap<TxnCacheKey, String>>> {
        &self.txn_cache
    }
}

fn build_router(state: TestState) -> Router {
    Router::new()
        .route("/_matrix/client/v3/register", post(auth::register::<TestState>))
        .route(
            "/_matrix/client/v3/login",
            get(auth::get_login_flows).post(auth::login::<TestState>),
        )
        .route("/_matrix/client/v3/logout", post(auth::logout::<TestState>))
        .route("/_matrix/client/v3/account/whoami", get(auth::whoami))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// POST /register with m.login.dummy auth, returns response.
async fn do_register(
    app: &Router,
    username: &str,
    password: &str,
) -> axum::response::Response {
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
    app.clone().oneshot(req).await.unwrap()
}

/// POST /login with password, returns response.
async fn do_login(
    app: &Router,
    username: &str,
    password: &str,
) -> axum::response::Response {
    let body = json!({
        "type": "m.login.password",
        "identifier": { "type": "m.id.user", "user": username },
        "password": password
    });
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/login")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

/// GET /whoami with bearer token, returns response.
async fn do_whoami(app: &Router, token: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/client/v3/account/whoami")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

/// POST /logout with bearer token, returns response.
async fn do_logout(app: &Router, token: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/logout")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(b"{}".as_slice()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

// ---------------------------------------------------------------------------
// Test 1: register_creates_account_returns_token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_creates_account_returns_token() {
    let db = TempDb::new().await;
    let state = TestState { storage: db.storage(), server_name: "localhost".into(), server_key: Arc::new(conduit::keys::generate_server_key()), txn_cache: Arc::new(RwLock::new(HashMap::new())) };
    let app = build_router(state);

    let resp = do_register(&app, "alice", "secret123").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = json_body(resp).await;
    assert!(body["user_id"].as_str().unwrap().starts_with("@alice:"));
    assert!(!body["access_token"].as_str().unwrap().is_empty());
    assert!(!body["device_id"].as_str().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Test 2: register_duplicate_user_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_duplicate_user_rejected() {
    let db = TempDb::new().await;
    let state = TestState { storage: db.storage(), server_name: "localhost".into(), server_key: Arc::new(conduit::keys::generate_server_key()), txn_cache: Arc::new(RwLock::new(HashMap::new())) };
    let app = build_router(state);

    let resp1 = do_register(&app, "bob", "pass1").await;
    assert_eq!(resp1.status(), StatusCode::OK);

    let resp2 = do_register(&app, "bob", "pass2").await;
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);

    let body = json_body(resp2).await;
    assert_eq!(body["errcode"].as_str().unwrap(), "M_USER_IN_USE");
}

// ---------------------------------------------------------------------------
// Test 3: login_with_correct_password_returns_token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_correct_password_returns_token() {
    let db = TempDb::new().await;
    let state = TestState { storage: db.storage(), server_name: "localhost".into(), server_key: Arc::new(conduit::keys::generate_server_key()), txn_cache: Arc::new(RwLock::new(HashMap::new())) };
    let app = build_router(state);

    // Register first.
    let reg = do_register(&app, "carol", "mypassword").await;
    assert_eq!(reg.status(), StatusCode::OK);
    let reg_body = json_body(reg).await;
    let reg_token = reg_body["access_token"].as_str().unwrap().to_owned();

    // Login with correct password.
    let resp = do_login(&app, "carol", "mypassword").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = json_body(resp).await;
    let login_token = body["access_token"].as_str().unwrap();
    assert!(!login_token.is_empty());
    // Login returns a *new* token (different from register token).
    assert_ne!(login_token, reg_token);
    assert!(body["user_id"].as_str().unwrap().starts_with("@carol:"));
}

// ---------------------------------------------------------------------------
// Test 4: login_with_wrong_password_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_wrong_password_rejected() {
    let db = TempDb::new().await;
    let state = TestState { storage: db.storage(), server_name: "localhost".into(), server_key: Arc::new(conduit::keys::generate_server_key()), txn_cache: Arc::new(RwLock::new(HashMap::new())) };
    let app = build_router(state);

    do_register(&app, "dave", "rightpass").await;

    let resp = do_login(&app, "dave", "wrongpass").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = json_body(resp).await;
    assert_eq!(body["errcode"].as_str().unwrap(), "M_FORBIDDEN");
}

// ---------------------------------------------------------------------------
// Test 5: whoami_with_valid_token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn whoami_with_valid_token() {
    let db = TempDb::new().await;
    let state = TestState { storage: db.storage(), server_name: "localhost".into(), server_key: Arc::new(conduit::keys::generate_server_key()), txn_cache: Arc::new(RwLock::new(HashMap::new())) };
    let app = build_router(state);

    let reg = do_register(&app, "eve", "pass").await;
    assert_eq!(reg.status(), StatusCode::OK);
    let body = json_body(reg).await;
    let token = body["access_token"].as_str().unwrap().to_owned();
    let user_id = body["user_id"].as_str().unwrap().to_owned();
    let device_id = body["device_id"].as_str().unwrap().to_owned();

    let resp = do_whoami(&app, &token).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let wb = json_body(resp).await;
    assert_eq!(wb["user_id"].as_str().unwrap(), user_id);
    assert_eq!(wb["device_id"].as_str().unwrap(), device_id);
}

// ---------------------------------------------------------------------------
// Test 6: whoami_with_no_token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn whoami_with_no_token() {
    let db = TempDb::new().await;
    let state = TestState { storage: db.storage(), server_name: "localhost".into(), server_key: Arc::new(conduit::keys::generate_server_key()), txn_cache: Arc::new(RwLock::new(HashMap::new())) };
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/client/v3/account/whoami")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(resp).await;
    assert_eq!(body["errcode"].as_str().unwrap(), "M_MISSING_TOKEN");
}

// ---------------------------------------------------------------------------
// Test 7: whoami_with_unknown_token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn whoami_with_unknown_token() {
    let db = TempDb::new().await;
    let state = TestState { storage: db.storage(), server_name: "localhost".into(), server_key: Arc::new(conduit::keys::generate_server_key()), txn_cache: Arc::new(RwLock::new(HashMap::new())) };
    let app = build_router(state);

    let resp = do_whoami(&app, "totally-made-up-token").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body = json_body(resp).await;
    assert_eq!(body["errcode"].as_str().unwrap(), "M_UNKNOWN_TOKEN");
}

// ---------------------------------------------------------------------------
// Test 8: logout_invalidates_token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_invalidates_token() {
    let db = TempDb::new().await;
    let state = TestState { storage: db.storage(), server_name: "localhost".into(), server_key: Arc::new(conduit::keys::generate_server_key()), txn_cache: Arc::new(RwLock::new(HashMap::new())) };
    let app = build_router(state);

    let reg = do_register(&app, "frank", "pass123").await;
    assert_eq!(reg.status(), StatusCode::OK);
    let token = json_body(reg).await["access_token"].as_str().unwrap().to_owned();

    // Whoami works before logout.
    assert_eq!(do_whoami(&app, &token).await.status(), StatusCode::OK);

    // Logout.
    let logout_resp = do_logout(&app, &token).await;
    assert_eq!(logout_resp.status(), StatusCode::OK);

    // Whoami fails after logout.
    let after = do_whoami(&app, &token).await;
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
}
