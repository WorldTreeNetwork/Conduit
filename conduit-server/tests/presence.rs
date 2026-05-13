//! Integration tests for E06 — Presence Layer.
//!
//! Covers stories 1mo.1 through 1mo.8:
//!   - Profile display name / avatar URL
//!   - Account data (global + per-room)
//!   - Typing EDU in /sync
//!   - Read receipts in /sync
//!   - Presence GET/PUT
//!
//! # Running
//! ```
//! DATABASE_URL=postgresql://postgres@localhost/conduit \
//!     cargo test --workspace --tests
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post, put},
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
    api::client::account_data as account_data_api,
    api::client::presence as presence_api,
    api::client::profile as profile_api,
    api::client::receipts as receipts_api,
    api::client::rooms,
    api::client::sync as sync_api,
    api::client::typing as typing_api,
};

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
        let db_name = format!("conduit_test_pres_{}_{}", tid, nanos).to_lowercase();

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

impl TestState {
    fn new(storage: Arc<dyn Storage>) -> Self {
        let (events_tx, _) = broadcast::channel(256);
        let (typing_store, typing_tx) = TypingStore::new();
        let presence_store = PresenceStore::new();
        Self {
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
    fn events_tx(&self) -> &broadcast::Sender<i64> {
        &self.events_tx
    }
    fn typing_store(&self) -> &Arc<TypingStore> {
        &self.typing_store
    }
    fn typing_tx(&self) -> &broadcast::Sender<String> {
        &self.typing_tx
    }
    fn presence_store(&self) -> &Arc<PresenceStore> {
        &self.presence_store
    }
}

fn build_router(state: TestState) -> Router {
    Router::new()
        .route("/_matrix/client/v3/register", post(auth::register::<TestState>))
        .route(
            "/_matrix/client/v3/login",
            get(auth::get_login_flows).post(auth::login::<TestState>),
        )
        .route("/_matrix/client/v3/createRoom", post(rooms::create_room::<TestState>))
        .route("/_matrix/client/v3/join/:roomIdOrAlias", post(rooms::join_room::<TestState>))
        .route("/_matrix/client/v3/sync", get(sync_api::sync::<TestState>))
        // Profile
        .route(
            "/_matrix/client/v3/profile/:userId/displayname",
            get(profile_api::get_displayname::<TestState>)
                .put(profile_api::put_displayname::<TestState>),
        )
        .route(
            "/_matrix/client/v3/profile/:userId/avatar_url",
            get(profile_api::get_avatar_url::<TestState>)
                .put(profile_api::put_avatar_url::<TestState>),
        )
        .route(
            "/_matrix/client/v3/profile/:userId",
            get(profile_api::get_profile::<TestState>),
        )
        // Account data
        .route(
            "/_matrix/client/v3/user/:userId/account_data/:type",
            get(account_data_api::get_account_data::<TestState>)
                .put(account_data_api::put_account_data::<TestState>),
        )
        .route(
            "/_matrix/client/v3/user/:userId/rooms/:roomId/account_data/:type",
            get(account_data_api::get_room_account_data::<TestState>)
                .put(account_data_api::put_room_account_data::<TestState>),
        )
        // Typing
        .route(
            "/_matrix/client/v3/rooms/:roomId/typing/:userId",
            put(typing_api::put_typing::<TestState>),
        )
        // Receipts
        .route(
            "/_matrix/client/v3/rooms/:roomId/receipt/:receiptType/:eventId",
            post(receipts_api::post_receipt::<TestState>),
        )
        // Presence
        .route(
            "/_matrix/client/v3/presence/:userId/status",
            get(presence_api::get_presence::<TestState>)
                .put(presence_api::put_presence::<TestState>),
        )
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
    assert_eq!(resp.status(), StatusCode::OK, "register failed");
    json_body(resp).await
}

async fn do_create_room(app: &Router, token: &str) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/createRoom")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(b"{}".as_slice()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "createRoom failed");
    json_body(resp).await["room_id"].as_str().unwrap().to_owned()
}

async fn do_sync(app: &Router, token: &str, since: Option<&str>) -> Value {
    let uri = match since {
        Some(s) => format!("/_matrix/client/v3/sync?since={s}"),
        None => "/_matrix/client/v3/sync".to_owned(),
    };
    let req = Request::builder()
        .method("GET")
        .uri(&uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "sync failed");
    json_body(resp).await
}

// ---------------------------------------------------------------------------
// 1mo.1: Displayname round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn displayname_round_trip() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "alice", "pass").await;
    let token = reg["access_token"].as_str().unwrap();
    let user_id = reg["user_id"].as_str().unwrap();

    // PUT displayname.
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/profile/{user_id}/displayname"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&json!({"displayname": "Alice"})).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET displayname.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v3/profile/{user_id}/displayname"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["displayname"], "Alice");
}

// ---------------------------------------------------------------------------
// 1mo.1: PUT another user's displayname → 403
// ---------------------------------------------------------------------------

#[tokio::test]
async fn displayname_other_user_rejected_on_put() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg_a = do_register(&app, "alice2", "pass").await;
    let reg_b = do_register(&app, "bob2", "pass").await;
    let token_a = reg_a["access_token"].as_str().unwrap();
    let user_b = reg_b["user_id"].as_str().unwrap();

    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/profile/{user_b}/displayname"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token_a}"))
        .body(Body::from(serde_json::to_vec(&json!({"displayname": "Evil"})).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// 1mo.1: Unauthenticated GET displayname works
// ---------------------------------------------------------------------------

#[tokio::test]
async fn displayname_public_get() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "alice3", "pass").await;
    let token = reg["access_token"].as_str().unwrap();
    let user_id = reg["user_id"].as_str().unwrap();

    // Set a displayname first.
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/profile/{user_id}/displayname"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&json!({"displayname": "Public Alice"})).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    // GET without auth.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v3/profile/{user_id}/displayname"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["displayname"], "Public Alice");
}

// ---------------------------------------------------------------------------
// 1mo.2: Avatar URL round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn avatar_url_round_trip() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "alice4", "pass").await;
    let token = reg["access_token"].as_str().unwrap();
    let user_id = reg["user_id"].as_str().unwrap();

    let url = "mxc://localhost/abc123";

    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/profile/{user_id}/avatar_url"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&json!({"avatar_url": url})).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v3/profile/{user_id}/avatar_url"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["avatar_url"], url);
}

// ---------------------------------------------------------------------------
// 1mo.3: Global account data round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn account_data_global_round_trip() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "alice5", "pass").await;
    let token = reg["access_token"].as_str().unwrap();
    let user_id = reg["user_id"].as_str().unwrap();

    let content = json!({"push_rules": {"global": {}}});

    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/user/{user_id}/account_data/m.push_rules"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&content).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v3/user/{user_id}/account_data/m.push_rules"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body, content);
}

// ---------------------------------------------------------------------------
// 1mo.4: Per-room account data round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn account_data_per_room_round_trip() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "alice6", "pass").await;
    let token = reg["access_token"].as_str().unwrap();
    let user_id = reg["user_id"].as_str().unwrap();
    let room_id = do_create_room(&app, token).await;

    let content = json!({"is_direct": true});

    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/user/{user_id}/rooms/{room_id}/account_data/m.direct"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&content).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v3/user/{user_id}/rooms/{room_id}/account_data/m.direct"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body, content);
}

// ---------------------------------------------------------------------------
// 1mo.3+1mo.8: Account data appears in /sync, not repeated on next /sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn account_data_appears_in_sync() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "alice7", "pass").await;
    let token = reg["access_token"].as_str().unwrap();
    let user_id = reg["user_id"].as_str().unwrap();

    // Initial sync to get a since token.
    let sync1 = do_sync(&app, token, None).await;
    let since = sync1["next_batch"].as_str().unwrap();

    // PUT account data.
    let content = json!({"some": "value"});
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/user/{user_id}/account_data/org.test.custom"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&content).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    // Incremental sync should include it.
    let sync2 = do_sync(&app, token, Some(since)).await;
    let ad_events = sync2["account_data"]["events"].as_array().unwrap();
    let found = ad_events.iter().any(|ev| {
        ev["type"] == "org.test.custom" && ev["content"]["some"] == "value"
    });
    assert!(found, "account_data not in sync: {sync2}");

    // Second incremental sync with the new since should NOT repeat it.
    let since2 = sync2["next_batch"].as_str().unwrap();
    let sync3 = do_sync(&app, token, Some(since2)).await;
    let ad_events3 = sync3["account_data"]["events"].as_array().unwrap();
    let repeated = ad_events3.iter().any(|ev| ev["type"] == "org.test.custom");
    assert!(!repeated, "account_data repeated in sync: {sync3}");
}

// ---------------------------------------------------------------------------
// 1mo.5+1mo.8: Typing emits via /sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn typing_emits_via_sync() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg_a = do_register(&app, "alice8", "pass").await;
    let token_a = reg_a["access_token"].as_str().unwrap();
    let user_a = reg_a["user_id"].as_str().unwrap();

    let room_id = do_create_room(&app, token_a).await;

    // A starts typing.
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/rooms/{room_id}/typing/{user_a}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token_a}"))
        .body(Body::from(
            serde_json::to_vec(&json!({"typing": true, "timeout": 30000})).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // A's /sync should see m.typing ephemeral.
    let sync = do_sync(&app, token_a, None).await;
    let room_block = &sync["rooms"]["join"][room_id.as_str()];
    let ephemeral = room_block["ephemeral"]["events"].as_array().unwrap();
    let typing_ev = ephemeral.iter().find(|ev| ev["type"] == "m.typing");
    assert!(typing_ev.is_some(), "no m.typing in ephemeral: {sync}");
    let typers = typing_ev.unwrap()["content"]["user_ids"].as_array().unwrap();
    assert!(
        typers.iter().any(|u| u.as_str() == Some(user_a)),
        "user_a not in typers: {typers:?}"
    );
}

// ---------------------------------------------------------------------------
// 1mo.5: Typing expires after TTL
// ---------------------------------------------------------------------------

#[tokio::test]
async fn typing_expires() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());

    // PUT typing with a 100ms timeout directly via the store.
    let room_id = "!testroom:localhost";
    let user_id = "@alice9:localhost";

    state.typing_store.set_typing(room_id, user_id, 100).await;

    // Immediately present.
    let typers = state.typing_store.typers_in_room(room_id).await;
    assert!(typers.contains(&user_id.to_owned()), "should be typing");

    // After 200ms, the entry should have expired.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let typers = state.typing_store.typers_in_room(room_id).await;
    assert!(!typers.contains(&user_id.to_owned()), "should have expired");
}

// ---------------------------------------------------------------------------
// 1mo.6+1mo.8: Read receipt round-trip via /sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn read_receipt_round_trip() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "alice10", "pass").await;
    let token = reg["access_token"].as_str().unwrap();

    let room_id = do_create_room(&app, token).await;

    // Use a synthetic event_id (no special chars to avoid URL encoding issues).
    let event_id = "$someeventidlocalhost";

    // Initial sync to get a since token.
    let sync1 = do_sync(&app, token, None).await;
    let since = sync1["next_batch"].as_str().unwrap();

    // POST receipt.
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{event_id}",
        ))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(b"{}".as_slice()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Incremental sync should include m.receipt ephemeral.
    let sync2 = do_sync(&app, token, Some(since)).await;
    let room_block = &sync2["rooms"]["join"][room_id.as_str()];
    let ephemeral = room_block["ephemeral"]["events"].as_array().unwrap();
    let receipt_ev = ephemeral.iter().find(|ev| ev["type"] == "m.receipt");
    assert!(receipt_ev.is_some(), "no m.receipt in sync: {sync2}");
}

// ---------------------------------------------------------------------------
// 1mo.7: Presence round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn presence_round_trip() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "alice11", "pass").await;
    let token = reg["access_token"].as_str().unwrap();
    let user_id = reg["user_id"].as_str().unwrap();

    // PUT presence.
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/presence/{user_id}/status"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({"presence": "online", "status_msg": "Working"})).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET presence.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v3/presence/{user_id}/status"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["presence"], "online");
    assert_eq!(body["status_msg"], "Working");
    assert!(body["last_active_ago"].as_u64().unwrap() < 5000);
}
