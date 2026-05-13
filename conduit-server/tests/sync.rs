//! Integration tests for `GET /_matrix/client/v3/sync`.
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
    api::client::rooms,
    api::client::sync as sync_api,
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
        let db_name = format!("conduit_test_sync_{}_{}", tid, nanos).to_lowercase();

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
        .route("/_matrix/client/v3/logout", post(auth::logout::<TestState>))
        .route("/_matrix/client/v3/account/whoami", get(auth::whoami))
        .route("/_matrix/client/v3/createRoom", post(rooms::create_room::<TestState>))
        .route("/_matrix/client/v3/join/:roomIdOrAlias", post(rooms::join_room::<TestState>))
        .route("/_matrix/client/v3/rooms/:roomId/leave", post(rooms::leave_room::<TestState>))
        .route("/_matrix/client/v3/rooms/:roomId/kick", post(rooms::kick_user::<TestState>))
        .route("/_matrix/client/v3/rooms/:roomId/ban", post(rooms::ban_user::<TestState>))
        .route("/_matrix/client/v3/rooms/:roomId/unban", post(rooms::unban_user::<TestState>))
        .route("/_matrix/client/v3/rooms/:roomId/invite", post(rooms::invite_user::<TestState>))
        .route(
            "/_matrix/client/v3/rooms/:roomId/send/:eventType/:txnId",
            put(rooms::send_message_event::<TestState>),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/state/:eventType",
            put(rooms::send_state_event::<TestState>)
                .get(rooms::get_state_event_no_key::<TestState>),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey",
            put(rooms::send_state_event_with_key::<TestState>)
                .get(rooms::get_state_event::<TestState>),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/state",
            get(rooms::get_room_state::<TestState>),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/joined_members",
            get(rooms::joined_members::<TestState>),
        )
        .route(
            "/_matrix/client/v3/rooms/:roomId/messages",
            get(rooms::get_messages::<TestState>),
        )
        .route("/_matrix/client/v3/sync", get(sync_api::sync::<TestState>))
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
    let body = json_body(resp).await;
    body["room_id"].as_str().unwrap().to_owned()
}

async fn do_send_message(app: &Router, token: &str, room_id: &str, txn: &str) {
    let body = json!({ "msgtype": "m.text", "body": "hello" });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "sendMessage failed");
}

async fn do_sync(app: &Router, token: &str, since: Option<&str>, timeout_ms: Option<u64>) -> Value {
    let mut uri = "/_matrix/client/v3/sync".to_owned();
    let mut params: Vec<String> = Vec::new();
    if let Some(s) = since {
        params.push(format!("since={s}"));
    }
    if let Some(t) = timeout_ms {
        params.push(format!("timeout={t}"));
    }
    if !params.is_empty() {
        uri = format!("{uri}?{}", params.join("&"));
    }
    let req = Request::builder()
        .method("GET")
        .uri(&uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "sync failed for uri {uri}");
    json_body(resp).await
}

// ---------------------------------------------------------------------------
// Test 1: initial_sync_empty_for_new_user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn initial_sync_empty_for_new_user() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "syncuser1", "secret").await;
    let token = reg["access_token"].as_str().unwrap();

    let body = do_sync(&app, token, None, None).await;

    assert!(body["next_batch"].as_str().is_some(), "next_batch must be present");
    let join = body["rooms"]["join"].as_object().unwrap();
    assert!(join.is_empty(), "new user should have no joined rooms, got: {join:?}");
}

// ---------------------------------------------------------------------------
// Test 2: initial_sync_shows_joined_rooms
// ---------------------------------------------------------------------------

#[tokio::test]
async fn initial_sync_shows_joined_rooms() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "syncuser2", "secret").await;
    let token = reg["access_token"].as_str().unwrap();

    let room_id = do_create_room(&app, token).await;

    let body = do_sync(&app, token, None, None).await;

    let join = body["rooms"]["join"].as_object().unwrap();
    assert!(
        join.contains_key(&room_id),
        "joined room {room_id} should appear in rooms.join; got keys: {:?}",
        join.keys().collect::<Vec<_>>()
    );

    // State should include at least m.room.create and m.room.member.
    let room_block = &join[&room_id];
    let state_events = room_block["state"]["events"].as_array().unwrap();
    let types: Vec<&str> = state_events
        .iter()
        .filter_map(|e| e["type"].as_str())
        .collect();
    assert!(
        types.contains(&"m.room.create"),
        "state should contain m.room.create; got: {types:?}"
    );
    assert!(
        types.contains(&"m.room.member"),
        "state should contain m.room.member; got: {types:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: incremental_sync_returns_only_new_events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn incremental_sync_returns_only_new_events() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "syncuser3", "secret").await;
    let token = reg["access_token"].as_str().unwrap();

    let room_id = do_create_room(&app, token).await;

    // Initial sync to get the token.
    let initial = do_sync(&app, token, None, None).await;
    let next_batch = initial["next_batch"].as_str().unwrap().to_owned();

    // Verify it starts with 's'.
    assert!(
        next_batch.starts_with('s'),
        "next_batch should start with 's', got: {next_batch}"
    );

    // Send a message.
    do_send_message(&app, token, &room_id, "txn-inc-1").await;

    // Incremental sync.
    let inc = do_sync(&app, token, Some(&next_batch), None).await;
    let join = inc["rooms"]["join"].as_object().unwrap();

    assert!(
        join.contains_key(&room_id),
        "room should appear in incremental sync after new message"
    );

    let timeline = join[&room_id]["timeline"]["events"].as_array().unwrap();
    assert!(
        !timeline.is_empty(),
        "incremental sync should return new message event"
    );

    // The event should be m.room.message.
    let msg_ev = timeline
        .iter()
        .find(|e| e["type"].as_str() == Some("m.room.message"));
    assert!(msg_ev.is_some(), "expected m.room.message in timeline, got: {timeline:?}");
}

// ---------------------------------------------------------------------------
// Test 4: incremental_sync_with_no_new_events_returns_empty_with_same_next_batch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn incremental_sync_with_no_new_events_returns_empty_delta() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "syncuser4", "secret").await;
    let token = reg["access_token"].as_str().unwrap();

    let _room_id = do_create_room(&app, token).await;

    // Initial sync.
    let initial = do_sync(&app, token, None, None).await;
    let next_batch = initial["next_batch"].as_str().unwrap().to_owned();

    // Immediate incremental sync with timeout=0 — no new events.
    let inc = do_sync(&app, token, Some(&next_batch), Some(0)).await;

    let inc_next_batch = inc["next_batch"].as_str().unwrap();
    // next_batch should equal the since we sent (no new events).
    assert_eq!(
        inc_next_batch, next_batch,
        "next_batch should be unchanged when there are no new events"
    );

    // rooms.join should be empty.
    let join = inc["rooms"]["join"].as_object().unwrap();
    assert!(
        join.is_empty(),
        "rooms.join should be empty with no new events, got: {join:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: long_poll_unblocks_on_new_event
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn long_poll_unblocks_on_new_event() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "syncuser5", "secret").await;
    let token = reg["access_token"].as_str().unwrap().to_owned();

    let room_id = do_create_room(&app, &token).await;

    // Initial sync to get current position.
    let initial = do_sync(&app, &token, None, None).await;
    let next_batch = initial["next_batch"].as_str().unwrap().to_owned();

    // Spawn long-poll in background with 5s timeout.
    let app2 = app.clone();
    let token2 = token.clone();
    let next_batch2 = next_batch.clone();
    let sync_task = tokio::spawn(async move {
        let mut uri = "/_matrix/client/v3/sync".to_owned();
        let params = format!("since={}&timeout=5000", next_batch2);
        uri = format!("{uri}?{params}");
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .header("authorization", format!("Bearer {token2}"))
            .body(Body::empty())
            .unwrap();
        let resp = app2.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "long-poll sync failed");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null)
    });

    // Brief delay to let the long-poll subscribe before we send the event.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a message — this should wake up the long-poll.
    do_send_message(&app, &token, &room_id, "txn-lp-1").await;

    // The long-poll should return within 3 seconds.
    let result = tokio::time::timeout(Duration::from_secs(3), sync_task)
        .await
        .expect("long-poll timed out — it didn't unblock when new event arrived")
        .expect("sync task panicked");

    let join = result["rooms"]["join"].as_object().unwrap();
    assert!(
        join.contains_key(&room_id),
        "long-poll response should include room with new message; got: {join:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: invalid_since_token_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_since_token_rejected() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "syncuser6", "secret").await;
    let token = reg["access_token"].as_str().unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/client/v3/sync?since=garbage")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "malformed since token should return 400"
    );
    let body = json_body(resp).await;
    assert_eq!(
        body["errcode"].as_str(),
        Some("M_INVALID_PARAM"),
        "errcode should be M_INVALID_PARAM, got: {body}"
    );
}
