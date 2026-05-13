//! Integration tests for Matrix room endpoints.
//!
//! Each test spins up an ephemeral Postgres DB, builds the full axum router,
//! and exercises endpoints via `tower::ServiceExt::oneshot`.
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
    routing::{get, post, put},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::RwLock;
use tower::util::ServiceExt as _;

use conduit::keys::ServerKey;
use conduit::storage::Storage;
use conduit_server::{
    PostgresStorage,
    api::client::{self as auth, AuthState, TxnCacheKey},
    api::client::rooms,
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
        let db_name = format!("conduit_test_rooms_{}_{}", tid, nanos).to_lowercase();

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
}

impl TestState {
    fn new(storage: Arc<dyn Storage>) -> Self {
        Self {
            storage,
            server_name: "localhost".into(),
            server_key: Arc::new(conduit::keys::generate_server_key()),
            txn_cache: Arc::new(RwLock::new(HashMap::new())),
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
        .route("/_matrix/client/v3/rooms/:roomId/send/:eventType/:txnId",
            put(rooms::send_message_event::<TestState>))
        .route("/_matrix/client/v3/rooms/:roomId/state/:eventType",
            put(rooms::send_state_event::<TestState>)
            .get(rooms::get_state_event_no_key::<TestState>))
        .route("/_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey",
            put(rooms::send_state_event_with_key::<TestState>)
            .get(rooms::get_state_event::<TestState>))
        .route("/_matrix/client/v3/rooms/:roomId/state",
            get(rooms::get_room_state::<TestState>))
        .route("/_matrix/client/v3/rooms/:roomId/joined_members",
            get(rooms::joined_members::<TestState>))
        .route("/_matrix/client/v3/rooms/:roomId/messages",
            get(rooms::get_messages::<TestState>))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Helper functions
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

async fn do_create_room(app: &Router, token: &str, body: Value) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/createRoom")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

async fn do_send_message(app: &Router, token: &str, room_id: &str, txn: &str) -> axum::response::Response {
    let body = json!({ "msgtype": "m.text", "body": "hello" });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

async fn do_joined_members(app: &Router, token: &str, room_id: &str) -> Value {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v3/rooms/{room_id}/joined_members"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = json_body(resp).await;
    assert_eq!(status, StatusCode::OK, "joined_members failed: {body}");
    body
}

async fn do_get_state(app: &Router, token: &str, room_id: &str) -> Value {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v3/rooms/{room_id}/state"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = json_body(resp).await;
    assert_eq!(status, StatusCode::OK, "get_state failed: {body}");
    body
}

async fn do_join(app: &Router, token: &str, room_id: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/_matrix/client/v3/join/{room_id}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(b"{}".as_slice()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

async fn do_invite(app: &Router, token: &str, room_id: &str, user_id: &str) -> axum::response::Response {
    let body = json!({ "user_id": user_id });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/_matrix/client/v3/rooms/{room_id}/invite"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

async fn do_kick(app: &Router, token: &str, room_id: &str, user_id: &str) -> axum::response::Response {
    let body = json!({ "user_id": user_id });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/_matrix/client/v3/rooms/{room_id}/kick"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

// ---------------------------------------------------------------------------
// Test 1: create_room_returns_room_id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_room_returns_room_id() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "alice", "secret").await;
    let token = reg["access_token"].as_str().unwrap();

    let resp = do_create_room(&app, token, json!({})).await;
    let status = resp.status();
    let body = json_body(resp).await;
    assert_eq!(status, StatusCode::OK, "createRoom failed: {body}");
    let room_id = body["room_id"].as_str().unwrap();
    assert!(room_id.starts_with('!'), "room_id should start with '!', got: {room_id}");
    assert!(room_id.contains(':'), "room_id should contain ':' separator");
}

// ---------------------------------------------------------------------------
// Test 2: create_room_creator_is_joined
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_room_creator_is_joined() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "bob", "secret").await;
    let token = reg["access_token"].as_str().unwrap();
    let user_id = reg["user_id"].as_str().unwrap();

    let create_resp = do_create_room(&app, token, json!({})).await;
    assert_eq!(create_resp.status(), StatusCode::OK);
    let room_id = json_body(create_resp).await["room_id"].as_str().unwrap().to_owned();
    let members = do_joined_members(&app, token, &room_id).await;
    let joined = &members["joined"];
    assert!(joined.get(user_id).is_some(), "creator should be in joined_members; got: {members}");
}

// ---------------------------------------------------------------------------
// Test 3: create_room_public_emits_initial_state_events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_room_public_emits_create_member_pl_jr_hv_events() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "charlie", "secret").await;
    let token = reg["access_token"].as_str().unwrap();

    let create_resp = do_create_room(&app, token, json!({ "visibility": "public" })).await;
    assert_eq!(create_resp.status(), StatusCode::OK);
    let room_id = json_body(create_resp).await["room_id"].as_str().unwrap().to_owned();

    let state_events = do_get_state(&app, token, &room_id).await;
    let evs: Vec<Value> = serde_json::from_value(state_events).unwrap();

    let types: Vec<&str> = evs.iter()
        .filter_map(|e| e["type"].as_str())
        .collect();

    for required in &["m.room.create", "m.room.member", "m.room.power_levels",
                       "m.room.join_rules", "m.room.history_visibility"] {
        assert!(
            types.contains(required),
            "expected event type {required} in state, got types: {types:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 4: send_message_returns_event_id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_message_returns_event_id() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "dave", "secret").await;
    let token = reg["access_token"].as_str().unwrap();

    let create_resp = do_create_room(&app, token, json!({})).await;
    let room_id = json_body(create_resp).await["room_id"].as_str().unwrap().to_owned();

    let resp = do_send_message(&app, token, &room_id, "txn001").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = json_body(resp).await;
    let event_id = body["event_id"].as_str().unwrap();
    assert!(event_id.starts_with('$'), "event_id should start with '$', got: {event_id}");
}

// ---------------------------------------------------------------------------
// Test 5: send_message_idempotent_on_txn_id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_message_idempotent_on_txn_id() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "eve", "secret").await;
    let token = reg["access_token"].as_str().unwrap();

    let create_resp = do_create_room(&app, token, json!({})).await;
    let room_id = json_body(create_resp).await["room_id"].as_str().unwrap().to_owned();

    let resp1 = do_send_message(&app, token, &room_id, "txn-idem-001").await;
    let resp2 = do_send_message(&app, token, &room_id, "txn-idem-001").await;

    assert_eq!(resp1.status(), StatusCode::OK);
    assert_eq!(resp2.status(), StatusCode::OK);

    let id1 = json_body(resp1).await["event_id"].as_str().unwrap().to_owned();
    let id2 = json_body(resp2).await["event_id"].as_str().unwrap().to_owned();
    assert_eq!(id1, id2, "same txn_id must return the same event_id");
}

// ---------------------------------------------------------------------------
// Test 6: send_state_event_updates_state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_state_event_updates_state() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "frank", "secret").await;
    let token = reg["access_token"].as_str().unwrap();

    let create_resp = do_create_room(&app, token, json!({})).await;
    let room_id = json_body(create_resp).await["room_id"].as_str().unwrap().to_owned();

    // PUT /rooms/{roomId}/state/m.room.name (empty state_key)
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.name"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&json!({ "name": "My Room" })).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = json_body(resp).await;
    assert_eq!(status, StatusCode::OK, "PUT /state/m.room.name failed: {body}");

    // GET /rooms/{roomId}/state should show m.room.name
    let state_events = do_get_state(&app, token, &room_id).await;
    let evs: Vec<Value> = serde_json::from_value(state_events).unwrap();
    let name_ev = evs.iter().find(|e| e["type"].as_str() == Some("m.room.name"));
    assert!(name_ev.is_some(), "m.room.name should appear in /state");
    assert_eq!(
        name_ev.unwrap()["content"]["name"].as_str(),
        Some("My Room"),
        "name content should be 'My Room'"
    );
}

// ---------------------------------------------------------------------------
// Test 7: get_messages_paginates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_messages_paginates() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg = do_register(&app, "grace", "secret").await;
    let token = reg["access_token"].as_str().unwrap();

    let create_resp = do_create_room(&app, token, json!({})).await;
    let room_id = json_body(create_resp).await["room_id"].as_str().unwrap().to_owned();

    // Send 10 messages.
    for i in 0..10 {
        do_send_message(&app, token, &room_id, &format!("txn-page-{i}")).await;
    }

    // GET /messages backwards with limit=3.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=b&limit=3"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = json_body(resp).await;
    let chunk = body["chunk"].as_array().unwrap();
    assert_eq!(chunk.len(), 3, "expected 3 events in the chunk, got {}", chunk.len());
}

// ---------------------------------------------------------------------------
// Test 8: invite_then_join_succeeds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invite_then_join_succeeds() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg_a = do_register(&app, "alice2", "secret").await;
    let token_a = reg_a["access_token"].as_str().unwrap().to_owned();

    let reg_b = do_register(&app, "bob2", "secret").await;
    let token_b = reg_b["access_token"].as_str().unwrap().to_owned();
    let user_b = reg_b["user_id"].as_str().unwrap().to_owned();

    // A creates invite-only room.
    let create_resp = do_create_room(&app, &token_a, json!({ "preset": "private_chat" })).await;
    assert_eq!(create_resp.status(), StatusCode::OK);
    let room_id = json_body(create_resp).await["room_id"].as_str().unwrap().to_owned();

    // A invites B.
    let invite_resp = do_invite(&app, &token_a, &room_id, &user_b).await;
    assert_eq!(invite_resp.status(), StatusCode::OK, "invite should succeed");

    // B joins.
    let join_resp = do_join(&app, &token_b, &room_id).await;
    assert_eq!(join_resp.status(), StatusCode::OK, "join after invite should succeed");

    // B should now be in joined_members.
    let members = do_joined_members(&app, &token_a, &room_id).await;
    assert!(members["joined"].get(&user_b).is_some(), "B should be in joined_members");
}

// ---------------------------------------------------------------------------
// Test 9: join_invite_only_without_invite_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn join_invite_only_without_invite_rejected() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg_a = do_register(&app, "alice3", "secret").await;
    let token_a = reg_a["access_token"].as_str().unwrap().to_owned();

    let reg_b = do_register(&app, "bob3", "secret").await;
    let token_b = reg_b["access_token"].as_str().unwrap().to_owned();

    // A creates invite-only room (no invite for B).
    let create_resp = do_create_room(&app, &token_a, json!({ "preset": "private_chat" })).await;
    assert_eq!(create_resp.status(), StatusCode::OK);
    let room_id = json_body(create_resp).await["room_id"].as_str().unwrap().to_owned();

    // B tries to join without being invited.
    let join_resp = do_join(&app, &token_b, &room_id).await;
    assert_eq!(join_resp.status(), StatusCode::FORBIDDEN, "join without invite should be 403");
}

// ---------------------------------------------------------------------------
// Test 10: kick_with_power_succeeds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kick_with_power_succeeds() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg_a = do_register(&app, "alice4", "secret").await;
    let token_a = reg_a["access_token"].as_str().unwrap().to_owned();

    let reg_b = do_register(&app, "bob4", "secret").await;
    let token_b = reg_b["access_token"].as_str().unwrap().to_owned();
    let user_b = reg_b["user_id"].as_str().unwrap().to_owned();

    // A creates public room, B joins.
    let create_resp = do_create_room(&app, &token_a, json!({ "visibility": "public" })).await;
    let room_id = json_body(create_resp).await["room_id"].as_str().unwrap().to_owned();

    let join_resp = do_join(&app, &token_b, &room_id).await;
    assert_eq!(join_resp.status(), StatusCode::OK);

    // Confirm B is joined.
    let members_before = do_joined_members(&app, &token_a, &room_id).await;
    assert!(members_before["joined"].get(&user_b).is_some(), "B should be joined before kick");

    // A kicks B.
    let kick_resp = do_kick(&app, &token_a, &room_id, &user_b).await;
    assert_eq!(kick_resp.status(), StatusCode::OK, "kick should succeed");

    // B should no longer be in joined_members.
    let members_after = do_joined_members(&app, &token_a, &room_id).await;
    assert!(
        members_after["joined"].get(&user_b).is_none(),
        "B should not be in joined_members after kick; got: {members_after}"
    );
}

// ---------------------------------------------------------------------------
// Test 11: kick_without_power_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kick_without_power_rejected() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let reg_a = do_register(&app, "alice5", "secret").await;
    let token_a = reg_a["access_token"].as_str().unwrap().to_owned();
    let user_a = reg_a["user_id"].as_str().unwrap().to_owned();

    let reg_b = do_register(&app, "bob5", "secret").await;
    let token_b = reg_b["access_token"].as_str().unwrap().to_owned();

    // A creates public room, B joins.
    let create_resp = do_create_room(&app, &token_a, json!({ "visibility": "public" })).await;
    let room_id = json_body(create_resp).await["room_id"].as_str().unwrap().to_owned();

    let join_resp = do_join(&app, &token_b, &room_id).await;
    assert_eq!(join_resp.status(), StatusCode::OK);

    // B (level 0) tries to kick A (level 100) — should fail.
    let kick_resp = do_kick(&app, &token_b, &room_id, &user_a).await;
    assert_eq!(kick_resp.status(), StatusCode::FORBIDDEN, "kick without power should be 403");
}

#[tokio::test]
async fn debug_routing() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    // Test routing with plain room_id (no special chars)
    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/client/v3/rooms/PLAINROOMID/joined_members")
        .header("authorization", "Bearer faketoken")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    eprintln!("PLAIN status={}", resp.status());

    // Test routing with ! and :
    let req2 = Request::builder()
        .method("GET")
        .uri("/_matrix/client/v3/rooms/!abc123:localhost/joined_members")
        .header("authorization", "Bearer faketoken")
        .body(Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    eprintln!("SPECIAL status={}", resp2.status());
}

#[tokio::test]
async fn debug_routing2() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    // Test a simple fixed route
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/createRoom")
        .header("content-type", "application/json")
        .header("authorization", "Bearer faketoken")
        .body(Body::from(b"{}".as_slice()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    eprintln!("createRoom (no token) status={}", resp.status());

    // Test the join route  
    let req3 = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/join/ROOMID")
        .header("content-type", "application/json")
        .header("authorization", "Bearer faketoken")
        .body(Body::from(b"{}".as_slice()))
        .unwrap();
    let resp3 = app.clone().oneshot(req3).await.unwrap();
    eprintln!("join ROOMID status={}", resp3.status());
    
    // Test kick
    let req4 = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/rooms/ROOMID/kick")
        .header("content-type", "application/json")
        .header("authorization", "Bearer faketoken")
        .body(Body::from(b"{\"user_id\":\"@x:y\"}".as_slice()))
        .unwrap();
    let resp4 = app.clone().oneshot(req4).await.unwrap();
    eprintln!("kick ROOMID status={}", resp4.status());
}
