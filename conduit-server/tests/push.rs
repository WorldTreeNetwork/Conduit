//! Integration tests for E11 Push endpoints (P1–P6).
//!
//! Covers:
//!   - dd8.1 P1: pusher set and list
//!   - dd8.2 P2: push rule storage + edit
//!   - dd8.3 P3: default push rules
//!   - dd8.4 P4: rule evaluator (event_match, room_member_count)
//!   - dd8.5 P5: push worker (unit-level action parsing)
//!   - dd8.6 P6: /notifications endpoint stub
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
    api::client::push as push_api,
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
        let db_name = format!("conduit_test_push_{}_{}", tid, nanos).to_lowercase();

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
        .route("/_matrix/client/v3/pushers",
            get(push_api::get_pushers::<TestState>))
        .route("/_matrix/client/v3/pushers/set",
            post(push_api::set_pusher::<TestState>))
        .route("/_matrix/client/v3/pushrules/",
            get(push_api::get_all_push_rules::<TestState>))
        .route("/_matrix/client/v3/pushrules/:scope/:kind/:ruleId",
            get(push_api::get_push_rule::<TestState>)
            .put(push_api::put_push_rule::<TestState>)
            .delete(push_api::delete_push_rule::<TestState>))
        .route("/_matrix/client/v3/pushrules/:scope/:kind/:ruleId/enabled",
            get(push_api::get_push_rule_enabled::<TestState>)
            .put(push_api::put_push_rule_enabled::<TestState>))
        .route("/_matrix/client/v3/pushrules/:scope/:kind/:ruleId/actions",
            get(push_api::get_push_rule_actions::<TestState>)
            .put(push_api::put_push_rule_actions::<TestState>))
        .route("/_matrix/client/v3/notifications",
            get(push_api::get_notifications::<TestState>))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn do_register(app: &Router, username: &str) -> String {
    let body = json!({
        "username": username,
        "password": "test123",
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
    json_body(resp).await["access_token"].as_str().unwrap().to_owned()
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

async fn authed_put(app: &Router, uri: &str, token: &str, body: Value) -> axum::response::Response {
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

async fn authed_delete(app: &Router, uri: &str, token: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

// ---------------------------------------------------------------------------
// Test: pusher_set_and_list (dd8.1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pusher_set_and_list() {
    let db = TempDb::new().await;
    let app = build_router(make_state(db.storage()));
    let token = do_register(&app, "alice").await;

    // List pushers — should be empty initially.
    let resp = authed_get(&app, "/_matrix/client/v3/pushers", &token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["pushers"].as_array().unwrap().len(), 0);

    // Set a pusher.
    let set_body = json!({
        "pushkey": "push_key_abc",
        "kind": "http",
        "app_id": "com.example.app",
        "app_display_name": "Example App",
        "device_display_name": "Alice's Phone",
        "lang": "en",
        "data": { "url": "https://push.example.com/_matrix/push/v1/notify" }
    });
    let resp = authed_post(&app, "/_matrix/client/v3/pushers/set", &token, set_body).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // List pushers — should now have one.
    let resp = authed_get(&app, "/_matrix/client/v3/pushers", &token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let pushers = body["pushers"].as_array().unwrap();
    assert_eq!(pushers.len(), 1);
    assert_eq!(pushers[0]["pushkey"].as_str().unwrap(), "push_key_abc");
    assert_eq!(pushers[0]["app_id"].as_str().unwrap(), "com.example.app");
    assert_eq!(pushers[0]["kind"].as_str().unwrap(), "http");

    // Delete the pusher (kind=null).
    let del_body = json!({
        "pushkey": "push_key_abc",
        "app_id": "com.example.app"
    });
    let resp = authed_post(&app, "/_matrix/client/v3/pushers/set", &token, del_body).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // List pushers — should be empty again.
    let resp = authed_get(&app, "/_matrix/client/v3/pushers", &token).await;
    let body = json_body(resp).await;
    assert_eq!(body["pushers"].as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// Test: push_rules_crud (dd8.2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn push_rules_crud() {
    let db = TempDb::new().await;
    let app = build_router(make_state(db.storage()));
    let token = do_register(&app, "bob").await;

    // PUT a new push rule.
    let rule_body = json!({
        "actions": ["notify"],
        "conditions": [{ "kind": "event_match", "key": "type", "pattern": "m.room.message" }]
    });
    let resp = authed_put(
        &app,
        "/_matrix/client/v3/pushrules/global/override/my_custom_rule",
        &token,
        rule_body,
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // GET the rule back.
    let resp = authed_get(
        &app,
        "/_matrix/client/v3/pushrules/global/override/my_custom_rule",
        &token,
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["rule_id"].as_str().unwrap(), "my_custom_rule");
    assert!(body["enabled"].as_bool().unwrap());

    // PUT /enabled to disable.
    let resp = authed_put(
        &app,
        "/_matrix/client/v3/pushrules/global/override/my_custom_rule/enabled",
        &token,
        json!({ "enabled": false }),
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // GET /enabled — should be false.
    let resp = authed_get(
        &app,
        "/_matrix/client/v3/pushrules/global/override/my_custom_rule/enabled",
        &token,
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(!body["enabled"].as_bool().unwrap());

    // PUT /actions.
    let resp = authed_put(
        &app,
        "/_matrix/client/v3/pushrules/global/override/my_custom_rule/actions",
        &token,
        json!({ "actions": ["dont_notify"] }),
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // GET /actions.
    let resp = authed_get(
        &app,
        "/_matrix/client/v3/pushrules/global/override/my_custom_rule/actions",
        &token,
    ).await;
    let body = json_body(resp).await;
    assert_eq!(body["actions"], json!(["dont_notify"]));

    // DELETE the rule.
    let resp = authed_delete(
        &app,
        "/_matrix/client/v3/pushrules/global/override/my_custom_rule",
        &token,
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // GET the rule — should be 404.
    let resp = authed_get(
        &app,
        "/_matrix/client/v3/pushrules/global/override/my_custom_rule",
        &token,
    ).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Test: default_push_rules_seeded (dd8.3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn default_push_rules_seeded() {
    let db = TempDb::new().await;
    let app = build_router(make_state(db.storage()));
    let token = do_register(&app, "carol").await;

    // GET all push rules — should auto-seed defaults.
    let resp = authed_get(&app, "/_matrix/client/v3/pushrules/", &token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let global = &body["global"];

    // Override rules should include .m.rule.master.
    let overrides = global["override"].as_array().unwrap();
    assert!(!overrides.is_empty(), "default override rules should be seeded");
    let master = overrides.iter().find(|r| r["rule_id"].as_str() == Some(".m.rule.master"));
    assert!(master.is_some(), ".m.rule.master should be in default rules");

    // Underride rules should include .m.rule.message.
    let underrides = global["underride"].as_array().unwrap();
    let msg_rule = underrides.iter().find(|r| r["rule_id"].as_str() == Some(".m.rule.message"));
    assert!(msg_rule.is_some(), ".m.rule.message should be in default rules");
}

// ---------------------------------------------------------------------------
// Test: push_rule_evaluator (dd8.4)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn push_rule_evaluator_basic_match() {
    use conduit_server::api::client::push::rules::{evaluate_rule, parse_actions, EvalContext, default_push_rules};
    use serde_json::json;

    let user_id = "@dave:localhost";
    let rules = default_push_rules(user_id);

    // A plain message event should match .m.rule.message (underride).
    let event = json!({
        "type": "m.room.message",
        "room_id": "!testroom:localhost",
        "sender": "@alice:localhost",
        "content": { "msgtype": "m.text", "body": "Hello!" }
    });
    let ctx = EvalContext {
        event: &event,
        displayname: None,
        member_count: 5,
        power_levels: None,
        sender: "@alice:localhost",
    };

    let mut matched = false;
    for rule in &rules {
        if let Some(actions) = evaluate_rule(rule, &ctx) {
            if actions.should_notify {
                matched = true;
                break;
            }
        }
    }
    assert!(matched, "plain message should trigger notify");

    // A notice should NOT notify (.m.rule.suppress_notices).
    let notice_event = json!({
        "type": "m.room.message",
        "room_id": "!testroom:localhost",
        "sender": "@bot:localhost",
        "content": { "msgtype": "m.notice", "body": "Bot output" }
    });
    let notice_ctx = EvalContext {
        event: &notice_event,
        displayname: None,
        member_count: 5,
        power_levels: None,
        sender: "@bot:localhost",
    };

    let mut notice_notify = false;
    for rule in &rules {
        if let Some(actions) = evaluate_rule(rule, &notice_ctx) {
            if actions.should_notify {
                notice_notify = true;
            }
            break; // first matching rule wins
        }
    }
    assert!(!notice_notify, ".m.rule.suppress_notices should block m.notice");
}

// ---------------------------------------------------------------------------
// Test: parse_actions helpers (dd8.4, dd8.5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_actions_variants() {
    use conduit_server::api::client::push::rules::parse_actions;
    use serde_json::json;

    let a = parse_actions(&json!(["notify", { "set_tweak": "highlight" }, { "set_tweak": "sound", "value": "default" }]));
    assert!(a.should_notify);
    assert!(a.highlight);
    assert_eq!(a.sound.as_deref(), Some("default"));

    let b = parse_actions(&json!(["dont_notify"]));
    assert!(!b.should_notify);
    assert!(!b.highlight);
    assert!(b.sound.is_none());
}

// ---------------------------------------------------------------------------
// Test: notifications_endpoint_stub (dd8.6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn notifications_endpoint_returns_empty_list() {
    let db = TempDb::new().await;
    let app = build_router(make_state(db.storage()));
    let token = do_register(&app, "eve").await;

    let resp = authed_get(&app, "/_matrix/client/v3/notifications", &token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    // The endpoint returns an empty list (v0 stub — full notif history is a follow-up).
    assert_eq!(body["notifications"].as_array().unwrap().len(), 0);
}
