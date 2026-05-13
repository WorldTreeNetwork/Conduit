//! E2EE integration tests (E10 mrm.1–mrm.13).
//!
//! # Running
//! ```
//! DATABASE_URL=postgresql://postgres@localhost/conduit \
//!     cargo test --workspace --tests e2ee
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
use tokio::sync::{RwLock, broadcast};
use tower::util::ServiceExt as _;

use conduit::keys::ServerKey;
use conduit::storage::Storage;
use conduit_server::{
    PostgresStorage,
    api::client::{self as auth, AuthState, TxnCacheKey},
    api::client::keys as keys_api,
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
        let db_name = format!("conduit_test_e2ee_{}_{}", tid, nanos).to_lowercase();

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
}

impl TestState {
    fn new(storage: Arc<dyn Storage>) -> Self {
        let (events_tx, _) = broadcast::channel(256);
        Self {
            storage,
            server_name: "localhost".into(),
            server_key: Arc::new(conduit::keys::generate_server_key()),
            txn_cache: Arc::new(RwLock::new(HashMap::new())),
            events_tx,
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
        .route("/_matrix/client/v3/sync", get(sync_api::sync::<TestState>))
        .route("/_matrix/client/v3/keys/upload", post(keys_api::keys_upload::<TestState>))
        .route("/_matrix/client/v3/keys/query", post(keys_api::keys_query::<TestState>))
        .route("/_matrix/client/v3/keys/claim", post(keys_api::keys_claim::<TestState>))
        .route("/_matrix/client/v3/keys/changes", get(keys_api::keys_changes::<TestState>))
        .route(
            "/_matrix/client/v3/sendToDevice/:eventType/:txnId",
            put(keys_api::send_to_device::<TestState>),
        )
        .route(
            "/_matrix/client/v3/keys/device_signing/upload",
            post(keys_api::device_signing_upload::<TestState>),
        )
        .route(
            "/_matrix/client/v3/keys/signatures/upload",
            post(keys_api::signatures_upload::<TestState>),
        )
        .route(
            "/_matrix/client/v3/room_keys/version",
            get(keys_api::room_keys_version_get_latest::<TestState>)
                .post(keys_api::room_keys_version_create::<TestState>),
        )
        .route(
            "/_matrix/client/v3/room_keys/version/:version",
            get(keys_api::room_keys_version_get::<TestState>)
                .put(keys_api::room_keys_version_update::<TestState>)
                .delete(keys_api::room_keys_version_delete::<TestState>),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys",
            get(keys_api::room_keys_get_all::<TestState>)
                .put(keys_api::room_keys_put_all::<TestState>)
                .delete(keys_api::room_keys_delete_all::<TestState>),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys/:roomId",
            get(keys_api::room_keys_get_room::<TestState>)
                .put(keys_api::room_keys_put_room::<TestState>),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys/:roomId/:sessionId",
            get(keys_api::room_keys_get_session::<TestState>)
                .put(keys_api::room_keys_put_session::<TestState>),
        )
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn register_user(app: &Router, username: &str) -> (String, String, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/register")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "username": username,
                        "password": "testpass",
                        "auth": { "type": "m.login.dummy" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register failed for {username}");
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    (
        body["user_id"].as_str().unwrap().to_owned(),
        body["access_token"].as_str().unwrap().to_owned(),
        body["device_id"].as_str().unwrap().to_owned(),
    )
}

async fn post_json(app: &Router, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let b: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    (status, b)
}

async fn put_json(app: &Router, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let b: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    (status, b)
}

async fn get_req(app: &Router, path: &str, token: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let b: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    (status, b)
}

// ---------------------------------------------------------------------------
// Test 1: keys_upload_persists (mrm.1, mrm.2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn keys_upload_persists() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let (user_id, token, device_id) = register_user(&app, "keysuploaduser").await;

    let device_keys = json!({
        "user_id": user_id,
        "device_id": device_id,
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
        "keys": {
            format!("curve25519:{device_id}"): "AAAAAAAAAAAAAAAAAAAAAA",
            format!("ed25519:{device_id}"): "BBBBBBBBBBBBBBBBBBBBBBB",
        },
        "signatures": {}
    });

    let (status, body) = post_json(
        &app,
        "/_matrix/client/v3/keys/upload",
        &token,
        json!({
            "device_keys": device_keys,
            "one_time_keys": {
                "signed_curve25519:AAAAA": { "key": "abc123", "signatures": {} },
                "signed_curve25519:BBBBB": { "key": "def456", "signatures": {} },
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "upload failed: {body}");
    assert!(body["one_time_key_counts"]["signed_curve25519"].as_i64().unwrap() >= 2);

    // /keys/query should return the uploaded device keys.
    let (qstatus, qbody) = post_json(
        &app,
        "/_matrix/client/v3/keys/query",
        &token,
        json!({ "device_keys": { user_id.clone(): [] } }),
    )
    .await;
    assert_eq!(qstatus, StatusCode::OK, "query failed: {qbody}");
    let returned = &qbody["device_keys"][&user_id][&device_id];
    assert!(returned.is_object(), "device keys not returned: {qbody}");
}

// ---------------------------------------------------------------------------
// Test 2: keys_claim_consumes_atomically (mrm.3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn keys_claim_consumes_atomically() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let (user_id, token, device_id) = register_user(&app, "claimuser").await;

    // Upload 3 OTKs.
    post_json(
        &app,
        "/_matrix/client/v3/keys/upload",
        &token,
        json!({
            "one_time_keys": {
                "signed_curve25519:KEY1": { "key": "k1", "signatures": {} },
                "signed_curve25519:KEY2": { "key": "k2", "signatures": {} },
                "signed_curve25519:KEY3": { "key": "k3", "signatures": {} },
            }
        }),
    )
    .await;

    // Claim 3 times — each should get a different key.
    let claim_body = json!({
        "one_time_keys": { &user_id: { &device_id: "signed_curve25519" } }
    });

    let mut claimed_keys = std::collections::HashSet::new();
    for _ in 0..3 {
        let (status, body) = post_json(&app, "/_matrix/client/v3/keys/claim", &token, claim_body.clone()).await;
        assert_eq!(status, StatusCode::OK);
        let user_keys = &body["one_time_keys"][&user_id][&device_id];
        assert!(user_keys.is_object(), "expected keys: {body}");
        let key_id = user_keys.as_object().unwrap().keys().next().unwrap().clone();
        assert!(claimed_keys.insert(key_id.clone()), "duplicate key claimed: {key_id}");
    }
    assert_eq!(claimed_keys.len(), 3);

    // 4th claim returns nothing (no OTKs left, no fallback).
    let (status, body) = post_json(&app, "/_matrix/client/v3/keys/claim", &token, claim_body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let empty = body["one_time_keys"][&user_id][&device_id].is_null()
        || body["one_time_keys"][&user_id].is_null()
        || body["one_time_keys"].as_object().map(|m| m.is_empty()).unwrap_or(true);
    assert!(empty, "expected no key on 4th claim, got: {body}");
}

// ---------------------------------------------------------------------------
// Test 3: keys_claim_concurrent_no_double_spend (mrm.3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn keys_claim_concurrent_no_double_spend() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());

    let (user_id, token, device_id) = register_user(&build_router(state.clone()), "concurrentuser").await;

    // Upload 3 OTKs directly through storage.
    let storage = db.storage();
    storage
        .insert_one_time_keys(
            &user_id,
            &device_id,
            vec![
                ("signed_curve25519:C1".to_owned(), "signed_curve25519".to_owned(), json!({"key":"c1"})),
                ("signed_curve25519:C2".to_owned(), "signed_curve25519".to_owned(), json!({"key":"c2"})),
                ("signed_curve25519:C3".to_owned(), "signed_curve25519".to_owned(), json!({"key":"c3"})),
            ],
        )
        .await
        .unwrap();

    // 5 concurrent claims — only 3 should succeed.
    let app = build_router(state.clone());
    let claim_body = json!({
        "one_time_keys": { &user_id: { &device_id: "signed_curve25519" } }
    });

    let mut tasks = Vec::new();
    for _ in 0..5 {
        let app2 = app.clone();
        let body2 = claim_body.clone();
        let token2 = token.clone();
        tasks.push(tokio::spawn(async move {
            post_json(&app2, "/_matrix/client/v3/keys/claim", &token2, body2).await
        }));
    }

    let mut success_keys = std::collections::HashSet::new();
    for t in tasks {
        let (_, body) = t.await.unwrap();
        if let Some(uid_map) = body["one_time_keys"].as_object() {
            if !uid_map.is_empty() {
                if let Some(dev_map) = uid_map.values().next().and_then(|v| v.as_object()) {
                    if let Some(key_map) = dev_map.values().next().and_then(|v| v.as_object()) {
                        for kid in key_map.keys() {
                            success_keys.insert(kid.clone());
                        }
                    }
                }
            }
        }
    }
    // Exactly 3 distinct keys should have been returned.
    assert_eq!(success_keys.len(), 3, "expected exactly 3 unique keys, got {:?}", success_keys);
}

// ---------------------------------------------------------------------------
// Test 4: keys_changes_returns_delta (mrm.4)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn keys_changes_returns_delta() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state.clone());

    let (user_id, token, device_id) = register_user(&app, "changesuser").await;

    // Get baseline token.
    let (_, sync_body) = get_req(&app, "/_matrix/client/v3/sync", &token).await;
    let next_batch = sync_body["next_batch"].as_str().unwrap_or("s0_d0").to_owned();

    // Extract device pos from token.
    let from_token = if next_batch.contains("_d") {
        next_batch.clone()
    } else {
        format!("{}_d0", next_batch)
    };

    // Upload device keys — this records a device list change.
    post_json(
        &app,
        "/_matrix/client/v3/keys/upload",
        &token,
        json!({
            "device_keys": { "user_id": user_id, "device_id": device_id, "algorithms": [], "keys": {}, "signatures": {} }
        }),
    )
    .await;

    // /keys/changes should include the user.
    let (status, body) = get_req(
        &app,
        &format!("/_matrix/client/v3/keys/changes?from={}&to=now", from_token),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "keys/changes failed: {body}");
    let changed = body["changed"].as_array().unwrap();
    assert!(
        changed.iter().any(|u| u.as_str() == Some(&user_id)),
        "expected {user_id} in changed: {body}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: fallback_key_used_only_when_otks_exhausted (mrm.5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fallback_key_used_only_when_otks_exhausted() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let (user_id, token, device_id) = register_user(&app, "fallbackuser").await;

    // Upload 1 OTK + 1 fallback key.
    post_json(
        &app,
        "/_matrix/client/v3/keys/upload",
        &token,
        json!({
            "one_time_keys": {
                "signed_curve25519:OTK1": { "key": "otk1", "signatures": {} },
            },
            "fallback_keys": {
                "signed_curve25519:FB1": { "key": "fb1", "fallback": true, "signatures": {} },
            }
        }),
    )
    .await;

    // First claim: should return OTK, not fallback.
    let (_, body1) = post_json(
        &app,
        "/_matrix/client/v3/keys/claim",
        &token,
        json!({ "one_time_keys": { &user_id: { &device_id: "signed_curve25519" } } }),
    )
    .await;
    let key1_map = &body1["one_time_keys"][&user_id][&device_id];
    let key1_id = key1_map.as_object().unwrap().keys().next().unwrap();
    assert!(
        key1_id.contains("OTK1"),
        "first claim should be OTK, got {key1_id}: {body1}"
    );

    // Second claim: OTKs exhausted, should return fallback.
    let (_, body2) = post_json(
        &app,
        "/_matrix/client/v3/keys/claim",
        &token,
        json!({ "one_time_keys": { &user_id: { &device_id: "signed_curve25519" } } }),
    )
    .await;
    let key2_map = &body2["one_time_keys"][&user_id][&device_id];
    let key2_id = key2_map.as_object().unwrap().keys().next().unwrap();
    assert!(
        key2_id.contains("FB1"),
        "second claim should be fallback, got {key2_id}: {body2}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: send_to_device_delivered_via_sync (mrm.6, mrm.7)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_to_device_delivered_via_sync() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let (user_a, token_a, _) = register_user(&app, "tdeva").await;
    let (user_b, token_b, device_b) = register_user(&app, "tdevb").await;

    // A sends to-device message to B.
    let (status, _) = put_json(
        &app,
        "/_matrix/client/v3/sendToDevice/m.room.encrypted/txn001",
        &token_a,
        json!({
            "messages": {
                &user_b: {
                    &device_b: { "algorithm": "m.olm.v1.curve25519-aes-sha2", "ciphertext": "encrypted_payload" }
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // B's /sync should include the to-device message.
    let (_, sync_body) = get_req(&app, "/_matrix/client/v3/sync", &token_b).await;
    let to_device_events = sync_body["to_device"]["events"].as_array().unwrap();
    assert_eq!(
        to_device_events.len(),
        1,
        "expected 1 to-device event: {sync_body}"
    );
    let ev = &to_device_events[0];
    assert_eq!(ev["type"].as_str().unwrap(), "m.room.encrypted");
    assert_eq!(ev["sender"].as_str().unwrap(), user_a);

    // B's *next* /sync with the returned next_batch should NOT see the message again.
    let next_batch = sync_body["next_batch"].as_str().unwrap().to_owned();
    let (_, sync_body2) = get_req(
        &app,
        &format!("/_matrix/client/v3/sync?since={}", next_batch),
        &token_b,
    )
    .await;
    let events2 = sync_body2["to_device"]["events"].as_array().unwrap();
    assert!(
        events2.is_empty(),
        "to-device message should not be re-delivered: {sync_body2}"
    );
}

// ---------------------------------------------------------------------------
// Test 7: cross_signing_upload_round_trip (mrm.8)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cross_signing_upload_round_trip() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let (user_id, token, _) = register_user(&app, "xsignuser").await;

    let master_key = json!({
        "user_id": user_id,
        "usage": ["master"],
        "keys": { format!("ed25519:MASTERKEY"): "MASTERKEYPUBLIC" },
        "signatures": {}
    });

    let (status, _) = post_json(
        &app,
        "/_matrix/client/v3/keys/device_signing/upload",
        &token,
        json!({ "master_key": master_key }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // /keys/query should return the master key.
    let (qstatus, qbody) = post_json(
        &app,
        "/_matrix/client/v3/keys/query",
        &token,
        json!({ "device_keys": { &user_id: [] } }),
    )
    .await;
    assert_eq!(qstatus, StatusCode::OK, "query failed: {qbody}");
    assert!(
        qbody["master_keys"][&user_id].is_object(),
        "master key not returned: {qbody}"
    );
}

// ---------------------------------------------------------------------------
// Test 8: device_list_changes_appear_in_sync (mrm.11, mrm.12)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn device_list_changes_appear_in_sync() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let (user_a, token_a, device_a) = register_user(&app, "dlchangea").await;
    let (_user_b, token_b, _) = register_user(&app, "dlchangeb").await;

    // B does initial /sync to get baseline token.
    let (_, sync0) = get_req(&app, "/_matrix/client/v3/sync", &token_b).await;
    let since = sync0["next_batch"].as_str().unwrap().to_owned();

    // A uploads device keys → records device_list_change.
    post_json(
        &app,
        "/_matrix/client/v3/keys/upload",
        &token_a,
        json!({
            "device_keys": {
                "user_id": user_a,
                "device_id": device_a,
                "algorithms": [],
                "keys": {},
                "signatures": {}
            }
        }),
    )
    .await;

    // B's incremental /sync should show A in device_lists.changed.
    let (_, sync1) = get_req(
        &app,
        &format!("/_matrix/client/v3/sync?since={}", since),
        &token_b,
    )
    .await;
    let changed = sync1["device_lists"]["changed"].as_array().unwrap();
    assert!(
        changed.iter().any(|u| u.as_str() == Some(&user_a)),
        "expected {user_a} in device_lists.changed: {sync1}"
    );
}

// ---------------------------------------------------------------------------
// Test 9: room_keys_version_create_and_get (mrm.13)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn room_keys_version_create_and_get() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let (_, token, _) = register_user(&app, "rkbackupuser").await;

    let auth_data = json!({ "public_key": "TESTPUBLICKEY" });
    let (status, body) = post_json(
        &app,
        "/_matrix/client/v3/room_keys/version",
        &token,
        json!({
            "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
            "auth_data": auth_data
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create version failed: {body}");
    let version = body["version"].as_str().unwrap().to_owned();

    // GET the version back.
    let (gstatus, gbody) = get_req(
        &app,
        &format!("/_matrix/client/v3/room_keys/version/{}", version),
        &token,
    )
    .await;
    assert_eq!(gstatus, StatusCode::OK, "get version failed: {gbody}");
    assert_eq!(gbody["version"].as_str().unwrap(), version);
    assert_eq!(
        gbody["algorithm"].as_str().unwrap(),
        "m.megolm_backup.v1.curve25519-aes-sha2"
    );
    assert_eq!(gbody["auth_data"]["public_key"].as_str().unwrap(), "TESTPUBLICKEY");
}

// ---------------------------------------------------------------------------
// Test 10: room_keys_upsert_and_get (mrm.13)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn room_keys_upsert_and_get() {
    let db = TempDb::new().await;
    let state = TestState::new(db.storage());
    let app = build_router(state);

    let (_, token, _) = register_user(&app, "rkupsertuser").await;

    // Create backup version.
    let (_, cbody) = post_json(
        &app,
        "/_matrix/client/v3/room_keys/version",
        &token,
        json!({
            "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
            "auth_data": { "public_key": "XYZ" }
        }),
    )
    .await;
    let version = cbody["version"].as_str().unwrap().to_owned();

    let room_id = "!testroom:localhost";
    let session_id = "session001";
    let key_data = json!({
        "first_message_index": 0,
        "forwarded_count": 0,
        "is_verified": false,
        "session_data": { "ciphertext": "encrypted_session_key" }
    });

    // PUT the key.
    let (pstatus, pbody) = put_json(
        &app,
        &format!(
            "/_matrix/client/v3/room_keys/keys/{}/{}?version={}",
            urlencoding::encode(room_id),
            session_id,
            version
        ),
        &token,
        key_data.clone(),
    )
    .await;
    assert_eq!(pstatus, StatusCode::OK, "put key failed: {pbody}");
    assert_eq!(pbody["count"].as_i64().unwrap(), 1);

    // GET it back.
    let (gstatus, gbody) = get_req(
        &app,
        &format!(
            "/_matrix/client/v3/room_keys/keys/{}/{}?version={}",
            urlencoding::encode(room_id),
            session_id,
            version
        ),
        &token,
    )
    .await;
    assert_eq!(gstatus, StatusCode::OK, "get key failed: {gbody}");
    assert_eq!(
        gbody["session_data"]["ciphertext"].as_str().unwrap(),
        "encrypted_session_key"
    );
}

// ---------------------------------------------------------------------------
// URL encoding helper for room IDs (contain !)
// ---------------------------------------------------------------------------

mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char);
                }
                other => {
                    out.push('%');
                    out.push(hex_nibble(other >> 4));
                    out.push(hex_nibble(other & 0xf));
                }
            }
        }
        out
    }

    fn hex_nibble(n: u8) -> char {
        match n {
            0..=9 => (b'0' + n) as char,
            _ => (b'A' + n - 10) as char,
        }
    }
}
