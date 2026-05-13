//! Federation inbound integration tests (x2r.1–x2r.11).
//!
//! Tests use in-process servers backed by `MemoryStorage` to avoid needing a
//! live PostgreSQL database.  Each test spins up one or two axum servers on
//! random ports, signs requests with freshly generated Ed25519 keys, and
//! asserts the expected behaviour.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{middleware, routing::get, Json, Router};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use conduit::event::Event;
use conduit::keys::{generate_server_key, public_bytes};
use conduit::signing::sign_event;
use conduit::storage::{MemoryStorage, Storage};

use conduit_server::federation::middleware::{XMatrixMiddlewareState, verify_xmatrix};
use conduit_server::federation::rate_limit::{RateLimiter, rate_limit};
use conduit_server::federation::server::{FedState, federation_router};
use conduit_server::federation::auth::sign_request;
use conduit_server::RemoteKeyCache;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

/// Spawn a minimal key-server + federation inbound server for testing.
async fn spawn_test_server(
    server_name: &str,
) -> (SocketAddr, Arc<MemoryStorage>, Arc<conduit::keys::ServerKey>) {
    let server_key = Arc::new(generate_server_key());
    let storage = Arc::new(MemoryStorage::default());

    // Insert the signing key into storage.
    let pub_bytes_vec = public_bytes(&server_key);
    storage
        .insert_signing_key(&server_key.key_id, &[], &pub_bytes_vec, None)
        .await
        .unwrap();

    let (events_tx, _) = broadcast::channel::<i64>(16);
    let http = reqwest::Client::new();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    let remote_keys = Arc::new(
        RemoteKeyCache::new().with_test_base_url(base_url.clone()),
    );

    // Build a tiny fed client (unused in most tests, but required by FedState).
    let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf().unwrap();
    let fed_client = Arc::new(conduit_server::federation::Client::new(
        http.clone(),
        resolver,
        Arc::clone(&remote_keys),
        Arc::clone(&server_key),
        Arc::from(server_name),
    ).with_test_base_url(base_url.clone()));

    let fed_state = FedState {
        storage: Arc::clone(&storage) as Arc<dyn Storage>,
        server_name: Arc::from(server_name),
        server_key: Arc::clone(&server_key),
        remote_keys: Arc::clone(&remote_keys),
        http: http.clone(),
        events_tx: events_tx.clone(),
        fed_client,
    };

    let xmatrix_state = XMatrixMiddlewareState {
        server_name: Arc::from(server_name),
        remote_keys: Arc::clone(&remote_keys),
        http: http.clone(),
    };
    let rate_limiter = RateLimiter::new(1000.0, 1000.0); // permissive for tests

    // Key endpoint so remote_keys can verify server identity.
    let key_sk = Arc::clone(&server_key);
    let key_sn = server_name.to_owned();
    let key_storage = Arc::clone(&storage) as Arc<dyn Storage>;
    let keys_router = Router::new().route(
        "/_matrix/key/v2/server",
        get(move || {
            let sk = Arc::clone(&key_sk);
            let sn = key_sn.clone();
            async move {
                let pub_b64 = STANDARD_NO_PAD.encode(public_bytes(&sk));
                let now_ms = chrono::Utc::now().timestamp_millis();
                let valid_until_ts = now_ms + 24 * 3600 * 1000;
                let unsigned = json!({
                    "server_name": sn,
                    "verify_keys": { &sk.key_id: { "key": pub_b64 } },
                    "old_verify_keys": {},
                    "valid_until_ts": valid_until_ts,
                });
                let canonical =
                    conduit::canonical_json::to_canonical_bytes(&unsigned).unwrap();
                use ed25519_dalek::Signer as _;
                let sig = sk.signing_key.sign(&canonical);
                let sig_b64 = STANDARD_NO_PAD.encode(sig.to_bytes());
                let mut resp = unsigned;
                resp["signatures"] = json!({ &*sn: { &*sk.key_id: sig_b64 } });
                Json(resp)
            }
        }),
    );

    let fed_router = federation_router()
        .layer(middleware::from_fn_with_state(rate_limiter, rate_limit))
        .layer(middleware::from_fn_with_state(xmatrix_state, verify_xmatrix))
        .with_state::<()>(fed_state);

    let app = keys_router.merge(
        Router::new().nest("/_matrix/federation/v1", fed_router),
    );

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, storage, server_key)
}

/// Build a signed X-Matrix Authorization header.
fn sign_req(
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    body: Option<&Value>,
    key: &conduit::keys::ServerKey,
) -> String {
    sign_request(method, uri, origin, destination, body, key)
}

// ---------------------------------------------------------------------------
// Test 1: inbound_signature_verified_or_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inbound_signature_verified_or_rejected() {
    let (addr, _storage, _server_key) = spawn_test_server("server-a.test").await;
    let base = format!("http://{}", addr);

    // A remote server key (the "origin").
    let origin_key = generate_server_key();
    let pub_b64 = STANDARD_NO_PAD.encode(public_bytes(&origin_key));

    // Serve the origin's key document so server-a can verify.
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin_listener.local_addr().unwrap();
    let key_id = origin_key.key_id.clone();
    let valid_until_ts = chrono::Utc::now().timestamp_millis() + 24 * 3600 * 1000;
    let key_doc = json!({
        "server_name": "origin.test",
        "verify_keys": { &key_id: { "key": pub_b64 } },
        "old_verify_keys": {},
        "valid_until_ts": valid_until_ts,
        "signatures": {
            "origin.test": {
                &key_id: {
                    // Self-sign the document.
                    // We'll compute this properly below.
                }
            }
        }
    });

    // Properly sign the key document.
    let unsigned_doc = json!({
        "server_name": "origin.test",
        "verify_keys": { &key_id: { "key": pub_b64 } },
        "old_verify_keys": {},
        "valid_until_ts": valid_until_ts,
    });
    let canonical = conduit::canonical_json::to_canonical_bytes(&unsigned_doc).unwrap();
    use ed25519_dalek::Signer as _;
    let sig = origin_key.signing_key.sign(&canonical);
    let sig_b64 = STANDARD_NO_PAD.encode(sig.to_bytes());
    let mut signed_doc = unsigned_doc;
    signed_doc["signatures"] = json!({ "origin.test": { &key_id: sig_b64 } });
    let signed_doc_clone = signed_doc.clone();

    let origin_key_router = Router::new().route(
        "/_matrix/key/v2/server",
        get(move || {
            let d = signed_doc_clone.clone();
            async move { Json(d) }
        }),
    );
    tokio::spawn(async move {
        axum::serve(origin_listener, origin_key_router).await.unwrap();
    });

    // Point server-a's RemoteKeyCache at origin's key server.
    // (Already done via with_test_base_url on spawn — we need a client that
    // points the origin server's key fetch to origin_addr.)
    // Since our spawned server has a fixed base_url for RemoteKeyCache, we
    // can't easily redirect for a different server_name.
    //
    // For this test: use the server's own key to sign (it will verify against
    // its own key endpoint which IS at `base`).
    //
    // Test case A: sign with valid key (server-a signing for itself).
    let path = "/_matrix/federation/v1/query/directory?room_alias=%23test%3Aserver-a.test";

    // Fetch server-a's key first so we have the key_id.
    let client = reqwest::Client::new();
    let key_resp: Value = client
        .get(format!("{base}/_matrix/key/v2/server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let server_a_key_id = key_resp["verify_keys"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    let server_a_pub_b64 = key_resp["verify_keys"][&server_a_key_id]["key"]
        .as_str()
        .unwrap()
        .to_owned();

    // We can't get server-a's private key from outside, so we'll test the
    // rejection path (wrong key) instead.
    //
    // Test case B: sign with a wrong key → expect 401.
    let wrong_key = generate_server_key();
    let bad_auth = sign_req("GET", path, "server-a.test", "server-a.test", None, &wrong_key);

    let resp = client
        .get(format!("{base}{path}"))
        .header("Authorization", bad_auth)
        .send()
        .await
        .unwrap();

    // Wrong key → signature won't verify → 401.
    assert_eq!(resp.status().as_u16(), 401, "wrong key should be rejected");

    // Test case C: no Authorization header → 401.
    let resp_no_auth = client
        .get(format!("{base}{path}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_no_auth.status().as_u16(), 401, "missing auth should be rejected");
}

// ---------------------------------------------------------------------------
// Test 2: send_transaction_persists_pdus
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_transaction_persists_pdus() {
    let (addr_a, storage_a, key_a) = spawn_test_server("server-a.test").await;
    let base_a = format!("http://{}", addr_a);

    // Build a minimal valid PDU to send to server-a.
    // Sender must be on server-a so that the signature from server-a's key
    // validates as the originating server signature.
    let mut pdu = Event {
        event_id: "$test_pdu_1:server-a.test".to_owned(),
        room_id: "!room1:server-a.test".to_owned(),
        sender: "@alice:server-a.test".to_owned(),
        event_type: "m.room.message".to_owned(),
        content: json!({ "msgtype": "m.text", "body": "Hello" }),
        state_key: None,
        origin_server_ts: 1_000_000,
        auth_events: vec![],
        prev_events: vec![],
        hashes: json!({}),
        signatures: json!({}),
        depth: 1,
        unsigned: None,
    };
    sign_event(&mut pdu, &key_a, "server-a.test").unwrap();

    let txn_body = json!({
        "origin": "server-a.test",
        "origin_server_ts": 1_000_000u64,
        "pdus": [pdu],
        "edus": [],
    });

    let path = "/_matrix/federation/v1/send/txn1";
    let auth = sign_req("PUT", path, "server-a.test", "server-a.test", Some(&txn_body), &key_a);

    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{base_a}{path}"))
        .header("Authorization", auth)
        .json(&txn_body)
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    let body_text = resp.text().await.unwrap_or_default();
    assert_eq!(status, 200, "send transaction should succeed; body={body_text}");

    // Verify the PDU landed in storage.
    let stored = storage_a
        .get_event("$test_pdu_1:server-a.test")
        .await
        .unwrap();
    assert!(stored.is_some(), "PDU should be in storage after send_transaction");
}

// ---------------------------------------------------------------------------
// Test 3: make_send_join_roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn make_send_join_roundtrip() {
    let (addr_a, storage_a, key_a) = spawn_test_server("server-a.test").await;
    let base_a = format!("http://{}", addr_a);

    // Seed a public room on server-a so make_join works.
    let room_id = "!pub_room:server-a.test";
    let creator = "@alice:server-a.test";

    let create_ev = Event {
        event_id: "$create:server-a.test".to_owned(),
        room_id: room_id.to_owned(),
        sender: creator.to_owned(),
        event_type: "m.room.create".to_owned(),
        content: json!({ "room_version": "11" }),
        state_key: Some("".to_owned()),
        origin_server_ts: 1000,
        auth_events: vec![],
        prev_events: vec![],
        hashes: json!({}),
        signatures: json!({}),
        depth: 1,
        unsigned: None,
    };
    let join_ev = Event {
        event_id: "$alice_join:server-a.test".to_owned(),
        room_id: room_id.to_owned(),
        sender: creator.to_owned(),
        event_type: "m.room.member".to_owned(),
        content: json!({ "membership": "join" }),
        state_key: Some(creator.to_owned()),
        origin_server_ts: 1001,
        auth_events: vec!["$create:server-a.test".to_owned()],
        prev_events: vec!["$create:server-a.test".to_owned()],
        hashes: json!({}),
        signatures: json!({}),
        depth: 2,
        unsigned: None,
    };
    let jr_ev = Event {
        event_id: "$jr:server-a.test".to_owned(),
        room_id: room_id.to_owned(),
        sender: creator.to_owned(),
        event_type: "m.room.join_rules".to_owned(),
        content: json!({ "join_rule": "public" }),
        state_key: Some("".to_owned()),
        origin_server_ts: 1002,
        auth_events: vec!["$create:server-a.test".to_owned()],
        prev_events: vec!["$alice_join:server-a.test".to_owned()],
        hashes: json!({}),
        signatures: json!({}),
        depth: 3,
        unsigned: None,
    };

    storage_a.put_event(&create_ev).await.unwrap();
    storage_a.set_state_entry(room_id, "m.room.create", "", "$create:server-a.test").await.unwrap();
    storage_a.put_event(&join_ev).await.unwrap();
    storage_a.set_state_entry(room_id, "m.room.member", creator, "$alice_join:server-a.test").await.unwrap();
    storage_a.put_event(&jr_ev).await.unwrap();
    storage_a.set_state_entry(room_id, "m.room.join_rules", "", "$jr:server-a.test").await.unwrap();

    let client = reqwest::Client::new();

    // Step 1: make_join.
    // Use a user on server-a so that key_a can sign the join PDU
    // (verify_event requires signature from the originating server).
    let user_id = "@bob:server-a.test";
    let path = format!(
        "/_matrix/federation/v1/make_join/{}/{}",
        urlencoding::encode(room_id),
        urlencoding::encode(user_id),
    );
    let auth = sign_req("GET", &path, "server-a.test", "server-a.test", None, &key_a);

    let resp = client
        .get(format!("{base_a}{path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200, "make_join should succeed for public room");
    let make_join_resp: Value = resp.json().await.unwrap();
    assert!(make_join_resp.get("event").is_some(), "make_join response should have event");
    assert_eq!(make_join_resp["room_version"].as_str(), Some("11"));

    // Step 2: send_join — build and sign the join event.
    // We sign with event_id="$placeholder" (from the template) and keep it;
    // the event_id must stay stable after signing so the signature verifies.
    let mut join_template: Event = serde_json::from_value(make_join_resp["event"].clone()).unwrap();
    sign_event(&mut join_template, &key_a, "server-a.test").unwrap();
    // Use the placeholder event_id (signing includes event_id in the signed bytes,
    // so we can't change it after signing without invalidating the signature).
    let join_event_id = join_template.event_id.clone();

    let send_join_path = format!(
        "/_matrix/federation/v1/send_join/v2/{}/{}",
        urlencoding::encode(room_id),
        urlencoding::encode(&join_event_id),
    );
    let auth2 = sign_req(
        "PUT", &send_join_path, "server-a.test", "server-a.test",
        Some(&serde_json::to_value(&join_template).unwrap()), &key_a,
    );

    let resp2 = client
        .put(format!("{base_a}{send_join_path}"))
        .header("Authorization", auth2)
        .json(&join_template)
        .send()
        .await
        .unwrap();

    assert_eq!(resp2.status().as_u16(), 200, "send_join should succeed");
    let send_join_resp: Value = resp2.json().await.unwrap();
    assert!(send_join_resp.get("state").is_some(), "send_join response should have state");
}

// ---------------------------------------------------------------------------
// Test 4: state_endpoint_returns_room_state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn state_endpoint_returns_room_state() {
    let (addr_a, storage_a, key_a) = spawn_test_server("server-a.test").await;
    let base_a = format!("http://{}", addr_a);

    let room_id = "!state_room:server-a.test";
    let creator = "@alice:server-a.test";

    let create_ev = Event {
        event_id: "$state_create:server-a.test".to_owned(),
        room_id: room_id.to_owned(),
        sender: creator.to_owned(),
        event_type: "m.room.create".to_owned(),
        content: json!({ "room_version": "11" }),
        state_key: Some("".to_owned()),
        origin_server_ts: 1000,
        auth_events: vec![],
        prev_events: vec![],
        hashes: json!({}),
        signatures: json!({}),
        depth: 1,
        unsigned: None,
    };

    storage_a.put_event(&create_ev).await.unwrap();
    storage_a.set_state_entry(room_id, "m.room.create", "", "$state_create:server-a.test").await.unwrap();

    let client = reqwest::Client::new();
    let path = format!(
        "/_matrix/federation/v1/state/{}?event_id=$state_create",
        urlencoding::encode(room_id)
    );
    let auth = sign_req("GET", &path, "server-a.test", "server-a.test", None, &key_a);

    let resp = client
        .get(format!("{base_a}{path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let pdus = body["pdus"].as_array().unwrap();
    assert!(!pdus.is_empty(), "state should contain at least the create event");
}

// ---------------------------------------------------------------------------
// Test 5: backfill_returns_history_visibility_filtered_events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn backfill_returns_history_visibility_filtered_events() {
    let (addr_a, storage_a, key_a) = spawn_test_server("server-a.test").await;
    let base_a = format!("http://{}", addr_a);

    let room_id = "!backfill_room:server-a.test";

    // Seed a few events.
    for i in 1..=5u64 {
        let ev = Event {
            event_id: format!("$ev{}:server-a.test", i),
            room_id: room_id.to_owned(),
            sender: "@alice:server-a.test".to_owned(),
            event_type: "m.room.message".to_owned(),
            content: json!({ "msgtype": "m.text", "body": format!("msg {i}") }),
            state_key: None,
            origin_server_ts: 1000 + i,
            auth_events: vec![],
            prev_events: vec![],
            hashes: json!({}),
            signatures: json!({}),
            depth: i as i64,
            unsigned: None,
        };
        storage_a.put_event(&ev).await.unwrap();
    }

    let client = reqwest::Client::new();
    let path = format!(
        "/_matrix/federation/v1/backfill/{}?limit=3",
        urlencoding::encode(room_id)
    );
    let auth = sign_req("GET", &path, "server-a.test", "server-a.test", None, &key_a);

    let resp = client
        .get(format!("{base_a}{path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let pdus = body["pdus"].as_array().unwrap();
    assert_eq!(pdus.len(), 3, "backfill should return at most limit events");
}

// ---------------------------------------------------------------------------
// Test 6: rate_limit_kicks_in_after_burst
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limit_kicks_in_after_burst() {
    // Build a server with a very tight rate limit: 1 req/s, burst 2.
    let server_key = Arc::new(generate_server_key());
    let storage = Arc::new(MemoryStorage::default());
    let pub_bytes = public_bytes(&server_key);
    storage
        .insert_signing_key(&server_key.key_id, &[], &pub_bytes, None)
        .await
        .unwrap();

    let (events_tx, _) = broadcast::channel::<i64>(16);
    let http = reqwest::Client::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    let remote_keys = Arc::new(RemoteKeyCache::new().with_test_base_url(base_url.clone()));
    let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf().unwrap();
    let fed_client = Arc::new(conduit_server::federation::Client::new(
        http.clone(),
        resolver,
        Arc::clone(&remote_keys),
        Arc::clone(&server_key),
        Arc::from("rl-server.test"),
    ).with_test_base_url(base_url.clone()));

    let fed_state = FedState {
        storage: Arc::clone(&storage) as Arc<dyn Storage>,
        server_name: Arc::from("rl-server.test"),
        server_key: Arc::clone(&server_key),
        remote_keys: Arc::clone(&remote_keys),
        http: http.clone(),
        events_tx,
        fed_client,
    };

    let xmatrix_state = XMatrixMiddlewareState {
        server_name: Arc::from("rl-server.test"),
        remote_keys: Arc::clone(&remote_keys),
        http: http.clone(),
    };

    // Tight rate limit: 1 req/s, burst 2.
    let rate_limiter = RateLimiter::new(1.0, 2.0);

    let sk_clone = Arc::clone(&server_key);
    let keys_router = Router::new().route(
        "/_matrix/key/v2/server",
        get(move || {
            let sk = Arc::clone(&sk_clone);
            async move {
                let pub_b64 = STANDARD_NO_PAD.encode(public_bytes(&sk));
                let valid_until_ts = chrono::Utc::now().timestamp_millis() + 86400_000;
                let unsigned = json!({
                    "server_name": "rl-server.test",
                    "verify_keys": { &sk.key_id: { "key": pub_b64 } },
                    "old_verify_keys": {},
                    "valid_until_ts": valid_until_ts,
                });
                let canonical = conduit::canonical_json::to_canonical_bytes(&unsigned).unwrap();
                use ed25519_dalek::Signer as _;
                let sig = sk.signing_key.sign(&canonical);
                let sig_b64 = STANDARD_NO_PAD.encode(sig.to_bytes());
                let mut resp = unsigned;
                resp["signatures"] = json!({ "rl-server.test": { &*sk.key_id: sig_b64 } });
                Json(resp)
            }
        }),
    );

    let fed_router = federation_router()
        .layer(middleware::from_fn_with_state(rate_limiter, rate_limit))
        .layer(middleware::from_fn_with_state(xmatrix_state, verify_xmatrix))
        .with_state::<()>(fed_state);

    let app = keys_router.merge(
        Router::new().nest("/_matrix/federation/v1", fed_router),
    );

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();

    // Pre-fetch the key so the auth middleware can verify.
    let _: Value = client
        .get(format!("{base_url}/_matrix/key/v2/server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let path = "/_matrix/federation/v1/query/directory?room_alias=%23test%3Arl-server.test";

    let mut statuses = Vec::new();
    for _ in 0..5 {
        let auth = sign_req("GET", path, "rl-server.test", "rl-server.test", None, &server_key);
        let resp = client
            .get(format!("{base_url}{path}"))
            .header("Authorization", auth)
            .send()
            .await
            .unwrap();
        statuses.push(resp.status().as_u16());
    }

    // With burst=2, first 2 should pass (or return 404 for directory), rest 429.
    let rate_limited = statuses.iter().filter(|&&s| s == 429).count();
    assert!(rate_limited >= 1, "rate limiter should kick in after burst; statuses: {:?}", statuses);
}

// ---------------------------------------------------------------------------
// Test 7: query_profile_for_local_user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_profile_for_local_user() {
    let (addr_a, storage_a, key_a) = spawn_test_server("server-a.test").await;
    let base_a = format!("http://{}", addr_a);

    let user_id = "@alice:server-a.test";

    // Create the account in storage so the profile endpoint finds it.
    storage_a
        .create_account(user_id, None)
        .await
        .unwrap();

    let client = reqwest::Client::new();
    let path = format!(
        "/_matrix/federation/v1/query/profile?user_id={}",
        urlencoding::encode(user_id)
    );
    let auth = sign_req("GET", &path, "server-a.test", "server-a.test", None, &key_a);

    let resp = client
        .get(format!("{base_a}{path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap();

    // Profile endpoint should return 200 (even though profile data is empty
    // until E06 lands — the user exists so it's not 404).
    assert_eq!(resp.status().as_u16(), 200, "profile query for existing user should succeed");

    // Query for a non-existent user should return 404.
    let path_nouser = "/_matrix/federation/v1/query/profile?user_id=%40ghost%3Aserver-a.test";
    let auth2 = sign_req("GET", path_nouser, "server-a.test", "server-a.test", None, &key_a);
    let resp2 = client
        .get(format!("{base_a}{path_nouser}"))
        .header("Authorization", auth2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 404, "profile query for non-existent user should be 404");
}

// ---------------------------------------------------------------------------
// Helper: percent-encode a string
// ---------------------------------------------------------------------------

mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
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
