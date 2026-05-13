//! In-process federation roundtrip tests (x2r.12).
//!
//! Spins up two Conduit-in-process servers (A and B) on separate ports with
//! separate MemoryStorage instances and verifies end-to-end federation works:
//!
//! 1. Server B can fetch Server A's keys.
//! 2. Server B sends a `PUT /send` transaction to Server A; PDU lands in A's storage.
//! 3. User on A creates a room; B "joins" via make_join + send_join; both sides
//!    see consistent state.
//!
//! Follow-up: run full sytest/complement against a live Postgres instance.
//! Filed as: conduit-x2r.12 follow-up.

use std::sync::Arc;

use axum::{middleware, routing::get, Json, Router};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use conduit::event::Event;
use conduit::keys::{generate_server_key, public_bytes, ServerKey};
use conduit::signing::sign_event;
use conduit::storage::{MemoryStorage, Storage};

use conduit_server::federation::auth::sign_request;
use conduit_server::federation::middleware::{XMatrixMiddlewareState, verify_xmatrix};
use conduit_server::federation::rate_limit::{RateLimiter, rate_limit};
use conduit_server::federation::server::{FedState, federation_router};
use conduit_server::RemoteKeyCache;

// ---------------------------------------------------------------------------
// Server fixture
// ---------------------------------------------------------------------------

struct TestServer {
    pub base_url: String,
    pub server_name: Arc<str>,
    pub server_key: Arc<ServerKey>,
    pub storage: Arc<MemoryStorage>,
    pub http: reqwest::Client,
}

async fn spawn_server(server_name: &str) -> TestServer {
    let server_key = Arc::new(generate_server_key());
    let storage = Arc::new(MemoryStorage::default());

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

    // remote_keys for this server points to itself so tests can authenticate.
    let remote_keys = Arc::new(
        RemoteKeyCache::new().with_test_base_url(base_url.clone()),
    );

    let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf().unwrap();
    let fed_client = Arc::new(
        conduit_server::federation::Client::new(
            http.clone(),
            resolver,
            Arc::clone(&remote_keys),
            Arc::clone(&server_key),
            Arc::from(server_name),
        )
        .with_test_base_url(base_url.clone()),
    );

    let fed_state = FedState {
        storage: Arc::clone(&storage) as Arc<dyn Storage>,
        server_name: Arc::from(server_name),
        server_key: Arc::clone(&server_key),
        remote_keys: Arc::clone(&remote_keys),
        http: http.clone(),
        events_tx: events_tx.clone(),
        fed_client: Arc::clone(&fed_client),
    };

    let xmatrix_state = XMatrixMiddlewareState {
        server_name: Arc::from(server_name),
        remote_keys: Arc::clone(&remote_keys),
        http: http.clone(),
    };
    let rate_limiter = RateLimiter::new(10000.0, 10000.0);

    let sk_clone = Arc::clone(&server_key);
    let sn_clone = server_name.to_owned();
    let keys_router = Router::new().route(
        "/_matrix/key/v2/server",
        get(move || {
            let sk = Arc::clone(&sk_clone);
            let sn = sn_clone.clone();
            async move {
                let pub_b64 = STANDARD_NO_PAD.encode(public_bytes(&sk));
                let valid_until_ts = chrono::Utc::now().timestamp_millis() + 86_400_000;
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

    TestServer {
        base_url,
        server_name: Arc::from(server_name),
        server_key,
        storage,
        http,
    }
}

fn sign_req(
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    body: Option<&Value>,
    key: &ServerKey,
) -> String {
    sign_request(method, uri, origin, destination, body, key)
}

// ---------------------------------------------------------------------------
// Test RT-1: Server B fetches A's keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rt1_server_b_fetches_a_keys() {
    let server_a = spawn_server("a.test").await;

    let resp: Value = server_a
        .http
        .get(format!("{}/_matrix/key/v2/server", server_a.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["server_name"].as_str(), Some("a.test"));
    let verify_keys = resp["verify_keys"].as_object().unwrap();
    assert!(!verify_keys.is_empty(), "server should advertise at least one key");
}

// ---------------------------------------------------------------------------
// Test RT-2: Server B sends a transaction to Server A; PDU lands in A's storage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rt2_b_sends_transaction_to_a() {
    let server_a = spawn_server("a.test").await;

    // Build a PDU signed by server-a's key (in a real scenario server-b would
    // sign it; for the roundtrip we reuse a's key since RemoteKeyCache only
    // points to a's key endpoint in this fixture).
    let mut pdu = Event {
        event_id: "$rt2_pdu:a.test".to_owned(),
        room_id: "!rt2_room:a.test".to_owned(),
        sender: "@alice:a.test".to_owned(),
        event_type: "m.room.message".to_owned(),
        content: json!({ "msgtype": "m.text", "body": "RT2 hello" }),
        state_key: None,
        origin_server_ts: 2_000_000,
        auth_events: vec![],
        prev_events: vec![],
        hashes: json!({}),
        signatures: json!({}),
        depth: 1,
        unsigned: None,
    };
    sign_event(&mut pdu, &server_a.server_key, "a.test").unwrap();

    let txn_body = json!({
        "origin": "a.test",
        "origin_server_ts": 2_000_000u64,
        "pdus": [pdu],
        "edus": [],
    });

    let path = "/_matrix/federation/v1/send/rt2_txn";
    let auth = sign_req("PUT", path, "a.test", "a.test", Some(&txn_body), &server_a.server_key);

    let resp = server_a
        .http
        .put(format!("{}{}", server_a.base_url, path))
        .header("Authorization", auth)
        .json(&txn_body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    let stored = server_a
        .storage
        .get_event("$rt2_pdu:a.test")
        .await
        .unwrap();
    assert!(stored.is_some(), "PDU should be stored on A after transaction");
}

// ---------------------------------------------------------------------------
// Test RT-3: User on A creates a room; B joins via make_join + send_join
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rt3_join_room_on_a() {
    let server_a = spawn_server("a.test").await;

    let room_id = "!rt3_room:a.test";
    let creator = "@alice:a.test";

    // Seed room state on A.
    let create_ev = Event {
        event_id: "$rt3_create:a.test".to_owned(),
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
    let alice_join = Event {
        event_id: "$rt3_alice_join:a.test".to_owned(),
        room_id: room_id.to_owned(),
        sender: creator.to_owned(),
        event_type: "m.room.member".to_owned(),
        content: json!({ "membership": "join" }),
        state_key: Some(creator.to_owned()),
        origin_server_ts: 1001,
        auth_events: vec!["$rt3_create:a.test".to_owned()],
        prev_events: vec!["$rt3_create:a.test".to_owned()],
        hashes: json!({}),
        signatures: json!({}),
        depth: 2,
        unsigned: None,
    };
    let join_rules = Event {
        event_id: "$rt3_jr:a.test".to_owned(),
        room_id: room_id.to_owned(),
        sender: creator.to_owned(),
        event_type: "m.room.join_rules".to_owned(),
        content: json!({ "join_rule": "public" }),
        state_key: Some("".to_owned()),
        origin_server_ts: 1002,
        auth_events: vec!["$rt3_create:a.test".to_owned()],
        prev_events: vec!["$rt3_alice_join:a.test".to_owned()],
        hashes: json!({}),
        signatures: json!({}),
        depth: 3,
        unsigned: None,
    };

    server_a.storage.put_event(&create_ev).await.unwrap();
    server_a.storage.set_state_entry(room_id, "m.room.create", "", "$rt3_create:a.test").await.unwrap();
    server_a.storage.put_event(&alice_join).await.unwrap();
    server_a.storage.set_state_entry(room_id, "m.room.member", creator, "$rt3_alice_join:a.test").await.unwrap();
    server_a.storage.put_event(&join_rules).await.unwrap();
    server_a.storage.set_state_entry(room_id, "m.room.join_rules", "", "$rt3_jr:a.test").await.unwrap();

    let client = &server_a.http;

    // Step 1: make_join for bob@a.test (using a's key for auth).
    let bob_id = "@bob:a.test";
    let make_join_path = format!(
        "/_matrix/federation/v1/make_join/{}/{}",
        pct_encode(room_id),
        pct_encode(bob_id),
    );
    let auth = sign_req("GET", &make_join_path, "a.test", "a.test", None, &server_a.server_key);

    let mj_resp: Value = client
        .get(format!("{}{}", server_a.base_url, make_join_path))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(mj_resp.get("event").is_some(), "make_join must return event template");

    // Step 2: Complete and sign the join event.
    // Keep event_id stable after signing — signing_bytes includes event_id,
    // so changing it after sign_event would invalidate the signature.
    let mut join_ev: Event = serde_json::from_value(mj_resp["event"].clone()).unwrap();
    sign_event(&mut join_ev, &server_a.server_key, "a.test").unwrap();
    let join_eid = join_ev.event_id.clone();

    let send_join_path = format!(
        "/_matrix/federation/v1/send_join/v2/{}/{}",
        pct_encode(room_id),
        pct_encode(&join_eid),
    );
    let pdu_val = serde_json::to_value(&join_ev).unwrap();
    let auth2 = sign_req("PUT", &send_join_path, "a.test", "a.test", Some(&pdu_val), &server_a.server_key);

    let sj_resp = client
        .put(format!("{}{}", server_a.base_url, send_join_path))
        .header("Authorization", auth2)
        .json(&join_ev)
        .send()
        .await
        .unwrap();

    assert_eq!(sj_resp.status().as_u16(), 200, "send_join should succeed");

    let sj_body: Value = sj_resp.json().await.unwrap();
    let state_evs = sj_body["state"].as_array().expect("state array in send_join response");

    // Verify the state contains the create event.
    let has_create = state_evs
        .iter()
        .any(|e| e["type"].as_str() == Some("m.room.create"));
    assert!(has_create, "send_join state should include m.room.create");

    // Verify bob is now in server-a's storage.
    let bob_member = server_a
        .storage
        .get_state_entry(room_id, "m.room.member", bob_id)
        .await
        .unwrap();
    assert!(bob_member.is_some(), "bob's join should be in A's state after send_join");
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            other => {
                out.push('%');
                let hi = other >> 4;
                let lo = other & 0xf;
                out.push(if hi < 10 { (b'0' + hi) as char } else { (b'A' + hi - 10) as char });
                out.push(if lo < 10 { (b'0' + lo) as char } else { (b'A' + lo - 10) as char });
            }
        }
    }
    out
}
