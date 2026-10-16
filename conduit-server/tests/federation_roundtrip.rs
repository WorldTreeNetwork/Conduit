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

use axum::{routing::get, Json, Router};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use conduit::event::Event;
use conduit::keys::{generate_server_key, public_bytes, ServerKey};
use conduit::event::Pdu;
use conduit::signing::sign_authored;
use conduit::storage::{MemoryStorage, Storage};

use conduit_server::federation::auth::sign_request;
use conduit_server::federation::rate_limit::RateLimiter;
use conduit_server::federation::server::{FedState, authenticated_federation_router};
use conduit_server::BlobStore;
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
        blob_store: BlobStore::new(std::env::temp_dir().join(format!("conduit_test_blob_rt_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()))).unwrap(),
        recent: Arc::new(conduit_server::federation::RecentEventCache::new()),
        app_services: Arc::new(Vec::new()),
        typing: Arc::new(conduit_server::api::client::TypingStore::default()),
        presence: Arc::new(conduit_server::api::client::PresenceStore::default()),
        federation_queue: None,
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

    let fed_router = authenticated_federation_router::<()>(fed_state, rate_limiter);

    let app = keys_router.merge(
        fed_router,
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

/// Sign `pdu` as `server` and wrap it with its derived (reference-hash) ID.
fn signed_event(key: &conduit::keys::ServerKey, server: &str, mut pdu: Pdu) -> Event {
    sign_authored(&mut pdu, key, server).unwrap();
    Event::new(conduit::hashing::event_id(&pdu).unwrap(), pdu)
}

#[tokio::test]
async fn rt2_b_sends_transaction_to_a() {
    let server_a = spawn_server("a.test").await;

    // A v11 wire PDU (no event_id) signed by server-a's key (RemoteKeyCache
    // only points to a's key endpoint in this fixture).
    let event = signed_event(&server_a.server_key, "a.test", Pdu::new(
        "!rt2_room:a.test", "@alice:a.test", "m.room.create", Some(String::new()),
        json!({ "room_version": "11" }), 2_000_000, vec![], vec![], 1,
    ));

    let txn_body = json!({
        "origin": "a.test",
        "origin_server_ts": 2_000_000u64,
        "pdus": [event.pdu],
        "edus": [],
    });
    assert!(txn_body["pdus"][0].get("event_id").is_none());

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
    let result: Value = resp.json().await.unwrap();
    assert_eq!(result["pdus"][&event.event_id], json!({}), "{result}");

    let stored = server_a.storage.get_event(&event.event_id).await.unwrap();
    assert!(stored.is_some(), "PDU should be stored on A under its derived ID");
}

// ---------------------------------------------------------------------------
// Test RT-3: User on A creates a room; B joins via make_join + send_join
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rt3_join_room_on_a() {
    let server_a = spawn_server("a.test").await;
    let key = &server_a.server_key;

    let room_id = "!rt3_room:a.test";
    let creator = "@alice:a.test";

    // Seed room state on A with real, signed v11 events.
    let create_ev = signed_event(key, "a.test", Pdu::new(
        room_id, creator, "m.room.create", Some(String::new()),
        json!({ "room_version": "11" }), 1000, vec![], vec![], 1,
    ));
    let alice_join = signed_event(key, "a.test", Pdu::new(
        room_id, creator, "m.room.member", Some(creator.to_owned()),
        json!({ "membership": "join" }), 1001,
        vec![create_ev.event_id.clone()], vec![create_ev.event_id.clone()], 2,
    ));
    let join_rules = signed_event(key, "a.test", Pdu::new(
        room_id, creator, "m.room.join_rules", Some(String::new()),
        json!({ "join_rule": "public" }), 1002,
        vec![create_ev.event_id.clone(), alice_join.event_id.clone()], vec![alice_join.event_id.clone()], 3,
    ));

    for (event, event_type, state_key) in [
        (&create_ev, "m.room.create", ""),
        (&alice_join, "m.room.member", creator),
        (&join_rules, "m.room.join_rules", ""),
    ] {
        server_a.storage.put_event(event).await.unwrap();
        server_a.storage.set_state_entry(room_id, event_type, state_key, &event.event_id).await.unwrap();
    }

    let client = &server_a.http;

    // Step 1: make_join for bob@a.test (using a's key for auth).
    let bob_id = "@bob:a.test";
    let versions = conduit::room_version::SUPPORTED
        .iter()
        .map(|version| format!("ver={version}"))
        .collect::<Vec<_>>()
        .join("&");
    let make_join_path = format!(
        "/_matrix/federation/v1/make_join/{}/{}?{versions}",
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

    let template = mj_resp.get("event").expect("make_join must return event template");
    assert!(template.get("event_id").is_none(), "v11 template has no event_id: {template}");

    // Step 2: Complete and sign the join event; its ID is derived.
    let join_ev = signed_event(key, "a.test", serde_json::from_value(template.clone()).unwrap());

    let send_join_path = format!(
        "/_matrix/federation/v2/send_join/{}/{}",
        pct_encode(room_id),
        pct_encode(&join_ev.event_id),
    );
    let pdu_val = serde_json::to_value(&join_ev.pdu).unwrap();
    let auth2 = sign_req("PUT", &send_join_path, "a.test", "a.test", Some(&pdu_val), &server_a.server_key);

    let sj_resp = client
        .put(format!("{}{}", server_a.base_url, send_join_path))
        .header("Authorization", auth2)
        .json(&pdu_val)
        .send()
        .await
        .unwrap();

    assert_eq!(sj_resp.status().as_u16(), 200, "send_join should succeed");

    let sj_body: Value = sj_resp.json().await.unwrap();
    let state_evs = sj_body["state"].as_array().expect("state array in send_join response");

    let has_create = state_evs
        .iter()
        .any(|e| e["type"].as_str() == Some("m.room.create"));
    assert!(has_create, "send_join state should include m.room.create");
    for pdu in state_evs.iter().chain(sj_body["auth_chain"].as_array().unwrap()).chain([&sj_body["event"]]) {
        assert!(pdu.get("event_id").is_none(), "no local event_id on the wire: {pdu}");
    }

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
