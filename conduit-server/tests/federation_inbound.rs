//! Federation inbound integration tests (x2r.1–x2r.11).
//!
//! Tests use in-process servers backed by `MemoryStorage` to avoid needing a
//! live PostgreSQL database.  Each test spins up one or two axum servers on
//! random ports, signs requests with freshly generated Ed25519 keys, and
//! asserts the expected behaviour.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::get, Json, Router};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use conduit::event::Event;
use conduit::keys::{generate_server_key, public_bytes};
use conduit::event::Pdu;
use conduit::signing::sign_authored;

/// Sign `pdu` as `server` and wrap it with its derived (reference-hash) ID.
fn signed_event(key: &conduit::keys::ServerKey, server: &str, mut pdu: Pdu) -> Event {
    sign_authored(&mut pdu, key, server).unwrap();
    Event::new(conduit::hashing::event_id(&pdu).unwrap(), pdu)
}
use conduit::storage::{MemoryStorage, Storage};

use conduit_server::federation::rate_limit::RateLimiter;
use conduit_server::federation::server::{FedState, authenticated_federation_router};
use conduit_server::federation::auth::sign_request;
use conduit_server::{BlobStore, RemoteKeyCache};

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
        blob_store: BlobStore::new(std::env::temp_dir().join(format!("conduit_test_blob_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()))).unwrap(),
        recent: Arc::new(conduit_server::federation::RecentEventCache::new()),
        app_services: Arc::new(Vec::new()),
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

    let fed_router = authenticated_federation_router::<()>(fed_state, rate_limiter);

    let app = keys_router.merge(
        fed_router,
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

    // Seed the room and sender membership needed to authorize a message.
    let create = signed_event(&key_a, "server-a.test", Pdu::new(
        "!room1:server-a.test", "@alice:server-a.test", "m.room.create", Some(String::new()),
        json!({"room_version": "11"}), 999_998, vec![], vec![], 1,
    ));
    let member = signed_event(&key_a, "server-a.test", Pdu::new(
        "!room1:server-a.test", "@alice:server-a.test", "m.room.member", Some(create.sender.clone()),
        json!({"membership": "join"}), 999_999, vec![create.event_id.clone()], vec![create.event_id.clone()], 2,
    ));
    for event in [&create, &member] {
        storage_a.put_event(event).await.unwrap();
        storage_a
            .set_state_entry(
                &event.room_id,
                &event.event_type,
                event.state_key.as_deref().unwrap(),
                &event.event_id,
            )
            .await
            .unwrap();
    }

    // A v11 wire PDU: no event_id; server-a derives it from the reference hash.
    let mut pdu = Pdu::new(
        "!room1:server-a.test", "@alice:server-a.test", "m.room.message", None,
        json!({ "msgtype": "m.text", "body": "Hello" }), 1_000_000,
        vec![create.event_id.clone(), member.event_id.clone()], vec![member.event_id.clone()], 3,
    );
    pdu.extensions.insert("org.conduit.test".into(), json!({"opaque": "preserve me"}));
    sign_authored(&mut pdu, &key_a, "server-a.test").unwrap();
    let event_id = conduit::hashing::event_id(&pdu).unwrap();

    let txn_body = json!({
        "origin": "server-a.test",
        "origin_server_ts": 1_000_000u64,
        "pdus": [pdu],
        "edus": [],
    });

    let path = "/_matrix/federation/v1/send/txn1";
    let auth = sign_req(
        "PUT",
        path,
        "server-a.test",
        "server-a.test",
        Some(&txn_body),
        &key_a,
    );

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
    assert_eq!(
        status, 200,
        "send transaction should succeed; body={body_text}"
    );
    let result: Value = serde_json::from_str(&body_text).unwrap();
    assert_eq!(result["pdus"][&event_id], json!({}), "{result}");

    // The PDU landed in storage under its derived ID, extension intact.
    let stored = storage_a.get_event(&event_id).await.unwrap().expect("stored");
    assert_eq!(stored.pdu, pdu);
}

#[tokio::test]
async fn standard_v2_routes_require_authentication() {
    let (addr, _, _) = spawn_test_server("routes.test").await;
    let client = reqwest::Client::new();
    for path in [
        "/_matrix/federation/v1/send/txn",
        "/_matrix/federation/v2/send_join/!room:routes.test/$join",
        "/_matrix/federation/v2/invite/!room:routes.test/$invite",
    ] {
        let response = client
            .put(format!("http://{addr}{path}"))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 401, "{path}");
        assert_eq!(
            response.json::<Value>().await.unwrap()["errcode"],
            "M_UNAUTHORIZED"
        );
    }
}

#[tokio::test]
async fn standard_v2_routes_verify_the_full_signed_uri() {
    let (addr, _, key) = spawn_test_server("routes.test").await;
    let client = reqwest::Client::new();
    for (path, body) in [
        (
            "/_matrix/federation/v2/send_join/!room:routes.test/$join",
            json!({}),
        ),
        (
            "/_matrix/federation/v2/invite/!room:routes.test/$invite",
            json!({"event": {}}),
        ),
    ] {
        // Valid authentication reaches the handler's PDU validation.
        let auth = sign_req("PUT", path, "routes.test", "routes.test", Some(&body), &key);
        let response = client
            .put(format!("http://{addr}{path}"))
            .header("Authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 400, "{path}");
        assert_eq!(
            response.json::<Value>().await.unwrap()["errcode"],
            "M_BAD_JSON"
        );

        // Signing a different URI must fail even though the body/key are valid.
        let auth = sign_req(
            "PUT",
            "/send_join/!room:routes.test/$join",
            "routes.test",
            "routes.test",
            Some(&body),
            &key,
        );
        let response = client
            .put(format!("http://{addr}{path}"))
            .header("Authorization", auth)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 401, "{path}");
    }
}

#[tokio::test]
async fn incorrectly_versioned_routes_are_not_exposed() {
    let (addr, _, _) = spawn_test_server("routes.test").await;
    let client = reqwest::Client::new();
    for path in [
        "/_matrix/federation/v1/send_join/v2/!room:routes.test/$join",
        "/_matrix/federation/v1/invite/v2/!room:routes.test/$invite",
    ] {
        let response = client
            .put(format!("http://{addr}{path}"))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 404, "{path}");
    }
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
    let create_ev = signed_event(&key_a, "server-a.test", Pdu::new(
        room_id, creator, "m.room.create", Some(String::new()),
        json!({ "room_version": "11" }), 1000, vec![], vec![], 1,
    ));
    let join_ev = signed_event(&key_a, "server-a.test", Pdu::new(
        room_id, creator, "m.room.member", Some(creator.to_owned()), json!({ "membership": "join" }), 1001,
        vec![create_ev.event_id.clone()], vec![create_ev.event_id.clone()], 2,
    ));
    let jr_ev = signed_event(&key_a, "server-a.test", Pdu::new(
        room_id, creator, "m.room.join_rules", Some(String::new()), json!({ "join_rule": "public" }), 1002,
        vec![create_ev.event_id.clone(), join_ev.event_id.clone()], vec![join_ev.event_id.clone()], 3,
    ));
    for (event, event_type, state_key) in [
        (&create_ev, "m.room.create", ""),
        (&join_ev, "m.room.member", creator),
        (&jr_ev, "m.room.join_rules", ""),
    ] {
        storage_a.put_event(event).await.unwrap();
        storage_a.set_state_entry(room_id, event_type, state_key, &event.event_id).await.unwrap();
    }

    let client = reqwest::Client::new();

    // Step 1: make_join for a user on server-a, so key_a can sign the join.
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
    let template = make_join_resp.get("event").expect("make_join response should have event");
    assert!(template.get("event_id").is_none(), "template must not carry event_id");
    assert_eq!(make_join_resp["room_version"].as_str(), Some("11"));

    // Step 2: sign the template; the path ID is the derived reference hash.
    let join = signed_event(&key_a, "server-a.test", serde_json::from_value(template.clone()).unwrap());
    let body = serde_json::to_value(&join.pdu).unwrap();
    let send_join = |event_id: String, body: Value| {
        let client = client.clone();
        let base_a = base_a.clone();
        let key_a = Arc::clone(&key_a);
        async move {
            let path = format!(
                "/_matrix/federation/v2/send_join/{}/{}",
                urlencoding::encode(room_id),
                urlencoding::encode(&event_id),
            );
            let auth = sign_req("PUT", &path, "server-a.test", "server-a.test", Some(&body), &key_a);
            client.put(format!("{base_a}{path}")).header("Authorization", auth).json(&body).send().await.unwrap()
        }
    };

    // A path ID that differs from the derived ID is refused, nothing stored.
    let wrong = send_join("$not-the-derived-id".into(), body.clone()).await;
    assert_eq!(wrong.status().as_u16(), 400);
    assert_eq!(wrong.json::<Value>().await.unwrap()["errcode"], "M_INVALID_PARAM");
    assert!(storage_a.get_event(&join.event_id).await.unwrap().is_none());

    let resp2 = send_join(join.event_id.clone(), body).await;
    assert_eq!(resp2.status().as_u16(), 200, "send_join should succeed");
    let send_join_resp: Value = resp2.json().await.unwrap();
    let state = send_join_resp["state"].as_array().expect("send_join response should have state");
    assert!(!state.is_empty());
    for pdu in state.iter().chain(send_join_resp["auth_chain"].as_array().unwrap()).chain([&send_join_resp["event"]]) {
        assert!(pdu.get("event_id").is_none(), "no local event_id on the wire: {pdu}");
    }
    assert_eq!(conduit::hashing::event_id(&serde_json::from_value::<Pdu>(send_join_resp["event"].clone()).unwrap()).unwrap(), join.event_id);
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
    let create_ev = signed_event(&key_a, "server-a.test", Pdu::new(
        room_id, creator, "m.room.create", Some(String::new()),
        json!({ "room_version": "11" }), 1000, vec![], vec![], 1,
    ));
    storage_a.put_event(&create_ev).await.unwrap();
    storage_a.set_state_entry(room_id, "m.room.create", "", &create_ev.event_id).await.unwrap();

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
    assert!(pdus.iter().all(|p| p.get("event_id").is_none()));
}

// ---------------------------------------------------------------------------
// Test 5: backfill_returns_history_visibility_filtered_events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn backfill_returns_history_visibility_filtered_events() {
    let (addr_a, storage_a, key_a) = spawn_test_server("server-a.test").await;
    let base_a = format!("http://{}", addr_a);

    let room_id = "!backfill_room:server-a.test";

    // Seed the membership that makes the room visible to the origin at
    // all.  Backfill filters against the requesting server's membership
    // now, so a room no user of theirs ever joined yields nothing.
    let join = signed_event(&key_a, "server-a.test", Pdu::new(
        room_id, "@alice:server-a.test", "m.room.member", Some("@alice:server-a.test".to_owned()),
        json!({ "membership": "join" }), 999, vec![], vec![], 0,
    ));
    storage_a.put_event(&join).await.unwrap();

    // Seed a few events.
    for i in 1..=5u64 {
        let ev = signed_event(&key_a, "server-a.test", Pdu::new(
            room_id, "@alice:server-a.test", "m.room.message", None,
            json!({ "msgtype": "m.text", "body": format!("msg {i}") }), 1000 + i, vec![], vec![], i as i64,
        ));
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
    assert!(pdus.iter().all(|p| p.get("event_id").is_none()));
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
        blob_store: BlobStore::new(std::env::temp_dir().join(format!("conduit_test_blob_rl_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()))).unwrap(),
        recent: Arc::new(conduit_server::federation::RecentEventCache::new()),
        app_services: Arc::new(Vec::new()),
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

    let fed_router = authenticated_federation_router::<()>(fed_state, rate_limiter);

    let app = keys_router.merge(
        fed_router,
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

#[tokio::test]
async fn federation_version_is_public_and_stable() {
    let (addr, _storage, _key) = spawn_test_server("version.test").await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/_matrix/federation/v1/version"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["server"]["name"], "version.test");
    assert_eq!(body["server"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["server"]["version"].as_str().unwrap().contains('.'));
}

#[tokio::test]
async fn federation_directory_openid_and_local_key_query() {
    let (addr, storage, key) = spawn_test_server("fed.test").await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // The requesting server's key must be fetchable. Point the cache at
    // this same listener by signing as fed.test itself.
    let _: Value = client.get(format!("{base}/_matrix/key/v2/server")).send().await.unwrap().json().await.unwrap();

    let room = "!pub:fed.test";
    let create = signed_event(
        &key,
        "fed.test",
        Pdu::new(
            room,
            "@alice:fed.test",
            "m.room.create",
            Some("".into()),
            json!({ "room_version": "11", "creator": "@alice:fed.test" }),
            1_000,
            vec![],
            vec![],
            1,
        ),
    );
    storage.put_event(&create).await.unwrap();
    storage.set_state_entry(room, "m.room.create", "", &create.event_id).await.unwrap();
    storage.set_room_published(room, true).await.unwrap();

    let path = "/_matrix/federation/v1/publicRooms";
    let auth = sign_req("GET", path, "fed.test", "fed.test", None, &key);
    let listed: Value = client
        .get(format!("{base}{path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed["chunk"][0]["room_id"], room);
    assert!(listed["total_room_count_estimate"].as_u64().unwrap() >= 1);

    let token = "openid-token-value";
    storage
        .insert_token(
            &conduit_server::api::client::probe::hash_bearer(token),
            "@alice:fed.test",
            "DEVICE",
            None,
        )
        .await
        .unwrap();
    let userinfo = format!("/_matrix/federation/v1/openid/userinfo?access_token={token}");
    let auth = sign_req("GET", &userinfo, "fed.test", "fed.test", None, &key);
    let who: Value = client
        .get(format!("{base}{userinfo}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(who["sub"], "@alice:fed.test");

    let query_path = "/_matrix/key/v2/query";
    let body = json!({ "server_keys": { "fed.test": {} } });
    let auth = sign_req("POST", query_path, "fed.test", "fed.test", Some(&body), &key);
    let keys: Value = client
        .post(format!("{base}{query_path}"))
        .header("Authorization", auth)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(keys["server_keys"][0]["server_name"], "fed.test");
    assert!(keys["server_keys"][0]["verify_keys"][&key.key_id]["key"].is_string());

    let get_key = "/_matrix/key/v2/query/fed.test";
    let auth = sign_req("GET", get_key, "fed.test", "fed.test", None, &key);
    let by_name: Value = client
        .get(format!("{base}{get_key}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(by_name["server_keys"][0]["server_name"], "fed.test");

    let post_path = "/_matrix/federation/v1/publicRooms";
    let filter = json!({ "filter": { "generic_search_term": "no-such-room" } });
    let auth = sign_req("POST", post_path, "fed.test", "fed.test", Some(&filter), &key);
    let filtered: Value = client
        .post(format!("{base}{post_path}"))
        .header("Authorization", auth)
        .json(&filter)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(filtered["chunk"].as_array().unwrap().len(), 0, "search term must filter the directory");

    let ts_path = format!("/_matrix/federation/v1/timestamp_to_event/{room}?ts=1000&dir=f");
    let auth = sign_req("GET", &ts_path, "fed.test", "fed.test", None, &key);
    let ts: Value = client
        .get(format!("{base}{ts_path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ts["event_id"], create.event_id);
    assert_eq!(ts["origin_server_ts"], 1000);

    let auth_path = format!("/_matrix/federation/v1/event_auth/{room}/{}", create.event_id);
    let auth = sign_req("GET", &auth_path, "fed.test", "fed.test", None, &key);
    let chain: Value = client
        .get(format!("{base}{auth_path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(chain["auth_chain"].is_array(), "event_auth returns an auth chain: {chain}");

    let join_rules = signed_event(
        &key,
        "fed.test",
        Pdu::new(
            room,
            "@alice:fed.test",
            "m.room.join_rules",
            Some("".into()),
            json!({ "join_rule": "knock" }),
            2_000,
            vec![create.event_id.clone()],
            vec![create.event_id.clone()],
            2,
        ),
    );
    storage.put_event(&join_rules).await.unwrap();
    storage.set_state_entry(room, "m.room.join_rules", "", &join_rules.event_id).await.unwrap();
    let knock_path = format!("/_matrix/federation/v1/make_knock/{room}/@kate:fed.test?ver=11");
    let auth = sign_req("GET", &knock_path, "fed.test", "fed.test", None, &key);
    let knock: Value = client
        .get(format!("{base}{knock_path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(knock["room_version"], "11");
    assert_eq!(knock["event"]["content"]["membership"], "knock");
    assert_eq!(knock["event"]["sender"], "@kate:fed.test");

    let old = "!old:fed.test";
    let old_create = signed_event(
        &key,
        "fed.test",
        Pdu::new(
            old,
            "@alice:fed.test",
            "m.room.create",
            Some("".into()),
            json!({ "room_version": "6", "creator": "@alice:fed.test" }),
            1_000,
            vec![],
            vec![],
            1,
        ),
    );
    storage.put_event(&old_create).await.unwrap();
    storage.set_state_entry(old, "m.room.create", "", &old_create.event_id).await.unwrap();
    let old_knock = format!("/_matrix/federation/v1/make_knock/{old}/@kate:fed.test");
    let auth = sign_req("GET", &old_knock, "fed.test", "fed.test", None, &key);
    let rejected = client
        .get(format!("{base}{old_knock}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 400);
    let rejected: Value = rejected.json().await.unwrap();
    assert_eq!(rejected["errcode"], "M_INCOMPATIBLE_ROOM_VERSION");

    let member = signed_event(
        &key,
        "fed.test",
        Pdu::new(
            room,
            "@alice:fed.test",
            "m.room.member",
            Some("@alice:fed.test".into()),
            json!({ "membership": "join" }),
            3_000,
            vec![create.event_id.clone()],
            vec![join_rules.event_id.clone()],
            3,
        ),
    );
    storage.put_event(&member).await.unwrap();
    storage.set_state_entry(room, "m.room.member", "@alice:fed.test", &member.event_id).await.unwrap();
    let leave_path = format!("/_matrix/federation/v1/make_leave/{room}/@alice:fed.test");
    let auth = sign_req("GET", &leave_path, "fed.test", "fed.test", None, &key);
    let leave: Value = client
        .get(format!("{base}{leave_path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(leave["event"]["content"]["membership"], "leave");
    assert_eq!(leave["event"]["state_key"], "@alice:fed.test");

    let hier_path = format!("/_matrix/federation/v1/hierarchy/{room}");
    let auth = sign_req("GET", &hier_path, "fed.test", "fed.test", None, &key);
    let hier: Value = client
        .get(format!("{base}{hier_path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(hier["rooms"][0]["room_id"], room);
    assert_eq!(hier["rooms"][0]["join_rule"], "knock");

    storage.create_account("@alice:fed.test", None).await.unwrap();
    storage
        .upsert_device("@alice:fed.test", "PHONE", Some("phone"))
        .await
        .unwrap();
    let devices_path = "/_matrix/federation/v1/user/devices/%40alice%3Afed.test";
    let auth = sign_req("GET", devices_path, "fed.test", "fed.test", None, &key);
    let devices: Value = client
        .get(format!("{base}{devices_path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(devices["user_id"], "@alice:fed.test");
    assert_eq!(devices["devices"][0]["device_id"], "PHONE");

    let query_keys = "/_matrix/federation/v1/user/keys/query";
    let qbody = json!({ "device_keys": { "@alice:fed.test": [] } });
    let auth = sign_req("POST", query_keys, "fed.test", "fed.test", Some(&qbody), &key);
    let queried: Value = client
        .post(format!("{base}{query_keys}"))
        .header("Authorization", auth)
        .json(&qbody)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(queried["device_keys"]["@alice:fed.test"].is_object());

    let claim = "/_matrix/federation/v1/user/keys/claim";
    let cbody = json!({ "one_time_keys": { "@alice:fed.test": { "PHONE": "signed_curve25519" } } });
    let auth = sign_req("POST", claim, "fed.test", "fed.test", Some(&cbody), &key);
    let claimed: Value = client
        .post(format!("{base}{claim}"))
        .header("Authorization", auth)
        .json(&cbody)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        claimed["one_time_keys"]["@alice:fed.test"],
        json!({}),
        "a device with no one-time key claims as an empty object: {claimed}"
    );
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
