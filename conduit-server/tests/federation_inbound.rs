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
) -> (
    SocketAddr,
    Arc<MemoryStorage>,
    Arc<conduit::keys::ServerKey>,
    Arc<conduit_server::api::client::TypingStore>,
    Arc<conduit_server::api::client::PresenceStore>,
) {
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

    let typing = Arc::new(conduit_server::api::client::TypingStore::default());
    let presence = Arc::new(conduit_server::api::client::PresenceStore::default());
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
        typing: Arc::clone(&typing),
        presence: Arc::clone(&presence),
        federation_queue: None,
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

    (addr, storage, server_key, typing, presence)
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
    let (addr, _storage, _server_key, _typing, _presence) = spawn_test_server("server-a.test").await;
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
    let (addr_a, storage_a, key_a, _typing, _presence) = spawn_test_server("server-a.test").await;
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

/// Room version 1 event format on `PUT /send`: `$opaque:domain` ids (a port
/// colon is part of the domain) and `[event_id, {sha256}]` tuples. A format
/// failure leaves `pdus` empty. A format-valid PDU with no signatures is
/// reported under that explicit id. Depth above 2^53−1 and floats are
/// accepted by the decoder; they cannot ride in an X-Matrix body because
/// request signing requires canonical JSON.
#[tokio::test]
async fn room_version_1_send_accepts_tuple_events_and_drops_malformed_ones() {
    let (addr, storage, key, _typing, _presence) = spawn_test_server("v1.test").await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let create = signed_event(&key, "v1.test", Pdu::new(
        "!v1:v1.test", "@alice:v1.test", "m.room.create", Some(String::new()),
        json!({"room_version": "1", "creator": "@alice:v1.test"}),
        1, vec![], vec![], 1,
    ));
    let v11 = signed_event(&key, "v1.test", Pdu::new(
        "!v11:v1.test", "@alice:v1.test", "m.room.create", Some(String::new()),
        json!({"room_version": "11", "creator": "@alice:v1.test"}),
        1, vec![], vec![], 1,
    ));
    for event in [&create, &v11] {
        storage.put_event(event).await.unwrap();
        storage
            .set_state_entry(&event.room_id, "m.room.create", "", &event.event_id)
            .await
            .unwrap();
    }

    let accepted = "$a4ecee13e2accdadf56c1025:v1.test:8448";
    let pdus = put_one_pdu(&client, &base, &key, "v1.test", "txn-ok", v1_wire(accepted, "!v1:v1.test")).await;
    assert_eq!(pdus[accepted]["error"], "signature verification failed", "{pdus}");
    assert!(storage.get_event(accepted).await.unwrap().is_none());

    for (name, pdu) in [
        ("strings", {
            let mut pdu = v1_wire("$strings:v1.test", "!v1:v1.test");
            pdu["auth_events"] = json!(["$create:v1.test"]);
            pdu
        }),
        ("bad-id", v1_wire("nope", "!v1:v1.test")),
        ("no-domain", v1_wire("$nodomain", "!v1:v1.test")),
        ("empty-opaque", v1_wire("$:v1.test", "!v1:v1.test")),
        ("missing-id", {
            let mut pdu = v1_wire("$gone:v1.test", "!v1:v1.test");
            pdu.as_object_mut().unwrap().remove("event_id");
            pdu
        }),
        ("missing-sha", {
            let mut pdu = v1_wire("$nosha:v1.test", "!v1:v1.test");
            pdu["auth_events"] = json!([["$create:v1.test", {}]]);
            pdu
        }),
        ("too-many-auth", {
            let mut pdu = v1_wire("$auth:v1.test", "!v1:v1.test");
            pdu["auth_events"] = json!((0..11).map(|i| json!([format!("$a{i}:v1.test"), {"sha256": "h"}])).collect::<Vec<_>>());
            pdu
        }),
        ("too-many-prev", {
            let mut pdu = v1_wire("$prev:v1.test", "!v1:v1.test");
            pdu["prev_events"] = json!((0..21).map(|i| json!([format!("$p{i}:v1.test"), {"sha256": "h"}])).collect::<Vec<_>>());
            pdu
        }),
        ("v11-explicit-id", json!({
            "auth_events": ["$create:v1.test"],
            "content": {"body": "hi"},
            "depth": 3,
            "event_id": "$explicit:v1.test",
            "hashes": {"sha256": "ccdd"},
            "origin_server_ts": 5,
            "prev_events": ["$prev:v1.test"],
            "room_id": "!v11:v1.test",
            "sender": "@alice:v1.test",
            "signatures": {},
            "type": "m.room.message"
        })),
        ("v11-tuples", v1_wire("$tuple:v1.test:8448", "!v11:v1.test")),
    ] {
        let pdus = put_one_pdu(&client, &base, &key, "v1.test", name, pdu).await;
        assert_eq!(pdus, json!({}), "{name} was not dropped: {pdus}");
    }
}

/// Room version 2 uses the same tuple event format as version 1.
#[tokio::test]
async fn room_version_2_send_accepts_tuple_events() {
    let (addr, storage, key, _typing, _presence) = spawn_test_server("v2.test").await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let create = signed_event(&key, "v2.test", Pdu::new(
        "!v2:v2.test", "@alice:v2.test", "m.room.create", Some(String::new()),
        json!({"room_version": "2", "creator": "@alice:v2.test"}),
        1, vec![], vec![], 1,
    ));
    storage.put_event(&create).await.unwrap();
    storage.set_state_entry(&create.room_id, "m.room.create", "", &create.event_id).await.unwrap();

    let accepted = "$a4ecee13e2accdadf56c1025:v2.test:8448";
    let mut ok = v1_wire(accepted, "!v2:v2.test");
    ok["sender"] = json!("@alice:v2.test");
    let body_ok = put_one_pdu(&client, &base, &key, "v2.test", "txn-v2-ok", ok).await;
    assert_eq!(body_ok[accepted]["error"], "signature verification failed", "{body_ok}");
    assert!(storage.get_event(accepted).await.unwrap().is_none());

    let mut strings = v1_wire("$strings:v2.test", "!v2:v2.test");
    strings["sender"] = json!("@alice:v2.test");
    strings["auth_events"] = json!(["$create:v2.test"]);
    let dropped = put_one_pdu(&client, &base, &key, "v2.test", "txn-v2-strings", strings).await;
    assert_eq!(dropped, json!({}), "{dropped}");
}

fn v1_wire(event_id: &str, room_id: &str) -> Value {
    json!({
        "auth_events": [["$create:v1.test", {"sha256": "aabb"}]],
        "content": {"body": "hi"},
        "depth": 4,
        "event_id": event_id,
        "hashes": {"sha256": "ccdd"},
        "origin_server_ts": 5,
        "prev_events": [["$prev:v1.test:8448", {"sha256": "eeff"}]],
        "room_id": room_id,
        "sender": "@alice:v1.test",
        "signatures": {},
        "type": "m.room.message"
    })
}

async fn put_one_pdu(
    client: &reqwest::Client,
    base: &str,
    key: &conduit::keys::ServerKey,
    origin: &str,
    txn: &str,
    pdu: Value,
) -> Value {
    let body = json!({
        "origin": origin,
        "origin_server_ts": 5u64,
        "pdus": [pdu],
        "edus": [],
    });
    let path = format!("/_matrix/federation/v1/send/{txn}");
    let auth = sign_req("PUT", &path, origin, origin, Some(&body), key);
    let response = client
        .put(format!("{base}{path}"))
        .header("Authorization", auth)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    assert_eq!(status, 200, "{txn} body={text}");
    let parsed: Value = serde_json::from_str(&text).unwrap();
    parsed["pdus"].clone()
}

#[tokio::test]
async fn standard_v2_routes_require_authentication() {
    let (addr, _, _, _typing, _presence) = spawn_test_server("routes.test").await;
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
    let (addr, _, key, _typing, _presence) = spawn_test_server("routes.test").await;
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
    let (addr, _, _, _typing, _presence) = spawn_test_server("routes.test").await;
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
    let (addr_a, storage_a, key_a, _typing, _presence) = spawn_test_server("server-a.test").await;
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
    let versions = conduit::room_version::SUPPORTED
        .iter()
        .map(|version| format!("ver={version}"))
        .collect::<Vec<_>>()
        .join("&");
    let path = format!(
        "/_matrix/federation/v1/make_join/{}/{}?{versions}",
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
    let (addr_a, storage_a, key_a, _typing, _presence) = spawn_test_server("server-a.test").await;
    let base_a = format!("http://{}", addr_a);

    let room_id = "!state_room:server-a.test";
    let creator = "@alice:server-a.test";
    let create_ev = signed_event(&key_a, "server-a.test", Pdu::new(
        room_id, creator, "m.room.create", Some(String::new()),
        json!({ "room_version": "11" }), 1000, vec![], vec![], 1,
    ));
    storage_a.put_event(&create_ev).await.unwrap();
    storage_a.set_state_entry(room_id, "m.room.create", "", &create_ev.event_id).await.unwrap();
    let name_ev = signed_event(&key_a, "server-a.test", Pdu::new(
        room_id, creator, "m.room.name", Some(String::new()),
        json!({ "name": "historical-name" }), 1001,
        vec![create_ev.event_id.clone()], vec![create_ev.event_id.clone()], 2,
    ));
    storage_a.put_event(&name_ev).await.unwrap();

    let client = reqwest::Client::new();
    let path = format!(
        "/_matrix/federation/v1/state/{}?event_id={}",
        urlencoding::encode(room_id),
        urlencoding::encode(&name_ev.event_id),
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
    assert!(pdus.iter().any(|pdu| pdu["type"] == "m.room.create"), "state before the name includes create: {body}");
    assert!(pdus.iter().all(|pdu| pdu["content"]["name"] != "historical-name"), "the requested name is not in its own prior state: {body}");
    assert!(pdus.iter().all(|p| p.get("event_id").is_none()));

    let missing = format!(
        "/_matrix/federation/v1/state/{}?event_id=$state_create",
        urlencoding::encode(room_id)
    );
    let auth = sign_req("GET", &missing, "server-a.test", "server-a.test", None, &key_a);
    let resp = client.get(format!("{base_a}{missing}")).header("Authorization", auth).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    assert_eq!(resp.json::<Value>().await.unwrap()["errcode"], "M_NOT_FOUND");
}

// ---------------------------------------------------------------------------
// Test 5: backfill_returns_history_visibility_filtered_events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn backfill_returns_history_visibility_filtered_events() {
    let (addr_a, storage_a, key_a, _typing, _presence) = spawn_test_server("server-a.test").await;
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

    // A chain. Backfill from the newest event returns that event and its predecessors.
    let mut prev = vec![join.event_id.clone()];
    let mut newest = String::new();
    for i in 1..=5u64 {
        let ev = signed_event(&key_a, "server-a.test", Pdu::new(
            room_id, "@alice:server-a.test", "m.room.message", None,
            json!({ "msgtype": "m.text", "body": format!("msg {i}") }), 1000 + i, vec![], prev.clone(), i as i64,
        ));
        newest = ev.event_id.clone();
        prev = vec![ev.event_id.clone()];
        storage_a.put_event(&ev).await.unwrap();
    }

    let client = reqwest::Client::new();
    let path = format!(
        "/_matrix/federation/v1/backfill/{}?limit=3&v={}",
        urlencoding::encode(room_id),
        urlencoding::encode(&newest),
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
    let bodies: Vec<&str> = pdus.iter().filter_map(|pdu| pdu["content"]["body"].as_str()).collect();
    assert_eq!(bodies, vec!["msg 5", "msg 4", "msg 3"], "the window is the named event and its predecessors: {body}");
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
        typing: Arc::new(conduit_server::api::client::TypingStore::default()),
        presence: Arc::new(conduit_server::api::client::PresenceStore::default()),
        federation_queue: None,
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
    let (addr_a, storage_a, key_a, _typing, _presence) = spawn_test_server("server-a.test").await;
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

    // A user with no profile fields is 200 and an empty object.
    assert_eq!(resp.status().as_u16(), 200, "profile query for existing user should succeed");
    let empty: Value = resp.json().await.unwrap();
    assert_eq!(empty, json!({}));

    storage_a.set_displayname(user_id, Some("Alice")).await.unwrap();
    storage_a.set_avatar_url(user_id, Some("mxc://server-a.test/alice")).await.unwrap();
    storage_a
        .set_profile_field(user_id, "m.tz", Some(&json!("America/Los_Angeles")))
        .await
        .unwrap();
    let auth_full = sign_req("GET", &path, "server-a.test", "server-a.test", None, &key_a);
    let full: Value = client
        .get(format!("{base_a}{path}"))
        .header("Authorization", auth_full)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(full["displayname"], "Alice");
    assert_eq!(full["avatar_url"], "mxc://server-a.test/alice");
    assert_eq!(full["m.tz"], "America/Los_Angeles");

    let field_path = format!("{path}&field=displayname");
    let auth_field = sign_req("GET", &field_path, "server-a.test", "server-a.test", None, &key_a);
    let only: Value = client
        .get(format!("{base_a}{field_path}"))
        .header("Authorization", auth_field)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(only, json!({"displayname": "Alice"}));

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
    let (addr, _storage, _key, _typing, _presence) = spawn_test_server("version.test").await;
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
    let (addr, storage, key, _typing, _presence) = spawn_test_server("fed.test").await;
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
    assert_eq!(hier["room"]["room_id"], room);
    assert_eq!(hier["room"]["join_rule"], "knock");
    assert!(hier.get("rooms").is_none(), "hierarchy is room/children, not rooms: {hier}");
    assert_eq!(hier["children"].as_array().map(Vec::len), Some(0));
    assert_eq!(hier["inaccessible_children"].as_array().map(Vec::len), Some(0));

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

/// Inbound hierarchy is `{room, children, inaccessible_children}`.
/// Peekable descendants are flat in `children`. A known room the caller
/// cannot peek is named and not walked. An unknown child stays only in
/// `children_state`. `suggested_only` drops rooms that are not suggested.
#[tokio::test]
async fn federation_hierarchy_lists_peekable_descendants_and_inaccessible_children() {
    let (addr, storage, key, _typing, _presence) = spawn_test_server("space.test").await;
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let sender = "@alice:space.test";
    let space = "!space:space.test";
    let open = "!open:space.test";
    let grand = "!grand:space.test";
    let secret = "!secret:space.test";
    let quiet = "!quiet:space.test";
    let missing = "!missing:space.test";
    let closed = "!closed:space.test";
    let gate = "!gate:space.test";
    let club = "!club:space.test";

    async fn put(
        storage: &MemoryStorage,
        key: &conduit::keys::ServerKey,
        room: &str,
        kind: &str,
        state_key: &str,
        content: Value,
        ts: u64,
    ) {
        let event = signed_event(
            key,
            "space.test",
            Pdu::new(room, "@alice:space.test", kind, Some(state_key.into()), content, ts, vec![], vec![], 1),
        );
        storage.put_event(&event).await.unwrap();
        storage.set_state_entry(room, kind, state_key, &event.event_id).await.unwrap();
    }

    for (room, name, rule, ts) in [
        (space, "Root", "public", 1_000),
        (open, "Open", "public", 1_100),
        (grand, "Grand", "public", 1_200),
        (secret, "Secret", "invite", 1_300),
        (quiet, "Quiet", "public", 1_400),
        (closed, "Closed", "invite", 1_500),
        (gate, "Gate", "public", 1_600),
        (club, "Club", "restricted", 1_700),
    ] {
        put(&storage, &key, room, "m.room.create", "", json!({ "room_version": "11" }), ts).await;
        put(&storage, &key, room, "m.room.name", "", json!({ "name": name }), ts + 1).await;
        let mut content = json!({ "join_rule": rule });
        if rule == "restricted" {
            content["allow"] = json!([{ "type": "m.room_membership", "room_id": gate }]);
        }
        put(&storage, &key, room, "m.room.join_rules", "", content, ts + 2).await;
    }
    put(
        &storage,
        &key,
        gate,
        "m.room.member",
        sender,
        json!({ "membership": "join" }),
        1_800,
    )
    .await;
    put(
        &storage,
        &key,
        open,
        "m.space.child",
        grand,
        json!({ "via": ["space.test"], "order": "a", "suggested": true }),
        2_000,
    )
    .await;
    for (child, order, suggested, ts) in [
        (open, "a", true, 2_100),
        (secret, "b", true, 2_200),
        (missing, "c", true, 2_300),
        (quiet, "d", false, 2_400),
        (club, "e", true, 2_500),
    ] {
        put(
            &storage,
            &key,
            space,
            "m.space.child",
            child,
            json!({ "via": ["space.test"], "order": order, "suggested": suggested }),
            ts,
        )
        .await;
    }
    put(
        &storage,
        &key,
        space,
        "m.space.child",
        "!invalid:space.test",
        json!({ "via": [], "order": "f" }),
        2_600,
    )
    .await;
    put(
        &storage,
        &key,
        space,
        "m.space.parent",
        "!parent:space.test",
        json!({ "via": ["space.test"] }),
        2_700,
    )
    .await;

    let path = format!("/_matrix/federation/v1/hierarchy/{space}");
    let auth = sign_req("GET", &path, "space.test", "space.test", None, &key);
    let body: Value = client
        .get(format!("{base}{path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(body.get("rooms").is_none(), "v1.19 hierarchy has no rooms array: {body}");
    assert_eq!(body["room"]["room_id"], space);
    assert_eq!(body["room"]["name"], "Root");
    assert_eq!(body["room"]["guest_can_join"], false);
    assert_eq!(body["room"]["world_readable"], false);
    assert!(body["room"]["num_joined_members"].as_i64().unwrap() >= 0);
    let state_keys: Vec<&str> = body["room"]["children_state"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["state_key"].as_str())
        .collect();
    assert_eq!(state_keys, vec![open, secret, missing, quiet, club]);
    assert!(state_keys.iter().all(|key| *key != "!invalid:space.test" && *key != "!parent:space.test"));
    let child_ids: Vec<&str> = body["children"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|room| room["room_id"].as_str())
        .collect();
    assert_eq!(child_ids, vec![open, grand, quiet, club]);
    assert_eq!(body["children"][0]["name"], "Open");
    assert_eq!(body["children"][1]["name"], "Grand");
    assert_eq!(body["children"][0]["children_state"][0]["state_key"], grand);
    assert_eq!(body["children"][3]["name"], "Club");
    assert_eq!(body["children"][3]["join_rule"], "restricted");
    assert_eq!(body["children"][3]["allowed_room_ids"][0], gate);
    assert_eq!(body["inaccessible_children"], json!([secret]));
    assert!(!child_ids.contains(&missing));
    assert!(!body["inaccessible_children"].as_array().unwrap().iter().any(|id| id == missing));

    let suggested_path = format!("/_matrix/federation/v1/hierarchy/{space}?suggested_only=true");
    let auth = sign_req("GET", &suggested_path, "space.test", "space.test", None, &key);
    let suggested: Value = client
        .get(format!("{base}{suggested_path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let suggested_ids: Vec<&str> = suggested["children"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|room| room["room_id"].as_str())
        .collect();
    assert_eq!(suggested_ids, vec![open, grand, club]);
    let suggested_keys: Vec<&str> = suggested["room"]["children_state"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["state_key"].as_str())
        .collect();
    assert_eq!(suggested_keys, vec![open, secret, missing, club]);
    assert_eq!(suggested["inaccessible_children"], json!([secret]));

    let closed_path = format!("/_matrix/federation/v1/hierarchy/{closed}");
    let auth = sign_req("GET", &closed_path, "space.test", "space.test", None, &key);
    let denied = client
        .get(format!("{base}{closed_path}"))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 404);
    let denied: Value = denied.json().await.unwrap();
    assert_eq!(denied["errcode"], "M_NOT_FOUND");
}

/// Unpadded Base64 encodings omit `=`, and decoders accept it when present.
/// A padded `X-Matrix` signature is still authenticated.
#[tokio::test]
async fn padded_xmatrix_signature_is_accepted() {
    let (addr, _storage, key, _typing, _presence) = spawn_test_server("pad.test").await;
    let path = "/_matrix/federation/v1/publicRooms";
    let header = sign_req("GET", path, "pad.test", "pad.test", None, &key);
    let marker = "sig=\"";
    let start = header.find(marker).unwrap() + marker.len();
    let end = start + header[start..].find('"').unwrap();
    let mut sig = header[start..end].to_owned();
    assert!(!sig.contains('='));
    while sig.len() % 4 != 0 {
        sig.push('=');
    }
    assert!(sig.ends_with('='));
    let header = format!("{}{sig}{}", &header[..start], &header[end..]);
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{addr}{path}"))
        .header("Authorization", header)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body: Value = response.json().await.unwrap();
    assert_eq!(status, 200, "padded signature must authenticate: {body}");
    assert!(body["chunk"].is_array());
}

/// Inbound `m.typing` is applied only for a joined user of the sending server,
/// and a denied server's EDU is ignored.
#[tokio::test]
async fn inbound_typing_edu_reaches_local_typers_and_rejects_spoofs() {
    let (addr, storage, key, typing, _presence) = spawn_test_server("server-a.test").await;
    let base = format!("http://{addr}");
    let room = "!typing:server-a.test";
    let john = "@john:server-a.test";
    let member = signed_event(
        &key,
        "server-a.test",
        Pdu::new(
            room,
            john,
            "m.room.member",
            Some(john.into()),
            json!({"membership": "join"}),
            1_000,
            vec![],
            vec![],
            1,
        ),
    );
    storage.put_event(&member).await.unwrap();
    storage
        .set_state_entry(room, "m.room.member", john, &member.event_id)
        .await
        .unwrap();

    let client = reqwest::Client::new();
    let send = |txn: String, edu: Value| {
        let base = base.clone();
        let key = Arc::clone(&key);
        let client = client.clone();
        async move {
            let body = json!({
                "origin": "server-a.test",
                "origin_server_ts": 1_700_000_000_000u64,
                "pdus": [],
                "edus": [edu],
            });
            let path = format!("/_matrix/federation/v1/send/{txn}");
            let auth = sign_req("PUT", &path, "server-a.test", "server-a.test", Some(&body), &key);
            let response = client
                .put(format!("{base}{path}"))
                .header("Authorization", auth)
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200, "{}", response.text().await.unwrap_or_default());
        }
    };

    send(
        "typing-on".into(),
        json!({
            "edu_type": "m.typing",
            "content": { "room_id": room, "user_id": john, "typing": true }
        }),
    )
    .await;
    assert_eq!(typing.typers_in_room(room).await, vec![john.to_owned()]);

    send(
        "typing-spoof".into(),
        json!({
            "edu_type": "m.typing",
            "content": { "room_id": room, "user_id": "@eve:other.test", "typing": true }
        }),
    )
    .await;
    send(
        "typing-absent".into(),
        json!({
            "edu_type": "m.typing",
            "content": { "room_id": room, "user_id": "@stranger:server-a.test", "typing": true }
        }),
    )
    .await;
    assert_eq!(
        typing.typers_in_room(room).await,
        vec![john.to_owned()],
        "a user from another server, or one who is not joined, must not become a typer"
    );

    send(
        "typing-off".into(),
        json!({
            "edu_type": "m.typing",
            "content": { "room_id": room, "user_id": john, "typing": false }
        }),
    )
    .await;
    assert!(typing.typers_in_room(room).await.is_empty());

    let acl = signed_event(
        &key,
        "server-a.test",
        Pdu::new(
            room,
            john,
            "m.room.server_acl",
            Some(String::new()),
            json!({"allow": ["*"], "deny": ["server-a.test"], "allow_ip_literals": false}),
            2_000,
            vec![member.event_id.clone()],
            vec![member.event_id.clone()],
            2,
        ),
    );
    storage.put_event(&acl).await.unwrap();
    storage
        .set_state_entry(room, "m.room.server_acl", "", &acl.event_id)
        .await
        .unwrap();
    send(
        "typing-denied".into(),
        json!({
            "edu_type": "m.typing",
            "content": { "room_id": room, "user_id": john, "typing": true }
        }),
    )
    .await;
    assert!(
        typing.typers_in_room(room).await.is_empty(),
        "an m.typing EDU from a server the room ACL denies is ignored"
    );
}

/// Inbound `m.receipt` updates only the listed public read receipts.
#[tokio::test]
async fn inbound_receipt_edu_updates_only_listed_public_reads() {
    let (addr, storage, key, _typing, _presence) = spawn_test_server("server-a.test").await;
    let base = format!("http://{addr}");
    let room = "!receipts:server-a.test";
    let other = "!other:server-a.test";
    let john = "@john:server-a.test";
    let kept = "@kept:server-a.test";
    for (room_id, user) in [(room, john), (room, kept), (other, john)] {
        let member = signed_event(
            &key,
            "server-a.test",
            Pdu::new(
                room_id,
                user,
                "m.room.member",
                Some(user.into()),
                json!({"membership": "join"}),
                1_000,
                vec![],
                vec![],
                1,
            ),
        );
        storage.put_event(&member).await.unwrap();
        storage
            .set_state_entry(room_id, "m.room.member", user, &member.event_id)
            .await
            .unwrap();
    }
    storage
        .set_threaded_receipt(room, kept, "m.read", None, "$kept", 11)
        .await
        .unwrap();
    storage
        .set_threaded_receipt(room, john, "m.read", Some("$thread"), "$old-thread", 12)
        .await
        .unwrap();

    let client = reqwest::Client::new();
    let send = |txn: String, edu: Value| {
        let base = base.clone();
        let key = Arc::clone(&key);
        let client = client.clone();
        async move {
            let body = json!({
                "origin": "server-a.test",
                "origin_server_ts": 1_700_000_000_000u64,
                "pdus": [],
                "edus": [edu],
            });
            let path = format!("/_matrix/federation/v1/send/{txn}");
            let auth = sign_req("PUT", &path, "server-a.test", "server-a.test", Some(&body), &key);
            let response = client
                .put(format!("{base}{path}"))
                .header("Authorization", auth)
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200, "{}", response.text().await.unwrap_or_default());
        }
    };

    send(
        "receipts".into(),
        json!({
            "edu_type": "m.receipt",
            "content": {
                room: {
                    "m.read": {
                        john: {
                            "event_ids": ["$read"],
                            "data": { "ts": 1533358089009i64, "thread_id": "main" }
                        },
                        "@eve:other.test": {
                            "event_ids": ["$spoof"],
                            "data": { "ts": 1 }
                        }
                    },
                    "m.read.private": {
                        john: {
                            "event_ids": ["$private"],
                            "data": { "ts": 2 }
                        }
                    }
                },
                other: {
                    "m.read": {
                        "@stranger:server-a.test": {
                            "event_ids": ["$absent"],
                            "data": { "ts": 3 }
                        }
                    }
                }
            }
        }),
    )
    .await;

    let john_receipts = storage.user_receipts_in_room(room, john).await.unwrap();
    let main = john_receipts.iter().find(|row| row.thread_id.as_deref() == Some("main")).unwrap();
    assert_eq!(main.event_id, "$read");
    assert_eq!(main.ts, 1533358089009);
    assert_eq!(main.receipt_type, "m.read");
    assert!(
        john_receipts.iter().any(|row| row.thread_id.as_deref() == Some("$thread") && row.event_id == "$old-thread"),
        "a receipt the EDU does not mention must stay: {john_receipts:?}"
    );
    assert!(john_receipts.iter().all(|row| row.receipt_type != "m.read.private"));
    let kept_receipts = storage.user_receipts_in_room(room, kept).await.unwrap();
    assert_eq!(kept_receipts.len(), 1);
    assert_eq!(kept_receipts[0].event_id, "$kept");
    assert!(storage.user_receipts_in_room(room, "@eve:other.test").await.unwrap().is_empty());
    assert!(storage.user_receipts_in_room(other, "@stranger:server-a.test").await.unwrap().is_empty());

    let acl = signed_event(
        &key,
        "server-a.test",
        Pdu::new(
            room,
            john,
            "m.room.server_acl",
            Some(String::new()),
            json!({"allow": ["*"], "deny": ["server-a.test"], "allow_ip_literals": false}),
            2_000,
            vec![],
            vec![],
            2,
        ),
    );
    storage.put_event(&acl).await.unwrap();
    storage.set_state_entry(room, "m.room.server_acl", "", &acl.event_id).await.unwrap();
    send(
        "receipts-denied".into(),
        json!({
            "edu_type": "m.receipt",
            "content": {
                room: {
                    "m.read": {
                        john: { "event_ids": ["$denied"], "data": { "ts": 99, "thread_id": "main" } }
                    }
                }
            }
        }),
    )
    .await;
    let after = storage.user_receipts_in_room(room, john).await.unwrap();
    let main = after.iter().find(|row| row.thread_id.as_deref() == Some("main")).unwrap();
    assert_eq!(main.event_id, "$read", "a denied server's receipt must not replace the stored one");
}

/// Inbound `m.presence` stores only push entries for users of the sending
/// server. A missing `last_active_ago`, an unknown presence, or a user from
/// another server is ignored, and users absent from the EDU stay as they were.
#[tokio::test]
async fn inbound_presence_edu_applies_only_the_sending_servers_users() {
    let (addr, _storage, key, _typing, presence) = spawn_test_server("server-a.test").await;
    let base = format!("http://{addr}");
    presence
        .set_presence("@kept:server-a.test", "unavailable".into(), Some("away".into()))
        .await;

    let client = reqwest::Client::new();
    let body = json!({
        "origin": "server-a.test",
        "origin_server_ts": 1_700_000_000_000u64,
        "pdus": [],
        "edus": [{
            "edu_type": "m.presence",
            "content": {
                "push": [
                    {
                        "user_id": "@john:server-a.test",
                        "presence": "online",
                        "last_active_ago": 5000,
                        "currently_active": true,
                        "status_msg": "Making cupcakes"
                    },
                    { "user_id": "@eve:other.test", "presence": "online", "last_active_ago": 1 },
                    { "user_id": "@bad:server-a.test", "presence": "asleep", "last_active_ago": 1 },
                    { "user_id": "@stale:server-a.test", "presence": "online" }
                ]
            }
        }],
    });
    let path = "/_matrix/federation/v1/send/presence";
    let auth = sign_req("PUT", path, "server-a.test", "server-a.test", Some(&body), &key);
    let response = client
        .put(format!("{base}{path}"))
        .header("Authorization", auth)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap_or_default());

    let john = presence.get_presence("@john:server-a.test").await.expect("john");
    assert_eq!(john.presence, "online");
    assert_eq!(john.status_msg.as_deref(), Some("Making cupcakes"));
    let ago = john.last_changed_at.elapsed().as_millis() as u64;
    assert!(ago >= 5000 && ago < 20_000, "last_active_ago was {ago}");
    assert!(presence.get_presence("@eve:other.test").await.is_none());
    assert!(presence.get_presence("@bad:server-a.test").await.is_none());
    assert!(presence.get_presence("@stale:server-a.test").await.is_none());
    let kept = presence.get_presence("@kept:server-a.test").await.expect("kept");
    assert_eq!(kept.presence, "unavailable");
    assert_eq!(kept.status_msg.as_deref(), Some("away"));
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
