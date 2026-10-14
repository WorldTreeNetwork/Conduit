//! add-pdu-wire journeys through the shipped binary and real PostgreSQL:
//! a remote server (`remote.test`, keys served by a local mock) speaks
//! signed X-Matrix federation to a production Conduit.
//!
//! Covered scenarios (openspec/changes/add-pdu-wire/specs/events-and-signing):
//! U+0000 over /send, explicit event_id, depth/size/field limits, transaction
//! replay, extension persistence across restart with no event_id on the
//! wire, /invite checks before co-signing, /send_join validation and the
//! restricted-join co-signature, client float replay, client U+0000 refusal.

mod common;

use std::sync::Arc;

use axum::{routing::get, Json, Router};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use common::production::Server;
use reqwest::Method;
use serde_json::{json, Value};

use conduit::event::Pdu;
use conduit::keys::{generate_server_key, public_bytes, ServerKey};
use conduit::signing::sign_authored;
use conduit_server::federation::auth::sign_request;

const REMOTE: &str = "remote.test";
const LOCAL: &str = "production.test";
const MAX_SAFE: i64 = 9_007_199_254_740_991;

fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

struct Remote {
    key: Arc<ServerKey>,
    keys_url: String,
}

/// Serve a self-signed `/_matrix/key/v2/server` document for `remote.test`.
async fn spawn_remote() -> Remote {
    let key = Arc::new(generate_server_key());
    let unsigned = json!({
        "server_name": REMOTE,
        "verify_keys": { key.key_id.clone(): { "key": STANDARD_NO_PAD.encode(public_bytes(&key)) } },
        "old_verify_keys": {},
        "valid_until_ts": chrono::Utc::now().timestamp_millis() + 3_600_000,
    });
    use ed25519_dalek::Signer as _;
    let sig = key.signing_key.sign(&conduit::canonical_json::to_canonical_bytes(&unsigned).unwrap());
    let mut doc = unsigned;
    doc["signatures"] = json!({ REMOTE: { key.key_id.clone(): STANDARD_NO_PAD.encode(sig.to_bytes()) } });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/_matrix/key/v2/server", get(move || {
        let doc = doc.clone();
        async move { Json(doc) }
    }));
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    Remote { key, keys_url: format!("http://{addr}") }
}

async fn federated_server(remote: &Remote) -> Server {
    Server::with_env(&[("CONDUIT_FEDERATION", "1"), ("CONDUIT_REMOTE_KEYS_OVERRIDE", &remote.keys_url)]).await
}

/// A signed federation request from `remote.test`.
async fn fed(server: &Server, remote: &Remote, method: Method, path: &str, body: Option<Value>, status: u16) -> Value {
    let auth = sign_request(method.as_str(), path, REMOTE, LOCAL, body.as_ref(), &remote.key);
    let mut request = server.http.request(method, format!("{}{path}", server.base_url)).header("Authorization", auth);
    if let Some(body) = &body {
        request = request.json(body);
    }
    let response = request.send().await.unwrap();
    let actual = response.status().as_u16();
    let text = response.text().await.unwrap();
    assert_eq!(actual, status, "{path}: {text}; server log: {}", server.logs());
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

fn sign(remote: &Remote, mut pdu: Pdu) -> (String, Value) {
    // Like sign_authored, without its 64-byte authoring margin, so tests can
    // build PDUs right at the 65536-byte receive limit.
    pdu.hashes = json!({ "sha256": conduit::hashing::content_hash(&pdu).unwrap() });
    conduit::signing::add_signature(&mut pdu, &remote.key, REMOTE).unwrap();
    (conduit::hashing::event_id(&pdu).unwrap(), serde_json::to_value(&pdu).unwrap())
}

fn create(room: &str, content: Value, depth: i64) -> Pdu {
    Pdu::new(room, "@r:remote.test", "m.room.create", Some(String::new()), content, 1_700_000_000_000, vec![], vec![], depth)
}

fn txn(pdus: Vec<Value>, edus: Vec<Value>) -> Value {
    json!({ "origin": REMOTE, "origin_server_ts": 1_700_000_000_000u64, "pdus": pdus, "edus": edus })
}

/// Pad a create event's content so the signed canonical PDU is exactly `size` bytes.
fn sized_create(remote: &Remote, room: &str, size: usize) -> (String, Value) {
    let mut pad = 0usize;
    loop {
        let (id, value) = sign(remote, create(room, json!({"room_version": "11", "pad": "x".repeat(pad)}), 1));
        let len = conduit::canonical_json::to_canonical_bytes(&value).unwrap().len();
        if len == size {
            return (id, value);
        }
        pad = (pad as i64 + size as i64 - len as i64).max(0) as usize;
    }
}

#[tokio::test]
async fn send_keeps_nul_content_drops_invalid_pdus_and_replays_identically() {
    let remote = spawn_remote().await;
    let mut server = federated_server(&remote).await;
    let alice = server.register("alice").await;

    let mut nul_pdu = create("!nul:remote.test", json!({"room_version": "11", "org.test": "a\u{0}b"}), 1);
    nul_pdu.extensions.insert("org.example.ext".into(), json!({"opaque": "preserve me", "unicode": "世界"}));
    let (nul_id, nul) = sign(&remote, nul_pdu);
    let (ordinary_id, ordinary) = sign(&remote, create("!ordinary:remote.test", json!({"room_version": "11"}), 1));
    let (_, nul_key) = sign(&remote, Pdu::new("!k:remote.test", "@r:remote.test", "org.test.state",
        Some("a\u{0}b".into()), json!({}), 1, vec![], vec![], 1));
    let (explicit_id, mut explicit) = sign(&remote, create("!explicit:remote.test", json!({"room_version": "11"}), 1));
    explicit["event_id"] = json!(explicit_id);
    let (depth_max_id, depth_max) = sign(&remote, create("!dmax:remote.test", json!({"room_version": "11"}), MAX_SAFE));
    let (depth_zero_id, depth_zero) = sign(&remote, create("!d0:remote.test", json!({"room_version": "11"}), 0));
    let (_, depth_negative) = sign(&remote, create("!dneg:remote.test", json!({"room_version": "11"}), -1));
    let (exact_id, exact) = sized_create(&remote, "!exact:remote.test", 65_536);
    let (_, over) = sized_create(&remote, "!over:remote.test", 65_537);
    let long_sender = format!("@{}:remote.test", "a".repeat(256 - 13));
    assert_eq!(long_sender.len(), 256);
    let mut long = create("!long:remote.test", json!({"room_version": "11"}), 1);
    long.sender = long_sender;
    let (_, long) = sign(&remote, long);
    // An EDU the database refuses (U+0000 in a to-device JSONB row) is dropped, not a 500.
    let nul_edu = json!({"edu_type": "m.direct_to_device", "content": {"sender": "@r:remote.test", "type": "m.test",
        "message_id": "nul-edu", "messages": {alice["user_id"].as_str().unwrap(): {"*": {"body": "a\u{0}b"}}}}});

    let body = txn(
        vec![nul, ordinary, nul_key, explicit, depth_max, depth_zero, depth_negative, exact, over, long],
        vec![json!({"edu_type": "org.unknown", "content": {}}), nul_edu],
    );
    let result = fed(&server, &remote, Method::PUT, "/_matrix/federation/v1/send/journey-1", Some(body.clone()), 200).await;
    let mut accepted: Vec<&str> = result["pdus"].as_object().unwrap().keys().map(String::as_str).collect();
    accepted.sort();
    let mut expected = vec![nul_id.as_str(), ordinary_id.as_str(), depth_max_id.as_str(), depth_zero_id.as_str(), exact_id.as_str()];
    expected.sort();
    assert_eq!(accepted, expected, "{result}");
    assert!(result["pdus"].as_object().unwrap().values().all(|v| v == &json!({})), "{result}");

    // Replay of the same transaction ID returns the identical stored response.
    let replay = fed(&server, &remote, Method::PUT, "/_matrix/federation/v1/send/journey-1", Some(body), 200).await;
    assert_eq!(replay, result);
    let path = format!("/_matrix/federation/v1/event/{}", enc(&explicit_id));
    fed(&server, &remote, Method::GET, &path, None, 404).await;

    // The NUL-bearing, extended PDU is served byte-exact, without event_id,
    // before and after a restart.
    let path = format!("/_matrix/federation/v1/event/{}", enc(&nul_id));
    for restart in [false, true] {
        if restart {
            server.stop();
            server.start().await;
        }
        let served = fed(&server, &remote, Method::GET, &path, None, 200).await["pdus"][0].clone();
        assert!(served.get("event_id").is_none(), "{served}");
        assert_eq!(served["content"]["org.test"], "a\u{0}b");
        assert_eq!(served["org.example.ext"], json!({"opaque": "preserve me", "unicode": "世界"}));
        let pdu: Pdu = serde_json::from_value(served).unwrap();
        assert_eq!(conduit::hashing::event_id(&pdu).unwrap(), nul_id);
        assert!(conduit::hashing::content_hash_matches(&pdu).unwrap());
    }
}

fn invite(remote: &Remote, room: &str, sender: &str, invitee: &str) -> Pdu {
    let mut pdu = Pdu::new(room, sender, "m.room.member", Some(invitee.into()),
        json!({"membership": "invite", "displayname": "Alice"}), 1_700_000_000_000, vec![], vec![], 1);
    sign_authored(&mut pdu, &remote.key, REMOTE).unwrap();
    pdu
}

#[tokio::test]
async fn invite_is_verified_and_path_checked_before_cosigning() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let alice_id = alice["user_id"].as_str().unwrap();
    let token = alice["access_token"].as_str().unwrap();

    let put_invite = |room: &str, event_id: &str, event: &Pdu, status: u16| {
        let path = format!("/_matrix/federation/v2/invite/{}/{}", enc(room), enc(event_id));
        let body = json!({"event": event, "invite_room_state": [], "room_version": "11"});
        let server = &server;
        let remote = &remote;
        async move { fed(server, remote, Method::PUT, &path, Some(body), status).await }
    };
    let id = |pdu: &Pdu| conduit::hashing::event_id(pdu).unwrap();

    // Forged inviter signature.
    let mut forged = invite(&remote, "!forged:remote.test", "@r:remote.test", alice_id);
    sign_authored(&mut forged, &generate_server_key(), REMOTE).unwrap();
    let forged_sig = forged.signatures[REMOTE].as_object().unwrap().values().last().unwrap().clone();
    forged.signatures = json!({ REMOTE: { remote.key.key_id.clone(): forged_sig } });
    let error = put_invite("!forged:remote.test", &id(&forged), &forged, 400).await;
    assert_eq!(error["errcode"], "M_INVALID_PARAM");
    // Path ID that is not the derived ID.
    let wrong_path = invite(&remote, "!path:remote.test", "@r:remote.test", alice_id);
    assert_eq!(put_invite("!path:remote.test", "$not-derived", &wrong_path, 400).await["errcode"], "M_INVALID_PARAM");
    // Content-hash mismatch: refused, never redacted-and-co-signed.
    let mut tampered = invite(&remote, "!hash:remote.test", "@r:remote.test", alice_id);
    tampered.content["displayname"] = json!("Mallory");
    assert_eq!(put_invite("!hash:remote.test", &id(&tampered), &tampered, 400).await["errcode"], "M_INVALID_PARAM");
    // Sender not on the requesting origin.
    let foreign = invite(&remote, "!origin:remote.test", "@r:other.test", alice_id);
    assert_eq!(put_invite("!origin:remote.test", &id(&foreign), &foreign, 400).await["errcode"], "M_INVALID_PARAM");

    // A valid invite is co-signed with hashes and identity unchanged.
    let valid = invite(&remote, "!valid:remote.test", "@r:remote.test", alice_id);
    let response = put_invite("!valid:remote.test", &id(&valid), &valid, 200).await;
    let event = &response["event"];
    assert!(event.get("event_id").is_none());
    assert_eq!(event["hashes"], valid.hashes);
    assert!(event["signatures"][LOCAL].is_object(), "co-signed: {event}");
    assert_eq!(event["signatures"][REMOTE], valid.signatures[REMOTE]);
    let returned: Pdu = serde_json::from_value(event.clone()).unwrap();
    assert_eq!(id(&returned), id(&valid));

    // Only the valid invite was stored.
    let sync = server.request(Method::GET, "/_matrix/client/v3/sync", Some(token), None, 200).await;
    let invites: Vec<&String> = sync["rooms"]["invite"].as_object().map(|m| m.keys().collect()).unwrap_or_default();
    assert_eq!(invites, vec!["!valid:remote.test"], "{sync}");
}

#[tokio::test]
async fn send_join_validates_sender_state_key_origin_and_path() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"].as_str().unwrap().to_owned();
    let joiner = "@r:remote.test";

    let make_join = format!("/_matrix/federation/v1/make_join/{}/{}?ver=11",
        enc(&room), enc(joiner));
    let template = fed(&server, &remote, Method::GET, &make_join, None, 200).await["event"].clone();
    assert!(template.get("event_id").is_none() && template.get("hashes").is_none(), "{template}");

    let send_join = |event_id: String, pdu: Value, status: u16| {
        let path = format!("/_matrix/federation/v2/send_join/{}/{}", enc(&room), enc(&event_id));
        let server = &server;
        let remote = &remote;
        async move { fed(server, remote, Method::PUT, &path, Some(pdu), status).await }
    };
    let signed = |mutate: &dyn Fn(&mut Pdu)| {
        let mut pdu: Pdu = serde_json::from_value(template.clone()).unwrap();
        mutate(&mut pdu);
        sign(&remote, pdu)
    };

    let (id, pdu) = signed(&|p| p.state_key = Some("@other:remote.test".into()));
    assert_eq!(send_join(id, pdu, 400).await["errcode"], "M_INVALID_PARAM");
    let (id, pdu) = signed(&|p| { p.sender = "@r:other.test".into(); p.state_key = Some("@r:other.test".into()); });
    assert_eq!(send_join(id, pdu, 400).await["errcode"], "M_INVALID_PARAM");
    let (_, pdu) = signed(&|_| {});
    assert_eq!(send_join("$not-derived".into(), pdu, 400).await["errcode"], "M_INVALID_PARAM");

    let (id, pdu) = signed(&|_| {});
    let response = send_join(id.clone(), pdu, 200).await;
    for wire in response["state"].as_array().unwrap().iter()
        .chain(response["auth_chain"].as_array().unwrap())
        .chain([&response["event"]])
    {
        assert!(wire.get("event_id").is_none(), "{wire}");
    }
    let event: Pdu = serde_json::from_value(response["event"].clone()).unwrap();
    assert_eq!(conduit::hashing::event_id(&event).unwrap(), id);
    assert!(event.signatures.get(LOCAL).is_none(), "an unrestricted join is not co-signed");

    // A restricted join naming an authoriser elsewhere is refused; one naming
    // our user is co-signed by us before verification.
    let template2 = fed(&server, &remote, Method::GET, &make_join.replace("%40r%3A", "%40r2%3A"), None, 200).await["event"].clone();
    let restricted = |authoriser: &str| {
        let mut pdu: Pdu = serde_json::from_value(template2.clone()).unwrap();
        pdu.content["join_authorised_via_users_server"] = json!(authoriser);
        sign(&remote, pdu)
    };
    let (id, pdu) = restricted("@admin:elsewhere.test");
    assert_eq!(send_join(id, pdu, 400).await["errcode"], "M_INVALID_PARAM");
    let (id, pdu) = restricted(alice["user_id"].as_str().unwrap());
    let response = send_join(id.clone(), pdu, 200).await;
    let event: Pdu = serde_json::from_value(response["event"].clone()).unwrap();
    assert_eq!(conduit::hashing::event_id(&event).unwrap(), id, "co-signing never changes the ID");
    assert!(event.signatures[LOCAL].is_object(), "resident co-signature present: {}", response["event"]);
}

#[tokio::test]
async fn client_floats_replay_and_client_nul_rules() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let user = alice["user_id"].as_str().unwrap();
    let device = alice["device_id"].as_str().unwrap();

    // A float in a client to-device body: the lane rule refuses non-canonical
    // to-device contents (400 M_BAD_JSON), but the replay sink must store the
    // body losslessly first (no 500), and a replay returns the stored answer.
    let body = json!({"messages": {user: {device: {"f": 1.5, "s": "a\u{0}b"}}}});
    let path = "/_matrix/client/v3/sendToDevice/m.test/float-1";
    let first = server.request(Method::PUT, path, Some(token), Some(body.clone()), 400).await;
    assert_eq!(first["errcode"], "M_BAD_JSON");
    let again = server.request(Method::PUT, path, Some(token), Some(json!({"messages": {}})), 400).await;
    assert_eq!(first, again, "replay returns the stored response");
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let (stored,): (Option<String>,) = sqlx::query_as("SELECT request_text FROM transactions WHERE txn_id = 'float-1'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(serde_json::from_str::<Value>(&stored.unwrap()).unwrap(), body, "float and U+0000 stored losslessly");
    let _ = device;

    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({})), 200)
        .await["room_id"].as_str().unwrap().to_owned();
    // U+0000 in an authored state key is refused before the event is built.
    let state = format!("/_matrix/client/v3/rooms/{}/state/org.test/a%00b", enc(&room));
    let error = server.request(Method::PUT, &state, Some(token), Some(json!({})), 400).await;
    assert_eq!(error["errcode"], "M_INVALID_PARAM");
    // U+0000 in content is stored and read back exactly.
    let send = format!("/_matrix/client/v3/rooms/{}/send/m.room.message/nul-1", enc(&room));
    let sent = server.request(Method::PUT, &send, Some(token), Some(json!({"msgtype": "m.text", "body": "a\u{0}b"})), 200).await;
    let event_id = sent["event_id"].as_str().unwrap();
    let get = format!("/_matrix/client/v3/rooms/{}/event/{}", enc(&room), enc(event_id));
    let event = server.request(Method::GET, &get, Some(token), None, 200).await;
    assert_eq!(event["content"]["body"], "a\u{0}b");
}
