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

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{routing::{get, post}, Json, Router};
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

#[tokio::test]
async fn minted_openid_token_is_redeemed_by_federation_userinfo() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let user = alice["user_id"].as_str().unwrap();
    let bob = server.register("bob").await;

    let minted = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/user/{}/openid/request_token", enc(user)),
            Some(token),
            Some(json!({})),
            200,
        )
        .await;
    assert_eq!(minted["token_type"], "Bearer");
    assert_eq!(minted["matrix_server_name"], LOCAL);
    assert_eq!(minted["expires_in"], 3600);
    let access = minted["access_token"].as_str().unwrap();
    assert!(!access.is_empty());

    let path = format!("/_matrix/federation/v1/openid/userinfo?access_token={access}");
    let who = fed(&server, &remote, Method::GET, &path, None, 200).await;
    assert_eq!(who["sub"], user, "{who}");

    let denied = fed(
        &server,
        &remote,
        Method::GET,
        "/_matrix/federation/v1/openid/userinfo?access_token=not-a-real-token",
        None,
        401,
    )
    .await;
    assert_eq!(denied["errcode"], "M_UNAUTHORIZED", "{denied}");
    let missing = fed(&server, &remote, Method::GET, "/_matrix/federation/v1/openid/userinfo", None, 400).await;
    assert_eq!(missing["errcode"], "M_BAD_JSON", "{missing}");

    let other = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/user/{}/openid/request_token", enc(user)),
            Some(bob["access_token"].as_str().unwrap()),
            Some(json!({})),
            403,
        )
        .await;
    assert_eq!(other["errcode"], "M_FORBIDDEN", "{other}");
}

#[tokio::test]
async fn server_acl_denies_remote_participation_until_lifted() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let carol = server.register("carol").await;
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let marker = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/acl-marker", enc(&room)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": "marker"})),
            200,
        )
        .await;
    let marker_id = marker["event_id"].as_str().unwrap().to_owned();

    let state_path = format!("/_matrix/federation/v1/state/{}", enc(&room));
    let ids_path = format!("/_matrix/federation/v1/state_ids/{}", enc(&room));
    let join_path = format!("/_matrix/federation/v1/make_join/{}/{}", enc(&room), enc("@r:remote.test"));
    let backfill_path = format!("/_matrix/federation/v1/backfill/{}?limit=1", enc(&room));
    let auth_path = format!("/_matrix/federation/v1/event_auth/{}/{}", enc(&room), enc(&marker_id));
    let missing_path = format!("/_matrix/federation/v1/get_missing_events/{}", enc(&room));
    let knock_path = format!("/_matrix/federation/v1/make_knock/{}/{}", enc(&room), enc("@r:remote.test"));
    let leave_path = format!("/_matrix/federation/v1/make_leave/{}/{}", enc(&room), enc("@r:remote.test"));
    let send_knock = format!("/_matrix/federation/v1/send_knock/{}/$unused", enc(&room));
    let send_leave = format!("/_matrix/federation/v2/send_leave/{}/$unused", enc(&room));

    let open_state = fed(&server, &remote, Method::GET, &state_path, None, 200).await;
    assert!(open_state["pdus"].as_array().unwrap().len() > 1, "{open_state}");
    assert!(fed(&server, &remote, Method::GET, &ids_path, None, 200).await["pdu_ids"].as_array().unwrap().len() > 1);
    assert!(fed(&server, &remote, Method::GET, &join_path, None, 200).await["event"].is_object());
    assert!(fed(&server, &remote, Method::GET, &backfill_path, None, 200).await["pdus"].is_array());
    assert!(fed(&server, &remote, Method::GET, &auth_path, None, 200).await["auth_chain"].is_array());
    assert!(fed(&server, &remote, Method::POST, &missing_path, Some(json!({"limit": 1})), 200).await["events"].is_array());

    let acl = format!("/_matrix/client/v3/rooms/{}/state/m.room.server_acl", enc(&room));
    server
        .request(
            Method::PUT,
            &acl,
            Some(token),
            Some(json!({"allow": ["*"], "deny": ["remote.test"], "allow_ip_literals": false})),
            200,
        )
        .await;

    let denied = |path: String, method: Method, body: Option<Value>| {
        let server = &server;
        let remote = &remote;
        async move {
            let response = fed(server, remote, method, &path, body, 403).await;
            assert_eq!(response["errcode"], "M_FORBIDDEN", "{path}: {response}");
            assert!(
                response["error"].as_str().unwrap_or("").contains("server ACL"),
                "{path}: {response}"
            );
        }
    };
    denied(state_path.clone(), Method::GET, None).await;
    denied(ids_path.clone(), Method::GET, None).await;
    denied(join_path.clone(), Method::GET, None).await;
    denied(backfill_path.clone(), Method::GET, None).await;
    denied(auth_path.clone(), Method::GET, None).await;
    denied(missing_path.clone(), Method::POST, Some(json!({"limit": 1}))).await;
    denied(knock_path.clone(), Method::GET, None).await;
    denied(leave_path.clone(), Method::GET, None).await;
    denied(send_knock.clone(), Method::PUT, Some(json!({}))).await;
    denied(send_leave.clone(), Method::PUT, Some(json!({}))).await;

    let (event_id, pdu) = sign(
        &remote,
        Pdu::new(
            &room,
            "@r:remote.test",
            "m.room.message",
            None,
            json!({"msgtype": "m.text", "body": "from a denied server"}),
            1_700_000_000_000,
            vec![],
            vec![],
            3,
        ),
    );
    let sent = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/acl-deny-1",
        Some(txn(vec![pdu], vec![])),
        200,
    )
    .await;
    assert_eq!(sent["pdus"][&event_id]["error"], "server ACL denies this server", "{sent}");
    server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{}/event/{}", enc(&room), enc(&event_id)),
            Some(token),
            None,
            404,
        )
        .await;

    let invite = format!("/_matrix/client/v3/rooms/{}/invite", enc(&room));
    let blocked = server
        .request(Method::POST, &invite, Some(token), Some(json!({"user_id": "@bob:remote.test"})), 403)
        .await;
    assert_eq!(blocked["errcode"], "M_FORBIDDEN", "{blocked}");
    server
        .request(Method::POST, &invite, Some(token), Some(json!({"user_id": carol["user_id"]})), 200)
        .await;

    server
        .request(Method::PUT, &acl, Some(token), Some(json!({"allow": ["*"], "deny": []})), 200)
        .await;
    assert!(fed(&server, &remote, Method::GET, &state_path, None, 200).await["pdus"].as_array().unwrap().len() > 1);
    assert!(fed(&server, &remote, Method::GET, &ids_path, None, 200).await["pdu_ids"].is_array());
    assert!(fed(&server, &remote, Method::GET, &join_path, None, 200).await["event"].is_object());
    assert!(fed(&server, &remote, Method::GET, &backfill_path, None, 200).await["pdus"].is_array());
    assert!(fed(&server, &remote, Method::GET, &auth_path, None, 200).await["auth_chain"].is_array());
    let knocking = fed(&server, &remote, Method::GET, &knock_path, None, 403).await;
    assert_eq!(knocking["errcode"], "M_FORBIDDEN", "{knocking}");
    assert!(!knocking["error"].as_str().unwrap_or("").contains("server ACL"), "{knocking}");
    let leaving = fed(&server, &remote, Method::GET, &leave_path, None, 403).await;
    assert!(leaving["error"].as_str().unwrap_or("").contains("not in the room"), "{leaving}");
    let knock_body = fed(&server, &remote, Method::PUT, &send_knock, Some(json!({})), 400).await;
    assert_eq!(knock_body["errcode"], "M_BAD_JSON", "{knock_body}");
}

struct PolicyRemote {
    remote: Remote,
    calls: Arc<AtomicU32>,
    policy_key: Arc<conduit::keys::ServerKey>,
    base_url: String,
}

/// Signs with a key that is not the published server key. Refuses body
/// "spam". The first request whose body is "retry-me" gets an invalid signature.
async fn spawn_policy() -> PolicyRemote {
    let server_key = Arc::new(generate_server_key());
    let unsigned = json!({
        "server_name": REMOTE,
        "verify_keys": { server_key.key_id.clone(): { "key": STANDARD_NO_PAD.encode(public_bytes(&server_key)) } },
        "old_verify_keys": {},
        "valid_until_ts": chrono::Utc::now().timestamp_millis() + 3_600_000,
    });
    use ed25519_dalek::Signer as _;
    let sig = server_key.signing_key.sign(&conduit::canonical_json::to_canonical_bytes(&unsigned).unwrap());
    let mut doc = unsigned;
    doc["signatures"] = json!({ REMOTE: { server_key.key_id.clone(): STANDARD_NO_PAD.encode(sig.to_bytes()) } });
    let generated = generate_server_key();
    let policy_key = Arc::new(conduit::keys::ServerKey {
        key_id: "ed25519:policy_server".into(),
        signing_key: generated.signing_key,
    });
    let calls = Arc::new(AtomicU32::new(0));
    let retries = Arc::new(AtomicU32::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let calls_sign = Arc::clone(&calls);
    let policy_for_sign = Arc::clone(&policy_key);
    let app = Router::new()
        .route("/_matrix/key/v2/server", get(move || {
            let doc = doc.clone();
            async move { Json(doc) }
        }))
        .route("/_matrix/policy/v1/sign", post(move |headers: HeaderMap, Json(body): Json<Value>| {
            let calls = Arc::clone(&calls_sign);
            let retries = Arc::clone(&retries);
            let policy_key = Arc::clone(&policy_for_sign);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let authed = headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .contains("X-Matrix");
                if !authed {
                    return (StatusCode::UNAUTHORIZED, Json(json!({"errcode": "M_FORBIDDEN", "error": "missing authorization"}))).into_response();
                }
                if body["content"]["body"] == "spam" {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"errcode": "M_FORBIDDEN", "error": "The message appears to contain possible spam"})),
                    ).into_response();
                }
                if body["content"]["body"] == "retry-me" && retries.fetch_add(1, Ordering::SeqCst) == 0 {
                    return (StatusCode::OK, Json(json!({ REMOTE: { "ed25519:policy_server": "not-a-real-signature" } }))).into_response();
                }
                let mut pdu: Pdu = serde_json::from_value(body).expect("policy request is a PDU");
                conduit::signing::add_signature(&mut pdu, &policy_key, REMOTE).unwrap();
                let signature = pdu.signatures[REMOTE]["ed25519:policy_server"].clone();
                (StatusCode::OK, Json(json!({ REMOTE: { "ed25519:policy_server": signature } }))).into_response()
            }
        }));
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    let base_url = format!("http://{addr}");
    PolicyRemote {
        remote: Remote { key: server_key, keys_url: base_url.clone() },
        calls,
        policy_key,
        base_url,
    }
}

#[tokio::test]
async fn policy_server_signature_is_required_before_a_client_event_is_sent() {
    let policy = spawn_policy().await;
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_REMOTE_KEYS_OVERRIDE", &policy.remote.keys_url),
        ("CONDUIT_FEDERATION_BASE_URL", &policy.base_url),
    ]).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"].as_str().unwrap().to_owned();

    let send = |body: &'static str, status: u16| {
        let server = &server;
        let room = room.clone();
        async move {
            let path = format!("/_matrix/client/v3/rooms/{}/send/m.room.message/{body}", enc(&room));
            server.request(Method::PUT, &path, Some(token), Some(json!({"msgtype": "m.text", "body": body})), status).await
        }
    };
    send("before-policy", 200).await;
    assert_eq!(policy.calls.load(Ordering::SeqCst), 0, "no policy server is configured");

    let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_bytes(&policy.policy_key));
    server.request(
        Method::PUT,
        &format!("/_matrix/client/v3/rooms/{}/state/m.room.policy", enc(&room)),
        Some(token),
        Some(json!({"via": REMOTE, "public_keys": {"ed25519": public_key}})),
        200,
    ).await;
    assert_eq!(policy.calls.load(Ordering::SeqCst), 0, "m.room.policy itself is not signed");
    send("before-join", 200).await;
    assert_eq!(policy.calls.load(Ordering::SeqCst), 0, "via has no joined user yet");

    let joiner = "@ps:remote.test";
    let make_join = format!("/_matrix/federation/v1/make_join/{}/{}", enc(&room), enc(joiner));
    let template = fed(&server, &policy.remote, Method::GET, &make_join, None, 200).await["event"].clone();
    let join_pdu: Pdu = serde_json::from_value(template).unwrap();
    let (join_id, join_body) = sign(&policy.remote, join_pdu);
    let send_join = format!("/_matrix/federation/v2/send_join/{}/{}", enc(&room), enc(&join_id));
    fed(&server, &policy.remote, Method::PUT, &send_join, Some(join_body), 200).await;
    assert_eq!(policy.calls.load(Ordering::SeqCst), 0, "the join predates an enabled policy server");

    let accepted = send("hello", 200).await;
    assert!(policy.calls.load(Ordering::SeqCst) >= 1, "the policy server was asked");
    let hello_id = accepted["event_id"].as_str().unwrap();
    let wire = fed(
        &server,
        &policy.remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(hello_id)),
        None,
        200,
    ).await;
    let stored: Pdu = serde_json::from_value(wire["pdus"][0].clone()).expect("wire pdu");
    conduit::signing::verify_event_signature(
        &stored,
        REMOTE,
        "ed25519:policy_server",
        &public_bytes(&policy.policy_key),
    ).expect("stored event carries the policy server signature");

    let calls_after_hello = policy.calls.load(Ordering::SeqCst);
    let retried = send("retry-me", 200).await;
    assert!(policy.calls.load(Ordering::SeqCst) >= calls_after_hello + 2, "an invalid signature is requested again");
    let retry_id = retried["event_id"].as_str().unwrap();
    let retry_wire = fed(
        &server,
        &policy.remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(retry_id)),
        None,
        200,
    ).await;
    let retry_pdu: Pdu = serde_json::from_value(retry_wire["pdus"][0].clone()).unwrap();
    conduit::signing::verify_event_signature(
        &retry_pdu,
        REMOTE,
        "ed25519:policy_server",
        &public_bytes(&policy.policy_key),
    ).expect("the retried signature verifies");

    let calls_before_spam = policy.calls.load(Ordering::SeqCst);
    let refused = send("spam", 400).await;
    assert_eq!(refused["errcode"], "M_FORBIDDEN", "{refused}");
    assert_eq!(refused["error"], "The message appears to contain possible spam", "{refused}");
    assert!(policy.calls.load(Ordering::SeqCst) > calls_before_spam);
    let messages = server.request(
        Method::GET,
        &format!("/_matrix/client/v3/rooms/{}/messages?dir=b&limit=20", enc(&room)),
        Some(token),
        None,
        200,
    ).await;
    assert!(messages["chunk"].as_array().unwrap().iter().all(|event| event["content"]["body"] != "spam"), "{messages}");

    let calls_before_disable = policy.calls.load(Ordering::SeqCst);
    server.request(
        Method::PUT,
        &format!("/_matrix/client/v3/rooms/{}/state/m.room.policy", enc(&room)),
        Some(token),
        Some(json!({})),
        200,
    ).await;
    assert_eq!(policy.calls.load(Ordering::SeqCst), calls_before_disable, "clearing m.room.policy is not signed");
    send("after-disable", 200).await;
    assert_eq!(policy.calls.load(Ordering::SeqCst), calls_before_disable, "a disabled policy server is not asked");
}
