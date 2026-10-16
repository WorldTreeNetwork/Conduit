//! add-pdu-wire journeys through the shipped binary and real PostgreSQL:
//! a remote server (`remote.test`, keys served by a local mock) speaks
//! signed X-Matrix federation to a production Conduit.
//!
//! Covered scenarios (openspec/changes/add-pdu-wire/specs/events-and-signing):
//! U+0000 over /send, explicit event_id, depth/size/field limits, transaction
//! replay, extension persistence across restart with no event_id on the
//! wire, /invite checks before co-signing, /send_join validation and the
//! restricted-join co-signature, client float replay, client U+0000 refusal,
//! per-PDU server ACL on /send with typing, receipt, presence, and signing-key EDUs.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{routing::{get, post, put}, Json, Router};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use sha2::Digest as _;
use common::production::Server;
use reqwest::Method;
use serde_json::{json, Value};

use conduit::event::Pdu;
use conduit::keys::{generate_server_key, public_bytes, server_key_from_bytes, ServerKey};
use conduit::signing::{add_signature, sign_authored};
use conduit_server::federation::auth::sign_request;

const REMOTE: &str = "remote.test";
const LOCAL: &str = "production.test";
const MAX_SAFE: i64 = 9_007_199_254_740_991;

fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Every room version this server can authorise, as repeated `ver` parameters.
fn supported_ver_query() -> String {
    conduit::room_version::SUPPORTED
        .iter()
        .map(|version| format!("ver={version}"))
        .collect::<Vec<_>>()
        .join("&")
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
    fed_as(server, remote, REMOTE, method, path, body, status).await
}

async fn fed_as(
    server: &Server,
    remote: &Remote,
    origin: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
    status: u16,
) -> Value {
    let auth = sign_request(method.as_str(), path, origin, LOCAL, body.as_ref(), &remote.key);
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

fn sign(remote: &Remote, pdu: Pdu) -> (String, Value) {
    sign_as(remote, REMOTE, pdu)
}

fn sign_as(remote: &Remote, origin: &str, mut pdu: Pdu) -> (String, Value) {
    // Like sign_authored, without its 64-byte authoring margin, so tests can
    // build PDUs right at the 65536-byte receive limit.
    pdu.hashes = json!({ "sha256": conduit::hashing::content_hash(&pdu).unwrap() });
    conduit::signing::add_signature(&mut pdu, &remote.key, origin).unwrap();
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
    // A to-device EDU whose content contains U+0000 is stored, not a 500.
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

/// A received v11 PDU is stored and served as the same canonical JSON.
/// Dropping an extension, injecting `event_id`, or rounding a number changes
/// those bytes and fails this test. Restart reads the stored copy, not the
/// request that was just parsed.
#[tokio::test]
async fn received_pdu_is_served_as_the_same_canonical_bytes() {
    let remote = spawn_remote().await;
    let mut server = federated_server(&remote).await;

    let mut pdu = create(
        "!wire:remote.test",
        json!({
            "room_version": "11",
            "org.test": "a\u{0}b",
            "nested": {"z": 1, "a": [true, false, null, "世界"]},
            "n": 9_007_199_254_740_991i64,
            "neg": -1,
            "empty": {},
            "list": []
        }),
        1,
    );
    pdu.extensions.insert(
        "org.example.ext".into(),
        json!({
            "opaque": "preserve me",
            "unicode": "世界",
            "nul": "a\u{0}b",
            "n": 9_007_199_254_740_991i64,
            "neg": -1,
            "flag": true,
            "nil": null,
            "tags": ["b", "a", {"z": 1, "a": [true, false, null]}],
            "empty": {}
        }),
    );
    pdu.extensions.insert("aaa".into(), json!("first"));
    pdu.extensions.insert("redacts".into(), json!("$not-a-redaction"));
    pdu.extensions.insert("zzz".into(), json!({"m": "last"}));
    let (id, sent) = sign(&remote, pdu);
    let sent_bytes = conduit::canonical_json::to_canonical_bytes(&sent).unwrap();

    let result = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/wire-exact",
        Some(txn(vec![sent], vec![])),
        200,
    )
    .await;
    assert_eq!(result["pdus"][&id], json!({}), "{result}");

    let path = format!("/_matrix/federation/v1/event/{}", enc(&id));
    for restart in [false, true] {
        if restart {
            server.stop();
            server.start().await;
        }
        let served = fed(&server, &remote, Method::GET, &path, None, 200).await["pdus"][0].clone();
        assert!(served.get("event_id").is_none(), "{served}");
        assert!(served.get("unsigned").is_none(), "{served}");
        let served_bytes = conduit::canonical_json::to_canonical_bytes(&served).unwrap();
        assert_eq!(
            served_bytes,
            sent_bytes,
            "served {}\nsent {}",
            String::from_utf8_lossy(&served_bytes),
            String::from_utf8_lossy(&sent_bytes),
        );
    }
}

/// A to-device message and a read receipt whose strings contain U+0000
/// arrive on PUT /send, the transaction returns 200, and /sync serves those
/// same characters after a restart. Replacing U+0000 with U+FFFD fails this.
#[tokio::test]
async fn send_delivers_nul_to_device_and_receipt_byte_exact() {
    let remote = spawn_remote().await;
    let mut server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let user_id = alice["user_id"].as_str().unwrap();
    let device_id = alice["device_id"].as_str().unwrap();
    let room = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({"preset": "public_chat"})),
            200,
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let joiner = "@r:remote.test";
    federation_join(&server, &remote, REMOTE, &room, joiner).await;
    let since = server
        .request(Method::GET, "/_matrix/client/v3/sync", Some(token), None, 200)
        .await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    let receipt_event = "$read\u{0}";
    let body = txn(
        vec![],
        vec![
            json!({
                "edu_type": "m.direct_to_device",
                "content": {
                    "sender": joiner,
                    "type": "m.room.encrypted",
                    "message_id": "nul-to-device",
                    "messages": { user_id: { device_id: { "body": "a\u{0}b" } } }
                }
            }),
            json!({
                "edu_type": "m.receipt",
                "content": {
                    room.clone(): {
                        "m.read": {
                            joiner: {
                                "event_ids": [receipt_event],
                                "data": { "ts": 1_700_000_000_000u64 }
                            }
                        }
                    }
                }
            }),
        ],
    );
    let sent = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/nul-edus",
        Some(body),
        200,
    )
    .await;
    assert!(sent.get("errcode").is_none(), "{sent}");

    server.stop();
    server.start().await;
    let sync = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/sync?since={since}"),
            Some(token),
            None,
            200,
        )
        .await;
    let to_device = sync["to_device"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["type"] == "m.room.encrypted")
        .unwrap_or_else(|| panic!("NUL to-device missing: {sync}"));
    assert_eq!(to_device["sender"], joiner, "{to_device}");
    assert_eq!(to_device["content"]["body"], "a\u{0}b", "{to_device}");
    let receipt = sync["rooms"]["join"][&room]["ephemeral"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["type"] == "m.receipt")
        .unwrap_or_else(|| panic!("NUL receipt missing: {sync}"));
    assert!(
        receipt["content"].get(receipt_event).is_some(),
        "receipt event id lost U+0000: {receipt}"
    );
    assert!(
        receipt["content"][receipt_event]["m.read"].get(joiner).is_some(),
        "{receipt}"
    );
}

/// Fifty PDUs and one hundred EDUs are accepted. One more of either is
/// `400 M_BAD_JSON`. The empty PDUs are invalid and produce no results;
/// raising either cap, or rejecting a legal transaction, fails this.
#[tokio::test]
async fn send_rejects_transactions_over_fifty_pdus_or_one_hundred_edus() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let edus = |n: usize| (0..n).map(|_| json!({"edu_type": "org.unknown", "content": {}})).collect();
    let pdus = |n: usize| (0..n).map(|_| json!({})).collect();

    let over_edus = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/over-edus",
        Some(txn(vec![], edus(101))),
        400,
    )
    .await;
    assert_eq!(over_edus["errcode"], "M_BAD_JSON", "{over_edus}");
    let at_edus = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/at-edus",
        Some(txn(vec![], edus(100))),
        200,
    )
    .await;
    assert!(at_edus.get("errcode").is_none(), "{at_edus}");

    let over_pdus = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/over-pdus",
        Some(txn(pdus(51), vec![])),
        400,
    )
    .await;
    assert_eq!(over_pdus["errcode"], "M_BAD_JSON", "{over_pdus}");
    let at_pdus = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/at-pdus",
        Some(txn(pdus(50), vec![])),
        200,
    )
    .await;
    assert!(at_pdus.get("errcode").is_none(), "{at_pdus}");
    assert!(at_pdus["pdus"].as_object().unwrap().is_empty(), "{at_pdus}");
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

    let make_join = format!(
        "/_matrix/federation/v1/make_join/{}/{}?{}",
        enc(&room),
        enc(joiner),
        supported_ver_query()
    );
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
    let alice_id = alice["user_id"].as_str().unwrap();
    let room_state = server
        .request(Method::GET, &format!("/_matrix/client/v3/rooms/{}/state", enc(&room)), Some(token), None, 200)
        .await;
    let alice_member = room_state
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["type"] == "m.room.member" && event["state_key"] == alice_id)
        .unwrap()["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let restricted = |authoriser: &str| {
        let mut pdu: Pdu = serde_json::from_value(template2.clone()).unwrap();
        pdu.content["join_authorised_via_users_server"] = json!(authoriser);
        if authoriser == alice_id {
            pdu.auth_events.push(alice_member.clone());
        }
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

/// make_join names a resident who can invite when the joiner is in an
/// allowed room, and uses the restricted-room error codes otherwise.
#[tokio::test]
async fn restricted_make_join_names_an_authoriser_or_refuses() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let alice_id = alice["user_id"].as_str().unwrap();

    let space = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"].as_str().unwrap().to_owned();
    let join_remote = |room: &str, user: &str| {
        let room = room.to_owned();
        let user = user.to_owned();
        let server = &server;
        let remote = &remote;
        async move {
            let path = format!("/_matrix/federation/v1/make_join/{}/{}?{}", enc(&room), enc(&user), supported_ver_query());
            let template = fed(server, remote, Method::GET, &path, None, 200).await["event"].clone();
            let pdu: Pdu = serde_json::from_value(template).unwrap();
            let (id, body) = sign(remote, pdu);
            let send = format!("/_matrix/federation/v2/send_join/{}/{}", enc(&room), enc(&id));
            fed(server, remote, Method::PUT, &send, Some(body), 200).await;
        }
    };
    join_remote(&space, "@r:remote.test").await;
    join_remote(&space, "@r2:remote.test").await;

    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "private_chat"})), 200)
        .await["room_id"].as_str().unwrap().to_owned();
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.join_rules", enc(&room)),
            Some(token),
            Some(json!({
                "join_rule": "restricted",
                "allow": [{ "type": "m.room_membership", "room_id": space }]
            })),
            200,
        )
        .await;

    let make = |user: &str| {
        let path = format!("/_matrix/federation/v1/make_join/{}/{}?{}", enc(&room), enc(user), supported_ver_query());
        let server = &server;
        let remote = &remote;
        async move { fed(server, remote, Method::GET, &path, None, 200).await }
    };
    let made = make("@r:remote.test").await;
    let template = &made["event"];
    assert_eq!(template["content"]["membership"], "join");
    assert_eq!(template["content"]["join_authorised_via_users_server"], alice_id);
    assert_eq!(template["sender"], "@r:remote.test");
    assert_eq!(template["state_key"], "@r:remote.test");
    let messages = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{}/messages?dir=b&limit=30", enc(&room)),
            Some(token),
            None,
            200,
        )
        .await;
    let alice_member = messages["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["type"] == "m.room.member" && event["state_key"] == alice_id)
        .unwrap();
    let alice_event = alice_member["event_id"].as_str().unwrap();
    assert!(
        template["auth_events"].as_array().unwrap().iter().any(|id| id == alice_event),
        "auth events include the authoriser: {template}"
    );

    let pdu: Pdu = serde_json::from_value(template.clone()).unwrap();
    let (id, body) = sign(&remote, pdu);
    let response = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v2/send_join/{}/{}", enc(&room), enc(&id)),
        Some(body),
        200,
    )
    .await;
    let event: Pdu = serde_json::from_value(response["event"].clone()).unwrap();
    assert_eq!(event.content["join_authorised_via_users_server"], alice_id);
    assert!(event.signatures[LOCAL].is_object(), "resident co-signed: {}", response["event"]);
    assert!(event.signatures[REMOTE].is_object(), "joining server signed: {}", response["event"]);

    let refused = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/make_join/{}/{}?{}", enc(&room), enc("@outsider:remote.test"), supported_ver_query()),
        None,
        403,
    )
    .await;
    assert_eq!(refused["errcode"], "M_FORBIDDEN");

    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.join_rules", enc(&room)),
            Some(token),
            Some(json!({
                "join_rule": "restricted",
                "allow": [{ "type": "m.room_membership", "room_id": "!unknown:remote.test" }]
            })),
            200,
        )
        .await;
    let unknown = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/make_join/{}/{}?{}", enc(&room), enc("@r2:remote.test"), supported_ver_query()),
        None,
        400,
    )
    .await;
    assert_eq!(unknown["errcode"], "M_UNABLE_TO_AUTHORISE_JOIN");

    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.join_rules", enc(&room)),
            Some(token),
            Some(json!({
                "join_rule": "restricted",
                "allow": [{ "type": "m.room_membership", "room_id": space }]
            })),
            200,
        )
        .await;
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/invite", enc(&room)),
            Some(token),
            Some(json!({"user_id": "@outsider:remote.test"})),
            200,
        )
        .await;
    let invited = make("@outsider:remote.test").await;
    assert!(
        invited["event"]["content"].get("join_authorised_via_users_server").is_none(),
        "an invite does not need an authoriser: {}",
        invited["event"]
    );

    server
        .request(Method::POST, &format!("/_matrix/client/v3/rooms/{}/leave", enc(&room)), Some(token), Some(json!({})), 200)
        .await;
    let ungranted = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/make_join/{}/{}?{}", enc(&room), enc("@r2:remote.test"), supported_ver_query()),
        None,
        400,
    )
    .await;
    assert_eq!(ungranted["errcode"], "M_UNABLE_TO_GRANT_JOIN");
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

    let state_path = format!(
        "/_matrix/federation/v1/state/{}?event_id={}",
        enc(&room),
        enc(&marker_id)
    );
    let ids_path = format!(
        "/_matrix/federation/v1/state_ids/{}?event_id={}",
        enc(&room),
        enc(&marker_id)
    );
    let join_path = format!("/_matrix/federation/v1/make_join/{}/{}?{}", enc(&room), enc("@r:remote.test"), supported_ver_query());
    let backfill_path = format!(
        "/_matrix/federation/v1/backfill/{}?limit=1&v={}",
        enc(&room),
        enc(&marker_id)
    );
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

/// `/send` applies `m.room.server_acl` per PDU inside HTTP 200. A denied
/// room's PDU carries an error and is not stored. A PDU for an allowed room
/// in the same transaction is accepted. Typing and receipt EDUs for the
/// denied room are ignored; the same EDUs for the allowed room are applied.
/// Presence and signing-key EDUs are stored. A content-hash mismatch is
/// kept as the redacted PDU. Lifting the ACL lets a later PDU through.
#[tokio::test]
async fn send_applies_acl_per_pdu_and_inbound_edus() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let joiner = "@r:remote.test";
    let make_room = || {
        let server = &server;
        async move {
            server
                .request(
                    Method::POST,
                    "/_matrix/client/v3/createRoom",
                    Some(token),
                    Some(json!({"preset": "public_chat"})),
                    200,
                )
                .await["room_id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let denied_room = make_room().await;
    let open_room = make_room().await;
    federation_join(&server, &remote, REMOTE, &denied_room, joiner).await;
    federation_join(&server, &remote, REMOTE, &open_room, joiner).await;

    let marker = |room: &str, txn_id: &str| {
        let room = room.to_owned();
        let txn_id = txn_id.to_owned();
        let server = &server;
        async move {
            server
                .request(
                    Method::PUT,
                    &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/{txn_id}", enc(&room)),
                    Some(token),
                    Some(json!({"msgtype": "m.text", "body": txn_id})),
                    200,
                )
                .await["event_id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let denied_marker = marker(&denied_room, "denied-marker").await;
    let open_marker = marker(&open_room, "open-marker").await;

    let auth_ids = |room: String| {
        let server = &server;
        async move {
            let state = server
                .request(
                    Method::GET,
                    &format!("/_matrix/client/v3/rooms/{}/state", enc(&room)),
                    Some(token),
                    None,
                    200,
                )
                .await;
            let mut power = String::new();
            let mut join = String::new();
            for event in state.as_array().unwrap() {
                match event["type"].as_str() {
                    Some("m.room.power_levels") => power = event["event_id"].as_str().unwrap().to_owned(),
                    Some("m.room.member") if event["state_key"] == joiner => {
                        join = event["event_id"].as_str().unwrap().to_owned();
                    }
                    _ => {}
                }
            }
            assert!(!power.is_empty() && !join.is_empty(), "{room}: {state}");
            (power, join)
        }
    };
    let (denied_power, denied_join) = auth_ids(denied_room.clone()).await;
    let (open_power, open_join) = auth_ids(open_room.clone()).await;
    let message = |room: &str, body: &str, power: &str, join: &str, depth: i64| {
        sign(
            &remote,
            Pdu::new(
                room,
                joiner,
                "m.room.message",
                None,
                json!({"msgtype": "m.text", "body": body}),
                1_700_000_000_000,
                vec![power.to_owned(), join.to_owned()],
                vec![join.to_owned()],
                depth,
            ),
        )
    };
    let (blocked_id, blocked) = message(&denied_room, "blocked-by-acl", &denied_power, &denied_join, 30);
    let (allowed_id, allowed) = message(&open_room, "allowed-by-acl", &open_power, &open_join, 30);
    let (mismatch_id, mut mismatched) = message(&open_room, "original-secret", &open_power, &open_join, 31);
    mismatched["content"]["body"] = json!("tampered-secret");

    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.server_acl", enc(&denied_room)),
            Some(token),
            Some(json!({"allow": ["*"], "deny": ["remote.test"], "allow_ip_literals": true})),
            200,
        )
        .await;

    let keys = common::keys::CrossSigning::new(joiner);
    let sent = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/acl-per-pdu",
        Some(txn(
            vec![blocked, allowed, mismatched.clone()],
            vec![
                json!({"edu_type": "m.typing", "content": {"room_id": denied_room, "user_id": joiner, "typing": true}}),
                json!({"edu_type": "m.typing", "content": {"room_id": open_room, "user_id": joiner, "typing": true}}),
                json!({
                    "edu_type": "m.receipt",
                    "content": {
                        denied_room.clone(): {"m.read": {joiner: {"event_ids": [denied_marker], "data": {"ts": 1_700_000_000_000u64}}}},
                        open_room.clone(): {"m.read": {joiner: {"event_ids": [open_marker], "data": {"ts": 1_700_000_000_000u64}}}},
                    }
                }),
                json!({
                    "edu_type": "m.presence",
                    "content": {"push": [
                        {"user_id": joiner, "presence": "online", "last_active_ago": 1000u64, "status_msg": "awake"},
                        {"user_id": "@spy:other.test", "presence": "online", "last_active_ago": 1000u64, "status_msg": "hidden"},
                    ]}
                }),
                json!({
                    "edu_type": "m.signing_key_update",
                    "content": {
                        "user_id": joiner,
                        "master_key": keys.master_key,
                        "self_signing_key": keys.self_signing_key,
                        "user_signing_key": keys.user_signing_key,
                    }
                }),
            ],
        )),
        200,
    )
    .await;
    assert_eq!(sent["pdus"][&blocked_id]["error"], "server ACL denies this server", "{sent}");
    assert_eq!(sent["pdus"][&allowed_id], json!({}), "{sent}");
    assert_eq!(sent["pdus"][&mismatch_id], json!({}), "{sent}");
    assert!(sent.get("errcode").is_none(), "a denied PDU does not fail the transaction: {sent}");

    let blocked_get = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&blocked_id)),
        None,
        404,
    )
    .await;
    assert_eq!(blocked_get["errcode"], "M_NOT_FOUND", "{blocked_get}");
    let redacted = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&mismatch_id)),
        None,
        200,
    )
    .await;
    let redacted_pdu = &redacted["pdus"][0];
    assert_eq!(redacted_pdu["content"], json!({}), "a hash mismatch is stored redacted: {redacted_pdu}");
    assert_eq!(redacted_pdu["hashes"], mismatched["hashes"], "{redacted_pdu}");
    assert!(!redacted.to_string().contains("tampered-secret"), "{redacted}");
    assert!(!redacted.to_string().contains("original-secret"), "{redacted}");

    let sync = server.request(Method::GET, "/_matrix/client/v3/sync", Some(token), None, 200).await;
    let bodies = |room: &str| -> Vec<String> {
        ["timeline", "state"]
            .into_iter()
            .flat_map(|section| {
                sync["rooms"]["join"][room][section]["events"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|event| event["content"]["body"].as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let denied_bodies = bodies(&denied_room);
    let open_bodies = bodies(&open_room);
    assert!(!denied_bodies.iter().any(|body| body == "blocked-by-acl"), "{denied_bodies:?}");
    assert!(open_bodies.iter().any(|body| body == "allowed-by-acl"), "{open_bodies:?}");
    assert!(!open_bodies.iter().any(|body| body == "tampered-secret" || body == "original-secret"), "{open_bodies:?}");

    let typing = |room: &str| -> Vec<String> {
        sync["rooms"]["join"][room]["ephemeral"]["events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|event| event["type"] == "m.typing")
            .flat_map(|event| {
                event["content"]["user_ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|user| user.as_str().map(str::to_owned))
            })
            .collect()
    };
    assert!(!typing(&denied_room).iter().any(|user| user == joiner), "denied typing: {sync}");
    assert!(typing(&open_room).iter().any(|user| user == joiner), "allowed typing: {sync}");
    let read = |room: &str, event_id: &str| {
        sync["rooms"]["join"][room]["ephemeral"]["events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|event| event["type"] == "m.receipt")
            .any(|event| event["content"][event_id]["m.read"].get(joiner).is_some())
    };
    assert!(!read(&denied_room, &denied_marker), "denied receipt: {sync}");
    assert!(read(&open_room, &open_marker), "allowed receipt: {sync}");
    let presence = sync["presence"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["sender"] == joiner)
        .unwrap_or_else(|| panic!("remote presence missing: {sync}"));
    assert_eq!(presence["content"]["presence"], "online", "{presence}");
    assert_eq!(presence["content"]["status_msg"], "awake", "{presence}");
    assert!(
        sync["presence"]["events"].as_array().unwrap().iter().all(|event| event["sender"] != "@spy:other.test"),
        "a presence entry from another server is ignored: {sync}"
    );

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .expect("production database");
    let stored: Vec<(String,)> = sqlx::query_as("SELECT key_type FROM cross_signing_keys WHERE user_id = $1 ORDER BY key_type")
        .bind(joiner)
        .fetch_all(&pool)
        .await
        .unwrap();
    pool.close().await;
    let stored: Vec<&str> = stored.iter().map(|row| row.0.as_str()).collect();
    assert_eq!(stored, vec!["master", "self_signing"], "user-signing keys in the EDU are not stored: {stored:?}");

    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.server_acl", enc(&denied_room)),
            Some(token),
            Some(json!({"allow": ["*"], "deny": []})),
            200,
        )
        .await;
    let (lifted_id, lifted) = message(&denied_room, "after-the-lift", &denied_power, &denied_join, 40);
    let lifted_txn = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/acl-lifted",
        Some(txn(
            vec![lifted],
            vec![json!({"edu_type": "m.typing", "content": {"room_id": denied_room, "user_id": joiner, "typing": true}})],
        )),
        200,
    )
    .await;
    assert_eq!(lifted_txn["pdus"][&lifted_id], json!({}), "{lifted_txn}");
    let after = server.request(Method::GET, "/_matrix/client/v3/sync", Some(token), None, 200).await;
    let after_bodies: Vec<&str> = after["rooms"]["join"][&denied_room]["timeline"]["events"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(after["rooms"]["join"][&denied_room]["state"]["events"].as_array().into_iter().flatten())
        .filter_map(|event| event["content"]["body"].as_str())
        .collect();
    assert!(after_bodies.contains(&"after-the-lift"), "{after_bodies:?}");
    assert!(!after_bodies.contains(&"blocked-by-acl"), "{after_bodies:?}");
    let typing_after: Vec<&str> = after["rooms"]["join"][&denied_room]["ephemeral"]["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| event["type"] == "m.typing")
        .flat_map(|event| event["content"]["user_ids"].as_array().into_iter().flatten().filter_map(|user| user.as_str()))
        .collect();
    assert!(typing_after.contains(&joiner), "typing applies once the ACL allows the server: {after}");
}

#[tokio::test]
async fn state_ids_are_the_room_state_before_the_event() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let name = |label: &str| {
        let server = &server;
        let room = room.clone();
        let label = label.to_owned();
        async move {
            server
                .request(
                    Method::PUT,
                    &format!("/_matrix/client/v3/rooms/{}/state/m.room.name/", enc(&room)),
                    Some(token),
                    Some(json!({"name": label})),
                    200,
                )
                .await["event_id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let first = name("first").await;
    let second = name("second").await;
    let third = name("third").await;
    let message = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/after-third", enc(&room)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": "after"})),
            200,
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let ids = |event_id: &str| {
        let path = format!(
            "/_matrix/federation/v1/state_ids/{}?event_id={}",
            enc(&room),
            enc(event_id)
        );
        let server = &server;
        let remote = &remote;
        async move {
            let body = fed(server, remote, Method::GET, &path, None, 200).await;
            body["pdu_ids"].as_array().unwrap().iter().map(|id| id.as_str().unwrap().to_owned()).collect::<Vec<_>>()
        }
    };
    let at_second = ids(&second).await;
    assert!(at_second.contains(&first), "state before the second name keeps the first: {at_second:?}");
    assert!(!at_second.contains(&second), "the requested event is not part of the snapshot: {at_second:?}");
    assert!(!at_second.contains(&third), "a later name is not the state at an earlier event: {at_second:?}");
    let at_third = ids(&third).await;
    assert!(at_third.contains(&second), "state before the third name is the second: {at_third:?}");
    assert!(!at_third.contains(&first), "the replaced name is not still current: {at_third:?}");
    assert!(!at_third.contains(&third), "{at_third:?}");
    let at_message = ids(&message).await;
    assert!(at_message.contains(&third), "a message sees the name that already happened: {at_message:?}");
    assert!(!at_message.iter().any(|id| id == &message), "{at_message:?}");

    let missing = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/state_ids/{}?event_id=$missing", enc(&room)),
        None,
        404,
    )
    .await;
    assert_eq!(missing["errcode"], "M_NOT_FOUND", "{missing}");
    let required = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/state_ids/{}", enc(&room)),
        None,
        400,
    )
    .await;
    assert_eq!(required["errcode"], "M_MISSING_PARAM", "{required}");

    let full = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/state/{}?event_id={}", enc(&room), enc(&second)),
        None,
        200,
    )
    .await;
    let names: Vec<&str> = full["pdus"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|pdu| pdu["content"]["name"].as_str())
        .collect();
    assert_eq!(names, vec!["first"], "full state at the second name is the first: {full}");
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
    let make_join = format!("/_matrix/federation/v1/make_join/{}/{}?{}", enc(&room), enc(joiner), supported_ver_query());
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

async fn timeline_bodies(server: &Server, token: &str, room: &str) -> Vec<String> {
    let sync = server.request(Method::GET, "/_matrix/client/v3/sync", Some(token), None, 200).await;
    sync["rooms"]["join"][room]["timeline"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["content"]["body"].as_str().map(str::to_owned))
        .collect()
}

fn policy_signature_holds(pdu: &Value, public: &[u8]) -> bool {
    let Ok(parsed) = serde_json::from_value::<Pdu>(pdu.clone()) else { return false };
    let Ok(mut redacted) = serde_json::to_value(conduit::redaction::redact(&parsed)) else { return false };
    let Some(map) = redacted.as_object_mut() else { return false };
    map.remove("signatures");
    map.remove("unsigned");
    let Ok(bytes) = conduit::canonical_json::to_canonical_bytes(&redacted) else { return false };
    let Some(signature) = pdu["signatures"][REMOTE]["ed25519:policy_server"].as_str() else { return false };
    let Ok(raw) = STANDARD_NO_PAD.decode(signature) else { return false };
    let Ok(raw) = <[u8; 64]>::try_from(raw.as_slice()) else { return false };
    let Ok(public) = <[u8; 32]>::try_from(public) else { return false };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&public) else { return false };
    key.verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&raw)).is_ok()
}

/// A PDU that already carries `ed25519:policy_server` is accepted without
/// asking again. A missing signature is requested and stored. A refusal is
/// HTTP 200, absent from `/sync`, and still returned by federation GET
/// `/event`. An invalid signature is requested a second time.
#[tokio::test]
async fn policy_server_refusal_soft_fails_a_federated_event() {
    let policy = spawn_policy().await;
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_REMOTE_KEYS_OVERRIDE", &policy.remote.keys_url),
        ("CONDUIT_FEDERATION_BASE_URL", &policy.base_url),
    ])
    .await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({"preset": "public_chat", "room_version": "12"})),
            200,
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_bytes(&policy.policy_key));
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.policy", enc(&room)),
            Some(token),
            Some(json!({"via": REMOTE, "public_keys": {"ed25519": public_key}})),
            200,
        )
        .await;
    let joiner = "@ps:remote.test";
    federation_join(&server, &policy.remote, REMOTE, &room, joiner).await;
    assert_eq!(policy.calls.load(Ordering::SeqCst), 0, "the join predates an enabled check on the resident's own events");

    let state = server
        .request(Method::GET, &format!("/_matrix/client/v3/rooms/{}/state", enc(&room)), Some(token), None, 200)
        .await;
    let mut power_id = String::new();
    let mut join_id = String::new();
    for event in state.as_array().unwrap() {
        match event["type"].as_str() {
            Some("m.room.power_levels") => power_id = event["event_id"].as_str().unwrap().to_owned(),
            Some("m.room.member") if event["state_key"] == joiner => {
                join_id = event["event_id"].as_str().unwrap().to_owned();
            }
            _ => {}
        }
    }
    assert!(!power_id.is_empty() && !join_id.is_empty(), "{state}");
    let policy_signer = server_key_from_bytes("ed25519:policy_server", policy.policy_key.signing_key.to_bytes().as_ref()).unwrap();
    let policy_public = public_bytes(&policy.policy_key);

    let message = |body: &str, ts: u64, depth: i64, with_policy: bool| {
        let pdu = Pdu::new(
            &room,
            joiner,
            "m.room.message",
            None,
            json!({"msgtype": "m.text", "body": body}),
            ts,
            vec![power_id.clone(), join_id.clone()],
            vec![join_id.clone()],
            depth,
        );
        let (id, value) = sign(&policy.remote, pdu);
        if !with_policy {
            return (id, value);
        }
        let mut signed: Pdu = serde_json::from_value(value).unwrap();
        add_signature(&mut signed, &policy_signer, REMOTE).unwrap();
        (conduit::hashing::event_id(&signed).unwrap(), serde_json::to_value(signed).unwrap())
    };
    let calls_before_signed = policy.calls.load(Ordering::SeqCst);
    let (signed_id, signed_pdu) = message("already-signed", 1_700_000_003_000, 40, true);
    let signed_result = fed(
        &server,
        &policy.remote,
        Method::PUT,
        "/_matrix/federation/v1/send/policy-already",
        Some(txn(vec![signed_pdu], vec![])),
        200,
    )
    .await;
    assert_eq!(signed_result["pdus"][&signed_id], json!({}), "{signed_result}");
    assert_eq!(policy.calls.load(Ordering::SeqCst), calls_before_signed, "a valid policy signature is not requested again");
    assert!(timeline_bodies(&server, token, &room).await.iter().any(|body| body == "already-signed"), "a recommended event reaches /sync");

    let calls_before_hello = policy.calls.load(Ordering::SeqCst);
    let (hello_id, hello_pdu) = message("hello-fed", 1_700_000_003_100, 41, false);
    let hello_result = fed(
        &server,
        &policy.remote,
        Method::PUT,
        "/_matrix/federation/v1/send/policy-hello",
        Some(txn(vec![hello_pdu], vec![])),
        200,
    )
    .await;
    assert_eq!(hello_result["pdus"][&hello_id], json!({}), "{hello_result}");
    assert!(policy.calls.load(Ordering::SeqCst) > calls_before_hello, "a missing policy signature is requested");
    let hello_wire = fed(
        &server,
        &policy.remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&hello_id)),
        None,
        200,
    )
    .await;
    assert!(
        policy_signature_holds(&hello_wire["pdus"][0], &policy_public),
        "the stored event carries the policy server signature: {}",
        hello_wire["pdus"][0]
    );
    assert!(timeline_bodies(&server, token, &room).await.iter().any(|body| body == "hello-fed"), "the signed event reaches /sync");

    let calls_before_spam = policy.calls.load(Ordering::SeqCst);
    let (spam_id, spam_pdu) = message("spam", 1_700_000_003_200, 42, false);
    let spam_result = fed(
        &server,
        &policy.remote,
        Method::PUT,
        "/_matrix/federation/v1/send/policy-spam",
        Some(txn(vec![spam_pdu], vec![])),
        200,
    )
    .await;
    assert_eq!(spam_result["pdus"][&spam_id], json!({}), "{spam_result}");
    assert_eq!(policy.calls.load(Ordering::SeqCst), calls_before_spam + 1, "a refusal is not retried");
    let spam_wire = fed(
        &server,
        &policy.remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&spam_id)),
        None,
        200,
    )
    .await;
    assert_eq!(spam_wire["pdus"][0]["content"]["body"], "spam", "{spam_wire}");
    assert!(spam_wire["pdus"][0]["signatures"][REMOTE].get("ed25519:policy_server").is_none(), "{spam_wire}");
    let seen = timeline_bodies(&server, token, &room).await;
    assert!(!seen.iter().any(|body| body == "spam"), "a refused event is soft-failed: {seen:?}");

    let calls_before_retry = policy.calls.load(Ordering::SeqCst);
    let (retry_id, retry_pdu) = message("retry-me", 1_700_000_003_300, 43, false);
    let retry_result = fed(
        &server,
        &policy.remote,
        Method::PUT,
        "/_matrix/federation/v1/send/policy-retry",
        Some(txn(vec![retry_pdu], vec![])),
        200,
    )
    .await;
    assert_eq!(retry_result["pdus"][&retry_id], json!({}), "{retry_result}");
    assert!(policy.calls.load(Ordering::SeqCst) >= calls_before_retry + 2, "an invalid signature is requested again");
    let retry_wire = fed(
        &server,
        &policy.remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&retry_id)),
        None,
        200,
    )
    .await;
    assert!(policy_signature_holds(&retry_wire["pdus"][0], &policy_public), "{retry_wire}");
    assert!(timeline_bodies(&server, token, &room).await.iter().any(|body| body == "retry-me"), "the retried event reaches /sync");

    let after = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/after-policy-soft", enc(&room)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": "still here"})),
            200,
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let after_pdu = fed(
        &server,
        &policy.remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&after)),
        None,
        200,
    )
    .await;
    let prevs = after_pdu["pdus"][0]["prev_events"].as_array().unwrap();
    assert!(prevs.iter().all(|id| id != &json!(spam_id)), "a soft-failed event is not a prev event: {after_pdu}");
}

#[tokio::test]
async fn blocked_invitee_rejects_federation_invites_on_v1_and_v2() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let alice_id = alice["user_id"].as_str().unwrap();
    let token = alice["access_token"].as_str().unwrap();
    let config = format!(
        "/_matrix/client/v3/user/{}/account_data/m.invite_permission_config",
        enc(alice_id)
    );
    server
        .request(Method::PUT, &config, Some(token), Some(json!({"default_action": "block"})), 200)
        .await;

    let blocked = invite(&remote, "!blocked:remote.test", "@r:remote.test", alice_id);
    let id = conduit::hashing::event_id(&blocked).unwrap();
    let v1_id = "$blockedv1:remote.test";
    let blocked_v1 = sign_v1(
        &remote,
        v1_member_event("!blocked:remote.test", "@r:remote.test", alice_id, v1_id, "Blocked"),
    );
    let member = format!(
        "/_matrix/client/v3/rooms/{}/state/m.room.member/{}",
        enc("!blocked:remote.test"),
        enc(alice_id)
    );
    let requests = [
        ("v1", v1_id, blocked_v1),
        ("v2", id.as_str(), json!({"event": &blocked, "invite_room_state": [], "room_version": "11"})),
    ];
    for (version, event_id, body) in requests {
        let path = format!(
            "/_matrix/federation/{version}/invite/{}/{}",
            enc("!blocked:remote.test"),
            enc(event_id)
        );
        let error = fed(&server, &remote, Method::PUT, &path, Some(body), 403).await;
        assert_eq!(error["errcode"], "M_INVITE_BLOCKED", "{version}: {error}");
        assert_eq!(error["error"], format!("{alice_id} is not accepting invites"));
        let stored = server.request(Method::GET, &member, Some(token), None, 403).await;
        assert!(stored.get("membership").is_none(), "{stored}");
    }

    server.request(Method::PUT, &config, Some(token), Some(json!({})), 200).await;
    let path = format!("/_matrix/federation/v2/invite/{}/{}", enc("!blocked:remote.test"), enc(&id));
    let accepted = fed(
        &server,
        &remote,
        Method::PUT,
        &path,
        Some(json!({"event": &blocked, "invite_room_state": [], "room_version": "11"})),
        200,
    )
    .await;
    assert!(accepted["event"]["signatures"][LOCAL].is_object(), "{accepted}");
    let sync = server.request(Method::GET, "/_matrix/client/v3/sync", Some(token), None, 200).await;
    assert!(sync["rooms"]["invite"].get("!blocked:remote.test").is_some(), "{sync}");
}

#[tokio::test]
async fn federation_guest_access_revocation_removes_local_guests() {
    let remote = spawn_remote().await;
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_REMOTE_KEYS_OVERRIDE", &remote.keys_url),
        ("CONDUIT_ALLOW_GUEST_ACCESS", "true"),
    ])
    .await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let bob = server.register("bob").await;
    let room = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({
                "preset": "public_chat",
                "room_version": "11",
                "initial_state": [{
                    "type": "m.room.guest_access",
                    "state_key": "",
                    "content": {"guest_access": "can_join"}
                }]
            })),
            200,
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    server
        .request(Method::POST, &format!("/_matrix/client/v3/join/{}", enc(&room)), Some(bob["access_token"].as_str().unwrap()), Some(json!({})), 200)
        .await;
    let guest = server
        .request(Method::POST, "/_matrix/client/v3/register?kind=guest", None, Some(json!({})), 200)
        .await;
    let guest_id = guest["user_id"].as_str().unwrap().to_owned();
    server
        .request(Method::POST, &format!("/_matrix/client/v3/join/{}", enc(&room)), Some(guest["access_token"].as_str().unwrap()), Some(json!({})), 200)
        .await;

    let joiner = "@r:remote.test";
    let make_join = format!("/_matrix/federation/v1/make_join/{}/{}?ver=11", enc(&room), enc(joiner));
    let template = fed(&server, &remote, Method::GET, &make_join, None, 200).await["event"].clone();
    let join_pdu: Pdu = serde_json::from_value(template).unwrap();
    let (join_id, join_body) = sign(&remote, join_pdu);
    let joined = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v2/send_join/{}/{}", enc(&room), enc(&join_id)),
        Some(join_body),
        200,
    )
    .await;
    assert!(joined["event"].is_object(), "{joined}");

    let mut levels = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.power_levels", enc(&room)),
            Some(token),
            None,
            200,
        )
        .await;
    levels["users"][joiner] = json!(100);
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.power_levels", enc(&room)),
            Some(token),
            Some(levels),
            200,
        )
        .await;

    let state = server
        .request(Method::GET, &format!("/_matrix/client/v3/rooms/{}/state", enc(&room)), Some(token), None, 200)
        .await;
    let event_id_of = |kind: &str, key: &str| {
        state
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["type"] == kind && event["state_key"] == key)
            .unwrap_or_else(|| panic!("missing {kind} {key} in {state}"))["event_id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (revoke_id, revoke) = sign(
        &remote,
        Pdu::new(
            &room,
            joiner,
            "m.room.guest_access",
            Some(String::new()),
            json!({"guest_access": "forbidden"}),
            // Later than the creator's event, and still inside the remote key's validity window.
            chrono::Utc::now().timestamp_millis() as u64 + 1_000,
            vec![event_id_of("m.room.create", ""), event_id_of("m.room.power_levels", ""), event_id_of("m.room.member", joiner)],
            vec![event_id_of("m.room.power_levels", "")],
            20,
        ),
    );
    let sent = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/guest-revoke-1",
        Some(txn(vec![revoke], vec![])),
        200,
    )
    .await;
    assert_eq!(sent["pdus"][&revoke_id], json!({}), "{sent}");

    let guest_member = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.member/{}", enc(&room), enc(&guest_id)),
            Some(token),
            None,
            200,
        )
        .await;
    assert_eq!(guest_member["membership"], "leave", "{guest_member}");
    let bob_member = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.member/{}", enc(&room), enc(bob["user_id"].as_str().unwrap())),
            Some(token),
            None,
            200,
        )
        .await;
    assert_eq!(bob_member["membership"], "join", "{bob_member}");
    let refused = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/join/{}", enc(&room)),
            Some(guest["access_token"].as_str().unwrap()),
            Some(json!({})),
            403,
        )
        .await;
    assert_eq!(refused["errcode"], "M_GUEST_ACCESS_FORBIDDEN", "{refused}");
}

fn key_document(server_name: &str, key: &ServerKey) -> Value {
    let unsigned = json!({
        "server_name": server_name,
        "verify_keys": { key.key_id.clone(): { "key": STANDARD_NO_PAD.encode(public_bytes(key)) } },
        "old_verify_keys": {},
        "valid_until_ts": chrono::Utc::now().timestamp_millis() + 3_600_000,
    });
    use ed25519_dalek::Signer as _;
    let sig = key.signing_key.sign(&conduit::canonical_json::to_canonical_bytes(&unsigned).unwrap());
    let mut doc = unsigned;
    doc["signatures"] = json!({ server_name: { key.key_id.clone(): STANDARD_NO_PAD.encode(sig.to_bytes()) } });
    doc
}

/// One key endpoint, a different document per `server_name` query.
async fn spawn_key_server(docs: Vec<Value>) -> String {
    let by_name: HashMap<String, Value> = docs
        .into_iter()
        .map(|doc| (doc["server_name"].as_str().unwrap().to_owned(), doc))
        .collect();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/_matrix/key/v2/server",
        get(move |Query(query): Query<HashMap<String, String>>| {
            let by_name = by_name.clone();
            async move {
                let name = query.get("server_name").map(String::as_str).unwrap_or("");
                Json(by_name.get(name).cloned().unwrap_or_else(|| json!({})))
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    format!("http://{addr}")
}

#[tokio::test]
async fn get_missing_events_returns_prev_events_between_the_bounds() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    federation_join(&server, &remote, REMOTE, &room, "@r:remote.test").await;
    let send = |txn: &str, body: &str| {
        let server = &server;
        let room = room.clone();
        let txn = txn.to_owned();
        let body = body.to_owned();
        async move {
            server
                .request(
                    Method::PUT,
                    &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/{txn}", enc(&room)),
                    Some(token),
                    Some(json!({"msgtype": "m.text", "body": body})),
                    200,
                )
                .await["event_id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let first = send("one", "one").await;
    let second = send("two", "two").await;
    let third = send("three", "three").await;
    let path = format!("/_matrix/federation/v1/get_missing_events/{}", enc(&room));
    let bodies = |payload: Value| {
        let server = &server;
        let remote = &remote;
        let path = path.clone();
        async move {
            let response = fed(server, remote, Method::POST, &path, Some(payload), 200).await;
            response["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|pdu| pdu["content"]["body"].as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        }
    };
    let between = bodies(json!({"earliest_events": [first], "latest_events": [third], "limit": 10})).await;
    assert_eq!(between, vec!["two"], "only the event strictly between the bounds: {between:?}");
    let limited = bodies(json!({"earliest_events": [], "latest_events": [third], "limit": 1})).await;
    assert_eq!(limited, vec!["two"], "the walk starts at prev_events and stops at the limit: {limited:?}");
    let second_pdu = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&second)),
        None,
        200,
    )
    .await;
    let depth = second_pdu["pdus"][0]["depth"].as_i64().unwrap();
    let too_deep = bodies(json!({
        "earliest_events": [first],
        "latest_events": [third],
        "limit": 10,
        "min_depth": depth + 1,
    }))
    .await;
    assert!(too_deep.is_empty(), "min_depth drops the shallower predecessor: {too_deep:?}");
}

#[tokio::test]
async fn backfill_returns_the_named_events_and_their_predecessors() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    federation_join(&server, &remote, REMOTE, &room, "@r:remote.test").await;
    let send = |txn: &str, body: &str| {
        let server = &server;
        let room = room.clone();
        let txn = txn.to_owned();
        let body = body.to_owned();
        async move {
            server
                .request(
                    Method::PUT,
                    &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/{txn}", enc(&room)),
                    Some(token),
                    Some(json!({"msgtype": "m.text", "body": body})),
                    200,
                )
                .await["event_id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let _one = send("one", "one").await;
    let two = send("two", "two").await;
    let _three = send("three", "three").await;
    let four = send("four", "four").await;
    let window = |event_id: &str, limit: u32| {
        let path = format!(
            "/_matrix/federation/v1/backfill/{}?limit={limit}&v={}",
            enc(&room),
            enc(event_id)
        );
        let server = &server;
        let remote = &remote;
        async move {
            let response = fed(server, remote, Method::GET, &path, None, 200).await;
            assert!(response["origin"].is_string(), "{response}");
            assert!(response["origin_server_ts"].is_number(), "{response}");
            response["pdus"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|pdu| pdu["content"]["body"].as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        }
    };
    let from_two = window(&two, 10).await;
    assert!(from_two.contains(&"two".to_owned()), "v itself is included: {from_two:?}");
    assert!(from_two.contains(&"one".to_owned()), "the predecessor of v is included: {from_two:?}");
    assert!(!from_two.iter().any(|body| body == "three" || body == "four"), "later events stay out: {from_two:?}");
    let capped = window(&four, 2).await;
    assert_eq!(capped, vec!["four".to_owned(), "three".to_owned()], "limit counts v and then its predecessors: {capped:?}");
    let missing = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/backfill/{}?limit=2", enc(&room)),
        None,
        400,
    )
    .await;
    assert_eq!(missing["errcode"], "M_MISSING_PARAM", "{missing}");
}

/// `send_join` `state` is the resolved room state from before the join.
/// The accepted membership is stored, and it is absent from that snapshot.
/// An overwritten room name keeps only the winner from before the join.
#[tokio::test]
async fn send_join_returns_state_from_before_the_join() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let alice_id = alice["user_id"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let name = |body: &str| {
        let body = body.to_owned();
        let server = &server;
        let room = room.clone();
        async move {
            server
                .request(
                    Method::PUT,
                    &format!("/_matrix/client/v3/rooms/{}/state/m.room.name", enc(&room)),
                    Some(token),
                    Some(json!({"name": body})),
                    200,
                )
                .await
        }
    };
    name("before").await;
    name("after").await;

    let joiner = "@r:remote.test";
    let make = format!("/_matrix/federation/v1/make_join/{}/{}?{}", enc(&room), enc(joiner), supported_ver_query());
    let template = fed(&server, &remote, Method::GET, &make, None, 200).await["event"].clone();
    let pdu: Pdu = serde_json::from_value(template).unwrap();
    let (id, body) = sign(&remote, pdu);
    let response = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v2/send_join/{}/{}", enc(&room), enc(&id)),
        Some(body),
        200,
    )
    .await;

    let state = response["state"].as_array().expect("state");
    assert!(state.iter().any(|event| event["type"] == "m.room.create"), "create is prior state: {response}");
    assert!(
        state.iter().any(|event| event["type"] == "m.room.name" && event["content"]["name"] == "after"),
        "the name that won before the join is included: {response}"
    );
    assert!(
        state.iter().all(|event| event["content"]["name"] != "before"),
        "the overwritten name is not current prior state: {response}"
    );
    assert!(
        state.iter().all(|event| !(event["type"] == "m.room.member" && event["state_key"] == joiner)),
        "the join itself is not part of the state from before it: {response}"
    );
    assert!(
        state.iter().any(|event| {
            event["type"] == "m.room.member" && event["state_key"] == alice_id && event["content"]["membership"] == "join"
        }),
        "members who joined earlier stay in the snapshot: {response}"
    );
    let returned: Pdu = serde_json::from_value(response["event"].clone()).unwrap();
    assert_eq!(conduit::hashing::event_id(&returned).unwrap(), id);
    let chain_ids: Vec<String> = response["auth_chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| {
            let pdu: Pdu = serde_json::from_value(event.clone()).unwrap();
            conduit::hashing::event_id(&pdu).unwrap()
        })
        .collect();
    for auth_id in &returned.auth_events {
        assert!(
            chain_ids.iter().any(|chain_id| chain_id == auth_id),
            "auth chain is missing {auth_id}, which the join cites; chain={chain_ids:?}"
        );
    }

    let current = server
        .request(Method::GET, &format!("/_matrix/client/v3/rooms/{}/state", enc(&room)), Some(token), None, 200)
        .await;
    assert!(
        current.as_array().unwrap().iter().any(|event| event["type"] == "m.room.member" && event["state_key"] == joiner),
        "the accepted join is current state after the response: {current}"
    );
}

async fn federation_join(server: &Server, remote: &Remote, origin: &str, room: &str, user: &str) {
    let make = format!("/_matrix/federation/v1/make_join/{}/{}?{}", enc(room), enc(user), supported_ver_query());
    let template = fed_as(server, remote, origin, Method::GET, &make, None, 200).await["event"].clone();
    let pdu: Pdu = serde_json::from_value(template).unwrap();
    let (id, body) = sign_as(remote, origin, pdu);
    let send = format!("/_matrix/federation/v2/send_join/{}/{}", enc(room), enc(&id));
    fed_as(server, remote, origin, Method::PUT, &send, Some(body), 200).await;
}

/// A missing `ver` list means room version 1. The resident returns 400
/// `M_INCOMPATIBLE_ROOM_VERSION` and the room's version when that list does
/// not include it. A listed version returns the unsigned join template.
#[tokio::test]
async fn make_join_rejects_room_versions_missing_from_ver() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let create = |version: &str| {
        let version = version.to_owned();
        let server = &server;
        async move {
            server
                .request(
                    Method::POST,
                    "/_matrix/client/v3/createRoom",
                    Some(token),
                    Some(json!({"preset": "public_chat", "room_version": version})),
                    200,
                )
                .await["room_id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let v12 = create("12").await;
    let v11 = create("11").await;
    let joiner = "@r:remote.test";
    let ask = |room: &str, query: &str, status: u16| {
        let path = if query.is_empty() {
            format!("/_matrix/federation/v1/make_join/{}/{}", enc(room), enc(joiner))
        } else {
            format!("/_matrix/federation/v1/make_join/{}/{}?{query}", enc(room), enc(joiner))
        };
        let server = &server;
        let remote = &remote;
        async move { fed(server, remote, Method::GET, &path, None, status).await }
    };

    let missing = ask(&v12, "", 400).await;
    assert_eq!(missing["errcode"], "M_INCOMPATIBLE_ROOM_VERSION", "{missing}");
    assert_eq!(missing["room_version"], "12", "{missing}");
    assert!(missing.get("event").is_none(), "{missing}");
    let only_old = ask(&v12, "ver=1&ver=11", 400).await;
    assert_eq!(only_old["errcode"], "M_INCOMPATIBLE_ROOM_VERSION", "{only_old}");
    assert_eq!(only_old["room_version"], "12", "{only_old}");
    let v11_missing = ask(&v11, "", 400).await;
    assert_eq!(v11_missing["room_version"], "11", "{v11_missing}");
    assert_eq!(v11_missing["errcode"], "M_INCOMPATIBLE_ROOM_VERSION", "{v11_missing}");

    let one = ask(&v12, "ver=12", 200).await;
    assert_eq!(one["room_version"], "12", "{one}");
    assert_eq!(one["event"]["type"], "m.room.member", "{one}");
    assert_eq!(one["event"]["sender"], joiner, "{one}");
    assert_eq!(one["event"]["state_key"], joiner, "{one}");
    assert_eq!(one["event"]["content"]["membership"], "join", "{one}");
    assert_eq!(one["event"]["room_id"], v12, "{one}");
    assert!(one["event"].get("event_id").is_none(), "{one}");
    let repeated = ask(&v12, "ver=1&ver=12", 200).await;
    assert_eq!(repeated["room_version"], "12", "{repeated}");
    assert_eq!(repeated["event"]["content"]["membership"], "join", "{repeated}");
    let eleven = ask(&v11, "ver=11", 200).await;
    assert_eq!(eleven["room_version"], "11", "{eleven}");

    let unknown = ask("!missing:production.test", "ver=12", 404).await;
    assert_eq!(unknown["errcode"], "M_NOT_FOUND", "{unknown}");
}

fn pdu_with_hash<'a>(pdus: &'a [Value], hash: &Value) -> &'a Value {
    pdus.iter()
        .find(|pdu| &pdu["hashes"]["sha256"] == hash)
        .unwrap_or_else(|| panic!("no pdu with content hash {hash} in {pdus:?}"))
}

/// A server that joined before `erase: true` still receives the original
/// message over `/event`, backfill and `get_missing_events`. A server whose
/// first join is after the erasure receives the redacted copy (empty message
/// content, original hashes, no redaction event).
#[tokio::test]
async fn later_joining_servers_get_redacted_federation_events() {
    let early_key = Arc::new(generate_server_key());
    let late_key = Arc::new(generate_server_key());
    let keys_url = spawn_key_server(vec![
        key_document(REMOTE, &early_key),
        key_document("late.test", &late_key),
    ])
    .await;
    let early = Remote { key: early_key, keys_url: keys_url.clone() };
    let late = Remote { key: late_key, keys_url: keys_url.clone() };
    let server = Server::with_env(&[("CONDUIT_FEDERATION", "1"), ("CONDUIT_REMOTE_KEYS_OVERRIDE", &keys_url)]).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();

    federation_join(&server, &early, REMOTE, &room, "@early:remote.test").await;

    let secret = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/secret", enc(&room)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": "my secret"})),
            200,
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let successor = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/after-secret", enc(&room)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": "later"})),
            200,
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let challenge = server
        .request(Method::POST, "/_matrix/client/v3/account/deactivate", Some(token), Some(json!({})), 401)
        .await;
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/deactivate",
            Some(token),
            Some(json!({
                "erase": true,
                "auth": {
                    "type": "m.login.password",
                    "identifier": {"type": "m.id.user", "user": "alice"},
                    "password": "test-password",
                    "session": challenge["session"],
                },
            })),
            200,
        )
        .await;

    federation_join(&server, &late, "late.test", &room, "@late:late.test").await;

    let event_path = format!("/_matrix/federation/v1/event/{}", enc(&secret));
    let early_event = fed_as(&server, &early, REMOTE, Method::GET, &event_path, None, 200).await;
    let early_pdu = &early_event["pdus"][0];
    let parsed: Pdu = serde_json::from_value(early_pdu.clone()).unwrap();
    assert_eq!(conduit::hashing::event_id(&parsed).unwrap(), secret, "resident keeps a verifiable PDU");
    assert_eq!(early_pdu["content"]["body"], "my secret");
    let hash = early_pdu["hashes"]["sha256"].clone();

    let late_event = fed_as(&server, &late, "late.test", Method::GET, &event_path, None, 200).await;
    let late_pdu = &late_event["pdus"][0];
    assert_eq!(late_pdu["hashes"]["sha256"], hash, "redacted copy keeps the original hashes");
    assert_eq!(late_pdu["content"], json!({}), "{late_pdu}");
    assert_eq!(late_pdu["sender"], early_pdu["sender"]);
    assert!(late_pdu.get("unsigned").is_none(), "erasure is not a redaction event: {late_pdu}");
    assert!(!late_event.to_string().contains("my secret"), "{late_event}");

    let backfill = format!(
        "/_matrix/federation/v1/backfill/{}?limit=50&v={}",
        enc(&room),
        enc(&successor)
    );
    let early_back = fed_as(&server, &early, REMOTE, Method::GET, &backfill, None, 200).await;
    let early_copy = pdu_with_hash(early_back["pdus"].as_array().unwrap(), &hash);
    assert_eq!(early_copy["content"]["body"], "my secret");
    let late_back = fed_as(&server, &late, "late.test", Method::GET, &backfill, None, 200).await;
    let late_copy = pdu_with_hash(late_back["pdus"].as_array().unwrap(), &hash);
    assert_eq!(late_copy["content"], json!({}), "{late_copy}");
    assert!(!late_back.to_string().contains("my secret"), "{late_back}");
    assert!(late_back["pdus"].as_array().unwrap().iter().all(|pdu| pdu["type"] != "m.room.redaction"));

    let missing = format!("/_matrix/federation/v1/get_missing_events/{}", enc(&room));
    let body = json!({"earliest_events": [], "latest_events": [successor], "limit": 10});
    let early_missing = fed_as(&server, &early, REMOTE, Method::POST, &missing, Some(body.clone()), 200).await;
    assert_eq!(pdu_with_hash(early_missing["events"].as_array().unwrap(), &hash)["content"]["body"], "my secret");
    let late_missing = fed_as(&server, &late, "late.test", Method::POST, &missing, Some(body), 200).await;
    assert_eq!(pdu_with_hash(late_missing["events"].as_array().unwrap(), &hash)["content"], json!({}));
    assert!(!late_missing.to_string().contains("my secret"), "{late_missing}");
}

async fn stored_event(server: &Server, event_id: &str) -> (String, String, String) {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .expect("production database");
    let row: (String, String, String) = sqlx::query_as(
        "SELECT content::text, pdu_json, id_integrity FROM events WHERE event_id = $1",
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    pool.close().await;
    row
}

/// An accepted redaction removes the unprotected keys from the events row
/// and from federation `GET /event`. Hashes and signatures stay. Room
/// version 5 keeps `aliases`; version 12 does not.
#[tokio::test]
async fn accepted_redaction_prunes_the_row_and_federation_get_event() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();

    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat", "room_version": "12"})), 200)
        .await["room_id"].as_str().unwrap().to_owned();
    let secret = "redact-me-body-9f3a";
    let sent = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/secret", enc(&room)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": secret})),
            200,
        )
        .await;
    let event_id = sent["event_id"].as_str().unwrap().to_owned();
    let (before_content, before_pdu, before_class) = stored_event(&server, &event_id).await;
    assert!(before_content.contains(secret), "{before_content}");
    assert!(before_pdu.contains(secret), "{before_pdu}");
    assert_eq!(before_class, "verified");
    let before: Value = serde_json::from_str(&before_pdu).unwrap();
    let hash = before["hashes"]["sha256"].clone();
    let signatures = before["signatures"].clone();

    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/redact/{}/prune", enc(&room), enc(&event_id)),
            Some(token),
            Some(json!({"reason": "spill"})),
            200,
        )
        .await;
    let (after_content, after_pdu, after_class) = stored_event(&server, &event_id).await;
    assert!(!after_content.contains(secret), "content column still holds the body: {after_content}");
    assert!(!after_pdu.contains(secret), "pdu_json still holds the body: {after_pdu}");
    assert_eq!(after_class, "redacted");
    let after: Value = serde_json::from_str(&after_pdu).unwrap();
    assert_eq!(after["hashes"]["sha256"], hash);
    assert_eq!(after["signatures"], signatures);
    assert!(after.get("event_id").is_none(), "{after}");

    let wire = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&event_id)),
        None,
        200,
    )
    .await;
    let pdu = &wire["pdus"][0];
    assert!(pdu.get("event_id").is_none(), "{pdu}");
    assert!(!pdu.to_string().contains(secret), "{pdu}");
    assert_eq!(pdu["content"], json!({}));
    assert_eq!(pdu["hashes"]["sha256"], hash, "federation keeps the original content hash");
    assert_eq!(pdu["signatures"], signatures);

    let served = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{}/event/{}", enc(&room), enc(&event_id)),
            Some(token),
            None,
            200,
        )
        .await;
    assert_eq!(served["content"], json!({}));
    assert_eq!(served["unsigned"]["redacted_because"]["content"]["reason"], "spill");

    let room5 = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "private_chat", "room_version": "5"})), 200)
        .await["room_id"].as_str().unwrap().to_owned();
    let alias = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.aliases/production.test", enc(&room5)),
            Some(token),
            Some(json!({"aliases": ["#kept:production.test"], "note": "drop-me-note"})),
            200,
        )
        .await;
    let alias_id = alias["event_id"].as_str().unwrap();
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/redact/{}/alias", enc(&room5), enc(alias_id)),
            Some(token),
            Some(json!({})),
            200,
        )
        .await;
    let (alias_content, alias_pdu, alias_class) = stored_event(&server, alias_id).await;
    assert!(!alias_content.contains("drop-me-note"), "{alias_content}");
    assert!(!alias_pdu.contains("drop-me-note"), "{alias_pdu}");
    assert!(alias_content.contains("#kept:production.test"), "v5 keeps aliases in the row: {alias_content}");
    assert!(alias_pdu.contains("#kept:production.test"), "v5 keeps aliases in pdu_json: {alias_pdu}");
    assert_eq!(alias_class, "redacted");
    let alias_wire = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(alias_id)),
        None,
        200,
    )
    .await;
    let alias_pdu_wire = &alias_wire["pdus"][0];
    assert_eq!(alias_pdu_wire["content"]["aliases"], json!(["#kept:production.test"]), "{alias_pdu_wire}");
    assert!(alias_pdu_wire["content"].get("note").is_none(), "{alias_pdu_wire}");
    assert!(!alias_wire.to_string().contains("drop-me-note"), "{alias_wire}");
}

fn member_path(room: &str, user: &str) -> String {
    format!("/_matrix/client/v3/rooms/{}/state/m.room.member/{}", enc(room), enc(user))
}

const V1_SIGN_FIELDS: &[&str] = &[
    "auth_events",
    "content",
    "depth",
    "event_id",
    "hashes",
    "membership",
    "origin",
    "origin_server_ts",
    "prev_events",
    "prev_state",
    "room_id",
    "sender",
    "state_key",
    "type",
];

fn v1_redact_content(event_type: &str, content: &Value) -> Value {
    let Some(map) = content.as_object() else {
        return json!({});
    };
    let fields: &[&str] = match event_type {
        "m.room.member" => &["membership"],
        "m.room.create" => &["creator"],
        "m.room.join_rules" => &["join_rule"],
        "m.room.power_levels" => &[
            "ban",
            "events",
            "events_default",
            "kick",
            "redact",
            "state_default",
            "users",
            "users_default",
        ],
        "m.room.aliases" => &["aliases"],
        "m.room.history_visibility" => &["history_visibility"],
        _ => &[],
    };
    let mut redacted = serde_json::Map::new();
    for field in fields {
        if let Some(value) = map.get(*field) {
            redacted.insert((*field).to_owned(), value.clone());
        }
    }
    Value::Object(redacted)
}

/// Room v1/v2 signing bytes: redacted event, `event_id` and tuple auth/prev
/// kept, signatures omitted, member content reduced to `membership`.
fn v1_signing_bytes(event: &Value) -> Vec<u8> {
    let map = event.as_object().unwrap();
    let mut kept = serde_json::Map::new();
    for key in V1_SIGN_FIELDS {
        if let Some(value) = map.get(*key) {
            kept.insert((*key).to_owned(), value.clone());
        }
    }
    if let Some(content) = kept.get("content").cloned() {
        let event_type = kept.get("type").and_then(Value::as_str).unwrap_or("");
        kept.insert("content".into(), v1_redact_content(event_type, &content));
    }
    conduit::canonical_json::to_canonical_bytes(&Value::Object(kept)).unwrap()
}

fn v1_content_hash(event: &Value) -> String {
    let mut copy = event.as_object().unwrap().clone();
    copy.remove("hashes");
    copy.remove("signatures");
    copy.remove("unsigned");
    let bytes = conduit::canonical_json::to_canonical_bytes(&Value::Object(copy)).unwrap();
    STANDARD_NO_PAD.encode(sha2::Sha256::digest(&bytes))
}

fn v1_member_event(room: &str, sender: &str, target: &str, event_id: &str, displayname: &str) -> Value {
    json!({
        "auth_events": [["$create:remote.test", {"sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]],
        "content": {"membership": "invite", "displayname": displayname},
        "depth": 5,
        "event_id": event_id,
        "origin": REMOTE,
        "origin_server_ts": chrono::Utc::now().timestamp_millis() as u64,
        "prev_events": [["$prev:remote.test", {"sha256": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}]],
        "room_id": room,
        "sender": sender,
        "state_key": target,
        "type": "m.room.member",
    })
}

fn sign_v1(remote: &Remote, mut event: Value) -> Value {
    event.as_object_mut().unwrap().remove("signatures");
    event["hashes"] = json!({"sha256": v1_content_hash(&event)});
    let bytes = v1_signing_bytes(&event);
    use ed25519_dalek::Signer as _;
    let signature = remote.key.signing_key.sign(&bytes);
    event["signatures"] = json!({
        REMOTE: { remote.key.key_id.clone(): STANDARD_NO_PAD.encode(signature.to_bytes()) }
    });
    event
}

async fn assert_local_v1_signature(server: &Server, event: &Value) {
    let document: Value = server
        .http
        .get(format!("{}/_matrix/key/v2/server", server.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let keys = document["verify_keys"].as_object().expect("published verify_keys");
    let bytes = v1_signing_bytes(event);
    let mut verified = false;
    for (key_id, entry) in keys {
        let Some(signature) = event["signatures"][LOCAL][key_id].as_str() else { continue };
        let public = STANDARD_NO_PAD.decode(entry["key"].as_str().unwrap()).unwrap();
        let raw = STANDARD_NO_PAD.decode(signature).unwrap();
        let public: [u8; 32] = public.try_into().unwrap();
        let raw: [u8; 64] = raw.try_into().unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&raw);
        key.verify_strict(&bytes, &signature).expect("local v1 signature");
        verified = true;
    }
    assert!(verified, "published server key did not sign the v1 invite: {event}");
}

#[tokio::test]
async fn ss_membership_send_knock_returns_state_array() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({
                "preset": "private_chat",
                "name": "Knock Room",
                "initial_state": [{"type": "m.room.join_rules", "state_key": "", "content": {"join_rule": "knock"}}]
            })),
            200,
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let knocker = "@knocker:remote.test";
    let made = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/make_knock/{}/{}?ver=12", enc(&room), enc(knocker)),
        None,
        200,
    )
    .await;
    assert_eq!(made["room_version"], "12");
    let template: Pdu = serde_json::from_value(made["event"].clone()).unwrap();
    let (knock_id, knock_body) = sign(&remote, template.clone());
    let knocked = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v1/send_knock/{}/{}", enc(&room), enc(&knock_id)),
        Some(knock_body),
        200,
    )
    .await;
    let state = knocked["knock_room_state"].as_array().expect("knock_room_state is an array");
    assert!(state.iter().any(|event| event["type"] == "m.room.create"), "{knocked}");
    assert!(
        state.iter().any(|event| event["type"] == "m.room.name" && event["content"]["name"] == "Knock Room"),
        "{knocked}"
    );
    let member = server.request(Method::GET, &member_path(&room, knocker), Some(token), None, 200).await;
    assert_eq!(member["membership"], "knock", "{member}");

    let mut joined = template.clone();
    joined.content["membership"] = json!("join");
    let (join_id, join_body) = sign(&remote, joined);
    let wrong = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v1/send_knock/{}/{}", enc(&room), enc(&join_id)),
        Some(join_body),
        400,
    )
    .await;
    assert_eq!(wrong["errcode"], "M_INVALID_PARAM", "{wrong}");

    let (_, mut forged) = sign(&remote, template);
    forged["signatures"][REMOTE][remote.key.key_id.as_str()] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let bad_sig = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v1/send_knock/{}/{}", enc(&room), enc(&knock_id)),
        Some(forged),
        400,
    )
    .await;
    assert_eq!(bad_sig["errcode"], "M_INVALID_PARAM", "{bad_sig}");

    let public = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let public_template: Pdu = serde_json::from_value(
        fed(
            &server,
            &remote,
            Method::GET,
            &format!("/_matrix/federation/v1/make_join/{}/{}?{}", enc(&public), enc(knocker), supported_ver_query()),
            None,
            200,
        )
        .await["event"]
        .clone(),
    )
    .unwrap();
    let mut public_knock = public_template;
    public_knock.content["membership"] = json!("knock");
    let (public_id, public_body) = sign(&remote, public_knock);
    let refused = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v1/send_knock/{}/{}", enc(&public), enc(&public_id)),
        Some(public_body),
        403,
    )
    .await;
    assert_eq!(refused["errcode"], "M_FORBIDDEN", "{refused}");

    let ancient = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({"preset": "public_chat", "room_version": "6"})),
            200,
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let incompatible = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v1/send_knock/{}/$unused", enc(&ancient)),
        Some(json!({})),
        400,
    )
    .await;
    assert_eq!(incompatible["errcode"], "M_INCOMPATIBLE_ROOM_VERSION", "{incompatible}");
}

#[tokio::test]
async fn ss_membership_v1_invite_keeps_v1_bytes() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let alice_id = alice["user_id"].as_str().unwrap();
    let token = alice["access_token"].as_str().unwrap();
    let event_id = "$v1invite:remote.test";
    let room = "!v1invite:remote.test";
    let sent = sign_v1(&remote, v1_member_event(room, "@r:remote.test", alice_id, event_id, "Kept"));
    let path = format!("/_matrix/federation/v1/invite/{}/{}", enc(room), enc(event_id));
    let response = fed(&server, &remote, Method::PUT, &path, Some(sent.clone()), 200).await;
    let event = &response["event"];
    let mut expected = sent.clone();
    expected["signatures"][LOCAL] = event["signatures"][LOCAL].clone();
    assert_eq!(event, &expected, "co-sign leaves every other field untouched");
    assert!(event["auth_events"][0].is_array(), "{event}");
    assert_eq!(event["event_id"], event_id);
    assert_eq!(event["content"]["displayname"], "Kept");
    assert_local_v1_signature(&server, event).await;
    let sync = server.request(Method::GET, "/_matrix/client/v3/sync", Some(token), None, 200).await;
    assert!(sync["rooms"]["invite"].get(room).is_some(), "{sync}");

    let wrapped = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v1/invite/{}/{}", enc("!wrapped:remote.test"), enc("$wrapped:remote.test")),
        Some(json!({"event": {"type": "m.room.member"}, "invite_room_state": [], "room_version": "11"})),
        400,
    )
    .await;
    assert_eq!(wrapped["errcode"], "M_INVALID_PARAM", "{wrapped}");

    let mut joined = v1_member_event(room, "@r:remote.test", alice_id, "$v1join:remote.test", "Kept");
    joined["content"]["membership"] = json!("join");
    let joined = sign_v1(&remote, joined);
    let rejected = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v1/invite/{}/{}", enc(room), enc("$v1join:remote.test")),
        Some(joined),
        400,
    )
    .await;
    assert_eq!(rejected["errcode"], "M_INVALID_PARAM", "{rejected}");

    let mut tampered = sent.clone();
    tampered["content"]["displayname"] = json!("Mallory");
    let hashed = fed(
        &server,
        &remote,
        Method::PUT,
        &path,
        Some(tampered),
        400,
    )
    .await;
    assert_eq!(hashed["errcode"], "M_INVALID_PARAM", "{hashed}");
}

#[tokio::test]
async fn ss_membership_send_leave_ends_membership() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let joiner = "@joiner:remote.test";
    federation_join(&server, &remote, REMOTE, &room, joiner).await;
    let leave_template: Pdu = serde_json::from_value(
        fed(
            &server,
            &remote,
            Method::GET,
            &format!("/_matrix/federation/v1/make_leave/{}/{}", enc(&room), enc(joiner)),
            None,
            200,
        )
        .await["event"]
        .clone(),
    )
    .unwrap();
    let (leave_id, leave_body) = sign(&remote, leave_template);
    let left = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v2/send_leave/{}/{}", enc(&room), enc(&leave_id)),
        Some(leave_body),
        200,
    )
    .await;
    assert_eq!(left, json!({}));
    let member = server.request(Method::GET, &member_path(&room, joiner), Some(token), None, 200).await;
    assert_eq!(member["membership"], "leave", "{member}");

    let guest = "@guest:remote.test";
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/invite", enc(&room)),
            Some(token),
            Some(json!({"user_id": guest})),
            200,
        )
        .await;
    let invited = server.request(Method::GET, &member_path(&room, guest), Some(token), None, 200).await;
    assert_eq!(invited["membership"], "invite", "{invited}");
    let reject_template: Pdu = serde_json::from_value(
        fed(
            &server,
            &remote,
            Method::GET,
            &format!("/_matrix/federation/v1/make_leave/{}/{}", enc(&room), enc(guest)),
            None,
            200,
        )
        .await["event"]
        .clone(),
    )
    .unwrap();
    let (reject_id, reject_body) = sign(&remote, reject_template);
    assert_eq!(
        fed(
            &server,
            &remote,
            Method::PUT,
            &format!("/_matrix/federation/v2/send_leave/{}/{}", enc(&room), enc(&reject_id)),
            Some(reject_body),
            200,
        )
        .await,
        json!({})
    );
    let rejected = server.request(Method::GET, &member_path(&room, guest), Some(token), None, 200).await;
    assert_eq!(rejected["membership"], "leave", "{rejected}");

    let stranger = "@stranger:remote.test";
    let missing = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/make_leave/{}/{}", enc(&room), enc(stranger)),
        None,
        403,
    )
    .await;
    assert_eq!(missing["errcode"], "M_FORBIDDEN", "{missing}");
    let (stranger_id, stranger_body) = sign(
        &remote,
        Pdu::new(
            &room,
            stranger,
            "m.room.member",
            Some(stranger.into()),
            json!({"membership": "leave"}),
            1_700_000_000_000,
            vec![],
            vec![],
            3,
        ),
    );
    let not_in_room = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v2/send_leave/{}/{}", enc(&room), enc(&stranger_id)),
        Some(stranger_body),
        403,
    )
    .await;
    assert_eq!(not_in_room["errcode"], "M_FORBIDDEN", "{not_in_room}");

    let join_template: Pdu = serde_json::from_value(
        fed(
            &server,
            &remote,
            Method::GET,
            &format!("/_matrix/federation/v1/make_join/{}/{}?{}", enc(&room), enc(joiner), supported_ver_query()),
            None,
            200,
        )
        .await["event"]
        .clone(),
    )
    .unwrap();
    let (rejoin_id, rejoin_body) = sign(&remote, join_template);
    let not_leave = fed(
        &server,
        &remote,
        Method::PUT,
        &format!("/_matrix/federation/v2/send_leave/{}/{}", enc(&room), enc(&rejoin_id)),
        Some(rejoin_body),
        400,
    )
    .await;
    assert_eq!(not_leave["errcode"], "M_INVALID_PARAM", "{not_leave}");
}

fn identity_signed(mxid: &str, token: &str, signer: &ed25519_dalek::SigningKey) -> Value {
    let unsigned = json!({"mxid": mxid, "token": token});
    let bytes = conduit::canonical_json::to_canonical_bytes(&unsigned).unwrap();
    use ed25519_dalek::Signer as _;
    let signature = STANDARD_NO_PAD.encode(signer.sign(&bytes).to_bytes());
    json!({"mxid": mxid, "token": token, "signatures": {"id.test": {"ed25519:0": signature}}})
}

/// An onbind invite for a room on another server is exchanged with the
/// inviting server. The homeserver still answers 200 when that exchange fails.
#[tokio::test]
async fn onbind_exchanges_a_remote_room_with_the_inviting_server() {
    use axum::extract::Path as AxPath;
    use tokio::sync::Mutex as AsyncMutex;

    let remote = spawn_remote().await;
    let seen = Arc::new(AsyncMutex::new(Vec::<Value>::new()));
    let recorded = seen.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/_matrix/key/v2/server",
            get({
                let doc = remote_key_document(&remote);
                move || {
                    let doc = doc.clone();
                    async move { Json(doc) }
                }
            }),
        )
        .route(
            "/_matrix/federation/v1/exchange_third_party_invite/:room_id",
            put(move |headers: HeaderMap, AxPath(room_id): AxPath<String>, Json(body): Json<Value>| {
                let seen = recorded.clone();
                async move {
                    let authed = headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                        .contains("X-Matrix");
                    seen.lock().await.push(json!({"room_id": room_id, "authed": authed, "body": body}));
                    if room_id.contains("down") {
                        return StatusCode::BAD_GATEWAY.into_response();
                    }
                    Json(json!({})).into_response()
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    let base = format!("http://{addr}");
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_REMOTE_KEYS_OVERRIDE", &base),
        ("CONDUIT_FEDERATION_BASE_URL", &base),
    ])
    .await;
    let alice = server.register("alice").await;
    let alice_id = alice["user_id"].as_str().unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]);
    let room = "!somewhere:remote.test";
    let sender = "@bob:remote.test";
    let onbind = |room_id: &str, address: &str| {
        let signed = identity_signed(alice_id, "abc123", &signer);
        json!({
            "medium": "email",
            "address": address,
            "mxid": alice_id,
            "invites": [{
                "medium": "email",
                "address": address,
                "mxid": alice_id,
                "room_id": room_id,
                "sender": sender,
                "signed": signed,
            }],
        })
    };
    let accepted = server
        .request(Method::PUT, "/_matrix/federation/v1/3pid/onbind", None, Some(onbind(room, "carol@example.org")), 200)
        .await;
    assert_eq!(accepted, json!({}));
    let calls = seen.lock().await.clone();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0]["authed"], true, "{calls:?}");
    assert_eq!(calls[0]["room_id"], room, "{calls:?}");
    let body = &calls[0]["body"];
    assert_eq!(body["type"], "m.room.member");
    assert_eq!(body["room_id"], room);
    assert_eq!(body["sender"], sender);
    assert_eq!(body["state_key"], alice_id);
    assert_eq!(body["content"]["membership"], "invite");
    assert_eq!(body["content"]["third_party_invite"]["display_name"], "carol@example.org");
    assert_eq!(body["content"]["third_party_invite"]["signed"]["token"], "abc123");
    assert_eq!(body["content"]["third_party_invite"]["signed"]["mxid"], alice_id);

    let failed = server
        .request(
            Method::PUT,
            "/_matrix/federation/v1/3pid/onbind",
            None,
            Some(onbind("!down:remote.test", "carol@example.org")),
            200,
        )
        .await;
    assert_eq!(failed, json!({}), "a failed exchange still completes the notification");
    assert_eq!(seen.lock().await.len(), 2);

    server
        .request(
            Method::PUT,
            "/_matrix/federation/v1/3pid/onbind",
            None,
            Some(onbind(&format!("!here:{LOCAL}"), "carol@example.org")),
            200,
        )
        .await;
    assert_eq!(seen.lock().await.len(), 2, "a room on this server is not exchanged remotely");
}

#[tokio::test]
async fn ss_membership_exchange_third_party_invite_issues_invite() {
    use axum::extract::Path as AxPath;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let remote = spawn_remote().await;
    let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
    let recorded = seen.clone();
    let invitee_key = remote.key.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let invitee_addr = listener.local_addr().unwrap();
    let invitee = Router::new()
        .route(
            "/_matrix/key/v2/server",
            get({
                let remote = remote_key_document(&remote);
                move || {
                    let remote = remote.clone();
                    async move { Json(remote) }
                }
            }),
        )
        .route(
            "/_matrix/federation/v2/invite/:room_id/:event_id",
            put(move |AxPath((_, event_id)): AxPath<(String, String)>, Json(body): Json<Value>| {
                let seen = recorded.clone();
                let key = invitee_key.clone();
                async move {
                    if body["event"]["content"]["third_party_invite"]["signed"]["token"] == "down" {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    let mut pdu: Pdu = serde_json::from_value(body["event"].clone()).unwrap();
                    conduit::signing::add_signature(&mut pdu, &key, REMOTE).unwrap();
                    seen.lock().await.push(json!({"path_event_id": event_id, "body": body, "event": pdu}));
                    Json(json!({"event": pdu})).into_response()
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, invitee).await.ok() });

    let identity = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let identity_addr = identity.local_addr().unwrap();
    let identity_app = Router::new()
        .route("/_matrix/identity/v2/pubkey/isvalid", get(|| async { Json(json!({"valid": true})) }))
        .route("/_matrix/identity/v2/pubkey/notvalid", get(|| async { Json(json!({"valid": false})) }));
    tokio::spawn(async move { axum::serve(identity, identity_app).await.ok() });
    let valid_url = format!("http://{identity_addr}/_matrix/identity/v2/pubkey/isvalid");
    let invalid_url = format!("http://{identity_addr}/_matrix/identity/v2/pubkey/notvalid");
    let base = format!("http://{invitee_addr}");

    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_REMOTE_KEYS_OVERRIDE", &base),
        ("CONDUIT_FEDERATION_BASE_URL", &base),
        ("CONDUIT_IS_INSECURE_HTTP", "1"),
        ("CONDUIT_IS_ALLOW_CIDRS", "127.0.0.0/8"),
    ])
    .await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let alice_id = alice["user_id"].as_str().unwrap();
    let bob = server.register("bob").await;
    let bob_id = bob["user_id"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "private_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let public = STANDARD_NO_PAD.encode(signer.verifying_key().to_bytes());
    let put_invite = |token_name: &str, url: &str| {
        let room = room.clone();
        let token = token.to_owned();
        let public = public.clone();
        let url = url.to_owned();
        let token_name = token_name.to_owned();
        let server = &server;
        async move {
            server
                .request(
                    Method::PUT,
                    &format!("/_matrix/client/v3/rooms/{}/state/m.room.third_party_invite/{token_name}", enc(&room)),
                    Some(&token),
                    Some(json!({
                        "display_name": "Carol",
                        "public_key": public,
                        "key_validity_url": url,
                        "public_keys": [{"public_key": public, "key_validity_url": url}],
                    })),
                    200,
                )
                .await
        }
    };
    put_invite("tok", &valid_url).await;
    put_invite("bad", &invalid_url).await;
    put_invite("down", &valid_url).await;

    let carol = "@carol:remote.test";
    let exchange = |sender: &str, mxid: &str, signed: Value, status: u16| {
        let sender = sender.to_owned();
        let mxid = mxid.to_owned();
        let room = room.clone();
        let server = &server;
        let remote = &remote;
        async move {
            fed(
                server,
                remote,
                Method::PUT,
                &format!("/_matrix/federation/v1/exchange_third_party_invite/{}", enc(&room)),
                Some(json!({
                    "type": "m.room.member",
                    "room_id": room,
                    "sender": sender,
                    "state_key": mxid,
                    "content": {
                        "membership": "invite",
                        "third_party_invite": {"display_name": "Carol", "signed": signed},
                    },
                })),
                status,
            )
            .await
        }
    };

    let unknown = exchange(alice_id, carol, identity_signed(carol, "missing", &signer), 404).await;
    assert_eq!(unknown["errcode"], "M_NOT_FOUND", "{unknown}");
    let mismatch = exchange(bob_id, carol, identity_signed(carol, "tok", &signer), 403).await;
    assert_eq!(mismatch["errcode"], "M_FORBIDDEN", "{mismatch}");
    let invalid = exchange(alice_id, carol, identity_signed(carol, "bad", &signer), 403).await;
    assert_eq!(invalid["errcode"], "M_FORBIDDEN", "{invalid}");
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let forged = exchange(alice_id, carol, identity_signed(carol, "tok", &other), 403).await;
    assert_eq!(forged["errcode"], "M_FORBIDDEN", "{forged}");
    let down = exchange(alice_id, "@down:remote.test", identity_signed("@down:remote.test", "down", &signer), 502).await;
    assert_eq!(down["errcode"], "M_UNKNOWN", "{down}");
    assert!(seen.lock().await.is_empty(), "a rejected exchange must not be stored from a failed invite");
    server.request(Method::GET, &member_path(&room, carol), Some(token), None, 404).await;
    server.request(Method::GET, &member_path(&room, "@down:remote.test"), Some(token), None, 404).await;

    let accepted = exchange(alice_id, carol, identity_signed(carol, "tok", &signer), 200).await;
    assert_eq!(accepted, json!({}));
    let calls = seen.lock().await.clone();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0]["body"]["room_version"], "12", "{calls:?}");
    let stripped = calls[0]["body"]["invite_room_state"].as_array().unwrap();
    assert!(stripped.iter().any(|event| event["type"] == "m.room.create"), "{calls:?}");
    assert_eq!(calls[0]["body"]["event"]["state_key"], carol);
    let event_id = calls[0]["path_event_id"].as_str().unwrap();
    let served = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(event_id)),
        None,
        200,
    )
    .await;
    let pdu = &served["pdus"][0];
    assert_eq!(pdu["content"]["membership"], "invite", "{pdu}");
    assert!(pdu["signatures"][LOCAL].is_object(), "{pdu}");
    assert!(pdu["signatures"][REMOTE].is_object(), "{pdu}");
    let stored = server.request(Method::GET, &member_path(&room, carol), Some(token), None, 200).await;
    assert_eq!(stored["membership"], "invite", "{stored}");
}

#[tokio::test]
async fn auth_event_selection_rejects_and_current_state_soft_fails() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({"preset": "public_chat"})),
            200,
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let joiner = "@r:remote.test";
    federation_join(&server, &remote, REMOTE, &room, joiner).await;

    let state = server
        .request(Method::GET, &format!("/_matrix/client/v3/rooms/{}/state", enc(&room)), Some(token), None, 200)
        .await;
    let mut create_id = String::new();
    let mut power_id = String::new();
    let mut join_id = String::new();
    for event in state.as_array().unwrap() {
        match event["type"].as_str() {
            Some("m.room.create") => create_id = event["event_id"].as_str().unwrap().to_owned(),
            Some("m.room.power_levels") => power_id = event["event_id"].as_str().unwrap().to_owned(),
            Some("m.room.member") if event["state_key"] == joiner => {
                join_id = event["event_id"].as_str().unwrap().to_owned();
            }
            _ => {}
        }
    }
    assert!(!create_id.is_empty() && !power_id.is_empty() && !join_id.is_empty(), "{state}");

    let (bad_id, bad) = sign(
        &remote,
        Pdu::new(
            &room,
            joiner,
            "m.room.message",
            None,
            json!({"msgtype": "m.text", "body": "wrong auth set"}),
            1_700_000_000_100,
            vec![power_id.clone(), join_id.clone(), "$not-selected".into()],
            vec![join_id.clone()],
            20,
        ),
    );
    let rejected = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/auth-select-1",
        Some(txn(vec![bad], vec![])),
        200,
    )
    .await;
    assert_eq!(rejected["pdus"][&bad_id]["error"], "auth check failed", "{rejected}");
    let missing = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&bad_id)),
        None,
        404,
    )
    .await;
    assert_eq!(missing["errcode"], "M_NOT_FOUND", "{missing}");

    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/ban", enc(&room)),
            Some(token),
            Some(json!({"user_id": joiner})),
            200,
        )
        .await;
    let (soft_id, soft) = sign(
        &remote,
        Pdu::new(
            &room,
            joiner,
            "m.room.message",
            None,
            json!({"msgtype": "m.text", "body": "sent before the ban arrived"}),
            1_700_000_000_200,
            vec![power_id, join_id.clone()],
            vec![join_id.clone()],
            21,
        ),
    );
    let accepted = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/soft-fail-1",
        Some(txn(vec![soft], vec![])),
        200,
    )
    .await;
    assert_eq!(accepted["pdus"][&soft_id], json!({}), "{accepted}");
    let served = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&soft_id)),
        None,
        200,
    )
    .await;
    assert_eq!(served["pdus"][0]["event_id"].as_str().unwrap_or(&soft_id), &soft_id);
    assert_eq!(served["pdus"][0]["content"]["body"], "sent before the ban arrived", "{served}");

    let sync = server.request(Method::GET, "/_matrix/client/v3/sync", Some(token), None, 200).await;
    let timeline = &sync["rooms"]["join"][&room]["timeline"]["events"];
    let bodies: Vec<&str> = timeline
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["content"]["body"].as_str())
        .collect();
    assert!(!bodies.contains(&"wrong auth set"), "{timeline}");
    assert!(!bodies.contains(&"sent before the ban arrived"), "{timeline}");

    let after = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/after-soft", enc(&room)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": "still here"})),
            200,
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let after_pdu = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&after)),
        None,
        200,
    )
    .await;
    let prevs = after_pdu["pdus"][0]["prev_events"].as_array().unwrap();
    assert!(
        prevs.iter().all(|id| id != &json!(soft_id) && id != &json!(bad_id)),
        "rejected and soft-failed events are not prev_events: {after_pdu}"
    );
}

/// A PDU whose auth event is not stored is fetched together with the events
/// that auth event cites. An event in that chain which fails the auth rules
/// is not stored, and the PDU is rejected.
#[tokio::test]
async fn fetched_auth_chain_that_fails_auth_is_not_stored() {
    let remote = spawn_remote().await;
    let events = Arc::new(std::sync::Mutex::new(HashMap::<String, Value>::new()));
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let events_route = Arc::clone(&events);
    let seen_route = Arc::clone(&seen);
    let app = Router::new().route("/_matrix/federation/v1/event/:event_id", get(move |Path(event_id): Path<String>| {
        let events_route = Arc::clone(&events_route);
        let seen_route = Arc::clone(&seen_route);
        async move {
            seen_route.lock().unwrap().push(event_id.clone());
            match events_route.lock().unwrap().get(&event_id).cloned() {
                Some(pdu) => Json(json!({"pdus": [pdu]})).into_response(),
                None => (StatusCode::NOT_FOUND, Json(json!({"errcode": "M_NOT_FOUND", "error": "Event not found"}))).into_response(),
            }
        }
    }));
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    let base_url = format!("http://{addr}");
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_REMOTE_KEYS_OVERRIDE", &remote.keys_url),
        ("CONDUIT_FEDERATION_BASE_URL", &base_url),
    ])
    .await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat", "room_version": "12"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let state = server
        .request(Method::GET, &format!("/_matrix/client/v3/rooms/{}/state", enc(&room)), Some(token), None, 200)
        .await;
    let mut create_id = String::new();
    let mut power_id = String::new();
    for event in state.as_array().unwrap() {
        match event["type"].as_str() {
            Some("m.room.create") => create_id = event["event_id"].as_str().unwrap().to_owned(),
            Some("m.room.power_levels") => power_id = event["event_id"].as_str().unwrap().to_owned(),
            _ => {}
        }
    }
    assert!(!create_id.is_empty() && !power_id.is_empty(), "{state}");

    let (member_id, member) = sign(
        &remote,
        Pdu::new(
            &room,
            "@evil:remote.test",
            "m.room.member",
            Some("@evil:remote.test".into()),
            json!({"membership": "join"}),
            1_700_000_004_000,
            vec![create_id, power_id],
            vec![],
            30,
        ),
    );
    let (power_bad_id, power_bad) = sign(
        &remote,
        Pdu::new(
            &room,
            "@evil:remote.test",
            "m.room.power_levels",
            Some(String::new()),
            json!({"users": {"@evil:remote.test": 100}}),
            1_700_000_004_100,
            vec![member_id.clone()],
            vec![],
            31,
        ),
    );
    events.lock().unwrap().insert(member_id.clone(), member);
    events.lock().unwrap().insert(power_bad_id.clone(), power_bad);
    let (message_id, message) = sign(
        &remote,
        Pdu::new(
            &room,
            "@evil:remote.test",
            "m.room.message",
            None,
            json!({"msgtype": "m.text", "body": "via a bad auth chain"}),
            1_700_000_004_200,
            vec![power_bad_id.clone()],
            vec![],
            32,
        ),
    );
    let result = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/auth-chain-1",
        Some(txn(vec![message], vec![])),
        200,
    )
    .await;
    assert_eq!(result["pdus"][&message_id]["error"], "auth check failed", "{result}");
    let fetched = seen.lock().unwrap().clone();
    assert!(fetched.iter().any(|id| id == &power_bad_id), "the cited auth event was fetched: {fetched:?}");
    assert!(fetched.iter().any(|id| id == &member_id), "the auth event of that auth event was fetched: {fetched:?}");
    for id in [&member_id, &power_bad_id, &message_id] {
        let missing = fed(&server, &remote, Method::GET, &format!("/_matrix/federation/v1/event/{}", enc(id)), None, 404).await;
        assert_eq!(missing["errcode"], "M_NOT_FOUND", "{id}: {missing}");
    }
}

fn event_texts(value: &Value, field: &str) -> Vec<String> {
    value[field]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|pdu| {
            pdu["content"]["topic"]
                .as_str()
                .or_else(|| pdu["content"]["body"].as_str())
                .map(str::to_owned)
        })
        .collect()
}

/// A topic that fails current-state auth is stored and served by GET /event,
/// but backfill and get_missing_events omit it unless a named event lists it.
/// After a later event is resolved with the sender's power restored, /sync
/// state carries the topic.
#[tokio::test]
async fn soft_failed_topic_is_omitted_until_referenced_and_syncs_when_selected() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({"preset": "public_chat"})),
            200,
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let joiner = "@r:remote.test";
    let other = "@r2:remote.test";
    federation_join(&server, &remote, REMOTE, &room, joiner).await;
    federation_join(&server, &remote, REMOTE, &room, other).await;

    let state = server
        .request(Method::GET, &format!("/_matrix/client/v3/rooms/{}/state", enc(&room)), Some(token), None, 200)
        .await;
    let event_id_of = |kind: &str, key: &str| {
        state
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["type"] == kind && event["state_key"] == key)
            .unwrap_or_else(|| panic!("missing {kind} {key} in {state}"))["event_id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let join_id = event_id_of("m.room.member", joiner);
    let other_id = event_id_of("m.room.member", other);

    let power_path = format!("/_matrix/client/v3/rooms/{}/state/m.room.power_levels", enc(&room));
    let mut levels = server.request(Method::GET, &power_path, Some(token), None, 200).await;
    levels["users"][joiner] = json!(100);
    let high_id = server
        .request(Method::PUT, &power_path, Some(token), Some(levels), 200)
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut levels = server.request(Method::GET, &power_path, Some(token), None, 200).await;
    levels["users"][joiner] = json!(0);
    let low_id = server
        .request(Method::PUT, &power_path, Some(token), Some(levels), 200)
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let now = chrono::Utc::now().timestamp_millis() as u64;
    let (topic_id, topic) = sign(
        &remote,
        Pdu::new(
            &room,
            joiner,
            "m.room.topic",
            Some(String::new()),
            json!({"topic": "fork"}),
            now,
            vec![high_id.clone(), join_id.clone()],
            vec![join_id.clone(), high_id.clone()],
            40,
        ),
    );
    let accepted = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/soft-topic-1",
        Some(txn(vec![topic], vec![])),
        200,
    )
    .await;
    assert_eq!(accepted["pdus"][&topic_id], json!({}), "topic soft-fails against the lowered power: {accepted}");
    let served = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/event/{}", enc(&topic_id)),
        None,
        200,
    )
    .await;
    assert_eq!(served["pdus"][0]["content"]["topic"], "fork", "{served}");

    let (linker_id, linker) = sign(
        &remote,
        Pdu::new(
            &room,
            other,
            "m.room.message",
            None,
            json!({"msgtype": "m.text", "body": "linker"}),
            now + 1,
            vec![low_id.clone(), other_id.clone()],
            vec![low_id.clone(), topic_id.clone()],
            500,
        ),
    );
    let linked = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/soft-topic-link",
        Some(txn(vec![linker], vec![])),
        200,
    )
    .await;
    assert_eq!(linked["pdus"][&linker_id], json!({}), "linker passes current auth and keeps the topic soft-failed: {linked}");

    let mainline = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/soft-topic-main", enc(&room)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": "mainline"})),
            200,
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let backfill = |event_id: &str| format!("/_matrix/federation/v1/backfill/{}?limit=50&v={}", enc(&room), enc(event_id));
    let from_main = event_texts(
        &fed(&server, &remote, Method::GET, &backfill(&mainline), None, 200).await,
        "pdus",
    );
    assert!(
        !from_main.iter().any(|text| text == "fork"),
        "backfill from an event that does not list the topic omits it: {from_main:?}"
    );
    assert!(
        from_main.iter().any(|text| text == "linker"),
        "the walk still returns the event that cites the topic: {from_main:?}"
    );
    let from_linker = event_texts(
        &fed(&server, &remote, Method::GET, &backfill(&linker_id), None, 200).await,
        "pdus",
    );
    assert!(
        from_linker.iter().any(|text| text == "fork"),
        "backfill includes the topic when v lists it: {from_linker:?}"
    );
    let from_topic = event_texts(
        &fed(&server, &remote, Method::GET, &backfill(&topic_id), None, 200).await,
        "pdus",
    );
    assert!(
        !from_topic.iter().any(|text| text == "fork"),
        "naming the soft-failed event itself is not a reference: {from_topic:?}"
    );

    let missing = format!("/_matrix/federation/v1/get_missing_events/{}", enc(&room));
    let missing_of = |latest: &str| json!({"earliest_events": [], "latest_events": [latest], "limit": 20});
    let missing_main = event_texts(
        &fed(&server, &remote, Method::POST, &missing, Some(missing_of(&mainline)), 200).await,
        "events",
    );
    assert!(
        !missing_main.iter().any(|text| text == "fork"),
        "get_missing_events omits an unreferenced soft-failed topic: {missing_main:?}"
    );
    let missing_linker = event_texts(
        &fed(&server, &remote, Method::POST, &missing, Some(missing_of(&linker_id)), 200).await,
        "events",
    );
    assert!(
        missing_linker.iter().any(|text| text == "fork"),
        "get_missing_events returns the topic when latest_events lists it: {missing_linker:?}"
    );

    let topics = |sync: &Value| -> Vec<String> {
        let room_sync = &sync["rooms"]["join"][&room];
        ["state", "timeline"]
            .into_iter()
            .flat_map(|section| {
                room_sync[section]["events"]
                    .as_array()
                    .map(|events| events.iter())
                    .into_iter()
                    .flatten()
                    .filter(|event| event["type"] == "m.room.topic")
                    .filter_map(|event| event["content"]["topic"].as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let before = server.request(Method::GET, "/_matrix/client/v3/sync", Some(token), None, 200).await;
    let before_topics = topics(&before);
    assert!(
        !before_topics.iter().any(|topic| topic == "fork"),
        "clients are not told about the topic while power still rejects it: {before_topics:?}"
    );

    let mut levels = server.request(Method::GET, &power_path, Some(token), None, 200).await;
    levels["users"][joiner] = json!(100);
    let restored = server
        .request(Method::PUT, &power_path, Some(token), Some(levels), 200)
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (after_id, after) = sign(
        &remote,
        Pdu::new(
            &room,
            other,
            "m.room.message",
            None,
            json!({"msgtype": "m.text", "body": "after"}),
            now + 2,
            vec![restored.clone(), other_id],
            vec![restored, topic_id.clone()],
            600,
        ),
    );
    let selected = fed(
        &server,
        &remote,
        Method::PUT,
        "/_matrix/federation/v1/send/soft-topic-select",
        Some(txn(vec![after], vec![])),
        200,
    )
    .await;
    assert_eq!(selected["pdus"][&after_id], json!({}), "the referencing event is accepted: {selected}");

    let after_sync = server.request(Method::GET, "/_matrix/client/v3/sync", Some(token), None, 200).await;
    let after_topics = topics(&after_sync);
    assert!(
        after_topics.iter().any(|topic| topic == "fork"),
        "sync state includes the topic once resolution selects it: {after_topics:?} {}",
        after_sync["rooms"]["join"][&room]
    );
}

/// `GET /query/{queryType}` serves profile and directory, and rejects any
/// other type. A missing signature is unauthorized.
#[tokio::test]
async fn generic_query_serves_known_types_and_rejects_unknown() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let alice_id = alice["user_id"].as_str().unwrap().to_owned();
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/profile/{}/displayname", enc(&alice_id)),
            Some(token),
            Some(json!({"displayname": "Alice"})),
            200,
        )
        .await;
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let alias = format!("#lobby:{LOCAL}");
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/directory/room/{}", enc(&alias)),
            Some(token),
            Some(json!({"room_id": room})),
            200,
        )
        .await;

    let unknown = fed(&server, &remote, Method::GET, "/_matrix/federation/v1/query/not-a-type", None, 404).await;
    assert_eq!(unknown["errcode"], "M_UNRECOGNIZED", "{unknown}");

    let unsigned = server
        .http
        .get(format!("{}/_matrix/federation/v1/query/not-a-type", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(unsigned.status().as_u16(), 401);
    let unsigned_body: Value = unsigned.json().await.unwrap();
    assert_eq!(unsigned_body["errcode"], "M_UNAUTHORIZED", "{unsigned_body}");

    let profile_path = format!("/_matrix/federation/v1/query/profile?user_id={}", enc(&alice_id));
    let profile = fed(&server, &remote, Method::GET, &profile_path, None, 200).await;
    assert_eq!(profile["displayname"], "Alice");
    let field_path = format!("{profile_path}&field=displayname");
    let field = fed(&server, &remote, Method::GET, &field_path, None, 200).await;
    assert_eq!(field, json!({"displayname": "Alice"}));
    let foreign = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/query/profile?user_id={}", enc("@ghost:remote.test")),
        None,
        404,
    )
    .await;
    assert_eq!(foreign["errcode"], "M_NOT_FOUND", "{foreign}");

    let directory = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/query/directory?room_alias={}", enc(&alias)),
        None,
        200,
    )
    .await;
    assert_eq!(directory["room_id"], room);
    assert_eq!(directory["servers"], json!([LOCAL]));
    let missing_alias = fed(
        &server,
        &remote,
        Method::GET,
        &format!("/_matrix/federation/v1/query/directory?room_alias={}", enc("#missing:production.test")),
        None,
        404,
    )
    .await;
    assert_eq!(missing_alias["errcode"], "M_NOT_FOUND", "{missing_alias}");

    let post_path = "/_matrix/federation/v1/query/not-a-type";
    let auth = sign_request("POST", post_path, REMOTE, LOCAL, None::<&Value>, &remote.key);
    let posted = server
        .http
        .post(format!("{}{post_path}", server.base_url))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status().as_u16(), 405);
    let allow = posted.headers().get("allow").and_then(|value| value.to_str().ok()).unwrap_or("");
    assert!(allow.contains("GET"), "405 keeps Allow, got {allow:?}");
    let posted_body: Value = posted.json().await.unwrap();
    assert_eq!(posted_body["errcode"], "M_UNRECOGNIZED", "{posted_body}");
}

/// Federation timestamp search returns the closest event in the requested
/// direction. An equal distance keeps the lower depth. `ts` and `dir` are
/// required. A side with no event is 404.
#[tokio::test]
async fn timestamp_to_event_picks_the_closest_event_in_each_direction() {
    let remote = spawn_remote().await;
    let server = federated_server(&remote).await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "public_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let joiner = "@r:remote.test";
    federation_join(&server, &remote, REMOTE, &room, joiner).await;
    let state = server
        .request(Method::GET, &format!("/_matrix/client/v3/rooms/{}/state", enc(&room)), Some(token), None, 200)
        .await;
    let mut power_id = String::new();
    let mut join_id = String::new();
    for event in state.as_array().unwrap() {
        match event["type"].as_str() {
            Some("m.room.power_levels") => power_id = event["event_id"].as_str().unwrap().to_owned(),
            Some("m.room.member") if event["state_key"] == joiner => {
                join_id = event["event_id"].as_str().unwrap().to_owned();
            }
            _ => {}
        }
    }
    assert!(!power_id.is_empty() && !join_id.is_empty(), "{state}");

    let mut prev = join_id.clone();
    let mut send_at = |ts: u64, depth: i64, txn_id: &'static str| {
        let (id, pdu) = sign(
            &remote,
            Pdu::new(
                &room,
                joiner,
                "m.room.message",
                None,
                json!({"msgtype": "m.text", "body": txn_id}),
                ts,
                vec![power_id.clone(), join_id.clone()],
                vec![prev.clone()],
                depth,
            ),
        );
        prev = id.clone();
        (id, pdu, txn_id)
    };
    let (early_id, early, early_txn) = send_at(1_000, 40, "early");
    let (near_id, near, near_txn) = send_at(5_000, 41, "near");
    let (tied_id, tied, tied_txn) = send_at(5_000, 42, "tied");
    for (pdu, txn_id) in [(early, early_txn), (near, near_txn), (tied, tied_txn)] {
        let result = fed(
            &server,
            &remote,
            Method::PUT,
            &format!("/_matrix/federation/v1/send/{txn_id}"),
            Some(txn(vec![pdu], vec![])),
            200,
        )
        .await;
        assert!(
            result["pdus"].as_object().unwrap().values().all(|value| value == &json!({})),
            "{txn_id}: {result}"
        );
    }

    let ask = |query: &str, status: u16| {
        let path = format!("/_matrix/federation/v1/timestamp_to_event/{}?{query}", enc(&room));
        let server = &server;
        let remote = &remote;
        async move { fed(server, remote, Method::GET, &path, None, status).await }
    };
    let found = ask("ts=1000&dir=f", 200).await;
    assert_eq!(found["event_id"], early_id, "{found}");
    assert_eq!(found["origin_server_ts"], 1000, "{found}");
    let backward = ask("ts=3000&dir=b", 200).await;
    assert_eq!(backward["event_id"], early_id, "{backward}");
    assert_eq!(backward["origin_server_ts"], 1000, "{backward}");
    let forward = ask("ts=3000&dir=f", 200).await;
    assert_eq!(forward["event_id"], near_id, "{forward}");
    assert_eq!(forward["origin_server_ts"], 5000, "{forward}");
    let tie = ask("ts=5000&dir=b", 200).await;
    assert_eq!(tie["event_id"], near_id, "lower depth wins an equal timestamp: {tie} vs {tied_id}");
    assert_eq!(tie["origin_server_ts"], 5000, "{tie}");

    assert_eq!(ask("ts=50&dir=b", 404).await["errcode"], "M_NOT_FOUND");
    assert_eq!(ask("ts=32503680000000&dir=f", 404).await["errcode"], "M_NOT_FOUND");
    assert_eq!(ask("dir=f", 400).await["errcode"], "M_INVALID_PARAM");
    assert_eq!(ask("ts=1000", 400).await["errcode"], "M_INVALID_PARAM");
    assert_eq!(ask("ts=1000&dir=z", 400).await["errcode"], "M_INVALID_PARAM");
    let unknown = fed(
        &server,
        &remote,
        Method::GET,
        "/_matrix/federation/v1/timestamp_to_event/!missing:remote.test?ts=1000&dir=f",
        None,
        404,
    )
    .await;
    assert_eq!(unknown["errcode"], "M_NOT_FOUND", "{unknown}");

    let unsigned = server
        .http
        .get(format!(
            "{}/_matrix/federation/v1/timestamp_to_event/{}?ts=1000&dir=f",
            server.base_url,
            enc(&room)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unsigned.status().as_u16(), 401);
}

fn remote_key_document(remote: &Remote) -> Value {
    let unsigned = json!({
        "server_name": REMOTE,
        "verify_keys": { remote.key.key_id.clone(): { "key": STANDARD_NO_PAD.encode(public_bytes(&remote.key)) } },
        "old_verify_keys": {},
        "valid_until_ts": chrono::Utc::now().timestamp_millis() + 3_600_000,
    });
    use ed25519_dalek::Signer as _;
    let signature = remote.key.signing_key.sign(&conduit::canonical_json::to_canonical_bytes(&unsigned).unwrap());
    let mut document = unsigned;
    document["signatures"] = json!({ REMOTE: { remote.key.key_id.clone(): STANDARD_NO_PAD.encode(signature.to_bytes()) } });
    document
}
