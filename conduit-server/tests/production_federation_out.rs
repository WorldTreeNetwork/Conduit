//! Outbound federation of room events and membership.
//!
//! Each test fails when the homeserver skips the federation call: the mock
//! records the request, and the stored room is the event that call produced.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Json, Path};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::Router;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use common::production::Server;
use conduit::event::{Event, Pdu};
use conduit::keys::{generate_server_key, public_bytes, ServerKey};
use conduit::signing::{add_signature, sign_authored};
use conduit::storage::Storage;
use ed25519_dalek::Signer as _;
use reqwest::Method;
use serde_json::{json, Value};

const PEER: &str = "peer.test";

fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn key_document(key: &ServerKey) -> Value {
    let mut document = json!({
        "server_name": PEER,
        "verify_keys": { &key.key_id: { "key": STANDARD_NO_PAD.encode(public_bytes(key)) } },
        "old_verify_keys": {},
        "valid_until_ts": chrono::Utc::now().timestamp_millis() + 86_400_000,
    });
    let canonical = conduit::canonical_json::to_canonical_bytes(&document).unwrap();
    let signature = STANDARD_NO_PAD.encode(key.signing_key.sign(&canonical).to_bytes());
    document["signatures"] = json!({ PEER: { &key.key_id: signature } });
    document
}

async fn serve(key: Arc<ServerKey>, routes: Router) -> String {
    let document = key_document(&key);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let app = routes.route("/_matrix/key/v2/server", get(move || {
            let document = document.clone();
            async move { Json(document) }
        }));
        axum::serve(listener, app).await.ok();
    });
    url
}

fn push_hit(hits: &Arc<Mutex<Vec<String>>>, name: &str) {
    hits.lock().unwrap().push(name.to_owned());
}

async fn wait_for_pdu(bodies: &Arc<Mutex<Vec<Value>>>, alice_id: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Some(found) = bodies.lock().unwrap().iter().find(|body| {
                body["pdus"].as_array().is_some_and(|pdus| {
                    pdus.iter().any(|pdu| {
                        pdu["type"] == "m.room.message" && pdu["sender"] == alice_id && pdu["content"]["body"] == "federate me"
                    })
                })
            }) {
                return found.clone();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("federation /send never carried the room event")
}

#[tokio::test]
async fn authored_room_events_are_sent_to_joined_servers() {
    let bodies = Arc::new(Mutex::new(Vec::<Value>::new()));
    let bodies_route = Arc::clone(&bodies);
    let url = serve(
        Arc::new(generate_server_key()),
        Router::new().route(
            "/_matrix/federation/v1/send/:txn",
            put(move |Json(body): Json<Value>| {
                let bodies = Arc::clone(&bodies_route);
                async move {
                    bodies.lock().unwrap().push(body);
                    Json(json!({ "pdus": {} }))
                }
            }),
        ),
    )
    .await;
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_FEDERATION_BASE_URL", url.as_str()),
    ])
    .await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let alice_id = alice["user_id"].as_str().unwrap().to_owned();
    let created = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "private_chat"})), 200)
        .await;
    let room = created["room_id"].as_str().unwrap().to_owned();
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let storage = conduit_server::PostgresStorage::new(pool);
    let member = "@erin:peer.test";
    let event = Event::new(
        "$member-join-erin-peer-test",
        Pdu::new(
            &room,
            member,
            "m.room.member",
            Some(member.to_owned()),
            json!({ "membership": "join" }),
            1_700_000_000_000,
            vec![],
            vec![],
            40,
        ),
    );
    storage.put_event(&event).await.unwrap();
    storage.set_state_entry(&room, "m.room.member", member, &event.event_id).await.unwrap();

    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/txn-federate", enc(&room)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": "federate me"})),
            200,
        )
        .await;
    let sent = wait_for_pdu(&bodies, &alice_id).await;
    let pdus = sent["pdus"].as_array().expect("pdus array");
    assert!(
        pdus.iter().any(|pdu| pdu["type"] == "m.room.message" && pdu["content"]["body"] == "federate me"),
        "PUT /send carried no room PDU: {sent}"
    );
}

fn signed_create(key: &ServerKey, room_id: &str) -> (String, Value) {
    let mut create = Pdu::new(
        room_id,
        "@erin:peer.test",
        "m.room.create",
        Some(String::new()),
        json!({"room_version": "11", "creator": "@erin:peer.test"}),
        1_700_000_000_000,
        vec![],
        vec![],
        1,
    );
    sign_authored(&mut create, key, PEER).unwrap();
    let event_id = conduit::hashing::event_id(&create).unwrap();
    (event_id, serde_json::to_value(&create).unwrap())
}

#[tokio::test]
async fn remote_join_uses_make_join_and_stores_returned_state() {
    let room = "!outjoin:peer.test";
    let key = Arc::new(generate_server_key());
    let (create_id, create_pdu) = signed_create(&key, room);
    let hits = Arc::new(Mutex::new(Vec::<String>::new()));
    let make_hits = Arc::clone(&hits);
    let send_hits = Arc::clone(&hits);
    let create_for_make = create_id.clone();
    let create_for_send = create_pdu.clone();
    let url = serve(
        Arc::clone(&key),
        Router::new()
            .route(
                "/_matrix/federation/v1/make_join/:room_id/:user_id",
                get(move |Path((room_id, user_id)): Path<(String, String)>| {
                    let hits = Arc::clone(&make_hits);
                    let create_id = create_for_make.clone();
                    async move {
                        push_hit(&hits, "make_join");
                        Json(json!({
                            "room_version": "11",
                            "event": {
                                "type": "m.room.member",
                                "room_id": room_id,
                                "sender": user_id,
                                "state_key": user_id,
                                "content": { "membership": "join" },
                                "auth_events": [create_id],
                                "prev_events": [create_id],
                                "depth": 2,
                                "origin_server_ts": 1_700_000_000_000u64
                            }
                        }))
                    }
                }),
            )
            .route(
                "/_matrix/federation/v2/send_join/:room_id/:event_id",
                put(move |Json(_body): Json<Value>| {
                    let hits = Arc::clone(&send_hits);
                    let create = create_for_send.clone();
                    async move {
                        push_hit(&hits, "send_join");
                        Json(json!({ "state": [create.clone()], "auth_chain": [create] }))
                    }
                }),
            )
            .route("/_matrix/federation/v1/send/:txn", put(|| async { Json(json!({ "pdus": {} })) })),
    )
    .await;
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_FEDERATION_BASE_URL", url.as_str()),
        ("CONDUIT_REMOTE_KEYS_OVERRIDE", url.as_str()),
    ])
    .await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let alice_id = alice["user_id"].as_str().unwrap().to_owned();
    let joined = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/join/{}?via={PEER}", enc(room)),
            Some(token),
            Some(json!({})),
            200,
        )
        .await;
    assert_eq!(joined["room_id"], room);
    let seen = hits.lock().unwrap().clone();
    assert!(seen.contains(&"make_join".to_owned()), "make_join was not called: {seen:?}");
    assert!(seen.contains(&"send_join".to_owned()), "send_join was not called: {seen:?}");

    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let storage = conduit_server::PostgresStorage::new(pool);
    let stored_create = storage.get_state_entry(room, "m.room.create", "").await.unwrap().expect("returned create was not stored");
    assert_eq!(stored_create.event_id, create_id, "stored create is not the event send_join returned");
    let member = storage.get_state_entry(room, "m.room.member", &alice_id).await.unwrap().expect("join membership missing");
    assert_eq!(member.content["membership"], "join");
    let client_member = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.member/{}", enc(room), enc(&alice_id)),
            Some(token),
            None,
            200,
        )
        .await;
    assert_eq!(client_member["membership"], "join");
}

#[tokio::test]
async fn remote_invite_is_delivered_and_stores_the_cosignature() {
    let key = Arc::new(generate_server_key());
    let hits = Arc::new(Mutex::new(Vec::<String>::new()));
    let route_hits = Arc::clone(&hits);
    let route_key = Arc::clone(&key);
    let url = serve(
        Arc::clone(&key),
        Router::new().route(
            "/_matrix/federation/v2/invite/:room_id/:event_id",
            put(move |Json(body): Json<Value>| {
                let hits = Arc::clone(&route_hits);
                let key = Arc::clone(&route_key);
                async move {
                    push_hit(&hits, "invite");
                    let mut pdu: Pdu = serde_json::from_value(body["event"].clone()).expect("invite event");
                    add_signature(&mut pdu, &key, PEER).unwrap();
                    Json(json!({ "event": pdu }))
                }
            }),
        ),
    )
    .await;
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_FEDERATION_BASE_URL", url.as_str()),
        ("CONDUIT_REMOTE_KEYS_OVERRIDE", url.as_str()),
    ])
    .await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let created = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "private_chat"})), 200)
        .await;
    let room = created["room_id"].as_str().unwrap().to_owned();
    let invitee = "@erin:peer.test";
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/invite", enc(&room)),
            Some(token),
            Some(json!({"user_id": invitee})),
            200,
        )
        .await;
    let seen = hits.lock().unwrap().clone();
    assert!(seen.contains(&"invite".to_owned()), "PUT /invite was not called: {seen:?}");
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let storage = conduit_server::PostgresStorage::new(pool);
    let member = storage.get_state_entry(&room, "m.room.member", invitee).await.unwrap().expect("invite missing");
    let stored = storage.get_event(&member.event_id).await.unwrap().expect("invite event missing");
    assert!(
        stored.signatures.get(PEER).and_then(Value::as_object).is_some_and(|keys| !keys.is_empty()),
        "stored invite has no {PEER} signature: {}\nserver log:\n{}",
        stored.signatures,
        server.logs()
    );
}

#[tokio::test]
async fn remote_knock_uses_make_knock_and_send_knock() {
    let room = "!outknock:peer.test";
    let hits = Arc::new(Mutex::new(Vec::<String>::new()));
    let make_hits = Arc::clone(&hits);
    let send_hits = Arc::clone(&hits);
    let url = serve(
        Arc::new(generate_server_key()),
        Router::new()
            .route(
                "/_matrix/federation/v1/make_knock/:room_id/:user_id",
                get(move |Path((room_id, user_id)): Path<(String, String)>| {
                    let hits = Arc::clone(&make_hits);
                    async move {
                        push_hit(&hits, "make_knock");
                        Json(json!({
                            "room_version": "11",
                            "event": {
                                "type": "m.room.member",
                                "room_id": room_id,
                                "sender": user_id,
                                "state_key": user_id,
                                "content": { "membership": "knock" },
                                "auth_events": [],
                                "prev_events": [],
                                "depth": 2,
                                "origin_server_ts": 1_700_000_000_000u64
                            }
                        }))
                    }
                }),
            )
            .route(
                "/_matrix/federation/v1/send_knock/:room_id/:event_id",
                put(move |Json(_body): Json<Value>| {
                    let hits = Arc::clone(&send_hits);
                    async move {
                        push_hit(&hits, "send_knock");
                        Json(json!({ "knock_room_state": [] }))
                    }
                }),
            ),
    )
    .await;
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_FEDERATION_BASE_URL", url.as_str()),
    ])
    .await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let knocked = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/knock/{}?via={PEER}", enc(room)),
            Some(token),
            Some(json!({"reason": "hello"})),
            200,
        )
        .await;
    assert_eq!(knocked["room_id"], room);
    let seen = hits.lock().unwrap().clone();
    assert!(seen.contains(&"make_knock".to_owned()), "make_knock was not called: {seen:?}");
    assert!(seen.contains(&"send_knock".to_owned()), "send_knock was not called: {seen:?}");
    let sync = server
        .request(Method::GET, "/_matrix/client/v3/sync", Some(token), None, 200)
        .await;
    assert!(
        sync["rooms"]["knock"].get(room).is_some(),
        "knock was not stored for /sync: {sync}"
    );
}

#[tokio::test]
async fn remote_invite_refusal_fails_and_drops_membership() {
    let sent = Arc::new(Mutex::new(Vec::<Value>::new()));
    let sent_route = Arc::clone(&sent);
    let url = serve(
        Arc::new(generate_server_key()),
        Router::new()
            .route(
                "/_matrix/federation/v2/invite/:room_id/:event_id",
                put(|| async {
                    (
                        StatusCode::FORBIDDEN,
                        Json(json!({"errcode": "M_FORBIDDEN", "error": "no thanks"})),
                    )
                }),
            )
            .route(
                "/_matrix/federation/v1/send/:txn",
                put(move |Json(body): Json<Value>| {
                    let sent = Arc::clone(&sent_route);
                    async move {
                        sent.lock().unwrap().push(body);
                        Json(json!({ "pdus": {} }))
                    }
                }),
            ),
    )
    .await;
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_FEDERATION_BASE_URL", url.as_str()),
        ("CONDUIT_REMOTE_KEYS_OVERRIDE", url.as_str()),
    ])
    .await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(json!({"preset": "private_chat"})), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let storage = conduit_server::PostgresStorage::new(pool.clone());
    let joined = "@joined:peer.test";
    let member = Event::new(
        "$member-join-joined-peer-test",
        Pdu::new(&room, joined, "m.room.member", Some(joined.to_owned()), json!({"membership": "join"}), 1_700_000_000_000, vec![], vec![], 40),
    );
    storage.put_event(&member).await.unwrap();
    storage.set_state_entry(&room, "m.room.member", joined, &member.event_id).await.unwrap();

    let invitee = "@refused:peer.test";
    let refused = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/invite", enc(&room)),
            Some(token),
            Some(json!({"user_id": invitee})),
            403,
        )
        .await;
    assert_eq!(refused["errcode"], "M_FORBIDDEN", "{refused}");
    assert!(
        storage.get_state_entry(&room, "m.room.member", invitee).await.unwrap().is_none(),
        "refused invite is still the membership"
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    let bodies = sent.lock().unwrap().clone();
    assert!(
        bodies.iter().all(|body| !body.to_string().contains(invitee)),
        "refused invite was sent: {bodies:?}"
    );
    let queued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM fed_outbound_queue WHERE payload_text LIKE $1",
    )
    .bind(format!("%{invitee}%"))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(queued, 0, "refused invite is still queued");
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(value) = u8::from_str_radix(&input[index + 1..index + 3], 16) {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out).unwrap()
}

fn event_id_from_send_path(path: &str) -> String {
    let rest = path.split("/send_join/").nth(1).unwrap_or(path);
    let encoded = rest.split('/').nth(1).unwrap_or(rest);
    percent_decode(encoded)
}

#[tokio::test]
async fn remote_join_room_version_3_uses_standard_base64_event_id() {
    let room = "!outv3:peer.test";
    let captured = Arc::new(Mutex::new(Vec::<(String, Value)>::new()));
    let make_room = room.to_owned();
    let send_captured = Arc::clone(&captured);
    let url = serve(
        Arc::new(generate_server_key()),
        Router::new()
            .route(
                "/_matrix/federation/v1/make_join/:room_id/:user_id",
                get(move |Path((room_id, user_id)): Path<(String, String)>| {
                    let room = make_room.clone();
                    async move {
                        assert_eq!(room_id, room);
                        Json(json!({
                            "room_version": "3",
                            "event": {
                                "type": "m.room.member",
                                "room_id": room_id,
                                "sender": user_id,
                                "state_key": user_id,
                                "content": { "membership": "join" },
                                "auth_events": [],
                                "prev_events": [],
                                "depth": 2,
                                "origin": PEER,
                                "origin_server_ts": 1_700_000_000_000u64
                            }
                        }))
                    }
                }),
            )
            .fallback(move |request: axum::extract::Request| {
                let captured = Arc::clone(&send_captured);
                async move {
                    let path = request.uri().path().to_owned();
                    if !path.contains("/send_join/") {
                        return (StatusCode::NOT_FOUND, Json(json!({}))).into_response();
                    }
                    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
                    let body: Value = serde_json::from_slice(&bytes).unwrap();
                    captured.lock().unwrap().push((path, body));
                    Json(json!({ "state": [], "auth_chain": [] })).into_response()
                }
            }),
    )
    .await;
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_FEDERATION_BASE_URL", url.as_str()),
    ])
    .await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let alice_id = alice["user_id"].as_str().unwrap().to_owned();
    let joined = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/join/{}?via={PEER}", enc(room)),
            Some(token),
            Some(json!({})),
            200,
        )
        .await;
    assert_eq!(joined["room_id"], room);
    let seen = captured.lock().unwrap().clone();
    let (path, body) = seen.first().expect("send_join was not called").clone();
    assert!(path.contains("/_matrix/federation/v2/send_join/"), "room version 3 left v2: {path}");
    let pdu: Pdu = serde_json::from_value(body).expect("send_join body");
    let expected = conduit::room_version::event_id_for(&pdu, 3).ok().flatten().expect("version 3 event id");
    let v11 = conduit::hashing::event_id(&pdu).unwrap();
    assert_ne!(expected, v11, "version 3 id collapsed to the v11 reference hash");
    assert!(!expected[1..].contains('_') && !expected[1..].contains('-'), "version 3 id is not standard base64: {expected}");
    assert_eq!(event_id_from_send_path(&path), expected);
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let storage = conduit_server::PostgresStorage::new(pool);
    let member = storage.get_state_entry(room, "m.room.member", &alice_id).await.unwrap().expect("join missing");
    assert_eq!(member.event_id, expected);
    assert_eq!(member.content["membership"], "join");
}

#[tokio::test]
async fn remote_join_room_version_2_uses_v1_event_format() {
    let room = "!outv1:peer.test";
    let captured = Arc::new(Mutex::new(Vec::<(String, Value)>::new()));
    let send_captured = Arc::clone(&captured);
    let url = serve(
        Arc::new(generate_server_key()),
        Router::new()
            .route(
                "/_matrix/federation/v1/make_join/:room_id/:user_id",
                get(move |Path((room_id, user_id)): Path<(String, String)>| async move {
                    Json(json!({
                        "room_version": "2",
                        "event": {
                            "type": "m.room.member",
                            "room_id": room_id,
                            "sender": user_id,
                            "state_key": user_id,
                            "content": { "membership": "join" },
                            "auth_events": [["$create:peer.test", {"sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]],
                            "prev_events": [["$prev:peer.test", {"sha256": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}]],
                            "depth": 2,
                            "origin_server_ts": 1_700_000_000_000u64
                        }
                    }))
                }),
            )
            .fallback(move |request: axum::extract::Request| {
                let captured = Arc::clone(&send_captured);
                async move {
                    let path = request.uri().path().to_owned();
                    if !path.contains("/send_join/") {
                        return (StatusCode::NOT_FOUND, Json(json!({}))).into_response();
                    }
                    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
                    let body: Value = serde_json::from_slice(&bytes).unwrap();
                    captured.lock().unwrap().push((path, body));
                    Json(json!({ "state": [], "auth_chain": [] })).into_response()
                }
            }),
    )
    .await;
    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_FEDERATION_BASE_URL", url.as_str()),
    ])
    .await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let alice_id = alice["user_id"].as_str().unwrap().to_owned();
    let joined = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/join/{}?via={PEER}", enc(room)),
            Some(token),
            Some(json!({})),
            200,
        )
        .await;
    assert_eq!(joined["room_id"], room);
    let seen = captured.lock().unwrap().clone();
    let (path, body) = seen.first().expect("send_join was not called").clone();
    assert!(path.contains("/_matrix/federation/v1/send_join/"), "room version 2 did not use v1 send_join: {path}");
    assert!(body.get("event_id").and_then(Value::as_str).is_some_and(|id| id.starts_with('$') && id.contains(':')), "{body}");
    assert!(body["auth_events"][0].is_array(), "v1 auth_events were flattened: {body}");
    assert!(body["prev_events"][0].is_array(), "v1 prev_events were flattened: {body}");
    assert!(body["signatures"].is_object(), "{body}");
    assert_eq!(event_id_from_send_path(&path), body["event_id"].as_str().unwrap());
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let storage = conduit_server::PostgresStorage::new(pool);
    let member = storage.get_state_entry(room, "m.room.member", &alice_id).await.unwrap().expect("join missing");
    assert_eq!(member.content["membership"], "join");
    assert_eq!(member.event_id, body["event_id"]);
}
