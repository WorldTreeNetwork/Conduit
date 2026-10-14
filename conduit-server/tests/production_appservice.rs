//! Application service and identity-server journeys through the shipped
//! binary and PostgreSQL (conduit-y99.34, conduit-y99.35, conduit-y99.36,
//! conduit-y99.18.1).  The application service and the identity server are
//! mock HTTP servers owned by each test.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::production::Server;
use reqwest::Method;
use serde_json::{json, Value};

const HS: &str = "production.test";

fn token(user: &Value) -> &str {
    user["access_token"].as_str().unwrap()
}

// ---------------------------------------------------------------------------
// Mock application service
// ---------------------------------------------------------------------------

/// One request the mock AS received.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    authorization: Option<String>,
    query: Option<String>,
    body: Value,
    /// Status the mock answered with.
    status: u16,
}

#[derive(Default)]
struct AsState {
    seen: Vec<Seen>,
    /// Answer 503 to transactions while set.
    failing: bool,
    /// Serve only the legacy unprefixed routes (404 on /_matrix/app/v1).
    legacy_only: bool,
}

type AsLog = Arc<Mutex<AsState>>;

async fn spawn_as(legacy_only: bool) -> (String, AsLog) {
    use axum::{body::to_bytes, extract::Request, http::StatusCode, Json, Router};
    let log: AsLog = Arc::new(Mutex::new(AsState { legacy_only, ..Default::default() }));
    let state = Arc::clone(&log);
    let app = Router::new().fallback(move |req: Request| {
        let state = Arc::clone(&state);
        async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_owned();
            let query = req.uri().query().map(str::to_owned);
            let authorization = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let bytes = to_bytes(req.into_body(), 1 << 20).await.unwrap();
            let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let mut s = state.lock().unwrap();
            let prefixed = path.starts_with("/_matrix/app/v1/");
            let status = if s.legacy_only && prefixed {
                404
            } else if path.contains("/transactions/") && s.failing {
                503
            } else if path.contains("/users/") || path.contains("/rooms/") {
                404
            } else {
                200
            };
            s.seen.push(Seen { method, path, authorization, query, body, status });
            let reply = if status == 200 { json!({}) } else { json!({"errcode": "M_UNRECOGNIZED"}) };
            (StatusCode::from_u16(status).unwrap(), Json(reply))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, log)
}

/// Successfully delivered transactions: `(txn_id, request)`.
fn delivered(log: &AsLog) -> Vec<(i64, Seen)> {
    log.lock()
        .unwrap()
        .seen
        .iter()
        .filter(|s| s.method == "PUT" && s.path.contains("/transactions/") && s.status == 200)
        .map(|s| (s.path.rsplit('/').next().unwrap().parse().unwrap(), s.clone()))
        .collect()
}

/// Every pushed event, in delivery order.
fn pushed_events(log: &AsLog) -> Vec<Value> {
    delivered(log)
        .into_iter()
        .flat_map(|(_, s)| s.body["events"].as_array().cloned().unwrap_or_default())
        .collect()
}

fn pushed_ephemeral(log: &AsLog) -> Vec<Value> {
    delivered(log)
        .into_iter()
        .flat_map(|(_, s)| s.body["ephemeral"].as_array().cloned().unwrap_or_default())
        .collect()
}

async fn wait_for(what: &str, server: &Server, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}; log: {}", server.logs());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn registration(id: &str, url: &str, extra: &str) -> String {
    format!(
        "id: {id}\nurl: \"{url}\"\nas_token: as_{id}\nhs_token: hs_{id}\nsender_localpart: {id}bot\n\
         rate_limited: false\n\
         namespaces:\n  users:\n    - exclusive: true\n      regex: '@{id}_.*:production\\.test'\n  \
         aliases:\n    - exclusive: false\n      regex: '#{id}_.*:production\\.test'\n  \
         rooms:\n    - exclusive: false\n      regex: '!nomatch:.*'\n{extra}"
    )
}

/// Start a server with the given registrations installed.
async fn server_with(registrations: &[(&str, String)]) -> Server {
    let mut server = Server::with_env(&[("CONDUIT_AS_BACKOFF_BASE_MS", "50")]).await;
    server.stop();
    let dir = server.files.path().join("app-services");
    std::fs::create_dir_all(&dir).unwrap();
    for (id, yaml) in registrations {
        std::fs::write(dir.join(format!("{id}.yaml")), yaml).unwrap();
    }
    server.start().await;
    server
}

async fn create_room(server: &Server, token: &str, body: Value) -> String {
    server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(body), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn send_text(server: &Server, token: &str, room: &str, txn: &str, body: &str) -> String {
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": body})),
            200,
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Register `localpart` as an AS-owned user (`m.login.application_service`).
async fn as_register(server: &Server, as_token: &str, localpart: &str) -> Value {
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            Some(as_token),
            Some(json!({"type": "m.login.application_service", "username": localpart, "inhibit_login": true})),
            200,
        )
        .await
}

// ---------------------------------------------------------------------------
// conduit-y99.34 — transaction push
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transactions_push_interesting_events_and_ephemeral_with_bearer_auth() {
    let (url, log) = spawn_as(false).await;
    let server = server_with(&[("irc", registration("irc", &url, "receive_ephemeral: true\n"))]).await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    as_register(&server, "as_irc", "irc_carol").await;

    // A room bridged through an alias in the AS's alias namespace.
    let bridged = create_room(&server, token(&alice), json!({"preset": "public_chat", "room_alias_name": "irc_chan"})).await;
    let in_bridged = send_text(&server, token(&alice), &bridged, "t1", "hello bridge").await;
    // An unrelated room: nothing in it may reach the AS...
    let private = create_room(&server, token(&bob), json!({"preset": "private_chat"})).await;
    let hidden = send_text(&server, token(&bob), &private, "t2", "not for the bridge").await;
    // ...until a namespaced user is its membership target.
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{private}/invite"),
            Some(token(&bob)),
            Some(json!({"user_id": "@irc_carol:production.test"})),
            200,
        )
        .await;

    wait_for("bridged message and invite", &server, || {
        let events = pushed_events(&log);
        events.iter().any(|e| e["event_id"] == in_bridged.as_str())
            && events.iter().any(|e| e["type"] == "m.room.member" && e["state_key"] == "@irc_carol:production.test")
    })
    .await;
    let events = pushed_events(&log);
    assert!(events.iter().all(|e| e["event_id"] != hidden.as_str()), "uninteresting event leaked: {events:?}");
    let message = events.iter().find(|e| e["event_id"] == in_bridged.as_str()).unwrap();
    assert_eq!(message["room_id"], bridged.as_str());
    assert_eq!(message["content"]["body"], "hello bridge");
    assert!(message.get("hashes").is_none() && message.get("signatures").is_none(), "client format: {message}");
    assert!(message["unsigned"].get("transaction_id").is_none());

    // Every transaction: Bearer hs_token, no query token, increasing txnIds.
    let txns = delivered(&log);
    for (_, seen) in &txns {
        assert_eq!(seen.authorization.as_deref(), Some("Bearer hs_irc"));
        assert_eq!(seen.query, None, "hs_token must not be sent in the query string");
        assert!(seen.path.starts_with("/_matrix/app/v1/transactions/"));
        assert!(seen.body["ephemeral"].is_array(), "receive_ephemeral: {}", seen.body);
    }
    let ids: Vec<i64> = txns.iter().map(|(id, _)| *id).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "txnIds must increase: {ids:?}");

    // Ephemeral: typing and receipts in the bridged room.
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{bridged}/typing/@alice:{HS}"),
            Some(token(&alice)),
            Some(json!({"typing": true, "timeout": 20000})),
            200,
        )
        .await;
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{bridged}/receipt/m.read/{in_bridged}"),
            Some(token(&alice)),
            Some(json!({})),
            200,
        )
        .await;
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{bridged}/receipt/m.read.private/{in_bridged}"),
            Some(token(&alice)),
            Some(json!({})),
            200,
        )
        .await;
    // Typing in the unrelated room is not pushed.
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{private}/typing/@bob:{HS}"),
            Some(token(&bob)),
            Some(json!({"typing": true, "timeout": 20000})),
            200,
        )
        .await;
    // Presence: alice shares the bridged room; bob shares nothing bridged.
    for (user, who) in [(&bob, "bob"), (&alice, "alice")] {
        server
            .request(
                Method::PUT,
                &format!("/_matrix/client/v3/presence/@{who}:{HS}/status"),
                Some(token(user)),
                Some(json!({"presence": "online", "status_msg": format!("{who} here")})),
                200,
            )
            .await;
    }
    wait_for("typing, receipt and presence EDUs", &server, || {
        let edus = pushed_ephemeral(&log);
        edus.iter().any(|e| e["type"] == "m.typing" && e["room_id"] == bridged.as_str())
            && edus.iter().any(|e| e["type"] == "m.receipt" && e["room_id"] == bridged.as_str())
            && edus.iter().any(|e| e["type"] == "m.presence" && e["sender"] == format!("@alice:{HS}"))
    })
    .await;
    let presence: Vec<_> = pushed_ephemeral(&log).into_iter().filter(|e| e["type"] == "m.presence").collect();
    assert!(presence.iter().all(|p| p["sender"] != format!("@bob:{HS}")), "{presence:?}");
    assert_eq!(presence[0]["content"]["presence"], "online");
    assert_eq!(presence[0]["content"]["status_msg"], "alice here");
    // Give a straggling private-room EDU the chance to (wrongly) arrive.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let edus = pushed_ephemeral(&log);
    let typing = edus.iter().find(|e| e["type"] == "m.typing" && e["room_id"] == bridged.as_str()).unwrap();
    assert_eq!(typing["content"]["user_ids"], json!([format!("@alice:{HS}")]));
    assert!(edus.iter().all(|e| e["room_id"] != private.as_str()), "{edus:?}");
    let receipts: Vec<_> = edus.iter().filter(|e| e["type"] == "m.receipt").collect();
    let read = &receipts[0]["content"][&in_bridged];
    assert!(read["m.read"][format!("@alice:{HS}")]["ts"].is_u64(), "{receipts:?}");
    // alice is not in the namespace: her private receipt stays private.
    assert!(receipts.iter().all(|r| r["content"][&in_bridged].get("m.read.private").is_none()), "{receipts:?}");
}

#[tokio::test]
async fn transactions_retry_with_identical_body_across_restart() {
    let (url, log) = spawn_as(false).await;
    let mut server = server_with(&[("irc", registration("irc", &url, ""))]).await;
    let alice = server.register("alice").await;
    let room = create_room(&server, token(&alice), json!({"preset": "public_chat", "room_alias_name": "irc_retry"})).await;
    let first = send_text(&server, token(&alice), &room, "a", "first").await;
    wait_for("first delivery", &server, || pushed_events(&log).iter().any(|e| e["event_id"] == first.as_str())).await;

    // The AS goes down: the next transaction is retried, never re-batched.
    log.lock().unwrap().failing = true;
    let second = send_text(&server, token(&alice), &room, "b", "second").await;
    let attempts = |log: &AsLog| -> Vec<Seen> {
        log.lock()
            .unwrap()
            .seen
            .iter()
            .filter(|s| s.path.contains("/transactions/") && s.status == 503)
            .cloned()
            .collect()
    };
    wait_for("two failed attempts", &server, || attempts(&log).len() >= 2).await;
    let failed = attempts(&log);
    assert!(failed.iter().all(|s| s.path == failed[0].path && s.body == failed[0].body), "retries must not alter the transaction");
    assert!(failed[0].body["events"].as_array().unwrap().iter().any(|e| e["event_id"] == second.as_str()));

    // Restart while the transaction is pending, with more traffic queued.
    server.stop();
    server.start().await;
    let third = send_text(&server, token(&alice), &room, "c", "third").await;
    wait_for("failed attempt after restart", &server, || attempts(&log).len() > failed.len()).await;
    let after_restart = attempts(&log);
    assert_eq!(after_restart.last().unwrap().path, failed[0].path, "same txnId after restart");
    assert_eq!(after_restart.last().unwrap().body, failed[0].body, "same body after restart");

    log.lock().unwrap().failing = false;
    wait_for("recovery", &server, || pushed_events(&log).iter().any(|e| e["event_id"] == third.as_str())).await;
    let txns = delivered(&log);
    let recovered = txns.iter().find(|(_, s)| s.path == failed[0].path).expect("frozen txn delivered");
    assert_eq!(recovered.1.body, failed[0].body);
    // Exactly once, in order.
    let ids: Vec<String> = pushed_events(&log)
        .iter()
        .filter(|e| e["type"] == "m.room.message")
        .map(|e| e["event_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, vec![first, second, third]);
    let txn_ids: Vec<i64> = txns.iter().map(|(id, _)| *id).collect();
    assert!(txn_ids.windows(2).all(|w| w[0] < w[1]), "{txn_ids:?}");
}

#[tokio::test]
async fn transactions_fall_back_to_legacy_routes() {
    let (url, log) = spawn_as(true).await;
    let server = server_with(&[("old", registration("old", &url, ""))]).await;
    let alice = server.register("alice").await;
    let room = create_room(&server, token(&alice), json!({"preset": "public_chat", "room_alias_name": "old_room"})).await;
    let event = send_text(&server, token(&alice), &room, "x", "legacy").await;
    wait_for("legacy delivery", &server, || pushed_events(&log).iter().any(|e| e["event_id"] == event.as_str())).await;
    let seen = log.lock().unwrap().seen.clone();
    let legacy = seen.iter().find(|s| s.status == 200 && s.path.starts_with("/transactions/")).unwrap();
    // The current route was tried first, with Bearer and no query token.
    let current = seen.iter().find(|s| s.path == format!("/_matrix/app/v1{}", legacy.path)).unwrap();
    assert_eq!(current.status, 404);
    assert_eq!(current.authorization.as_deref(), Some("Bearer hs_old"));
    assert_eq!(current.query, None);
    assert_eq!(legacy.query.as_deref(), Some("access_token=hs_old"));
}

// ---------------------------------------------------------------------------
// conduit-y99.35 / conduit-y99.18.1 — client-server API extensions
// ---------------------------------------------------------------------------

/// `path` with the AS identity-assertion query appended.
fn as_user(path: &str, user: &str) -> String {
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{path}{sep}user_id={}", user.replace('@', "%40").replace(':', "%3A"))
}

#[tokio::test]
async fn identity_assertion_devices_registration_and_login() {
    let (url, _log) = spawn_as(false).await;
    let server = server_with(&[("irc", registration("irc", &url, ""))]).await;
    let alice = server.register("alice").await;
    let carol = format!("@irc_carol:{HS}");
    let whoami = "/_matrix/client/v3/account/whoami";

    // No user_id: the AS acts as its sender user, device-less.
    let me = server.request(Method::GET, whoami, Some("as_irc"), None, 200).await;
    assert_eq!(me, json!({"user_id": format!("@ircbot:{HS}")}));

    // Unregistered namespace user, foreign users, remote look-alikes.
    let refused = server.request(Method::GET, &as_user(whoami, &carol), Some("as_irc"), None, 403).await;
    assert_eq!(refused["errcode"], "M_FORBIDDEN");
    for outsider in [format!("@alice:{HS}"), "@irc_carol:elsewhere.test".to_owned()] {
        let refused = server.request(Method::GET, &as_user(whoami, &outsider), Some("as_irc"), None, 403).await;
        assert_eq!(refused["errcode"], "M_FORBIDDEN", "{outsider}");
    }

    // Registration type m.login.application_service needs the as_token.
    let body = json!({"type": "m.login.application_service", "username": "irc_carol", "inhibit_login": true});
    let missing = server.request(Method::POST, "/_matrix/client/v3/register", None, Some(body.clone()), 401).await;
    assert_eq!(missing["errcode"], "M_MISSING_TOKEN");
    let unknown = server.request(Method::POST, "/_matrix/client/v3/register", Some("nope"), Some(body.clone()), 401).await;
    assert_eq!(unknown["errcode"], "M_UNKNOWN_TOKEN");
    let registered = server.request(Method::POST, "/_matrix/client/v3/register", Some("as_irc"), Some(body), 200).await;
    assert_eq!(registered, json!({"user_id": carol}));
    let me = server.request(Method::GET, &as_user(whoami, &carol), Some("as_irc"), None, 200).await;
    assert_eq!(me, json!({"user_id": carol}));

    // Device masquerading: unknown device is M_UNKNOWN_DEVICE.
    let bad = server
        .request(Method::GET, &format!("{}&device_id=NOPE", as_user(whoami, &carol)), Some("as_irc"), None, 400)
        .await;
    assert_eq!(bad["errcode"], "M_UNKNOWN_DEVICE");

    // conduit-y99.18.1: AS creates a device with PUT (201), updates (200).
    let device_path = as_user("/_matrix/client/v3/devices/BRIDGEDEV", &carol);
    server.request(Method::PUT, &device_path, Some("as_irc"), Some(json!({"display_name": "IRC"})), 201).await;
    server.request(Method::PUT, &device_path, Some("as_irc"), Some(json!({"display_name": "IRC 2"})), 200).await;
    let devices = server.request(Method::GET, &as_user("/_matrix/client/v3/devices", &carol), Some("as_irc"), None, 200).await;
    assert_eq!(devices["devices"][0]["device_id"], "BRIDGEDEV");
    assert_eq!(devices["devices"][0]["display_name"], "IRC 2");
    let me = server
        .request(Method::GET, &format!("{}&device_id=BRIDGEDEV", as_user(whoami, &carol)), Some("as_irc"), None, 200)
        .await;
    assert_eq!(me, json!({"user_id": carol, "device_id": "BRIDGEDEV"}));
    // Ordinary clients may not create devices this way.
    let not_found = server
        .request(Method::PUT, "/_matrix/client/v3/devices/NEWDEV", Some(token(&alice)), Some(json!({})), 404)
        .await;
    assert_eq!(not_found["errcode"], "M_NOT_FOUND");
    // Device-less key upload is refused; with a device it works.
    let keyless = server
        .request(Method::POST, &as_user("/_matrix/client/v3/keys/upload", &carol), Some("as_irc"), Some(json!({})), 400)
        .await;
    assert_eq!(keyless["errcode"], "M_MISSING_PARAM");

    // Cross-signing replacement needs no UIA for the AS (spec v1.17).
    let signing = as_user("/_matrix/client/v3/keys/device_signing/upload", &carol);
    let first = common::keys::CrossSigning::new(&carol);
    server.request(Method::POST, &signing, Some("as_irc"), Some(first.upload_body()), 200).await;
    let second = common::keys::CrossSigning::new(&carol);
    server.request(Method::POST, &signing, Some("as_irc"), Some(second.upload_body()), 200).await;

    // Device deletion without UIA (DELETE and POST /delete_devices).
    server.request(Method::DELETE, &device_path, Some("as_irc"), Some(json!({})), 200).await;
    server.request(Method::PUT, &as_user("/_matrix/client/v3/devices/D2", &carol), Some("as_irc"), Some(json!({})), 201).await;
    server
        .request(Method::POST, &as_user("/_matrix/client/v3/delete_devices", &carol), Some("as_irc"), Some(json!({"devices": ["D2"]})), 200)
        .await;
    let devices = server.request(Method::GET, &as_user("/_matrix/client/v3/devices", &carol), Some("as_irc"), None, 200).await;
    assert_eq!(devices["devices"], json!([]));

    // m.login.application_service login.
    let flows = server.request(Method::GET, "/_matrix/client/v3/login", None, None, 200).await;
    assert!(flows["flows"].as_array().unwrap().iter().any(|f| f["type"] == "m.login.application_service"));
    let login = |user: &str| json!({"type": "m.login.application_service", "identifier": {"type": "m.id.user", "user": user}});
    let session = server.request(Method::POST, "/_matrix/client/v3/login", Some("as_irc"), Some(login("irc_carol")), 200).await;
    assert_eq!(session["user_id"], carol.as_str());
    let me = server.request(Method::GET, whoami, Some(token(&session)), None, 200).await;
    assert_eq!(me["user_id"], carol.as_str());
    let exclusive = server.request(Method::POST, "/_matrix/client/v3/login", Some("as_irc"), Some(login("alice")), 403).await;
    assert_eq!(exclusive["errcode"], "M_EXCLUSIVE");
    let unregistered = server.request(Method::POST, "/_matrix/client/v3/login", Some("as_irc"), Some(login("irc_nobody")), 403).await;
    assert_eq!(unregistered["errcode"], "M_FORBIDDEN");
    let no_token = server.request(Method::POST, "/_matrix/client/v3/login", None, Some(login("irc_carol")), 403).await;
    assert_eq!(no_token["errcode"], "M_FORBIDDEN");
}

#[tokio::test]
async fn timestamp_massaging_sync_and_alias_exclusivity() {
    let (url, _log) = spawn_as(false).await;
    // This registration holds its alias namespace exclusively.
    let exclusive = registration("irc", &url, "")
        .replace("aliases:\n    - exclusive: false", "aliases:\n    - exclusive: true");
    assert!(exclusive.contains("aliases:\n    - exclusive: true"));
    let server = server_with(&[("irc", exclusive)]).await;
    let alice = server.register("alice").await;
    let carol = format!("@irc_carol:{HS}");
    as_register(&server, "as_irc", "irc_carol").await;
    let room = create_room(&server, token(&alice), json!({"preset": "public_chat"})).await;
    server
        .request(Method::POST, &as_user(&format!("/_matrix/client/v3/join/{room}"), &carol), Some("as_irc"), Some(json!({})), 200)
        .await;

    // ts on send and on state, honoured for the AS.
    let send = format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/t1?ts=1234567890123");
    let sent = server
        .request(Method::PUT, &as_user(&send, &carol), Some("as_irc"), Some(json!({"msgtype": "m.text", "body": "old"})), 200)
        .await;
    let event_path = |id: &str| format!("/_matrix/client/v3/rooms/{room}/event/{id}");
    let event = server.request(Method::GET, &event_path(sent["event_id"].as_str().unwrap()), Some(token(&alice)), None, 200).await;
    assert_eq!(event["origin_server_ts"], 1234567890123u64);
    assert_eq!(event["sender"], carol.as_str());
    let state = format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic?ts=1000");
    // carol lacks power for the topic; alice's AS-less ts is ignored.
    let topic = server
        .request(Method::PUT, &state, Some(token(&alice)), Some(json!({"topic": "t"})), 200)
        .await;
    let event = server.request(Method::GET, &event_path(topic["event_id"].as_str().unwrap()), Some(token(&alice)), None, 200).await;
    assert_ne!(event["origin_server_ts"], 1000, "ts is an application-service privilege");
    let member_state = format!("/_matrix/client/v3/rooms/{room}/state/org.example.bridge/{}?ts=2000", carol.replace('@', "%40").replace(':', "%3A"));
    let bridged_state = server
        .request(Method::PUT, &as_user(&member_state, &carol), Some("as_irc"), Some(json!({"x": 1})), 403)
        .await;
    assert_eq!(bridged_state["errcode"], "M_FORBIDDEN", "auth rules still apply");
    let invalid = server
        .request(
            Method::PUT,
            &as_user(&format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/t2?ts=abc"), &carol),
            Some("as_irc"),
            Some(json!({"msgtype": "m.text", "body": "x"})),
            400,
        )
        .await;
    assert_eq!(invalid["errcode"], "M_INVALID_PARAM");

    // /sync as a virtual user.
    let sync = server
        .request(Method::GET, &as_user("/_matrix/client/v3/sync?timeout=0", &carol), Some("as_irc"), None, 200)
        .await;
    assert!(sync["rooms"]["join"][&room].is_object(), "{sync}");

    // Alias namespaces are exclusive.
    let put_alias = |alias: &str| format!("/_matrix/client/v3/directory/room/{}", alias.replace('#', "%23").replace(':', "%3A"));
    let taken = server
        .request(Method::PUT, &put_alias(&format!("#irc_chan:{HS}")), Some(token(&alice)), Some(json!({"room_id": room})), 400)
        .await;
    assert_eq!(taken["errcode"], "M_EXCLUSIVE");
    let taken = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token(&alice)), Some(json!({"room_alias_name": "irc_new"})), 400)
        .await;
    assert_eq!(taken["errcode"], "M_EXCLUSIVE");
    server
        .request(Method::PUT, &as_user(&put_alias(&format!("#irc_chan:{HS}")), &carol), Some("as_irc"), Some(json!({"room_id": room})), 200)
        .await;
    let outside = server
        .request(Method::PUT, &put_alias(&format!("#elsewhere:{HS}")), Some("as_irc"), Some(json!({"room_id": room})), 400)
        .await;
    assert_eq!(outside["errcode"], "M_EXCLUSIVE");
}

#[tokio::test]
async fn appservice_requests_are_exempt_from_rate_limits() {
    let (url, _log) = spawn_as(false).await;
    let limited = registration("lim", &url, "").replace("rate_limited: false", "rate_limited: true");
    let server = server_with(&[("irc", registration("irc", &url, "")), ("lim", limited)]).await;
    let alice = server.register("alice").await;
    as_register(&server, "as_lim", "lim_x").await;
    let burst = |token: String, path: String| {
        let http = server.http.clone();
        let url = format!("{}{path}", server.base_url);
        async move {
            // 8 workers x 60 requests: well past the 200-request burst
            // before the 100/s refill can catch up.
            let mut set = tokio::task::JoinSet::new();
            for _ in 0..8 {
                let (http, url, token) = (http.clone(), url.clone(), token.clone());
                set.spawn(async move {
                    let mut limited = 0;
                    for _ in 0..60 {
                        let status = http.get(&url).bearer_auth(&token).send().await.unwrap().status();
                        if status.as_u16() == 429 {
                            limited += 1;
                        }
                    }
                    limited
                });
            }
            let mut limited = 0;
            while let Some(n) = set.join_next().await {
                limited += n.unwrap();
            }
            limited
        }
    };
    let whoami = "/_matrix/client/v3/account/whoami".to_owned();
    assert!(burst(token(&alice).to_owned(), whoami.clone()).await > 0, "the limiter must be active for users");
    assert_eq!(burst("as_irc".into(), whoami.clone()).await, 0, "AS sender is exempt");
    assert_eq!(burst("as_lim".into(), whoami.clone()).await, 0, "the sender is excluded even when rate_limited");
    assert!(
        burst("as_lim".into(), as_user(&whoami, &format!("@lim_x:{HS}"))).await > 0,
        "masqueraded users of a rate_limited AS are limited"
    );
}
