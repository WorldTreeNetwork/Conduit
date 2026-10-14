//! Push rules, notification counts, /notifications and push gateway
//! delivery through the shipped binary and real PostgreSQL
//! (conduit-y99.30, conduit-y99.31). A mock push gateway runs in-test.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use common::production::Server;
use reqwest::Method;
use serde_json::{json, Value};

static TXN: AtomicU64 = AtomicU64::new(0);

struct User {
    id: String,
    token: String,
}

async fn user(server: &Server, name: &str) -> User {
    let registered = server.register(name).await;
    User {
        id: registered["user_id"].as_str().unwrap().to_owned(),
        token: registered["access_token"].as_str().unwrap().to_owned(),
    }
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

async fn raw(server: &Server, method: Method, path: &str, token: &str, body: Option<Value>) -> (u16, Value) {
    let mut request = server
        .http
        .request(method, format!("{}{path}", server.base_url))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}: {text}")))
}

async fn errcode(server: &Server, method: Method, path: &str, who: &User, body: Option<Value>) -> (u16, String) {
    let (status, body) = raw(server, method, path, &who.token, body).await;
    (status, body["errcode"].as_str().unwrap_or("").to_owned())
}

async fn create_room(server: &Server, who: &User, body: Value) -> String {
    server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(&who.token), Some(body), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn join(server: &Server, who: &User, room: &str) {
    server
        .request(Method::POST, &format!("/_matrix/client/v3/join/{}", encode(room)), Some(&who.token), Some(json!({})), 200)
        .await;
}

async fn send(server: &Server, who: &User, room: &str, kind: &str, content: Value) -> String {
    let txn = TXN.fetch_add(1, Ordering::SeqCst);
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/{kind}/p{txn}", encode(room)),
            Some(&who.token),
            Some(content),
            200,
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn text(server: &Server, who: &User, room: &str, body: &str) -> String {
    send(server, who, room, "m.room.message", json!({"msgtype": "m.text", "body": body})).await
}

async fn receipt(server: &Server, who: &User, room: &str, event: &str, body: Value) {
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/receipt/m.read/{}", encode(room), encode(event)),
            Some(&who.token),
            Some(body),
            200,
        )
        .await;
}

async fn sync(server: &Server, who: &User, since: Option<&str>, filter: Option<Value>) -> Value {
    let mut path = "/_matrix/client/v3/sync?timeout=0".to_owned();
    if let Some(since) = since {
        path.push_str(&format!("&since={}", encode(since)));
    }
    if let Some(filter) = filter {
        path.push_str(&format!("&filter={}", encode(&filter.to_string())));
    }
    server.request(Method::GET, &path, Some(&who.token), None, 200).await
}

fn unread(sync: &Value, room: &str) -> (u64, u64) {
    let counts = &sync["rooms"]["join"][room]["unread_notifications"];
    (
        counts["notification_count"].as_u64().unwrap_or_else(|| panic!("no counts: {sync}")),
        counts["highlight_count"].as_u64().unwrap(),
    )
}

/// Alice creates a public room that bob and carol join (three members, so
/// the one-to-one rules do not apply).
async fn trio(server: &Server) -> (User, User, User, String) {
    let alice = user(server, "alice").await;
    let bob = user(server, "bob").await;
    let carol = user(server, "carol").await;
    let room = create_room(server, &alice, json!({"preset": "public_chat", "name": "Ops"})).await;
    join(server, &bob, &room).await;
    join(server, &carol, &room).await;
    (alice, bob, carol, room)
}

// ---------------------------------------------------------------------------
// Push rules API (conduit-y99.30)
// ---------------------------------------------------------------------------

fn rule_ids(ruleset: &Value, kind: &str) -> Vec<String> {
    ruleset[kind]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["rule_id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn push_rules_api_follows_spec() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let base = "/_matrix/client/v3/pushrules/global";

    let all = server.request(Method::GET, "/_matrix/client/v3/pushrules/", Some(&alice.token), None, 200).await;
    let global = server.request(Method::GET, &format!("{base}/"), Some(&alice.token), None, 200).await;
    assert_eq!(all["global"], global);
    assert_eq!(
        rule_ids(&global, "override"),
        [
            ".m.rule.master", ".m.rule.suppress_notices", ".m.rule.invite_for_me", ".m.rule.member_event",
            ".m.rule.is_user_mention", ".m.rule.is_room_mention", ".m.rule.tombstone", ".m.rule.reaction",
            ".m.rule.room.server_acl", ".m.rule.suppress_edits",
        ]
    );
    assert_eq!(
        rule_ids(&global, "underride"),
        [".m.rule.call", ".m.rule.encrypted_room_one_to_one", ".m.rule.room_one_to_one", ".m.rule.message", ".m.rule.encrypted"]
    );
    assert!(global["content"].as_array().unwrap().is_empty());
    let mention = &global["override"][4];
    assert_eq!(mention["default"], true);
    assert_eq!(mention["conditions"][0]["key"], "content.m\\.mentions.user_ids");
    assert_eq!(mention["conditions"][0]["value"], alice.id.as_str());
    let invite = &global["override"][2];
    assert_eq!(invite["conditions"][2]["pattern"], alice.id.as_str());
    assert_eq!(global["override"][0]["enabled"], false);

    // Creation: enabled, user-defined, most important of its kind.
    for id in ["first", "second"] {
        server
            .request(
                Method::PUT,
                &format!("{base}/content/{id}"),
                Some(&alice.token),
                Some(json!({"pattern": id, "actions": ["notify"]})),
                200,
            )
            .await;
    }
    let rule = server.request(Method::GET, &format!("{base}/content/second"), Some(&alice.token), None, 200).await;
    assert_eq!(rule, json!({"rule_id": "second", "default": false, "enabled": true, "pattern": "second", "actions": ["notify"]}));
    let ids = |v: &Value| rule_ids(v, "content");
    let rules = server.request(Method::GET, &format!("{base}/"), Some(&alice.token), None, 200).await;
    assert_eq!(ids(&rules), ["second", "first"]);
    // before / after.
    server
        .request(Method::PUT, &format!("{base}/content/third?after=first"), Some(&alice.token), Some(json!({"pattern": "t", "actions": []})), 200)
        .await;
    server
        .request(Method::PUT, &format!("{base}/content/zeroth?before=second"), Some(&alice.token), Some(json!({"pattern": "z", "actions": []})), 200)
        .await;
    server
        .request(Method::PUT, &format!("{base}/content/middle?before=first&after=second"), Some(&alice.token), Some(json!({"pattern": "m", "actions": []})), 200)
        .await;
    let rules = server.request(Method::GET, &format!("{base}/"), Some(&alice.token), None, 200).await;
    assert_eq!(ids(&rules), ["zeroth", "second", "middle", "first", "third"]);
    // An update without before/after keeps the rule's place and enabled state.
    server
        .request(Method::PUT, &format!("{base}/content/middle/enabled"), Some(&alice.token), Some(json!({"enabled": false})), 200)
        .await;
    server
        .request(Method::PUT, &format!("{base}/content/middle"), Some(&alice.token), Some(json!({"pattern": "mm", "actions": ["notify"]})), 200)
        .await;
    let rules = server.request(Method::GET, &format!("{base}/"), Some(&alice.token), None, 200).await;
    assert_eq!(ids(&rules), ["zeroth", "second", "middle", "first", "third"]);
    assert_eq!(rules["content"][2]["pattern"], "mm");
    assert_eq!(rules["content"][2]["enabled"], false);

    // Errors.
    let put = |path: String, body: Value| (Method::PUT, path, Some(body));
    for ((method, path, body), expected) in [
        (put(format!("{base}/content/x?before=nope"), json!({"pattern": "x", "actions": []})), (400, "M_UNKNOWN")),
        (put(format!("{base}/content/x?after=.m.rule.master"), json!({"pattern": "x", "actions": []})), (400, "M_UNKNOWN")),
        (put(format!("{base}/override/.m.rule.mine"), json!({"actions": []})), (400, "M_INVALID_PARAM")),
        (put(format!("{base}/override/a%2Fb"), json!({"actions": []})), (400, "M_INVALID_PARAM")),
        (put(format!("{base}/override/a%5Cb"), json!({"actions": []})), (400, "M_INVALID_PARAM")),
        (put(format!("{base}/sideways/x"), json!({"actions": []})), (400, "M_INVALID_PARAM")),
        (put(format!("{base}/content/x"), json!({"actions": ["notify"]})), (400, "M_MISSING_PARAM")),
        (put(format!("{base}/override/x"), json!({"conditions": []})), (400, "M_MISSING_PARAM")),
        (put(format!("{base}/override/x"), json!({"actions": ["explode"]})), (400, "M_INVALID_PARAM")),
        (put(format!("{base}/override/x"), json!({"actions": [], "conditions": [{"key": "type"}]})), (400, "M_INVALID_PARAM")),
        (put(format!("{base}/override/missing/actions"), json!({"actions": []})), (404, "M_NOT_FOUND")),
        (put(format!("{base}/override/missing/enabled"), json!({"enabled": true})), (404, "M_NOT_FOUND")),
        (put(format!("{base}/override/.m.rule.master/enabled"), json!({"enabled": "yes"})), (400, "M_BAD_JSON")),
        ((Method::GET, format!("{base}/override/missing"), None), (404, "M_NOT_FOUND")),
        ((Method::GET, format!("{base}/override/missing/enabled"), None), (404, "M_NOT_FOUND")),
        ((Method::GET, format!("{base}/override/missing/actions"), None), (404, "M_NOT_FOUND")),
        ((Method::DELETE, format!("{base}/override/missing"), None), (404, "M_NOT_FOUND")),
        ((Method::DELETE, format!("{base}/override/.m.rule.master"), None), (400, "M_INVALID_PARAM")),
        ((Method::GET, "/_matrix/client/v3/pushrules/device/override/x".to_owned(), None), (404, "M_UNRECOGNIZED")),
    ] {
        let (status, code) = errcode(&server, method.clone(), &path, &alice, body).await;
        assert_eq!((status, code.as_str()), expected, "{method} {path}");
    }

    // Server-default rules: enabled and actions are mutable, and survive.
    server
        .request(Method::PUT, &format!("{base}/override/.m.rule.master/enabled"), Some(&alice.token), Some(json!({"enabled": true})), 200)
        .await;
    server
        .request(
            Method::PUT,
            &format!("{base}/underride/.m.rule.message/actions"),
            Some(&alice.token),
            Some(json!({"actions": ["notify", {"set_tweak": "sound", "value": "bing"}, "dont_notify"]})),
            200,
        )
        .await;
    let enabled = server.request(Method::GET, &format!("{base}/override/.m.rule.master/enabled"), Some(&alice.token), None, 200).await;
    assert_eq!(enabled, json!({"enabled": true}));
    let actions = server.request(Method::GET, &format!("{base}/underride/.m.rule.message/actions"), Some(&alice.token), None, 200).await;
    assert_eq!(actions, json!({"actions": ["notify", {"set_tweak": "sound", "value": "bing"}]}));
    let message = server.request(Method::GET, &format!("{base}/underride/.m.rule.message"), Some(&alice.token), None, 200).await;
    assert_eq!(message["default"], true);
    assert_eq!(message["conditions"][0]["pattern"], "m.room.message");

    // Delete a user rule.
    server.request(Method::DELETE, &format!("{base}/content/third"), Some(&alice.token), None, 200).await;
    let (status, _) = errcode(&server, Method::GET, &format!("{base}/content/third"), &alice, None).await;
    assert_eq!(status, 404);

    // m.push_rules account data mirrors the ruleset and reaches /sync.
    let rules = server.request(Method::GET, &format!("{base}/"), Some(&alice.token), None, 200).await;
    let stored = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/user/{}/account_data/m.push_rules", encode(&alice.id)),
            Some(&alice.token),
            None,
            200,
        )
        .await;
    assert_eq!(stored, json!({"global": rules}));
    let synced = sync(&server, &alice, None, None).await;
    let event = synced["account_data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "m.push_rules")
        .unwrap_or_else(|| panic!("no m.push_rules in {synced}"))
        .clone();
    assert_eq!(event["content"]["global"], rules);
    let since = synced["next_batch"].as_str().unwrap().to_owned();
    server
        .request(Method::PUT, &format!("{base}/sender/{}", encode("@spam:production.test")), Some(&alice.token), Some(json!({"actions": []})), 200)
        .await;
    let next = sync(&server, &alice, Some(&since), None).await;
    let event = next["account_data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "m.push_rules")
        .unwrap_or_else(|| panic!("rule change not synced: {next}"));
    assert_eq!(rule_ids(&event["content"]["global"], "sender"), ["@spam:production.test"]);
}

// ---------------------------------------------------------------------------
// Evaluation, counts, receipts and /notifications (conduit-y99.30)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unread_counts_follow_rules_and_receipts() {
    let server = Server::new().await;
    let (alice, bob, carol, room) = trio(&server).await;
    let initial = sync(&server, &alice, None, None).await;
    assert_eq!(unread(&initial, &room), (0, 0), "membership events never notify");
    let mut since = initial["next_batch"].as_str().unwrap().to_owned();

    // A plain message notifies; the count arrives with the event itself.
    let hello = text(&server, &bob, &room, "hello").await;
    let next = sync(&server, &alice, Some(&since), None).await;
    let timeline = &next["rooms"]["join"][&room]["timeline"]["events"];
    assert!(timeline.as_array().unwrap().iter().any(|e| e["event_id"] == hello.as_str()));
    assert_eq!(unread(&next, &room), (1, 0));
    since = next["next_batch"].as_str().unwrap().to_owned();

    // Suppressed: notices, edits, reactions, the user's own messages.
    send(&server, &bob, &room, "m.room.message", json!({"msgtype": "m.notice", "body": "bot"})).await;
    send(&server, &bob, &room, "m.room.message", json!({
        "msgtype": "m.text", "body": "* hello!", "m.new_content": {"msgtype": "m.text", "body": "hello!"},
        "m.relates_to": {"rel_type": "m.replace", "event_id": hello}
    }))
    .await;
    send(&server, &bob, &room, "m.reaction", json!({"m.relates_to": {"rel_type": "m.annotation", "event_id": hello, "key": "+1"}})).await;
    text(&server, &alice, &room, "my own").await;
    // A user mention highlights.
    send(&server, &bob, &room, "m.room.message", json!({
        "msgtype": "m.text", "body": "alice: look", "m.mentions": {"user_ids": [alice.id]}
    }))
    .await;
    // @room from an unprivileged sender is an ordinary message ...
    send(&server, &bob, &room, "m.room.message", json!({"msgtype": "m.text", "body": "@room", "m.mentions": {"room": true}})).await;
    let next = sync(&server, &alice, Some(&since), None).await;
    // Alice's own message marked "hello" read; mention + @room remain.
    assert_eq!(unread(&next, &room), (2, 1));
    // ... but from the room creator (power 100) it highlights for others.
    let bob_sync = sync(&server, &bob, None, None).await;
    let before = unread(&bob_sync, &room);
    send(&server, &alice, &room, "m.room.message", json!({"msgtype": "m.text", "body": "@room", "m.mentions": {"room": true}})).await;
    let bob_sync = sync(&server, &bob, None, None).await;
    assert_eq!(unread(&bob_sync, &room), (before.0 + 1, before.1 + 1));

    // A read receipt clears everything up to it; later events count again.
    let last = text(&server, &carol, &room, "latest").await;
    let next = sync(&server, &alice, None, None).await;
    // Alice's own @room read everything before it; only "latest" counts.
    assert_eq!(unread(&next, &room), (1, 0));
    receipt(&server, &alice, &room, &last, json!({})).await;
    let next = sync(&server, &alice, None, None).await;
    assert_eq!(unread(&next, &room), (0, 0));
    text(&server, &carol, &room, "after receipt").await;
    let next = sync(&server, &alice, None, None).await;
    assert_eq!(unread(&next, &room), (1, 0));

    // A private receipt also clears.
    let later = text(&server, &carol, &room, "one more").await;
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/receipt/m.read.private/{}", encode(&room), encode(&later)),
            Some(&alice.token),
            Some(json!({})),
            200,
        )
        .await;
    assert_eq!(unread(&sync(&server, &alice, None, None).await, &room), (0, 0));

    // Rule changes apply to later events: a room rule with no actions
    // silences the room; the master rule silences everything.
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/pushrules/global/room/{}", encode(&room)),
            Some(&alice.token),
            Some(json!({"actions": []})),
            200,
        )
        .await;
    text(&server, &bob, &room, "muted").await;
    assert_eq!(unread(&sync(&server, &alice, None, None).await, &room), (0, 0));
    server
        .request(Method::DELETE, &format!("/_matrix/client/v3/pushrules/global/room/{}", encode(&room)), Some(&alice.token), None, 200)
        .await;
    server
        .request(Method::PUT, "/_matrix/client/v3/pushrules/global/override/.m.rule.master/enabled", Some(&alice.token), Some(json!({"enabled": true})), 200)
        .await;
    text(&server, &bob, &room, "master muted").await;
    assert_eq!(unread(&sync(&server, &alice, None, None).await, &room), (0, 0));
    server
        .request(Method::PUT, "/_matrix/client/v3/pushrules/global/override/.m.rule.master/enabled", Some(&alice.token), Some(json!({"enabled": false})), 200)
        .await;
    // A content rule highlights a keyword at word boundaries only.
    server
        .request(
            Method::PUT,
            "/_matrix/client/v3/pushrules/global/content/deploys",
            Some(&alice.token),
            Some(json!({"pattern": "deploy*", "actions": ["notify", {"set_tweak": "highlight"}]})),
            200,
        )
        .await;
    text(&server, &bob, &room, "redeploy soon").await;
    text(&server, &bob, &room, "Deploying now").await;
    assert_eq!(unread(&sync(&server, &alice, None, None).await, &room), (2, 1));
}

#[tokio::test]
async fn thread_notifications_are_split_when_requested() {
    let server = Server::new().await;
    let (alice, bob, _carol, room) = trio(&server).await;
    let root = text(&server, &alice, &room, "thread root").await;
    let thread = |body: &str| json!({
        "msgtype": "m.text", "body": body,
        "m.relates_to": {"rel_type": "m.thread", "event_id": root, "is_falling_back": true, "m.in_reply_to": {"event_id": root}}
    });
    let reply = send(&server, &bob, &room, "m.room.message", thread("in thread")).await;
    send(&server, &bob, &room, "m.room.message", thread("again")).await;
    text(&server, &bob, &room, "main timeline").await;
    // A reaction to a threaded event belongs to the thread (relation hops),
    // but reactions never notify; an edit is suppressed too.
    send(&server, &bob, &room, "m.reaction", json!({"m.relates_to": {"rel_type": "m.annotation", "event_id": reply, "key": "x"}})).await;

    // Without the filter flag, threads fold into the room counts.
    let plain = sync(&server, &alice, None, None).await;
    assert_eq!(unread(&plain, &room), (3, 0));
    assert!(plain["rooms"]["join"][&room].get("unread_thread_notifications").is_none());

    let filter = json!({"room": {"timeline": {"unread_thread_notifications": true}}});
    let split = sync(&server, &alice, None, Some(filter.clone())).await;
    assert_eq!(unread(&split, &room), (1, 0));
    assert_eq!(
        split["rooms"]["join"][&room]["unread_thread_notifications"],
        json!({ root.clone(): {"notification_count": 2, "highlight_count": 0} })
    );

    // A threaded receipt clears only its thread.
    receipt(&server, &alice, &room, &reply, json!({"thread_id": root})).await;
    let split = sync(&server, &alice, None, Some(filter.clone())).await;
    assert_eq!(unread(&split, &room), (1, 0));
    assert_eq!(
        split["rooms"]["join"][&room]["unread_thread_notifications"][&root]["notification_count"],
        1
    );
    // An unthreaded receipt on the newest event clears everything.
    let newest = text(&server, &alice, &room, "mine").await;
    receipt(&server, &alice, &room, &newest, json!({})).await;
    let split = sync(&server, &alice, None, Some(filter)).await;
    assert_eq!(unread(&split, &room), (0, 0));
    assert_eq!(split["rooms"]["join"][&room]["unread_thread_notifications"], json!({}));
}

#[tokio::test]
async fn notifications_endpoint_lists_paginates_and_filters() {
    let server = Server::new().await;
    let (alice, bob, _carol, room) = trio(&server).await;
    // Invites notify the invitee (.m.rule.invite_for_me).
    let dave = user(&server, "dave").await;
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/invite", encode(&room)),
            Some(&alice.token),
            Some(json!({"user_id": dave.id})),
            200,
        )
        .await;
    let invites = server.request(Method::GET, "/_matrix/client/v3/notifications", Some(&dave.token), None, 200).await;
    assert_eq!(invites["notifications"][0]["event"]["type"], "m.room.member");
    assert_eq!(invites["notifications"][0]["event"]["state_key"], dave.id.as_str());

    let first = text(&server, &bob, &room, "one").await;
    let mention = send(&server, &bob, &room, "m.room.message", json!({
        "msgtype": "m.text", "body": "two", "m.mentions": {"user_ids": [alice.id]}
    }))
    .await;
    let third = text(&server, &bob, &room, "three").await;
    receipt(&server, &alice, &room, &mention, json!({})).await;

    let all = server.request(Method::GET, "/_matrix/client/v3/notifications", Some(&alice.token), None, 200).await;
    let list = all["notifications"].as_array().unwrap();
    let ids: Vec<_> = list.iter().map(|n| n["event"]["event_id"].as_str().unwrap()).collect();
    assert_eq!(ids, [third.as_str(), mention.as_str(), first.as_str()], "newest first");
    assert!(all.get("next_token").is_none());
    assert_eq!(list[0]["read"], false);
    assert_eq!(list[1]["read"], true);
    assert_eq!(list[2]["read"], true);
    assert_eq!(list[0]["room_id"], room.as_str());
    assert_eq!(list[0]["actions"], json!(["notify"]));
    assert_eq!(list[1]["actions"][2], json!({"set_tweak": "highlight"}));
    assert!(list[0]["ts"].as_i64().unwrap() > 0);
    assert_eq!(list[0]["event"]["content"]["body"], "three");

    let page = server.request(Method::GET, "/_matrix/client/v3/notifications?limit=2", Some(&alice.token), None, 200).await;
    assert_eq!(page["notifications"].as_array().unwrap().len(), 2);
    let token = page["next_token"].as_str().expect("next_token").to_owned();
    let rest = server
        .request(Method::GET, &format!("/_matrix/client/v3/notifications?limit=2&from={}", encode(&token)), Some(&alice.token), None, 200)
        .await;
    assert_eq!(rest["notifications"].as_array().unwrap().len(), 1);
    assert_eq!(rest["notifications"][0]["event"]["event_id"], first.as_str());
    assert!(rest.get("next_token").is_none());

    let highlights = server.request(Method::GET, "/_matrix/client/v3/notifications?only=highlight", Some(&alice.token), None, 200).await;
    let list = highlights["notifications"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["event"]["event_id"], mention.as_str());

    // Bob is never notified about his own messages.
    let own = server.request(Method::GET, "/_matrix/client/v3/notifications", Some(&bob.token), None, 200).await;
    assert!(own["notifications"].as_array().unwrap().is_empty(), "{own}");

    for query in ["limit=0", "limit=x", "from=abc"] {
        let (status, code) = errcode(&server, Method::GET, &format!("/_matrix/client/v3/notifications?{query}"), &alice, None).await;
        assert_eq!((status, code.as_str()), (400, "M_INVALID_PARAM"), "{query}");
    }
}

// ---------------------------------------------------------------------------
// Pushers and push gateway delivery (conduit-y99.31)
// ---------------------------------------------------------------------------

/// A mock push gateway. Responses are taken from `script` in order, then
/// `200 {"rejected": []}`.
#[derive(Clone, Default)]
struct Gateway {
    received: Arc<Mutex<Vec<Value>>>,
    script: Arc<Mutex<Vec<(u16, Value)>>>,
}

async fn notify(State(gateway): State<Gateway>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    gateway.received.lock().unwrap().push(body);
    let next = {
        let mut script = gateway.script.lock().unwrap();
        if script.is_empty() { None } else { Some(script.remove(0)) }
    };
    let (status, body) = next.unwrap_or((200, json!({"rejected": []})));
    (StatusCode::from_u16(status).unwrap(), Json(body))
}

impl Gateway {
    async fn start() -> (Self, String) {
        let gateway = Gateway::default();
        let app = Router::new().route("/_matrix/push/v1/notify", post(notify)).with_state(gateway.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (gateway, format!("http://{address}/_matrix/push/v1/notify"))
    }

    fn script(&self, responses: Vec<(u16, Value)>) {
        *self.script.lock().unwrap() = responses;
    }

    fn for_event(&self, event_id: &str) -> Vec<Value> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|n| n["notification"]["event_id"] == event_id)
            .cloned()
            .collect()
    }

    async fn wait_for(&self, event_id: &str, count: usize) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let got = self.for_event(event_id);
            if got.len() >= count {
                return got;
            }
            assert!(Instant::now() < deadline, "gateway got {} of {count} for {event_id}", got.len());
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

fn pusher(url: &str, pushkey: &str, extra_data: Value) -> Value {
    let mut data = json!({"url": url});
    for (k, v) in extra_data.as_object().unwrap() {
        data[k] = v.clone();
    }
    json!({
        "pushkey": pushkey, "kind": "http", "app_id": "org.example.app",
        "app_display_name": "Example", "device_display_name": "Phone", "lang": "en",
        "profile_tag": "tag", "data": data
    })
}

async fn set_pusher(server: &Server, who: &User, body: Value) {
    server
        .request(Method::POST, "/_matrix/client/v3/pushers/set", Some(&who.token), Some(body), 200)
        .await;
}

#[tokio::test]
async fn pushers_set_validates_appends_and_deletes() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let url = "https://push.example.org/_matrix/push/v1/notify";
    let path = "/_matrix/client/v3/pushers/set";

    for (body, expected) in [
        (json!({"app_id": "a", "kind": "http"}), (400, "M_MISSING_PARAM")),
        (json!({"pushkey": "k", "app_id": "a"}), (400, "M_MISSING_PARAM")),
        (json!({"pushkey": "k", "app_id": "a", "kind": "http", "lang": "en", "data": {"url": url}}), (400, "M_MISSING_PARAM")),
        (json!({"pushkey": "k", "app_id": "a", "kind": "http", "app_display_name": "A", "device_display_name": "D", "lang": "en", "data": {}}), (400, "M_MISSING_PARAM")),
        (pusher("https://push.example.org/elsewhere", "k", json!({})), (400, "M_INVALID_PARAM")),
        (pusher("not a url", "k", json!({})), (400, "M_INVALID_PARAM")),
        (pusher(url, "k", json!({"format": "full"})), (400, "M_INVALID_PARAM")),
        (pusher(url, &"k".repeat(513), json!({})), (400, "M_INVALID_PARAM")),
        ({ let mut p = pusher(url, "k", json!({})); p["app_id"] = json!("a".repeat(65)); p }, (400, "M_INVALID_PARAM")),
        ({ let mut p = pusher(url, "k", json!({})); p["kind"] = json!("email"); p }, (400, "M_INVALID_PARAM")),
    ] {
        let (status, code) = errcode(&server, Method::POST, path, &alice, Some(body.clone())).await;
        assert_eq!((status, code.as_str()), expected, "{body}");
    }

    set_pusher(&server, &alice, pusher(url, "shared", json!({"format": "event_id_only", "custom": 1}))).await;
    let listed = server.request(Method::GET, "/_matrix/client/v3/pushers", Some(&alice.token), None, 200).await;
    assert_eq!(
        listed["pushers"],
        json!([{
            "pushkey": "shared", "kind": "http", "app_id": "org.example.app", "app_display_name": "Example",
            "device_display_name": "Phone", "lang": "en", "profile_tag": "tag",
            "data": {"url": url, "format": "event_id_only", "custom": 1}
        }])
    );
    // append: true keeps other users' pushers with the same key...
    set_pusher(&server, &bob, { let mut p = pusher(url, "shared", json!({})); p["append"] = json!(true); p }).await;
    let alice_list = server.request(Method::GET, "/_matrix/client/v3/pushers", Some(&alice.token), None, 200).await;
    assert_eq!(alice_list["pushers"].as_array().unwrap().len(), 1);
    // ...append: false (the default) takes the key over.
    set_pusher(&server, &bob, pusher(url, "shared", json!({}))).await;
    let alice_list = server.request(Method::GET, "/_matrix/client/v3/pushers", Some(&alice.token), None, 200).await;
    assert!(alice_list["pushers"].as_array().unwrap().is_empty());
    let bob_list = server.request(Method::GET, "/_matrix/client/v3/pushers", Some(&bob.token), None, 200).await;
    assert_eq!(bob_list["pushers"].as_array().unwrap().len(), 1);
    // kind: null deletes.
    set_pusher(&server, &bob, json!({"pushkey": "shared", "app_id": "org.example.app", "kind": null})).await;
    let bob_list = server.request(Method::GET, "/_matrix/client/v3/pushers", Some(&bob.token), None, 200).await;
    assert!(bob_list["pushers"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn gateway_receives_spec_notify_payloads() {
    let server = Server::new().await;
    let (gateway, url) = Gateway::start().await;
    let (alice, bob, _carol, room) = trio(&server).await;
    server
        .request(Method::PUT, &format!("/_matrix/client/v3/profile/{}/displayname", encode(&bob.id)), Some(&bob.token), Some(json!({"displayname": "Bobby"})), 200)
        .await;
    set_pusher(&server, &alice, pusher(&url, "full-key", json!({"custom": "x"}))).await;
    set_pusher(&server, &alice, pusher(&url, "slim-key", json!({"format": "event_id_only"}))).await;

    let event = send(&server, &bob, &room, "m.room.message", json!({
        "msgtype": "m.text", "body": "ping", "m.mentions": {"user_ids": [alice.id]}
    }))
    .await;
    let got = gateway.wait_for(&event, 2).await;
    let full = got.iter().find(|n| n["notification"]["devices"][0]["pushkey"] == "full-key").unwrap();
    let n = &full["notification"];
    assert_eq!(n["event_id"], event.as_str());
    assert_eq!(n["room_id"], room.as_str());
    assert_eq!(n["type"], "m.room.message");
    assert_eq!(n["sender"], bob.id.as_str());
    assert_eq!(n["sender_display_name"], "Bobby");
    assert_eq!(n["room_name"], "Ops");
    assert_eq!(n["content"]["body"], "ping");
    assert_eq!(n["counts"], json!({"unread": 1}));
    assert_eq!(n["prio"], "high");
    let device = &n["devices"][0];
    assert_eq!(device["app_id"], "org.example.app");
    assert!(device["pushkey_ts"].as_i64().unwrap() > 1_600_000_000);
    assert_eq!(device["data"], json!({"custom": "x"}), "url is stripped, custom keys forwarded");
    assert_eq!(device["tweaks"], json!({"sound": "default", "highlight": true}));

    let slim = got.iter().find(|n| n["notification"]["devices"][0]["pushkey"] == "slim-key").unwrap();
    let n = slim["notification"].as_object().unwrap();
    let mut keys: Vec<_> = n.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["counts", "devices", "event_id", "prio", "room_id"]);
    assert_eq!(n["devices"][0]["data"], json!({"format": "event_id_only"}));

    // Counts track unread notifications; tweak-less messages are low priority.
    let second = text(&server, &bob, &room, "again").await;
    let got = gateway.wait_for(&second, 2).await;
    assert_eq!(got[0]["notification"]["counts"], json!({"unread": 2}));
    assert_eq!(got[0]["notification"]["prio"], "low");
    assert_eq!(got[0]["notification"]["devices"][0]["tweaks"], json!({}));

    // No push for the user's own events or for non-notifying events.
    let own = text(&server, &alice, &room, "mine").await;
    let notice = send(&server, &bob, &room, "m.room.message", json!({"msgtype": "m.notice", "body": "bot"})).await;
    let marker = text(&server, &bob, &room, "marker").await;
    gateway.wait_for(&marker, 2).await;
    assert!(gateway.for_event(&own).is_empty());
    assert!(gateway.for_event(&notice).is_empty());
}

#[tokio::test]
async fn gateway_failures_retry_and_rejected_pushkeys_remove_pushers() {
    let server = Server::with_env(&[("CONDUIT_PUSH_RETRY_BASE_MS", "50")]).await;
    let (gateway, url) = Gateway::start().await;
    let (alice, bob, _carol, room) = trio(&server).await;
    set_pusher(&server, &alice, pusher(&url, "flaky", json!({}))).await;

    // 5xx is retried with backoff until the gateway accepts.
    gateway.script(vec![(500, json!({})), (503, json!({}))]);
    let event = text(&server, &bob, &room, "retry me").await;
    let attempts = gateway.wait_for(&event, 3).await;
    assert_eq!(attempts.len(), 3);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(gateway.for_event(&event).len(), 3, "delivered once accepted, no further retries");

    // A 4xx refusal is permanent for that notification.
    gateway.script(vec![(400, json!({"errcode": "M_BAD_JSON"}))]);
    let refused = text(&server, &bob, &room, "refused").await;
    gateway.wait_for(&refused, 1).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(gateway.for_event(&refused).len(), 1);

    // A pushkey listed in `rejected` loses its pusher.
    gateway.script(vec![(200, json!({"rejected": ["flaky"]}))]);
    let rejected = text(&server, &bob, &room, "rejected").await;
    gateway.wait_for(&rejected, 1).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let list = server.request(Method::GET, "/_matrix/client/v3/pushers", Some(&alice.token), None, 200).await;
        if list["pushers"].as_array().unwrap().is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "rejected pusher not removed: {list}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let after = text(&server, &bob, &room, "after removal").await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(gateway.for_event(&after).is_empty(), "no requests for removed pushkeys");
}
