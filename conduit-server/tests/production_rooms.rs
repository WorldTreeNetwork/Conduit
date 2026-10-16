//! Room content journeys (conduit-y99.19) through the shipped binary and a
//! real PostgreSQL: single events, members, context, redaction, forget,
//! read markers, tags, relations, threads, timestamp lookup, search,
//! reports, upgrades, space hierarchy and ignored users.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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

async fn get(server: &Server, who: &User, path: &str, status: u16) -> Value {
    server.request(Method::GET, path, Some(&who.token), None, status).await
}

async fn post(server: &Server, who: &User, path: &str, body: Value, status: u16) -> Value {
    server.request(Method::POST, path, Some(&who.token), Some(body), status).await
}

async fn put(server: &Server, who: &User, path: &str, body: Value, status: u16) -> Value {
    server.request(Method::PUT, path, Some(&who.token), Some(body), status).await
}

async fn create_room(server: &Server, who: &User, body: Value) -> String {
    post(server, who, "/_matrix/client/v3/createRoom", body, 200).await["room_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn join(server: &Server, who: &User, room: &str) {
    post(server, who, &format!("/_matrix/client/v3/join/{room}"), json!({}), 200).await;
}

async fn leave(server: &Server, who: &User, room: &str) {
    post(server, who, &format!("/_matrix/client/v3/rooms/{room}/leave"), json!({}), 200).await;
}

async fn send(server: &Server, who: &User, room: &str, kind: &str, content: Value) -> String {
    let txn = TXN.fetch_add(1, Ordering::SeqCst);
    let path = format!("/_matrix/client/v3/rooms/{room}/send/{kind}/t{txn}");
    put(server, who, &path, content, 200).await["event_id"].as_str().unwrap().to_owned()
}

async fn text(server: &Server, who: &User, room: &str, body: &str) -> String {
    send(server, who, room, "m.room.message", json!({"msgtype": "m.text", "body": body})).await
}

async fn state(server: &Server, who: &User, room: &str, kind: &str, key: &str, content: Value) -> String {
    let path = if key.is_empty() {
        format!("/_matrix/client/v3/rooms/{room}/state/{kind}")
    } else {
        format!("/_matrix/client/v3/rooms/{room}/state/{kind}/{key}")
    };
    put(server, who, &path, content, 200).await["event_id"].as_str().unwrap().to_owned()
}

fn ids(events: &Value) -> Vec<String> {
    events
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_owned())
        .collect()
}

async fn make_admin(server: &Server, who: &User) {
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    sqlx::query("UPDATE accounts SET is_admin = true WHERE user_id = $1")
        .bind(&who.id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

async fn sync(server: &Server, who: &User, query: &str) -> Value {
    get(server, who, &format!("/_matrix/client/v3/sync?timeout=0{query}"), 200).await
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn events_members_context_and_joined_rooms() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let carol = user(&server, "carol").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat"})).await;
    let before_bob = sync(&server, &alice, "").await["next_batch"].as_str().unwrap().to_owned();
    join(&server, &bob, &room).await;
    let mut messages = Vec::new();
    for n in 1..=5 {
        messages.push(text(&server, &alice, &room, &format!("message {n}")).await);
    }

    // GET /event: client format, 404 for unknown and for non-members alike.
    let event = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/event/{}", messages[0]), 200).await;
    assert_eq!(event["content"]["body"], "message 1");
    assert_eq!(event["room_id"], room.as_str());
    assert!(event["unsigned"]["age"].is_u64());
    for pdu_field in ["hashes", "signatures", "auth_events", "prev_events", "depth"] {
        assert!(event.get(pdu_field).is_none(), "client format must not expose {pdu_field}");
    }
    let missing = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/event/$nope"), 404).await;
    assert_eq!(missing["errcode"], "M_NOT_FOUND");
    let hidden = get(&server, &carol, &format!("/_matrix/client/v3/rooms/{room}/event/{}", messages[0]), 404).await;
    assert_eq!(hidden["errcode"], "M_NOT_FOUND");

    // GET /joined_rooms.
    let joined = get(&server, &bob, "/_matrix/client/v3/joined_rooms", 200).await;
    assert_eq!(joined["joined_rooms"], json!([room]));
    assert_eq!(get(&server, &carol, "/_matrix/client/v3/joined_rooms", 200).await["joined_rooms"], json!([]));

    // GET /members with membership filters and `at`.
    let members = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/members"), 200).await;
    let mut member_ids: Vec<_> = members["chunk"].as_array().unwrap().iter().map(|m| m["state_key"].clone()).collect();
    member_ids.sort_by_key(|id| id.to_string());
    assert_eq!(member_ids, vec![json!(alice.id), json!(bob.id)]);
    assert!(members["chunk"].as_array().unwrap().iter().all(|m| m["type"] == "m.room.member"));
    let none = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/members?not_membership=join"), 200).await;
    assert_eq!(none["chunk"], json!([]));
    let invalid = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/members?membership=lurk"), 400).await;
    assert_eq!(invalid["errcode"], "M_INVALID_PARAM");
    let earlier = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/members?at={before_bob}"), 200).await;
    assert_eq!(ids(&earlier["chunk"]).len(), 1);
    assert_eq!(earlier["chunk"][0]["state_key"], alice.id.as_str());
    let forbidden = get(&server, &carol, &format!("/_matrix/client/v3/rooms/{room}/members"), 403).await;
    assert_eq!(forbidden["errcode"], "M_FORBIDDEN");

    // GET /context: reverse-chronological before, chronological after,
    // tokens usable with /messages.
    let context = get(
        &server,
        &bob,
        &format!("/_matrix/client/v3/rooms/{room}/context/{}?limit=4", messages[2]),
        200,
    )
    .await;
    assert_eq!(context["event"]["event_id"], messages[2].as_str());
    assert_eq!(ids(&context["events_before"]), vec![messages[1].clone(), messages[0].clone()]);
    assert_eq!(ids(&context["events_after"]), vec![messages[3].clone(), messages[4].clone()]);
    assert!(context["state"].as_array().unwrap().iter().any(|s| s["type"] == "m.room.create"));
    let start = context["start"].as_str().unwrap();
    let older = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1&from={start}"), 200).await;
    assert_eq!(older["chunk"][0]["type"], "m.room.member", "bob's join precedes message 1");
    let end = context["end"].as_str().unwrap();
    let newer_id = text(&server, &alice, &room, "message 6").await;
    let newer = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/messages?dir=f&limit=1&from={end}"), 200).await;
    assert_eq!(ids(&newer["chunk"]), vec![newer_id.clone()]);

    // Filtered context with lazy-loaded members only names the senders.
    let filter = encode(r#"{"types":["m.room.message"],"lazy_load_members":true}"#);
    let filtered = get(
        &server,
        &bob,
        &format!("/_matrix/client/v3/rooms/{room}/context/{}?limit=2&filter={filter}", messages[2]),
        200,
    )
    .await;
    let state_types: Vec<_> = filtered["state"].as_array().unwrap().iter().map(|s| s["type"].clone()).collect();
    assert!(state_types.is_empty(), "a types filter applies to state too: {state_types:?}");
    let filter = encode(r#"{"lazy_load_members":true}"#);
    let lazy = get(
        &server,
        &bob,
        &format!("/_matrix/client/v3/rooms/{room}/context/{}?limit=2&filter={filter}", messages[2]),
        200,
    )
    .await;
    let lazy_members: Vec<_> = lazy["state"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["type"] == "m.room.member")
        .map(|s| s["state_key"].clone())
        .collect();
    assert_eq!(lazy_members, vec![json!(alice.id)], "only senders' members are lazy-loaded");
    let not_visible = get(&server, &carol, &format!("/_matrix/client/v3/rooms/{room}/context/{}", messages[2]), 404).await;
    assert_eq!(not_visible["errcode"], "M_NOT_FOUND");

    // A departed member keeps pre-departure history and members only.
    leave(&server, &bob, &room).await;
    let after_leave = text(&server, &alice, &room, "after bob left").await;
    get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/event/{}", messages[0]), 200).await;
    get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/event/{after_leave}"), 404).await;
    let departed = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/members"), 200).await;
    let bob_member = departed["chunk"].as_array().unwrap().iter().find(|m| m["state_key"] == bob.id.as_str()).unwrap();
    assert_eq!(bob_member["content"]["membership"], "leave");
    join(&server, &carol, &room).await;
    let still = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/members"), 200).await;
    assert!(
        !still["chunk"].as_array().unwrap().iter().any(|m| m["state_key"] == carol.id.as_str()),
        "members after a departure are not visible to the departed user"
    );
}

#[tokio::test]
async fn redaction_permissions_idempotency_and_serving() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let carol = user(&server, "carol").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat"})).await;
    join(&server, &bob, &room).await;
    let since = sync(&server, &bob, "").await["next_batch"].as_str().unwrap().to_owned();
    let bob_own = text(&server, &bob, &room, "bob regrets this").await;
    let bob_other = text(&server, &bob, &room, "moderated").await;
    let alice_msg = text(&server, &alice, &room, "alice speaks").await;

    // Own event: allowed, and idempotent per transaction ID.
    let path = format!("/_matrix/client/v3/rooms/{room}/redact/{bob_own}/r1");
    let first = put(&server, &bob, &path, json!({"reason": "typo"}), 200).await;
    let again = put(&server, &bob, &path, json!({"reason": "typo"}), 200).await;
    assert_eq!(first["event_id"], again["event_id"]);
    let redaction_id = first["event_id"].as_str().unwrap().to_owned();

    // Another user's event needs the redact level.
    let denied = put(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/redact/{alice_msg}/r2"), json!({}), 403).await;
    assert_eq!(denied["errcode"], "M_FORBIDDEN");
    let via_send = put(
        &server,
        &bob,
        &format!("/_matrix/client/v3/rooms/{room}/send/m.room.redaction/r3"),
        json!({"redacts": alice_msg}),
        403,
    )
    .await;
    assert_eq!(via_send["errcode"], "M_FORBIDDEN", "/send obeys the same redaction rules");
    put(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/redact/{bob_other}/r4"), json!({}), 200).await;
    let unknown = put(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/redact/$missing/r5"), json!({}), 404).await;
    assert_eq!(unknown["errcode"], "M_NOT_FOUND");

    // Served redacted, with redacted_because, everywhere.
    let served = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/event/{bob_own}"), 200).await;
    assert_eq!(served["content"], json!({}));
    assert_eq!(served["unsigned"]["redacted_because"]["event_id"], redaction_id.as_str());
    assert_eq!(served["unsigned"]["redacted_because"]["content"]["reason"], "typo");
    assert_eq!(served["unsigned"]["redacted_because"]["content"]["redacts"], bob_own.as_str());
    let page = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=20"), 200).await;
    let in_messages = page["chunk"].as_array().unwrap().iter().find(|e| e["event_id"] == bob_own.as_str()).unwrap();
    assert_eq!(in_messages["content"], json!({}));
    assert_eq!(in_messages["unsigned"]["redacted_because"]["event_id"], redaction_id.as_str());
    let redaction_event = page["chunk"].as_array().unwrap().iter().find(|e| e["event_id"] == redaction_id.as_str()).unwrap();
    assert_eq!(redaction_event["redacts"], bob_own.as_str(), "top-level redacts for older clients");
    let delta = sync(&server, &bob, &format!("&since={since}")).await;
    let timeline = &delta["rooms"]["join"][&room]["timeline"]["events"];
    let synced = timeline.as_array().unwrap().iter().find(|e| e["event_id"] == bob_own.as_str()).unwrap();
    assert_eq!(synced["content"], json!({}));
    assert_eq!(synced["unsigned"]["redacted_because"]["event_id"], redaction_id.as_str());
    let kept = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/event/{alice_msg}"), 200).await;
    assert_eq!(kept["content"]["body"], "alice speaks");

    // A server administrator may redact local users' events without power.
    make_admin(&server, &carol).await;
    join(&server, &carol, &room).await;
    let alice_second = text(&server, &alice, &room, "admin target").await;
    put(&server, &carol, &format!("/_matrix/client/v3/rooms/{room}/redact/{alice_second}/r6"), json!({}), 200).await;
    let gone = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/event/{alice_second}"), 200).await;
    assert_eq!(gone["content"], json!({}));
}

#[tokio::test]
async fn forget_hides_departed_rooms_until_rejoin() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat"})).await;
    join(&server, &bob, &room).await;
    let message = text(&server, &alice, &room, "remember me").await;

    let joined = post(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/forget"), json!({}), 400).await;
    assert_eq!(joined["errcode"], "M_UNKNOWN");
    leave(&server, &bob, &room).await;
    let with_leave = sync(&server, &bob, "&filter=%7B%22room%22%3A%7B%22include_leave%22%3Atrue%7D%7D").await;
    assert!(with_leave["rooms"]["leave"].get(&room).is_some());
    get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/event/{message}"), 200).await;

    post(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/forget"), json!({}), 200).await;
    let forgotten = sync(&server, &bob, "&filter=%7B%22room%22%3A%7B%22include_leave%22%3Atrue%7D%7D").await;
    assert!(forgotten["rooms"]["leave"].get(&room).is_none(), "forgotten rooms are excluded from sync");
    get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/event/{message}"), 404).await;
    get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/members"), 403).await;

    // Rejoining un-forgets; forgetting an unknown room is a no-op.
    join(&server, &bob, &room).await;
    get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/event/{message}"), 200).await;
    post(&server, &bob, "/_matrix/client/v3/rooms/!unknown:production.test/forget", json!({}), 200).await;
}

#[tokio::test]
async fn read_markers_and_room_tags() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat"})).await;
    join(&server, &bob, &room).await;
    let first = text(&server, &alice, &room, "one").await;
    let second = text(&server, &alice, &room, "two").await;
    let since = sync(&server, &bob, "").await["next_batch"].as_str().unwrap().to_owned();

    post(
        &server,
        &bob,
        &format!("/_matrix/client/v3/rooms/{room}/read_markers"),
        json!({"m.fully_read": first, "m.read": second, "m.read.private": second}),
        200,
    )
    .await;
    let marker = get(
        &server,
        &bob,
        &format!("/_matrix/client/v3/user/{}/rooms/{room}/account_data/m.fully_read", bob.id),
        200,
    )
    .await;
    assert_eq!(marker["event_id"], first.as_str());
    let unknown = post(
        &server,
        &bob,
        &format!("/_matrix/client/v3/rooms/{room}/read_markers"),
        json!({"m.fully_read": "$missing"}),
        404,
    )
    .await;
    assert_eq!(unknown["errcode"], "M_NOT_FOUND");

    // Tags.
    let tags_path = format!("/_matrix/client/v3/user/{}/rooms/{room}/tags", bob.id);
    put(&server, &bob, &format!("{tags_path}/u.work"), json!({"order": 0.5}), 200).await;
    put(&server, &bob, &format!("{tags_path}/m.favourite"), json!({}), 200).await;
    let bad = put(&server, &bob, &format!("{tags_path}/u.bad"), json!({"order": "first"}), 400).await;
    assert_eq!(bad["errcode"], "M_BAD_JSON");
    let tags = get(&server, &bob, &tags_path, 200).await;
    assert_eq!(tags["tags"], json!({"u.work": {"order": 0.5}, "m.favourite": {}}));
    let other = get(&server, &alice, &tags_path, 403).await;
    assert_eq!(other["errcode"], "M_FORBIDDEN");

    let delta = sync(&server, &bob, &format!("&since={since}")).await;
    let joined = &delta["rooms"]["join"][&room];
    let account_data = joined["account_data"]["events"].as_array().unwrap();
    assert!(account_data.iter().any(|e| e["type"] == "m.fully_read" && e["content"]["event_id"] == first.as_str()));
    assert!(account_data.iter().any(|e| e["type"] == "m.tag" && e["content"]["tags"]["u.work"]["order"] == 0.5));
    let receipt = joined["ephemeral"]["events"].as_array().unwrap().iter().find(|e| e["type"] == "m.receipt").unwrap();
    assert!(receipt["content"][&second]["m.read"].get(&bob.id).is_some());
    assert!(receipt["content"][&second]["m.read.private"].get(&bob.id).is_some());

    // Alice sees the public receipt but never the private one.
    let alice_view = sync(&server, &alice, "").await;
    let receipts: Vec<_> = alice_view["rooms"]["join"][&room]["ephemeral"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "m.receipt")
        .cloned()
        .collect();
    assert!(receipts.iter().all(|e| e["content"][&second].get("m.read.private").is_none()));

    server.request(Method::DELETE, &format!("{tags_path}/u.work"), Some(&bob.token), None, 200).await;
    server.request(Method::DELETE, &format!("{tags_path}/u.never"), Some(&bob.token), None, 200).await;
    let tags = get(&server, &bob, &tags_path, 200).await;
    assert_eq!(tags["tags"], json!({"m.favourite": {}}));
}

#[tokio::test]
async fn relations_threads_and_edit_aggregation() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let carol = user(&server, "carol").await;
    let outsider = user(&server, "dave").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat"})).await;
    join(&server, &bob, &room).await;
    join(&server, &carol, &room).await;
    let root = text(&server, &alice, &room, "thread root").await;
    let thread = |body: &str| {
        json!({"msgtype": "m.text", "body": body, "m.relates_to": {"rel_type": "m.thread", "event_id": root}})
    };
    let t1 = send(&server, &bob, &room, "m.room.message", thread("first reply")).await;
    let t2 = send(&server, &bob, &room, "m.room.message", thread("second reply")).await;
    let edit = |body: &str| {
        json!({"msgtype": "m.text", "body": format!("* {body}"), "m.new_content": {"msgtype": "m.text", "body": body},
               "m.relates_to": {"rel_type": "m.replace", "event_id": root}})
    };
    let _e1 = send(&server, &alice, &room, "m.room.message", edit("edited once")).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    let e2 = send(&server, &alice, &room, "m.room.message", edit("edited twice")).await;
    let forged = send(&server, &bob, &room, "m.room.message", edit("not yours")).await;
    let reaction = send(&server, &bob, &room, "m.reaction", json!({"m.relates_to": {"rel_type": "m.annotation", "event_id": root, "key": "👍"}})).await;
    let nested = send(&server, &carol, &room, "m.room.message", json!({"body": "ref", "m.relates_to": {"rel_type": "m.reference", "event_id": t1}})).await;

    // All direct children, newest first.
    let all = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/relations/{root}"), 200).await;
    assert_eq!(ids(&all["chunk"]), vec![reaction.clone(), forged.clone(), e2.clone(), _e1.clone(), t2.clone(), t1.clone()]);
    assert!(all.get("recursion_depth").is_none(), "absent unless recurse was supplied");
    let threads_only = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/relations/{root}/m.thread"), 200).await;
    assert_eq!(ids(&threads_only["chunk"]), vec![t2.clone(), t1.clone()]);
    let reactions = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/relations/{root}/m.annotation/m.reaction"), 200).await;
    assert_eq!(ids(&reactions["chunk"]), vec![reaction.clone()]);
    let none = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/relations/{root}/m.thread/m.reaction"), 200).await;
    assert_eq!(none["chunk"], json!([]));

    // Pagination both ways.
    let page1 = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/relations/{root}/m.thread?limit=1"), 200).await;
    assert_eq!(ids(&page1["chunk"]), vec![t2.clone()]);
    let next = page1["next_batch"].as_str().unwrap();
    let page2 = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/relations/{root}/m.thread?limit=1&from={next}"), 200).await;
    assert_eq!(ids(&page2["chunk"]), vec![t1.clone()]);
    assert!(page2.get("next_batch").is_none());
    assert_eq!(page2["prev_batch"], next);
    let forward = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/relations/{root}/m.thread?dir=f"), 200).await;
    assert_eq!(ids(&forward["chunk"]), vec![t1.clone(), t2.clone()]);
    let bad_dir = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/relations/{root}?dir=x"), 400).await;
    assert_eq!(bad_dir["errcode"], "M_INVALID_PARAM");

    // recurse follows children of children.
    let deep = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/relations/{root}?recurse=true"), 200).await;
    assert!(ids(&deep["chunk"]).contains(&nested));
    assert_eq!(deep["recursion_depth"], 3);
    let shallow = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/relations/{root}?recurse=false"), 200).await;
    assert!(!ids(&shallow["chunk"]).contains(&nested));
    assert_eq!(shallow["recursion_depth"], 1);
    let hidden = get(&server, &outsider, &format!("/_matrix/client/v1/rooms/{room}/relations/{root}"), 404).await;
    assert_eq!(hidden["errcode"], "M_NOT_FOUND");

    // Bundled aggregations on the root.
    let served = get(&server, &carol, &format!("/_matrix/client/v3/rooms/{room}/event/{root}"), 200).await;
    assert_eq!(served["content"]["body"], "thread root", "edited content is never replaced");
    let relations = &served["unsigned"]["m.relations"];
    assert_eq!(relations["m.replace"]["event_id"], e2.as_str(), "latest valid edit; bob's forgery ignored");
    assert_eq!(relations["m.thread"]["count"], 2);
    assert_eq!(relations["m.thread"]["latest_event"]["event_id"], t2.as_str());
    assert_eq!(relations["m.thread"]["current_user_participated"], false);
    assert!(relations.get("m.annotation").is_none(), "annotations are not aggregated");
    let as_bob = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/event/{root}"), 200).await;
    assert_eq!(as_bob["unsigned"]["m.relations"]["m.thread"]["current_user_participated"], true);
    let referenced = get(&server, &carol, &format!("/_matrix/client/v3/rooms/{room}/event/{t1}"), 200).await;
    assert_eq!(referenced["unsigned"]["m.relations"]["m.reference"]["chunk"], json!([{"event_id": nested}]));

    // Redacting the latest edit reverts the aggregation to the previous one.
    put(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/redact/{e2}/x1"), json!({}), 200).await;
    let reverted = get(&server, &carol, &format!("/_matrix/client/v3/rooms/{room}/event/{root}"), 200).await;
    assert_eq!(reverted["unsigned"]["m.relations"]["m.replace"]["event_id"], _e1.as_str());

    // /threads lists roots by latest activity, with bundles.
    let other_root = text(&server, &carol, &room, "second thread").await;
    let t3 = send(&server, &carol, &room, "m.room.message", json!({"body": "x", "m.relates_to": {"rel_type": "m.thread", "event_id": other_root}})).await;
    let threads = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/threads"), 200).await;
    assert_eq!(ids(&threads["chunk"]), vec![other_root.clone(), root.clone()]);
    assert_eq!(threads["chunk"][0]["unsigned"]["m.relations"]["m.thread"]["latest_event"]["event_id"], t3.as_str());
    let first = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/threads?limit=1"), 200).await;
    assert_eq!(ids(&first["chunk"]), vec![other_root.clone()]);
    let from = first["next_batch"].as_str().unwrap();
    let rest = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/threads?limit=1&from={from}"), 200).await;
    assert_eq!(ids(&rest["chunk"]), vec![root.clone()]);
    let mine = get(&server, &bob, &format!("/_matrix/client/v1/rooms/{room}/threads?include=participated"), 200).await;
    assert_eq!(ids(&mine["chunk"]), vec![root.clone()]);
    let alices = get(&server, &alice, &format!("/_matrix/client/v1/rooms/{room}/threads?include=participated"), 200).await;
    assert_eq!(ids(&alices["chunk"]), vec![root.clone()], "the root's sender participates");
    // Send-time rules: no duplicate annotations, no threads off relations.
    let duplicate = put(
        &server,
        &bob,
        &format!("/_matrix/client/v3/rooms/{room}/send/m.reaction/dup1"),
        json!({"m.relates_to": {"rel_type": "m.annotation", "event_id": root, "key": "👍"}}),
        400,
    )
    .await;
    assert_eq!(duplicate["errcode"], "M_DUPLICATE_ANNOTATION");
    let other_key = send(&server, &bob, &room, "m.reaction", json!({"m.relates_to": {"rel_type": "m.annotation", "event_id": root, "key": "🎉"}})).await;
    put(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/redact/{reaction}/unreact"), json!({}), 200).await;
    send(&server, &bob, &room, "m.reaction", json!({"m.relates_to": {"rel_type": "m.annotation", "event_id": root, "key": "👍"}})).await;
    assert_ne!(other_key, reaction);
    let nested_thread = put(
        &server,
        &carol,
        &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/nest1"),
        json!({"body": "x", "m.relates_to": {"rel_type": "m.thread", "event_id": t1}}),
        400,
    )
    .await;
    assert_eq!(nested_thread["errcode"], "M_UNKNOWN");

    let bad = get(&server, &carol, &format!("/_matrix/client/v1/rooms/{room}/threads?include=some"), 400).await;
    assert_eq!(bad["errcode"], "M_INVALID_PARAM");
    let outside = get(&server, &outsider, &format!("/_matrix/client/v1/rooms/{room}/threads"), 403).await;
    assert_eq!(outside["errcode"], "M_FORBIDDEN");
}

#[tokio::test]
async fn timestamp_to_event_finds_nearest_visible_event() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let outsider = user(&server, "bob").await;
    let room = create_room(&server, &alice, json!({"preset": "private_chat"})).await;
    let mut events = Vec::new();
    for n in 0..3 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        events.push(text(&server, &alice, &room, &format!("tick {n}")).await);
    }
    let middle = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/event/{}", events[1]), 200).await;
    let ts = middle["origin_server_ts"].as_u64().unwrap();
    let path = |query: &str| format!("/_matrix/client/v1/rooms/{room}/timestamp_to_event?{query}");
    let forward = get(&server, &alice, &path(&format!("ts={ts}&dir=f")), 200).await;
    assert_eq!(forward["event_id"], events[1].as_str());
    assert_eq!(forward["origin_server_ts"], ts);
    let backward = get(&server, &alice, &path(&format!("ts={}&dir=b", ts + 1)), 200).await;
    assert_eq!(backward["event_id"], events[1].as_str());
    let after = get(&server, &alice, &path(&format!("ts={}&dir=f", ts + 1)), 200).await;
    assert_eq!(after["event_id"], events[2].as_str());
    let future = get(&server, &alice, &path(&format!("ts={}&dir=f", ts + 3_600_000)), 404).await;
    assert_eq!(future["errcode"], "M_NOT_FOUND");
    let no_dir = get(&server, &alice, &path(&format!("ts={ts}")), 400).await;
    assert_eq!(no_dir["errcode"], "M_INVALID_PARAM");
    let denied = get(&server, &outsider, &path(&format!("ts={ts}&dir=f")), 403).await;
    assert_eq!(denied["errcode"], "M_FORBIDDEN");
}

#[tokio::test]
async fn search_room_events_with_ordering_context_and_groupings() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let outsider = user(&server, "carol").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat", "name": "Fox Den"})).await;
    join(&server, &bob, &room).await;
    state(&server, &bob, &room, "m.room.member", &bob.id, json!({"membership": "join", "displayname": "Bobby"})).await;
    let quick = text(&server, &alice, &room, "the quick brown fox").await;
    let lazy = text(&server, &bob, &room, "lazy dogs sleeping").await;
    let secret = text(&server, &bob, &room, "fox secret to redact").await;
    put(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/redact/{secret}/s1"), json!({}), 200).await;
    let other_room = create_room(&server, &alice, json!({"preset": "private_chat"})).await;
    let elsewhere = text(&server, &alice, &other_room, "another fox elsewhere").await;

    let search = |criteria: Value| json!({"search_categories": {"room_events": criteria}});
    let result = post(&server, &bob, "/_matrix/client/v3/search", search(json!({"search_term": "fox"})), 200).await;
    let events = &result["search_categories"]["room_events"];
    let found: Vec<_> = events["results"].as_array().unwrap().iter().map(|r| r["result"]["event_id"].clone()).collect();
    assert_eq!(events["count"], 2, "message and room name; redacted and invisible rooms excluded: {found:?}");
    assert!(found.contains(&json!(quick)));
    assert!(!found.contains(&json!(secret)) && !found.contains(&json!(elsewhere)));
    assert!(events["results"].as_array().unwrap().iter().all(|r| r["rank"].is_number()));
    assert_eq!(events["highlights"], json!(["fox"]));

    let body_only = post(&server, &bob, "/_matrix/client/v3/search", search(json!({"search_term": "fox", "keys": ["content.body"]})), 200).await;
    assert_eq!(body_only["search_categories"]["room_events"]["count"], 1);
    let stemmed = post(&server, &bob, "/_matrix/client/v3/search", search(json!({"search_term": "sleep"})), 200).await;
    assert_eq!(stemmed["search_categories"]["room_events"]["results"][0]["result"]["event_id"], lazy.as_str());

    // Ordering and pagination.
    let recent = post(&server, &bob, "/_matrix/client/v3/search", search(json!({"search_term": "fox", "order_by": "recent", "filter": {"limit": 1}})), 200).await;
    let page = &recent["search_categories"]["room_events"];
    assert_eq!(page["results"][0]["result"]["event_id"], quick.as_str(), "newest first");
    let next = page["next_batch"].as_str().unwrap();
    let second = post(
        &server,
        &bob,
        &format!("/_matrix/client/v3/search?next_batch={next}"),
        search(json!({"search_term": "fox", "order_by": "recent", "filter": {"limit": 1}})),
        200,
    )
    .await;
    let second = &second["search_categories"]["room_events"];
    assert_eq!(second["results"][0]["result"]["type"], "m.room.name");
    assert!(second.get("next_batch").is_none());

    // Context, profiles, state and groupings.
    let rich = post(
        &server,
        &bob,
        "/_matrix/client/v3/search",
        search(json!({
            "search_term": "lazy",
            "event_context": {"before_limit": 1, "after_limit": 1, "include_profile": true},
            "include_state": true,
            "groupings": {"group_by": [{"key": "room_id"}, {"key": "sender"}]},
        })),
        200,
    )
    .await;
    let rich = &rich["search_categories"]["room_events"];
    let context = &rich["results"][0]["context"];
    assert_eq!(ids(&context["events_before"]), vec![quick.clone()]);
    assert_eq!(ids(&context["events_after"]), vec![secret.clone()]);
    assert_eq!(context["events_after"][0]["content"], json!({}), "context events are served redacted");
    assert_eq!(context["profile_info"][&bob.id]["displayname"], "Bobby");
    assert!(context["start"].is_string() && context["end"].is_string());
    assert!(rich["state"][&room].as_array().unwrap().iter().any(|s| s["type"] == "m.room.name"));
    assert_eq!(rich["groups"]["room_id"][&room]["results"], json!([lazy]));
    assert_eq!(rich["groups"]["sender"][&bob.id]["results"], json!([lazy]));

    // Outsiders find nothing; bad input is rejected.
    let nothing = post(&server, &outsider, "/_matrix/client/v3/search", search(json!({"search_term": "fox"})), 200).await;
    assert_eq!(nothing["search_categories"]["room_events"]["count"], 0);
    let missing = post(&server, &bob, "/_matrix/client/v3/search", json!({"search_categories": {"room_events": {}}}), 400).await;
    assert_eq!(missing["errcode"], "M_BAD_JSON");
    let bad_order = post(&server, &bob, "/_matrix/client/v3/search", search(json!({"search_term": "fox", "order_by": "random"})), 400).await;
    assert_eq!(bad_order["errcode"], "M_INVALID_PARAM");

    // History after a departure stays unsearchable for the leaver.
    leave(&server, &bob, &room).await;
    text(&server, &alice, &room, "fox after bob left").await;
    let left = post(&server, &bob, "/_matrix/client/v3/search", search(json!({"search_term": "fox", "keys": ["content.body"]})), 200).await;
    assert_eq!(left["search_categories"]["room_events"]["count"], 1);
}

#[tokio::test]
async fn reports_are_stored_for_administrators() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let carol = user(&server, "carol").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat"})).await;
    join(&server, &bob, &room).await;
    let event = text(&server, &alice, &room, "offensive").await;

    post(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/report/{event}"), json!({"reason": "spam"}), 200).await;
    let not_joined = post(&server, &carol, &format!("/_matrix/client/v3/rooms/{room}/report/{event}"), json!({"reason": "x"}), 404).await;
    assert_eq!(not_joined["errcode"], "M_NOT_FOUND");
    post(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/report/$missing"), json!({}), 404).await;

    post(&server, &carol, &format!("/_matrix/client/v3/rooms/{room}/report"), json!({"reason": "bad room"}), 200).await;
    let no_room = post(&server, &carol, "/_matrix/client/v3/rooms/!nope:production.test/report", json!({"reason": "x"}), 404).await;
    assert_eq!(no_room["errcode"], "M_NOT_FOUND");
    let no_reason = post(&server, &carol, &format!("/_matrix/client/v3/rooms/{room}/report"), json!({}), 400).await;
    assert_eq!(no_reason["errcode"], "M_BAD_JSON");

    post(&server, &carol, &format!("/_matrix/client/v3/users/{}/report", alice.id), json!({"reason": ""}), 200).await;
    let no_user = post(&server, &carol, "/_matrix/client/v3/users/@ghost:production.test/report", json!({"reason": "x"}), 404).await;
    assert_eq!(no_user["errcode"], "M_NOT_FOUND");

    let denied = get(&server, &bob, "/_matrix/conduit/admin/v1/reports", 403).await;
    assert_eq!(denied["errcode"], "M_FORBIDDEN");
    make_admin(&server, &alice).await;
    let reports = get(&server, &alice, "/_matrix/conduit/admin/v1/reports", 200).await;
    let reports = reports["reports"].as_array().unwrap();
    assert_eq!(reports.len(), 3);
    assert_eq!(reports[0]["kind"], "event");
    assert_eq!(reports[0]["event_id"], event.as_str());
    assert_eq!(reports[0]["reporter"], bob.id.as_str());
    assert_eq!(reports[0]["reason"], "spam");
    assert_eq!(reports[1]["kind"], "room");
    assert_eq!(reports[2]["kind"], "user");
    assert_eq!(reports[2]["target_user_id"], alice.id.as_str());
}

#[tokio::test]
async fn room_upgrade_replaces_and_tombstones() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let room = create_room(
        &server,
        &alice,
        json!({"preset": "public_chat", "name": "Old", "topic": "History", "room_alias_name": "upgrade-me",
               "creation_content": {"type": "org.example.board"}}),
    )
    .await;
    state(&server, &alice, &room, "m.room.canonical_alias", "", json!({"alias": "#upgrade-me:production.test"})).await;
    join(&server, &bob, &room).await;
    let path = format!("/_matrix/client/v3/rooms/{room}/upgrade");

    let denied = post(&server, &bob, &path, json!({"new_version": "11"}), 403).await;
    assert_eq!(denied["errcode"], "M_FORBIDDEN");
    let unsupported = post(&server, &alice, &path, json!({"new_version": "999"}), 400).await;
    assert_eq!(unsupported["errcode"], "M_UNSUPPORTED_ROOM_VERSION");
    let upgraded = post(&server, &alice, &path, json!({"new_version": "11"}), 200).await;
    let new_room = upgraded["replacement_room"].as_str().unwrap().to_owned();
    assert_ne!(new_room, room);

    let tombstone = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/state/m.room.tombstone"), 200).await;
    assert_eq!(tombstone["replacement_room"], new_room.as_str());
    assert!(tombstone["body"].is_string());
    let create = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{new_room}/state/m.room.create"), 200).await;
    assert_eq!(create["predecessor"]["room_id"], room.as_str());
    assert_eq!(create["room_version"], "11");
    assert_eq!(create["type"], "org.example.board", "the room type carries over");
    let name = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{new_room}/state/m.room.name"), 200).await;
    assert_eq!(name["name"], "Old");
    let topic = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{new_room}/state/m.room.topic"), 200).await;
    assert_eq!(topic["topic"], "History");
    let alias = get(&server, &alice, "/_matrix/client/v3/directory/room/%23upgrade-me:production.test", 200).await;
    assert_eq!(alias["room_id"], new_room.as_str());
    let canonical = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{new_room}/state/m.room.canonical_alias"), 200).await;
    assert_eq!(canonical["alias"], "#upgrade-me:production.test");

    // The old room is locked down; the new one is joinable.
    let old_pl = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/state/m.room.power_levels"), 200).await;
    assert!(old_pl["events_default"].as_i64().unwrap() >= 50);
    assert!(old_pl["invite"].as_i64().unwrap() >= 50);
    let blocked = put(
        &server,
        &bob,
        &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/late"),
        json!({"msgtype": "m.text", "body": "too late"}),
        403,
    )
    .await;
    assert_eq!(blocked["errcode"], "M_FORBIDDEN");
    join(&server, &bob, &new_room).await;
    let new_pl = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{new_room}/state/m.room.power_levels"), 200).await;
    assert_eq!(new_pl["users"][&alice.id], 100);
    assert_eq!(new_pl["events_default"], 0);
}

#[tokio::test]
async fn space_hierarchy_walks_children_depth_first() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let space = create_room(
        &server,
        &alice,
        json!({"preset": "public_chat", "name": "Space", "creation_content": {"type": "m.space"}}),
    )
    .await;
    let room_a = create_room(&server, &alice, json!({"preset": "public_chat", "name": "A"})).await;
    let room_b = create_room(&server, &alice, json!({"preset": "public_chat", "name": "B"})).await;
    let private = create_room(&server, &alice, json!({"preset": "private_chat", "name": "Private"})).await;
    let room_d = create_room(&server, &alice, json!({"preset": "public_chat", "name": "D"})).await;
    let child = |order: &str, suggested: bool| json!({"via": ["production.test"], "order": order, "suggested": suggested});
    state(&server, &alice, &space, "m.space.child", &room_a, child("b", false)).await;
    state(&server, &alice, &space, "m.space.child", &room_b, child("a", true)).await;
    state(&server, &alice, &space, "m.space.child", &private, child("c", false)).await;
    state(&server, &alice, &space, "m.space.child", "!unknown:production.test", child("d", false)).await;
    state(&server, &alice, &space, "m.space.child", &room_d, json!({"via": []})).await; // invalid: empty via
    state(&server, &alice, &room_a, "m.space.child", &room_d, child("a", false)).await;
    state(&server, &alice, &room_d, "m.space.child", &space, child("a", false)).await; // loop
    join(&server, &bob, &space).await;

    let path = format!("/_matrix/client/v1/rooms/{space}/hierarchy");
    let rooms_of = |body: &Value| -> Vec<String> {
        body["rooms"].as_array().unwrap().iter().map(|r| r["room_id"].as_str().unwrap().to_owned()).collect()
    };
    let full = get(&server, &bob, &path, 200).await;
    assert_eq!(rooms_of(&full), vec![space.clone(), room_b.clone(), room_a.clone(), room_d.clone()]);
    let root = &full["rooms"][0];
    assert_eq!(root["name"], "Space");
    assert_eq!(root["num_joined_members"], 2);
    assert_eq!(root["join_rule"], "public");
    assert_eq!(root["world_readable"], false);
    assert_eq!(root["guest_can_join"], false);
    assert_eq!(root["room_version"], "12");
    assert_eq!(root["room_type"], "m.space");
    assert!(full["rooms"][1].get("room_type").is_none(), "ordinary rooms have no type");
    assert_eq!(root["children_state"].as_array().unwrap().len(), 4, "invalid children are not listed");
    assert!(root["children_state"].as_array().unwrap().iter().all(|c| c["type"] == "m.space.child" && c["origin_server_ts"].is_u64()));
    assert!(full.get("next_batch").is_none());

    let suggested = get(&server, &bob, &format!("{path}?suggested_only=true"), 200).await;
    assert_eq!(rooms_of(&suggested), vec![space.clone(), room_b.clone()]);
    let shallow = get(&server, &bob, &format!("{path}?max_depth=1"), 200).await;
    assert_eq!(rooms_of(&shallow), vec![space.clone(), room_b.clone(), room_a.clone()]);
    assert_eq!(shallow["rooms"][2]["children_state"].as_array().unwrap().len(), 1);

    let page1 = get(&server, &bob, &format!("{path}?limit=2"), 200).await;
    assert_eq!(rooms_of(&page1), vec![space.clone(), room_b.clone()]);
    let next = page1["next_batch"].as_str().unwrap();
    let page2 = get(&server, &bob, &format!("{path}?limit=2&from={next}"), 200).await;
    assert_eq!(rooms_of(&page2), vec![room_a.clone(), room_d.clone()]);
    let changed = get(&server, &bob, &format!("{path}?limit=2&from={next}&max_depth=1"), 400).await;
    assert_eq!(changed["errcode"], "M_INVALID_PARAM");

    // The private child is listed for its members only; private roots 403.
    let as_alice = get(&server, &alice, &path, 200).await;
    assert!(rooms_of(&as_alice).contains(&private));
    let denied = get(&server, &bob, &format!("/_matrix/client/v1/rooms/{private}/hierarchy"), 403).await;
    assert_eq!(denied["errcode"], "M_FORBIDDEN");
}

#[tokio::test]
async fn ignored_users_are_filtered_from_sync_messages_and_invites() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let room = create_room(
        &server,
        &alice,
        json!({"preset": "public_chat", "power_level_content_override": {"users": {alice.id.clone(): 100, bob.id.clone(): 50}}}),
    )
    .await;
    join(&server, &bob, &room).await;
    put(
        &server,
        &alice,
        &format!("/_matrix/client/v3/user/{}/account_data/m.ignored_user_list", alice.id),
        json!({"ignored_users": {bob.id.clone(): {}}}),
        200,
    )
    .await;
    let since = sync(&server, &alice, "").await["next_batch"].as_str().unwrap().to_owned();
    let hidden = text(&server, &bob, &room, "you cannot see me").await;
    let topic = state(&server, &bob, &room, "m.room.topic", "", json!({"topic": "still visible"})).await;
    let shown = text(&server, &alice, &room, "visible").await;

    let delta = sync(&server, &alice, &format!("&since={since}")).await;
    let timeline = ids(&delta["rooms"]["join"][&room]["timeline"]["events"]);
    assert!(!timeline.contains(&hidden), "ignored users' messages are withheld");
    assert!(timeline.contains(&topic), "state events from ignored users are still sent");
    assert!(timeline.contains(&shown));
    let page = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=20"), 200).await;
    assert!(!ids(&page["chunk"]).contains(&hidden));
    let context = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/context/{shown}"), 200).await;
    assert!(!ids(&context["events_before"]).contains(&hidden));

    // Invites from ignored users are not delivered.
    let invite_room = create_room(&server, &bob, json!({"preset": "private_chat"})).await;
    post(&server, &bob, &format!("/_matrix/client/v3/rooms/{invite_room}/invite"), json!({"user_id": alice.id}), 200).await;
    let invites = sync(&server, &alice, "").await;
    assert!(invites["rooms"]["invite"].get(&invite_room).is_none());

    // Un-ignoring resumes delivery of new events.
    put(
        &server,
        &alice,
        &format!("/_matrix/client/v3/user/{}/account_data/m.ignored_user_list", alice.id),
        json!({"ignored_users": {}}),
        200,
    )
    .await;
    let resumed_since = sync(&server, &alice, "").await["next_batch"].as_str().unwrap().to_owned();
    let back = text(&server, &bob, &room, "back again").await;
    let resumed = sync(&server, &alice, &format!("&since={resumed_since}")).await;
    assert!(ids(&resumed["rooms"]["join"][&room]["timeline"]["events"]).contains(&back));
}

#[tokio::test]
async fn messages_filter_backfills_to_the_limit_and_to_is_exclusive() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat"})).await;
    text(&server, &alice, &room, "A").await;
    state(&server, &alice, &room, "m.room.topic", "", json!({"topic": "between"})).await;
    send(
        &server,
        &alice,
        &room,
        "m.room.message",
        json!({"msgtype": "m.text", "body": "B", "url": "https://example.test/b"}),
    )
    .await;
    state(&server, &alice, &room, "m.room.name", "", json!({"name": "between"})).await;
    text(&server, &alice, &room, "C").await;

    let filter = encode(r#"{"types":["m.room.message"]}"#);
    let page = get(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=3&filter={filter}"),
        200,
    )
    .await;
    let bodies: Vec<_> = page["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["content"]["body"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(bodies, vec!["C".to_owned(), "B".to_owned(), "A".to_owned()], "{page}");
    assert!(page["chunk"].as_array().unwrap().iter().all(|event| event["type"] == "m.room.message"));

    let urls = encode(r#"{"contains_url":true}"#);
    let linked = get(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10&filter={urls}"),
        200,
    )
    .await;
    let linked_bodies: Vec<_> = linked["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["content"]["body"].as_str().unwrap_or("").to_owned())
        .collect();
    assert_eq!(linked_bodies, vec!["B".to_owned()], "{linked}");

    let broken = get(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&filter={}", encode("{")),
        400,
    )
    .await;
    assert_eq!(broken["errcode"], "M_BAD_JSON");

    let open = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"), 200).await;
    let start = open["start"].as_str().unwrap();
    assert!(!open["chunk"].as_array().unwrap().is_empty(), "{open}");
    let stopped = get(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&from={start}&to={start}"),
        200,
    )
    .await;
    assert_eq!(stopped["chunk"].as_array().unwrap().len(), 0, "to is exclusive: {stopped}");
    assert!(stopped.get("end").is_none(), "nothing remains inside the bound: {stopped}");
}

#[tokio::test]
async fn canonical_alias_must_point_at_the_room() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat", "room_alias_name": "cheese"})).await;
    let other = create_room(&server, &alice, json!({"preset": "public_chat", "room_alias_name": "other"})).await;
    let path = format!("/_matrix/client/v3/rooms/{room}/state/m.room.canonical_alias");

    let syntax = put(&server, &alice, &path, json!({"alias": "cheese"}), 400).await;
    assert_eq!(syntax["errcode"], "M_INVALID_PARAM", "{syntax}");
    let missing = put(&server, &alice, &path, json!({"alias": "#missing:production.test"}), 400).await;
    assert_eq!(missing["errcode"], "M_BAD_ALIAS", "{missing}");
    let elsewhere = put(&server, &alice, &path, json!({"alias": "#other:production.test"}), 400).await;
    assert_eq!(elsewhere["errcode"], "M_BAD_ALIAS", "{elsewhere}");
    let alt = put(
        &server,
        &alice,
        &path,
        json!({"alias": "#cheese:production.test", "alt_aliases": ["#missing:production.test"]}),
        400,
    )
    .await;
    assert_eq!(alt["errcode"], "M_BAD_ALIAS", "{alt}");
    put(&server, &alice, &path, json!({"alias": "#cheese:production.test"}), 200).await;
    // Clearing the alias is an event with no alias fields.
    put(&server, &alice, &path, json!({}), 200).await;
    let _ = other;
}

#[tokio::test]
async fn client_events_reject_oversize_identifiers_and_pdus() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat"})).await;
    let key = "k".repeat(255);
    state(&server, &alice, &room, "com.example.limit", &key, json!({"ok": true})).await;
    let too_long = put(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/state/com.example.limit/{}", "k".repeat(256)),
        json!({"ok": false}),
        413,
    )
    .await;
    assert_eq!(too_long["errcode"], "M_TOO_LARGE", "{too_long}");
    let huge = put(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/huge"),
        json!({"msgtype": "m.text", "body": "x".repeat(70_000)}),
        413,
    )
    .await;
    assert_eq!(huge["errcode"], "M_TOO_LARGE", "{huge}");
}

#[tokio::test]
async fn room_upgrade_applies_requested_creators_and_copies_settings() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let room = create_room(
        &server,
        &alice,
        json!({
            "preset": "public_chat",
            "creation_content": {"additional_creators": ["@carol:production.test"]}
        }),
    )
    .await;
    let old_create = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/state/m.room.create"), 200).await;
    assert_eq!(old_create["additional_creators"], json!(["@carol:production.test"]));
    join(&server, &bob, &room).await;
    let tags = format!("/_matrix/client/v3/user/{}/rooms/{room}/tags/u.work", bob.id);
    put(&server, &bob, &tags, json!({"order": 0.25}), 200).await;
    put(
        &server,
        &bob,
        &format!("/_matrix/client/v3/pushrules/global/room/{}", encode(&room)),
        json!({"actions": []}),
        200,
    )
    .await;

    let rejected = post(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/upgrade"),
        json!({"new_version": "12", "additional_creators": ["bob"]}),
        400,
    )
    .await;
    assert_eq!(rejected["errcode"], "M_INVALID_PARAM", "{rejected}");
    get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/state/m.room.tombstone"), 404).await;

    let upgraded = post(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/upgrade"),
        json!({"new_version": "12", "additional_creators": [bob.id]}),
        200,
    )
    .await;
    let new_room = upgraded["replacement_room"].as_str().unwrap();
    let create = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{new_room}/state/m.room.create"), 200).await;
    assert_eq!(create["additional_creators"], json!([bob.id]), "request list replaces, it is not merged: {create}");
    assert_eq!(create["room_version"], "12");

    // The upgrader's join during upgrade copied nothing of Bob's. Bob's join does.
    let before = get(
        &server,
        &bob,
        &format!("/_matrix/client/v3/user/{}/rooms/{new_room}/tags", bob.id),
        200,
    )
    .await;
    assert!(before["tags"].get("u.work").is_none(), "{before}");
    join(&server, &bob, new_room).await;
    let after = get(
        &server,
        &bob,
        &format!("/_matrix/client/v3/user/{}/rooms/{new_room}/tags", bob.id),
        200,
    )
    .await;
    assert_eq!(after["tags"]["u.work"]["order"], 0.25, "{after}");
    let rule = get(
        &server,
        &bob,
        &format!("/_matrix/client/v3/pushrules/global/room/{}", encode(new_room)),
        200,
    )
    .await;
    assert_eq!(rule["actions"], json!([]), "{rule}");

    // Versions before 12 ignore additional_creators.
    let legacy = create_room(&server, &alice, json!({"preset": "public_chat", "room_version": "11"})).await;
    let legacy_new = post(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{legacy}/upgrade"),
        json!({"new_version": "11", "additional_creators": [bob.id]}),
        200,
    )
    .await["replacement_room"]
        .as_str()
        .unwrap()
        .to_owned();
    let legacy_create = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{legacy_new}/state/m.room.create"), 200).await;
    assert!(legacy_create.get("additional_creators").is_none(), "{legacy_create}");
}

#[tokio::test]
async fn client_events_report_age_membership_replacements_and_redactions() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let room = create_room(
        &server,
        &alice,
        json!({
            "preset": "public_chat",
            "initial_state": [{
                "type": "m.room.history_visibility",
                "state_key": "",
                "content": {"history_visibility": "joined"}
            }]
        }),
    )
    .await;
    let secret = state(&server, &alice, &room, "m.room.topic", "", json!({"topic": "secret"})).await;
    join(&server, &bob, &room).await;
    let later = state(&server, &alice, &room, "m.room.topic", "", json!({"topic": "later"})).await;
    let echo = put(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/echo-format"),
        json!({"msgtype": "m.text", "body": "echo"}),
        200,
    )
    .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let page = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=30"), 200).await;
    let find = |chunk: &Value, id: &str| {
        chunk["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["event_id"] == id)
            .unwrap_or_else(|| panic!("{id} missing in {chunk}"))
            .clone()
    };
    let topic = find(&page, &later);
    assert_eq!(topic["unsigned"]["prev_content"]["topic"], "secret", "{topic}");
    assert_eq!(topic["unsigned"]["replaces_state"], secret, "{topic}");
    assert_eq!(topic["unsigned"]["membership"], "join", "{topic}");
    assert!(topic["unsigned"]["age"].as_u64().is_some(), "{topic}");
    let message = find(&page, &echo);
    assert!(message["unsigned"].get("prev_content").is_none(), "{message}");
    assert!(message["unsigned"].get("replaces_state").is_none(), "{message}");
    assert_eq!(message["unsigned"]["transaction_id"], "echo-format", "{message}");
    assert_eq!(message["unsigned"]["membership"], "join", "{message}");

    let bob_page = get(&server, &bob, &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=30"), 200).await;
    let hidden = find(&bob_page, &later);
    assert_eq!(hidden["unsigned"]["replaces_state"], secret, "replaces_state ignores visibility: {hidden}");
    assert!(hidden["unsigned"].get("prev_content").is_none(), "pre-join topic stays hidden: {hidden}");

    let redaction = put(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/redact/{echo}/redact-echo"),
        json!({"reason": "gone"}),
        200,
    )
    .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let served = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/event/{echo}"), 200).await;
    assert_eq!(served["content"], json!({}), "{served}");
    assert_eq!(served["unsigned"]["redacted_because"]["event_id"], redaction, "{served}");
    assert!(served["unsigned"]["age"].as_u64().is_some(), "{served}");
    let again = get(&server, &alice, &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=30"), 200).await;
    let redacted = find(&again, &echo);
    assert_eq!(redacted["content"], json!({}), "{redacted}");
    assert_eq!(redacted["unsigned"]["redacted_because"]["event_id"], redaction, "{redacted}");
    assert_eq!(redacted["unsigned"]["transaction_id"], "echo-format", "{redacted}");
    let full = sync(&server, &alice, "").await;
    let synced = full["rooms"]["join"][&room]["timeline"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["event_id"] == echo)
        .expect("redacted event in sync");
    assert_eq!(synced["unsigned"]["redacted_because"]["event_id"], redaction, "{synced}");
    assert_eq!(synced["unsigned"]["transaction_id"], "echo-format", "{synced}");
    assert!(synced["unsigned"]["age"].as_u64().is_some(), "{synced}");
}

#[tokio::test]
async fn room_messages_require_msgtype_and_body() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat"})).await;
    let path = format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/shape");
    let missing = put(&server, &alice, &path, json!({"body": "no type"}), 400).await;
    assert_eq!(missing["errcode"], "M_BAD_JSON", "{missing}");
    let again = put(&server, &alice, &path, json!({"msgtype": "m.text", "body": "now valid"}), 400).await;
    assert_eq!(again, missing, "the rejected transaction is replayed");
    let sent = put(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/shape-ok"),
        json!({"msgtype": "m.text", "body": ""}),
        200,
    )
    .await;
    assert!(sent["event_id"].as_str().unwrap().starts_with('$'));
    let no_body = put(
        &server,
        &alice,
        &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/no-body"),
        json!({"msgtype": "m.text"}),
        400,
    )
    .await;
    assert_eq!(no_body["errcode"], "M_BAD_JSON", "{no_body}");
}
