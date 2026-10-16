//! add-pdu-wire storage contract against real PostgreSQL (and memory):
//!
//! - the authoritative `pdu_json` round trip through every public event read,
//!   with extensions, U+0000 and 2^53-1, across a pool restart;
//! - legacy rows: classification, serving, and unchanged client history
//!   before/after inline classification and the sweep;
//! - migrations 0090/0091 rewrite no table and legacy JSONB rows still work;
//! - U+0000 and floats in the replay and outbox sinks;
//! - to-device content keeps U+0000 in text and projects U+FFFD into JSONB.

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use conduit::event::{Event, IntegrityClass, Pdu};
use conduit::keys::{generate_server_key, ServerKey};
use conduit::room_content::SearchKeys;
use conduit::signing::sign_authored;
use conduit::storage::{MemoryStorage, Storage, TransactionKey};
use conduit_server::PostgresStorage;

const ROOM: &str = "!room:x.test";
const ALICE: &str = "@alice:x.test";
const MAX_SAFE: u64 = 9_007_199_254_740_991;

fn signed(key: &ServerKey, mut pdu: Pdu) -> Event {
    sign_authored(&mut pdu, key, "x.test").unwrap();
    Event::new(conduit::hashing::event_id(&pdu).unwrap(), pdu)
}

/// A small room whose events exercise every reader: state, membership, a
/// message with extensions / U+0000 / 2^53-1, a redaction and a thread child.
fn fixture_events(key: &ServerKey) -> Vec<Event> {
    let create = signed(key, Pdu::new(ROOM, ALICE, "m.room.create", Some(String::new()),
        json!({"room_version": "11"}), 1_000, vec![], vec![], 1));
    let member = signed(key, Pdu::new(ROOM, ALICE, "m.room.member", Some(ALICE.into()),
        json!({"membership": "join", "displayname": "Al\u{0}ice"}), 1_001,
        vec![create.event_id.clone()], vec![create.event_id.clone()], 2));
    let message = signed(key, Pdu::new(ROOM, ALICE, "m.room.message", None,
        json!({"msgtype": "m.text", "body": "hello wo\u{0}rld", "n": MAX_SAFE}), 1_002,
        vec![create.event_id.clone(), member.event_id.clone()], vec![member.event_id.clone()], 3));
    let mut thread_pdu = Pdu::new(ROOM, ALICE, "m.room.message", None,
        json!({"body": "reply", "m.relates_to": {"rel_type": "m.thread", "event_id": message.event_id}}), 1_003,
        vec![create.event_id.clone(), member.event_id.clone()], vec![message.event_id.clone()], 4);
    thread_pdu.extensions.insert("org.example.ext".into(), json!({"nested": ["a\u{0}", MAX_SAFE]}));
    let thread = signed(key, thread_pdu);
    let redaction = signed(key, Pdu::new(ROOM, ALICE, "m.room.redaction", None,
        json!({"redacts": message.event_id}), 1_004,
        vec![create.event_id.clone(), member.event_id.clone()], vec![thread.event_id.clone()], 5));
    vec![create, member, message, thread, redaction]
}

async fn write_fixture(store: &dyn Storage, events: &[Event]) {
    for event in events {
        store.put_event(event).await.unwrap();
        if let Some(state_key) = &event.state_key {
            store.set_state_entry(&event.room_id, &event.event_type, state_key, &event.event_id).await.unwrap();
        }
    }
}

/// Every public `Storage` method that returns events must return them intact.
async fn assert_every_read_round_trips(store: &dyn Storage, events: &[Event]) {
    let by_id = |id: &str| events.iter().find(|e| e.event_id == id).unwrap_or_else(|| panic!("unexpected {id}"));
    let message = &events[2];
    let pruned_message = conduit::room_version::redact_pdu(&message.pdu, 11);
    let check = |label: &str, got: &Event| {
        let want = by_id(&got.event_id);
        let want_pdu = if want.event_id == message.event_id { &pruned_message } else { &want.pdu };
        assert_eq!(&got.pdu, want_pdu, "{label}: {}", got.event_id);
        assert_eq!(got.hashes, want.hashes, "{label}: hashes survive redaction");
        assert_eq!(got.signatures, want.signatures, "{label}: signatures survive redaction");
    };
    for event in events {
        check("get_event", &store.get_event(&event.event_id).await.unwrap().unwrap());
    }
    let room_events = store.room_events(ROOM).await.unwrap();
    assert_eq!(room_events.len(), events.len());
    room_events.iter().for_each(|e| check("room_events", e));
    store.get_current_state(ROOM).await.unwrap().iter().for_each(|e| check("get_current_state", e));
    check("get_state_entry", &store.get_state_entry(ROOM, "m.room.member", ALICE).await.unwrap().unwrap());
    store.current_memberships(ALICE).await.unwrap().iter().for_each(|e| check("current_memberships", e));
    let (page, _) = store.room_events_paginated(ROOM, 'f', 0, 100).await.unwrap();
    assert_eq!(page.len(), events.len());
    page.iter().for_each(|e| check("room_events_paginated", e));
    store.member_events_for_user(ROOM, ALICE).await.unwrap().iter().for_each(|(_, e)| check("member_events_for_user", e));
    store.member_events_for_server(ROOM, "x.test").await.unwrap().iter().for_each(|(_, e)| check("member_events_for_server", e));
    let since = store.events_since(0, 100).await.unwrap();
    assert_eq!(since.len(), events.len());
    since.iter().for_each(|e| check("events_since", e));
    store.room_events_with_positions(ROOM).await.unwrap().iter().for_each(|(_, e)| check("room_events_with_positions", e));
    store.state_events_through(ROOM, i64::MAX).await.unwrap().iter().for_each(|(_, e)| check("state_events_through", e));
    let redactions = store.redactions_targeting(ROOM, &[message.event_id.clone()]).await.unwrap();
    assert_eq!(redactions.len(), 1);
    redactions.iter().for_each(|e| check("redactions_targeting", e));
    let children = store.relation_children(ROOM, &[message.event_id.clone()]).await.unwrap();
    assert_eq!(children.len(), 1);
    children.iter().for_each(|(_, e)| check("relation_children", e));
    store.events_near_timestamp(ROOM, 1_002, true, 10).await.unwrap().iter().for_each(|e| check("events_near_timestamp", e));
    let hits = store.search_room_events(&[ROOM.to_owned()], "reply", SearchKeys::ALL, false, 10).await.unwrap();
    assert!(!hits.is_empty(), "search found the thread reply");
    hits.iter().for_each(|hit| check("search_room_events", &hit.event));
    // The accepted redaction removed the body. The wire form is that prune,
    // with the original hashes, and still has no event_id.
    let wire = store.get_wire_pdu(&message.event_id).await.unwrap().unwrap();
    assert_eq!(wire.pdu(), &pruned_message);
    assert!(wire.content.get("body").is_none(), "{wire:?}");
    assert_eq!(wire.hashes, message.hashes);
    assert!(serde_json::to_value(&wire).unwrap().get("event_id").is_none());
    let thread = &events[3];
    let thread_wire = store.get_wire_pdu(&thread.event_id).await.unwrap().unwrap();
    assert_eq!(thread_wire.pdu(), &thread.pdu, "an unredacted extension still round-trips");
}

#[tokio::test]
async fn extended_pdu_survives_every_read_and_a_pool_restart_on_postgres() {
    let db = TempDb::new().await;
    let key = generate_server_key();
    let events = fixture_events(&key);
    write_fixture(&db.storage(), &events).await;
    let reopened = db.reopen().await;
    assert_every_read_round_trips(&reopened, &events).await;
    // New rows are written authoritative and verified.
    let rows: Vec<(String, Option<String>)> = sqlx::query_as("SELECT id_integrity, pdu_json FROM events")
        .fetch_all(&db.pool).await.unwrap();
    let redacted = rows.iter().filter(|(class, _)| class == "redacted").count();
    assert_eq!(redacted, 1, "the redacted message is the only pruned row: {rows:?}");
    assert!(rows.iter().all(|(class, json)| json.is_some() && (class == "verified" || class == "redacted")), "{rows:?}");
}

#[tokio::test]
async fn extended_pdu_survives_every_read_in_memory() {
    let store = MemoryStorage::default();
    let key = generate_server_key();
    let events = fixture_events(&key);
    write_fixture(&store, &events).await;
    assert_every_read_round_trips(&store, &events).await;
}

/// The reference hash the code before 56498e3 produced: unredacted, with
/// `"event_id": ""` included.
fn pre_56498e3_id(pdu: &Pdu) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let mut value = serde_json::to_value(pdu).unwrap();
    value["event_id"] = json!("");
    value.as_object_mut().unwrap().remove("signatures");
    let bytes = conduit::canonical_json::to_canonical_bytes(&value).unwrap();
    format!("${}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

/// Insert a legacy row: projections only, `pdu_json` NULL, `unchecked`.
async fn insert_legacy(pool: &PgPool, event_id: &str, pdu: &Pdu) {
    sqlx::query(
        "INSERT INTO events (event_id, room_id, sender, type, state_key, content, auth_events, prev_events,
            signatures, hashes, unsigned, origin_server_ts, depth)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, $11, $12)",
    )
    .bind(event_id).bind(&pdu.room_id).bind(&pdu.sender).bind(&pdu.event_type).bind(&pdu.state_key)
    .bind(&pdu.content).bind(&pdu.auth_events).bind(&pdu.prev_events).bind(&pdu.signatures).bind(&pdu.hashes)
    .bind(pdu.origin_server_ts as i64).bind(pdu.depth)
    .execute(pool).await.unwrap();
}

#[tokio::test]
async fn legacy_rows_are_classified_served_safely_and_client_history_is_unchanged() {
    let db = TempDb::new().await;
    let store = db.storage();
    let key = generate_server_key();

    // (a) A local row hashed the pre-56498e3 way: its ID cannot be reproduced.
    let local = signed(&key, Pdu::new(ROOM, ALICE, "m.room.message", None, json!({"body": "old local"}), 10, vec![], vec![], 1));
    let old_id = pre_56498e3_id(&local.pdu);
    insert_legacy(&db.pool, &old_id, &local.pdu).await;
    // (b) A lossy remote row: signed with an extension that ingest dropped.
    let mut remote_pdu = Pdu::new(ROOM, "@bob:y.test", "m.room.message", None, json!({"body": "lossy remote"}), 11, vec![], vec![], 2);
    remote_pdu.extensions.insert("org.remote.ext".into(), json!(true));
    let remote = signed(&key, remote_pdu);
    let mut lost = remote.pdu.clone();
    lost.extensions.clear();
    insert_legacy(&db.pool, &remote.event_id, &lost).await;
    // (c) A good legacy row.
    let good = signed(&key, Pdu::new(ROOM, ALICE, "m.room.message", None, json!({"body": "fine"}), 12, vec![], vec![], 3));
    insert_legacy(&db.pool, &good.event_id, &good.pdu).await;

    let before = store.get_event(&remote.event_id).await.unwrap().unwrap();
    assert_eq!(before.content["body"], "lossy remote");

    // Inline classification on a federation read.
    let (class, wire) = store.get_wire_pdu_with_class(&remote.event_id).await.unwrap().unwrap();
    assert_eq!(class, IntegrityClass::ContentMismatch);
    let wire = wire.unwrap();
    assert_eq!(wire.content, json!({}), "served as its v11 redaction");
    assert_eq!(wire.event_id(), remote.event_id);
    let after_inline = store.get_event(&remote.event_id).await.unwrap().unwrap();
    assert_eq!(after_inline, before, "client read unchanged by inline classification");

    // The background sweep classifies the rest.
    let sweep = store.verify_legacy_event_ids(1000).await.unwrap();
    assert_eq!((sweep.verified, sweep.content_mismatch, sweep.id_mismatch), (1, 0, 1));
    assert_eq!(store.verify_legacy_event_ids(1000).await.unwrap().total(), 0);
    let after_sweep = db.reopen().await.get_event(&remote.event_id).await.unwrap().unwrap();
    assert_eq!(after_sweep, before, "client read unchanged after the sweep");

    // The pre-56498e3 row: kept under its original primary key, never served.
    assert!(store.get_event(&old_id).await.unwrap().is_some());
    assert!(store.get_wire_pdu(&old_id).await.unwrap().is_none());
    assert!(store.get_wire_pdu(&good.event_id).await.unwrap().is_some());
    let classes: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT event_id, id_integrity, pdu_json IS NOT NULL FROM events ORDER BY stream_position")
        .fetch_all(&db.pool).await.unwrap();
    assert_eq!(classes, vec![
        (old_id, "id_mismatch".into(), false),
        (remote.event_id.clone(), "content_mismatch".into(), true),
        (good.event_id.clone(), "verified".into(), true),
    ]);
    // Retained history keeps the unredacted rebuilt Pdu.
    let stored: (String,) = sqlx::query_as("SELECT pdu_json FROM events WHERE event_id = $1")
        .bind(&remote.event_id).fetch_one(&db.pool).await.unwrap();
    assert!(stored.0.contains("lossy remote"));
}

#[tokio::test]
async fn migrations_0090_and_0091_rewrite_no_table_and_keep_legacy_rows_readable() {
    let db = TempDb::empty().await;
    let mut before = sqlx::migrate!("./migrations");
    before.migrations = Cow::Owned(before.migrations.iter().filter(|m| m.version < 90).cloned().collect());
    before.run(&db.pool).await.unwrap();

    let key = generate_server_key();
    let event = signed(&key, Pdu::new(ROOM, ALICE, "m.room.message", None, json!({"body": "pre"}), 1, vec![], vec![], 1));
    insert_legacy(&db.pool, &event.event_id, &event.pdu).await;
    sqlx::query("INSERT INTO transactions (scope, owner, endpoint, txn_id, request, result) VALUES ('federation', 'a.test', 'send', 't1', $1, $2)")
        .bind(json!({"legacy": "request"})).bind(json!({"legacy": "result"})).execute(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO fed_outbound_queue (destination, kind, txn_id, payload) VALUES ('d.test', 'transaction', 'q1', $1)")
        .bind(json!({"pdus": [], "edus": [{"edu_type": "legacy"}]})).execute(&db.pool).await.unwrap();

    let relfilenodes = |pool: PgPool| async move {
        sqlx::query_as::<_, (String, i64)>(
            "SELECT relname::text, relfilenode::bigint FROM pg_class
             WHERE relname IN ('events', 'transactions', 'fed_outbound_queue') ORDER BY relname")
            .fetch_all(&pool).await.unwrap()
    };
    let nodes_before = relfilenodes(db.pool.clone()).await;
    sqlx::migrate!("./migrations").run(&db.pool).await.unwrap();
    assert_eq!(relfilenodes(db.pool.clone()).await, nodes_before, "no table was rewritten");

    let store = db.storage();
    let key_t1 = TransactionKey { scope: "federation".into(), owner: "a.test".into(), endpoint: "send".into(), txn_id: "t1".into() };
    assert_eq!(store.transaction_result(&key_t1).await.unwrap(), Some(json!({"legacy": "result"})));
    assert_eq!(store.transaction_original(&key_t1).await.unwrap(), Some(json!({"legacy": "request"})));
    let queued = store.next_pending_outbound("d.test", 10).await.unwrap();
    assert_eq!(queued[0].payload, json!({"pdus": [], "edus": [{"edu_type": "legacy"}]}));
    assert_eq!(store.get_event(&event.event_id).await.unwrap().unwrap().pdu, event.pdu);
    let class: (String,) = sqlx::query_as("SELECT id_integrity FROM events").fetch_one(&db.pool).await.unwrap();
    assert_eq!(class.0, "unchecked");

    // New rows use only the TEXT columns.
    let key_t2 = TransactionKey { scope: "federation".into(), owner: "a.test".into(), endpoint: "send".into(), txn_id: "t2".into() };
    store.transaction_request(&key_t2, &json!({"new": 1})).await.unwrap();
    store.finish_transaction(&key_t2, &json!({"done": 1})).await.unwrap();
    let row: (Option<Value>, Option<Value>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT request, result, request_text, result_text FROM transactions WHERE txn_id = 't2'")
        .fetch_one(&db.pool).await.unwrap();
    assert_eq!((row.0, row.1), (None, None));
    assert!(row.2.is_some() && row.3.is_some());
}

#[tokio::test]
async fn replay_and_outbox_sinks_keep_nul_and_floats() {
    let db = TempDb::new().await;
    let store = db.storage();
    let body = json!({"pdus": [{"content": {"body": "a\u{0}b"}}], "f": 1.5, "edus": []});
    let key = TransactionKey { scope: "federation".into(), owner: "a.test".into(), endpoint: "send".into(), txn_id: "nul".into() };
    assert_eq!(store.transaction_request(&key, &body).await.unwrap(), body);
    let result = json!({"pdus": {"$x": {}}, "f": 2.25, "s": "\u{0}"});
    assert_eq!(store.finish_transaction(&key, &result).await.unwrap(), result);
    assert_eq!(db.reopen().await.transaction_result(&key).await.unwrap(), Some(result));

    // Local state content with U+0000 federates: the outbox payload is exact.
    let payload = json!({"pdus": [{"type": "m.room.topic", "content": {"topic": "t\u{0}opic"}}], "edus": []});
    let id = store.enqueue_outbound("d.test", "transaction", "txn-nul", &payload).await.unwrap();
    let queued = store.next_pending_outbound("d.test", 10).await.unwrap();
    assert_eq!(queued[0].payload, payload);

    store.record_legacy_snapshot_verdicts(id, &json!({"$a": "id_mismatch"}), Some("withheld: legacy id_mismatch")).await.unwrap();
    let row: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT legacy_snapshot_verdicts, last_error FROM fed_outbound_queue WHERE id = $1")
        .bind(id).fetch_one(&db.pool).await.unwrap();
    assert_eq!(serde_json::from_str::<Value>(&row.0.unwrap()).unwrap(), json!({"$a": "id_mismatch"}));
    assert_eq!(row.1.as_deref(), Some("withheld: legacy id_mismatch"));
}

#[tokio::test]
async fn to_device_content_keeps_nul_and_projects_replacement() {
    use conduit::storage::ToDeviceDelivery;
    let db = TempDb::new().await;
    let store = db.storage();
    store.create_account("@bob:x.test", None).await.unwrap();
    store.upsert_device("@bob:x.test", "B", None).await.unwrap();
    let key = TransactionKey::federation("y.test", "edu-nul");
    let delivery = ToDeviceDelivery {
        target_user: "@bob:x.test".into(),
        target_device: "B".into(),
        sender: "@s:y.test".into(),
        event_type: "m.test".into(),
        content: json!({"body": "a\u{0}b"}),
    };
    assert!(store.deliver_to_device_once(&key, &[delivery.clone()], &[]).await.unwrap());
    let queued = store.drain_to_device("@bob:x.test", "B", 0, 10).await.unwrap();
    assert_eq!(queued.len(), 1, "{queued:?}");
    assert_eq!(queued[0].content["body"], "a\u{0}b");
    let again = db.reopen().await.drain_to_device("@bob:x.test", "B", 0, 10).await.unwrap();
    assert_eq!(again[0].content, queued[0].content);
    // The JSONB projection is not the delivered copy.
    let projected: serde_json::Value = sqlx::query_scalar("SELECT content FROM to_device_queue")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(projected["body"], "a\u{FFFD}b");
}

// ---------------------------------------------------------------------------
// TempDb (same pattern as storage_pg.rs)
// ---------------------------------------------------------------------------

struct TempDb {
    admin_url: String,
    db_name: String,
    pool: PgPool,
}

impl TempDb {
    async fn empty() -> Self {
        let admin_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres@localhost/postgres".to_owned());
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let db_name = format!("conduit_test_pdu_{}_{}", nanos, uuid_like());
        let admin_pool = PgPoolOptions::new().max_connections(2).connect(&admin_url).await.unwrap();
        sqlx::query(&format!("CREATE DATABASE {db_name}")).execute(&admin_pool).await.unwrap();
        admin_pool.close().await;
        let pool = PgPoolOptions::new().max_connections(5)
            .connect(&replace_db_in_url(&admin_url, &db_name)).await.unwrap();
        TempDb { admin_url, db_name, pool }
    }

    async fn new() -> Self {
        let db = Self::empty().await;
        sqlx::migrate!("./migrations").run(&db.pool).await.unwrap();
        db
    }

    fn storage(&self) -> PostgresStorage {
        PostgresStorage::new(self.pool.clone())
    }

    async fn reopen(&self) -> PostgresStorage {
        let pool = PgPoolOptions::new().max_connections(5)
            .connect(&replace_db_in_url(&self.admin_url, &self.db_name)).await.unwrap();
        PostgresStorage::new(pool)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::process::Command::new("psql")
            .args([&self.admin_url, "-c", &format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.db_name)])
            .output();
    }
}

fn uuid_like() -> String {
    format!("{:?}", std::thread::current().id()).chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase()
}

fn replace_db_in_url(url: &str, db: &str) -> String {
    match url.rfind('/') {
        Some(idx) => format!("{}/{}", &url[..idx], db),
        None => format!("{url}/{db}"),
    }
}
