//! Integration tests for [`PostgresStorage`] against a real local Postgres.
//!
//! Each test creates an ephemeral database (`conduit_test_<unique>`), runs all
//! migrations, exercises the storage methods, then drops the database on
//! cleanup.  Tests are fully isolated — no shared state between them.
//!
//! # Running
//!
//! ```
//! DATABASE_URL=postgresql://postgres@localhost/conduit \
//!     cargo test --workspace --tests
//! ```
//!
//! The `DATABASE_URL` env-var is only used to locate the admin connection
//! (we connect to the `postgres` maintenance DB for CREATE/DROP DATABASE).

use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Utc;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use conduit::event::Event;
use conduit::storage::Storage;
use conduit_server::PostgresStorage;

// ---------------------------------------------------------------------------
// TempDb — ephemeral test database fixture
// ---------------------------------------------------------------------------

/// Creates a fresh Postgres database for a single test and drops it on `Drop`.
///
/// Isolation strategy: each test gets its own DB named
/// `conduit_test_<thread_id>_<unix_nanos>`.  Because async tests run on a
/// thread pool we combine both to get a collision-resistant name without
/// pulling in the `uuid` crate.
struct TempDb {
    admin_url: String,
    db_name: String,
    pool: PgPool,
}

impl TempDb {
    async fn new() -> Self {
        let admin_url =
            std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://postgres@localhost/postgres".to_owned());

        // Build unique name: conduit_test_<thread_id>_<nanos>
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let tid = format!("{:?}", std::thread::current().id())
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();
        let db_name = format!("conduit_test_{}_{}", tid, nanos).to_lowercase();

        // Connect to admin DB and create the test database.
        let admin_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&admin_url)
            .await
            .expect("connect to admin postgres");

        sqlx::query(&format!("CREATE DATABASE {db_name}"))
            .execute(&admin_pool)
            .await
            .unwrap_or_else(|e| panic!("CREATE DATABASE {db_name}: {e}"));

        admin_pool.close().await;

        // Build the URL for the new database by replacing the DB component.
        let test_url = replace_db_in_url(&admin_url, &db_name);
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&test_url)
            .await
            .unwrap_or_else(|e| panic!("connect to test db {db_name}: {e}"));

        // Run migrations.
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .unwrap_or_else(|e| panic!("migrations on {db_name}: {e}"));

        TempDb {
            admin_url,
            db_name,
            pool,
        }
    }

    fn storage(&self) -> PostgresStorage {
        PostgresStorage::new(self.pool.clone())
    }

    /// Open a *second* pool against the same database — simulates a process
    /// restart connecting to a pre-existing database.
    async fn reopen(&self) -> PostgresStorage {
        let test_url = replace_db_in_url(&self.admin_url, &self.db_name);
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&test_url)
            .await
            .unwrap_or_else(|e| panic!("reopen pool on {}: {e}", self.db_name));
        PostgresStorage::new(pool)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        // Best-effort cleanup: drop the ephemeral database.  We must use a
        // synchronous command here because `Drop` cannot be async.
        //
        // `WITH (FORCE)` (PG 13+) terminates any remaining connections before
        // dropping, which handles the case where the pool hasn't fully drained
        // yet when Drop fires during parallel test execution.
        let _ = std::process::Command::new("psql")
            .args([
                &self.admin_url,
                "-c",
                &format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.db_name),
            ])
            .output();
    }
}

/// Replace the database segment of a postgres URL.
///
/// Handles both `postgresql://host/db` and `postgresql://user@host/db` forms.
fn replace_db_in_url(url: &str, new_db: &str) -> String {
    // Strip trailing slashes then replace everything after the last `/`.
    let url = url.trim_end_matches('/');
    if let Some(pos) = url.rfind('/') {
        format!("{}/{}", &url[..pos], new_db)
    } else {
        format!("{}/{}", url, new_db)
    }
}

// ---------------------------------------------------------------------------
// Helper: build a minimal Event for testing
// ---------------------------------------------------------------------------

fn make_event(event_id: &str, room_id: &str, event_type: &str, state_key: Option<&str>) -> Event {
    Event {
        event_id: event_id.to_owned(),
        room_id: room_id.to_owned(),
        sender: "@alice:localhost".to_owned(),
        event_type: event_type.to_owned(),
        state_key: state_key.map(|s| s.to_owned()),
        content: json!({ "test": true }),
        origin_server_ts: 1_700_000_000_000,
    }
}

// ---------------------------------------------------------------------------
// Test 1: accounts_round_trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn accounts_round_trip() {
    let db = TempDb::new().await;
    let s = db.storage();

    // create_account
    s.create_account("@alice:localhost", Some("hash_abc")).await.unwrap();

    // get_account — should exist
    let acct = s.get_account("@alice:localhost").await.unwrap().expect("account must exist");
    assert_eq!(acct.user_id, "@alice:localhost");
    assert_eq!(acct.password_hash.as_deref(), Some("hash_abc"));
    assert!(!acct.is_admin);
    assert!(acct.deactivated_at.is_none());

    // get_account — unknown user
    let none = s.get_account("@nobody:localhost").await.unwrap();
    assert!(none.is_none());

    // set_admin
    s.set_admin("@alice:localhost", true).await.unwrap();
    let acct = s.get_account("@alice:localhost").await.unwrap().unwrap();
    assert!(acct.is_admin);

    // deactivate_account
    s.deactivate_account("@alice:localhost").await.unwrap();
    let acct = s.get_account("@alice:localhost").await.unwrap().unwrap();
    assert!(acct.deactivated_at.is_some());

    // create_account — duplicate must fail
    let err = s.create_account("@alice:localhost", None).await;
    assert!(err.is_err(), "duplicate create_account should fail");
}

// ---------------------------------------------------------------------------
// Test 2: devices_round_trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn devices_round_trip() {
    let db = TempDb::new().await;
    let s = db.storage();

    // Prerequisite: account must exist (FK on devices.user_id).
    s.create_account("@bob:localhost", None).await.unwrap();

    // upsert_device — insert
    s.upsert_device("@bob:localhost", "DEVICE1", Some("Bob's Phone")).await.unwrap();

    // get_device — hit
    let dev = s.get_device("@bob:localhost", "DEVICE1").await.unwrap().expect("device must exist");
    assert_eq!(dev.user_id, "@bob:localhost");
    assert_eq!(dev.device_id, "DEVICE1");
    assert_eq!(dev.display_name.as_deref(), Some("Bob's Phone"));

    // get_device — miss
    let none = s.get_device("@bob:localhost", "MISSING").await.unwrap();
    assert!(none.is_none());

    // upsert_device — update display name
    s.upsert_device("@bob:localhost", "DEVICE1", Some("Bob's Laptop")).await.unwrap();
    let dev = s.get_device("@bob:localhost", "DEVICE1").await.unwrap().unwrap();
    assert_eq!(dev.display_name.as_deref(), Some("Bob's Laptop"));

    // list_devices_for_user — multiple devices
    s.upsert_device("@bob:localhost", "DEVICE2", None).await.unwrap();
    let mut devices = s.list_devices_for_user("@bob:localhost").await.unwrap();
    devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].device_id, "DEVICE1");
    assert_eq!(devices[1].device_id, "DEVICE2");
}

// ---------------------------------------------------------------------------
// Test 3: tokens_round_trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tokens_round_trip() {
    let db = TempDb::new().await;
    let s = db.storage();

    // Set up account + device (FK chain: access_tokens → devices → accounts).
    s.create_account("@carol:localhost", None).await.unwrap();
    s.upsert_device("@carol:localhost", "DEV_A", None).await.unwrap();
    s.upsert_device("@carol:localhost", "DEV_B", None).await.unwrap();

    // insert_token — no expiry
    s.insert_token("hash_no_expiry", "@carol:localhost", "DEV_A", None).await.unwrap();

    // lookup_token — hit
    let owner = s.lookup_token("hash_no_expiry").await.unwrap().expect("token must resolve");
    assert_eq!(owner.user_id, "@carol:localhost");
    assert_eq!(owner.device_id, "DEV_A");

    // lookup_token — miss
    let none = s.lookup_token("hash_does_not_exist").await.unwrap();
    assert!(none.is_none());

    // insert_token — with expiry in the past → lookup returns None
    let past = Utc::now() - chrono::Duration::hours(1);
    s.insert_token("hash_expired", "@carol:localhost", "DEV_B", Some(past)).await.unwrap();
    let expired = s.lookup_token("hash_expired").await.unwrap();
    assert!(expired.is_none(), "expired token should not resolve");

    // insert_token — with expiry in the future → lookup returns Some
    let future = Utc::now() + chrono::Duration::hours(1);
    s.insert_token("hash_future", "@carol:localhost", "DEV_B", Some(future)).await.unwrap();
    let owner = s.lookup_token("hash_future").await.unwrap().expect("future token must resolve");
    assert_eq!(owner.device_id, "DEV_B");

    // revoke_token — after revoke, lookup returns None
    s.revoke_token("hash_no_expiry").await.unwrap();
    let revoked = s.lookup_token("hash_no_expiry").await.unwrap();
    assert!(revoked.is_none(), "revoked token should not resolve");
}

// ---------------------------------------------------------------------------
// Test 4: signing_keys_round_trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn signing_keys_round_trip() {
    let db = TempDb::new().await;
    let s = db.storage();

    // No keys yet.
    let none = s.current_signing_key().await.unwrap();
    assert!(none.is_none());

    // Insert two keys.
    s.insert_signing_key("ed25519:key1", b"priv1", b"pub1", Some(9_999_999)).await.unwrap();
    // Small sleep-free ordering: key2 inserted after key1 → key2 is newest.
    // `created_at` defaults to `now()` with sub-ms precision; in practice the
    // two inserts are distinct timestamps, but to be safe we rely on insertion
    // order + `created_at DESC` ordering in the impl.
    s.insert_signing_key("ed25519:key2", b"priv2", b"pub2", None).await.unwrap();

    // current_signing_key returns the most recently inserted one.
    let current = s.current_signing_key().await.unwrap().expect("must have a key");
    assert_eq!(current.key_id, "ed25519:key2");
    assert_eq!(current.private_key, b"priv2");
    assert_eq!(current.public_key, b"pub2");
    assert!(current.valid_until_ts.is_none());

    // signing_keys_for_verification returns both.
    let all = s.signing_keys_for_verification().await.unwrap();
    assert_eq!(all.len(), 2);
    let ids: Vec<&str> = all.iter().map(|k| k.key_id.as_str()).collect();
    assert!(ids.contains(&"ed25519:key1"), "key1 must be present");
    assert!(ids.contains(&"ed25519:key2"), "key2 must be present");
}

// ---------------------------------------------------------------------------
// Test 5: events_round_trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn events_round_trip() {
    let db = TempDb::new().await;
    let s = db.storage();

    let e1 = make_event("$evt1:localhost", "!room1:localhost", "m.room.message", None);
    let e2 = make_event("$evt2:localhost", "!room1:localhost", "m.room.message", None);
    let e3 = make_event("$evt3:localhost", "!room2:localhost", "m.room.message", None);

    // put_event
    s.put_event(&e1).await.unwrap();
    s.put_event(&e2).await.unwrap();
    s.put_event(&e3).await.unwrap();

    // get_event — hit
    let got = s.get_event("$evt1:localhost").await.unwrap().expect("event must exist");
    assert_eq!(got.event_id, "$evt1:localhost");
    assert_eq!(got.room_id, "!room1:localhost");
    assert_eq!(got.event_type, "m.room.message");
    assert_eq!(got.origin_server_ts, 1_700_000_000_000);

    // get_event — miss
    let none = s.get_event("$missing:localhost").await.unwrap();
    assert!(none.is_none());

    // room_events — filters by room_id
    let room1_events = s.room_events("!room1:localhost").await.unwrap();
    assert_eq!(room1_events.len(), 2);
    let ids: Vec<&str> = room1_events.iter().map(|e| e.event_id.as_str()).collect();
    assert!(ids.contains(&"$evt1:localhost"));
    assert!(ids.contains(&"$evt2:localhost"));

    let room2_events = s.room_events("!room2:localhost").await.unwrap();
    assert_eq!(room2_events.len(), 1);
    assert_eq!(room2_events[0].event_id, "$evt3:localhost");

    // room_events — empty room
    let empty = s.room_events("!nonexistent:localhost").await.unwrap();
    assert!(empty.is_empty());

    // put_event — idempotent (ON CONFLICT DO NOTHING)
    s.put_event(&e1).await.unwrap();
}

// ---------------------------------------------------------------------------
// Test 6: room_current_state_round_trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn room_current_state_round_trip() {
    let db = TempDb::new().await;
    let s = db.storage();

    let room_id = "!stateroom:localhost";

    // Events must exist before room_current_state can reference them (FK).
    let create_evt = make_event("$create:localhost", room_id, "m.room.create", Some(""));
    let member_evt = make_event("$member_alice:localhost", room_id, "m.room.member", Some("@alice:localhost"));
    let topic_evt = make_event("$topic:localhost", room_id, "m.room.topic", Some(""));

    s.put_event(&create_evt).await.unwrap();
    s.put_event(&member_evt).await.unwrap();
    s.put_event(&topic_evt).await.unwrap();

    // set_state_entry
    s.set_state_entry(room_id, "m.room.create", "", "$create:localhost").await.unwrap();
    s.set_state_entry(room_id, "m.room.member", "@alice:localhost", "$member_alice:localhost").await.unwrap();
    s.set_state_entry(room_id, "m.room.topic", "", "$topic:localhost").await.unwrap();

    // get_state_entry — hit
    let got = s.get_state_entry(room_id, "m.room.create", "").await.unwrap()
        .expect("create state must exist");
    assert_eq!(got.event_id, "$create:localhost");

    let got = s.get_state_entry(room_id, "m.room.member", "@alice:localhost").await.unwrap()
        .expect("member state must exist");
    assert_eq!(got.event_id, "$member_alice:localhost");

    // get_state_entry — miss
    let none = s.get_state_entry(room_id, "m.room.power_levels", "").await.unwrap();
    assert!(none.is_none());

    // get_current_state — all three entries
    let state = s.get_current_state(room_id).await.unwrap();
    assert_eq!(state.len(), 3);
    let ids: Vec<&str> = state.iter().map(|e| e.event_id.as_str()).collect();
    assert!(ids.contains(&"$create:localhost"));
    assert!(ids.contains(&"$member_alice:localhost"));
    assert!(ids.contains(&"$topic:localhost"));

    // set_state_entry — upsert replaces existing entry
    let topic_v2 = make_event("$topic_v2:localhost", room_id, "m.room.topic", Some(""));
    s.put_event(&topic_v2).await.unwrap();
    s.set_state_entry(room_id, "m.room.topic", "", "$topic_v2:localhost").await.unwrap();
    let got = s.get_state_entry(room_id, "m.room.topic", "").await.unwrap().unwrap();
    assert_eq!(got.event_id, "$topic_v2:localhost");

    // get_current_state — still three entries after the upsert
    let state = s.get_current_state(room_id).await.unwrap();
    assert_eq!(state.len(), 3);
}

// ---------------------------------------------------------------------------
// Test 7: persists_across_pool_restart (the "process restart" check)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn persists_across_pool_restart() {
    let db = TempDb::new().await;

    // --- Write phase: pool #1 ---
    {
        let s1 = db.storage();

        s1.create_account("@restart:localhost", Some("hash_restart")).await.unwrap();
        s1.set_admin("@restart:localhost", true).await.unwrap();
        s1.upsert_device("@restart:localhost", "DEV_RESTART", Some("Restart Device")).await.unwrap();
        s1.insert_token("token_restart_hash", "@restart:localhost", "DEV_RESTART", None).await.unwrap();
        s1.insert_signing_key("ed25519:restart_key", b"restart_priv", b"restart_pub", None).await.unwrap();

        let evt = make_event("$restart_evt:localhost", "!restart_room:localhost", "m.room.create", Some(""));
        s1.put_event(&evt).await.unwrap();
        s1.set_state_entry("!restart_room:localhost", "m.room.create", "", "$restart_evt:localhost").await.unwrap();

        // s1 (and its pool) go out of scope here — simulating process exit.
    }

    // --- Read phase: pool #2 (same DB, new connection pool) ---
    let s2 = db.reopen().await;

    // Account persisted.
    let acct = s2.get_account("@restart:localhost").await.unwrap().expect("account must survive restart");
    assert_eq!(acct.user_id, "@restart:localhost");
    assert_eq!(acct.password_hash.as_deref(), Some("hash_restart"));
    assert!(acct.is_admin, "admin flag must survive restart");
    assert!(acct.deactivated_at.is_none());

    // Device persisted.
    let dev = s2.get_device("@restart:localhost", "DEV_RESTART").await.unwrap()
        .expect("device must survive restart");
    assert_eq!(dev.display_name.as_deref(), Some("Restart Device"));

    // Token persisted and resolves correctly.
    let owner = s2.lookup_token("token_restart_hash").await.unwrap()
        .expect("token must survive restart");
    assert_eq!(owner.user_id, "@restart:localhost");
    assert_eq!(owner.device_id, "DEV_RESTART");

    // Signing key persisted.
    let key = s2.current_signing_key().await.unwrap().expect("signing key must survive restart");
    assert_eq!(key.key_id, "ed25519:restart_key");
    assert_eq!(key.private_key, b"restart_priv");
    assert_eq!(key.public_key, b"restart_pub");

    // Event persisted.
    let evt = s2.get_event("$restart_evt:localhost").await.unwrap()
        .expect("event must survive restart");
    assert_eq!(evt.room_id, "!restart_room:localhost");

    // Room state persisted.
    let state_evt = s2.get_state_entry("!restart_room:localhost", "m.room.create", "").await.unwrap()
        .expect("room state must survive restart");
    assert_eq!(state_evt.event_id, "$restart_evt:localhost");
}
