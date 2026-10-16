//! PostgreSQL implementation of [`conduit::storage::Storage`].
//!
//! `PostgresStorage` wraps a `sqlx::PgPool` and implements every method of
//! the `Storage` trait using compile-time-checked `sqlx::query!` macros.
//! Requires `DATABASE_URL` to be set at build time for macro expansion.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use serde_json::Value;

use conduit::{
    Error, Result,
    event::{Event, IntegrityClass, WirePdu},
    storage::{
        RefreshTokenRecord,
        Account, AuditEntry, Device, DirectoryScope, DlqEntry, MediaMetadata, OutboundEntry,
        Pusher, PushRule, RoomKeyVersion, SigningKey, Storage, ThumbnailMetadata,
        ToDeviceMessage, TokenOwner, UserDirectoryEntry,
    },
};

// ---------------------------------------------------------------------------
// PostgresStorage
// ---------------------------------------------------------------------------

pub struct PostgresStorage {
    pool: PgPool,
    lock_pool: PgPool,
    /// Highest stream position the legacy integrity sweep has visited.
    sweep_cursor: std::sync::atomic::AtomicI64,
}

impl PostgresStorage {
    pub fn new(pool: PgPool) -> Self {
        // Keep lifetime advisory locks off the data pool. Otherwise several
        // guarded requests can occupy every connection needed for their writes.
        let lock_pool = sqlx::postgres::PgPoolOptions::new().max_connections(4)
            .connect_lazy_with((*pool.connect_options()).clone());
        Self { pool, lock_pool, sweep_cursor: std::sync::atomic::AtomicI64::new(0) }
    }

    /// Classify a legacy (`unchecked`) row from its own bytes and persist the
    /// class. `verified` and `content_mismatch` rows get `pdu_json` backfilled
    /// with the rebuilt, unredacted Pdu, so client reads are byte-identical
    /// before and after; `id_mismatch` rows keep `pdu_json` NULL. Never
    /// rewrites a primary key. Only an `unchecked` row is updated.
    async fn classify_legacy_row(&self, event: &Event, had_pdu_json: bool) -> Result<IntegrityClass> {
        let class = conduit::event::classify(&event.event_id, &event.pdu);
        let backfill = match class {
            IntegrityClass::IdMismatch => None,
            _ if had_pdu_json => None,
            _ => conduit::canonical_json::to_canonical_string(&event.pdu).ok(),
        };
        if class == IntegrityClass::IdMismatch {
            let derived = conduit::hashing::event_id(&event.pdu).unwrap_or_default();
            tracing::warn!(event_id = %event.event_id, %derived,
                "legacy event row does not reproduce its ID; it will not be served over federation");
        }
        sqlx::query!(
            "UPDATE events SET id_integrity = $2, pdu_json = COALESCE(pdu_json, $3) WHERE event_id = $1 AND id_integrity = 'unchecked'",
            event.event_id, class.as_str(), backfill
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(class)
    }

    /// Convenience constructor that wraps self in `Arc<dyn Storage>`.
    pub fn into_arc(self) -> Arc<dyn Storage> {
        Arc::new(self)
    }
}

struct PostgresTransactionGuard {
    _transaction: sqlx::Transaction<'static, sqlx::Postgres>,
}
impl conduit::storage::TransactionGuard for PostgresTransactionGuard {}

// ---------------------------------------------------------------------------
// Helper: map sqlx errors to conduit::Error
// ---------------------------------------------------------------------------

/// Map a sqlx error, keeping the PostgreSQL data-exception class (SQLSTATE
/// 22xxx, e.g. U+0000 in JSONB/TEXT) distinct so callers can drop that one
/// item deterministically instead of failing a whole request.
fn map_sqlx(e: sqlx::Error) -> Error {
    if let sqlx::Error::Database(db) = &e {
        if let Some(code) = db.code() {
            if code.starts_with("22") {
                return Error::StorageData(format!("SQLSTATE {code}"));
            }
        }
    }
    Error::Storage(e.to_string())
}

// ---------------------------------------------------------------------------
// Lossless JSON text (replay + outbox sinks; add-pdu-wire migration 0091)
// ---------------------------------------------------------------------------

/// Lossless JSON text: `serde_json` keeps floats and escapes U+0000 as
/// `\u0000`. Never the Matrix canonical encoder, which refuses floats.
fn json_text(value: &Value) -> String {
    serde_json::to_string(value).expect("serde_json::Value always serialises")
}

/// Prefer the text column; fall back to the legacy JSONB column.
fn text_or_json(text: Option<String>, legacy: Option<Value>) -> Result<Value> {
    match text {
        Some(text) => serde_json::from_str(&text).map_err(|e| Error::Storage(format!("stored JSON text: {e}"))),
        None => Ok(legacy.unwrap_or(Value::Null)),
    }
}

// ---------------------------------------------------------------------------
// Events: the single row decoder and writer (add-pdu-wire)
// ---------------------------------------------------------------------------

/// The columns every `events` read selects.
struct EventRow {
    event_id: String,
    pdu_json: Option<String>,
    room_id: String,
    sender: String,
    event_type: String,
    state_key: Option<String>,
    content: Value,
    origin_server_ts: i64,
    auth_events: Vec<String>,
    prev_events: Vec<String>,
    hashes: Value,
    signatures: Value,
    depth: i64,
    unsigned: Option<Value>,
}

/// Rebuild a Pdu from the projection columns (legacy rows: no extensions).
fn projected_pdu(row: &EventRow) -> conduit::event::Pdu {
    conduit::event::Pdu {
        room_id: row.room_id.clone(),
        sender: row.sender.clone(),
        event_type: row.event_type.clone(),
        content: row.content.clone(),
        state_key: row.state_key.clone(),
        origin_server_ts: row.origin_server_ts as u64,
        auth_events: row.auth_events.clone(),
        prev_events: row.prev_events.clone(),
        hashes: row.hashes.clone(),
        signatures: row.signatures.clone(),
        depth: row.depth,
        extensions: Default::default(),
    }
}

/// The single `events` row decoder: `pdu_json` (authoritative) when present,
/// otherwise the projection columns exactly as pre-change reads returned.
fn event_from_row(row: EventRow) -> Event {
    let pdu = match row.pdu_json.as_deref().map(serde_json::from_str::<conduit::event::Pdu>) {
        Some(Ok(pdu)) => pdu,
        Some(Err(error)) => {
            tracing::error!(event_id = %row.event_id, %error, "unreadable pdu_json; using projections");
            projected_pdu(&row)
        }
        None => projected_pdu(&row),
    };
    Event { event_id: row.event_id, pdu, unsigned: row.unsigned }
}

/// Insert one event: authoritative canonical `pdu_json`, NUL-safe JSONB
/// projections, NUL-free unsigned, and its integrity class. A row whose
/// reference hash equals its ID is `verified` (including PDUs redacted on
/// receipt: the redaction is the authoritative copy); otherwise `id_mismatch`.
async fn insert_event(connection: &mut sqlx::PgConnection, event: &Event) -> Result<()> {
    use conduit::wire::{project_nul, strip_nul_unsigned};
    let (pdu_json, integrity) = match conduit::canonical_json::to_canonical_string(&event.pdu) {
        Ok(text) => {
            let verified = conduit::hashing::event_id(&event.pdu).is_ok_and(|id| id == event.event_id);
            (text, if verified { "verified" } else { "id_mismatch" })
        }
        // Not canonical JSON (e.g. a float): cannot be hashed, never served.
        Err(_) => (json_text(&serde_json::to_value(&event.pdu)?), "id_mismatch"),
    };
    let room_id = if event.room_id.is_empty() {
        conduit::room_version::room_id_from_event_id(&event.event_id)
    } else {
        event.room_id.clone()
    };
    sqlx::query!(
        r#"
        INSERT INTO events
            (event_id, room_id, sender, type, state_key, content,
             auth_events, prev_events, signatures, hashes, unsigned,
             origin_server_ts, depth, pdu_json, id_integrity)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        ON CONFLICT (event_id) DO NOTHING
        "#,
        event.event_id,
        room_id,
        event.sender,
        event.event_type,
        event.state_key,
        project_nul(&event.content),
        &event.auth_events,
        &event.prev_events,
        project_nul(&event.signatures),
        project_nul(&event.hashes),
        strip_nul_unsigned(event.unsigned.as_ref()),
        event.origin_server_ts as i64,
        event.depth,
        pdu_json,
        integrity,
    )
    .execute(connection)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

/// After a row is inserted, drop unprotected keys from any event an
/// *applying* redaction now covers. Hashes and signatures stay. The write
/// is in the caller's transaction, so the redaction and the prune commit
/// together. A redaction that does not apply (another server, below the
/// redact level) leaves the target untouched.
async fn prune_after_insert(conn: &mut sqlx::PgConnection, event: &Event) -> Result<()> {
    let mut ids = Vec::new();
    if let Some(target) = conduit::room_content::redaction_target(event) {
        ids.push(target.to_owned());
    }
    ids.push(event.event_id.clone());
    ids.sort();
    ids.dedup();
    for id in ids {
        prune_target(conn, &id).await?;
    }
    Ok(())
}

async fn load_pdu(conn: &mut sqlx::PgConnection, event_id: &str) -> Result<Option<Event>> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT event_id, pdu_json FROM events WHERE event_id = $1 FOR UPDATE",
    )
    .bind(event_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(map_sqlx)?;
    let Some((id, pdu_json)) = row else { return Ok(None) };
    let Some(pdu_json) = pdu_json else { return Ok(None) };
    let pdu: conduit::event::Pdu = serde_json::from_str(&pdu_json)
        .map_err(|error| Error::Storage(format!("unreadable pdu_json for {id}: {error}")))?;
    Ok(Some(Event::new(id, pdu)))
}

async fn prune_target(conn: &mut sqlx::PgConnection, event_id: &str) -> Result<()> {
    let Some(target) = load_pdu(conn, event_id).await? else { return Ok(()) };
    let redaction_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT event_id, pdu_json FROM events
         WHERE room_id = $1 AND type = 'm.room.redaction'
           AND content->>'redacts' = $2 AND pdu_json IS NOT NULL",
    )
    .bind(&target.room_id)
    .bind(&target.event_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(map_sqlx)?;
    let mut applies = false;
    for (redaction_id, pdu_json) in redaction_rows {
        let pdu: conduit::event::Pdu = serde_json::from_str(&pdu_json)
            .map_err(|error| Error::Storage(format!("unreadable redaction {redaction_id}: {error}")))?;
        let redaction = Event::new(redaction_id, pdu);
        let (power_levels, creator) = redaction_auth(conn, &redaction).await?;
        if conduit::room_content::redaction_applies(&redaction, &target, power_levels.as_ref(), creator.as_deref()) {
            applies = true;
            break;
        }
    }
    if !applies {
        return Ok(());
    }
    let version: Option<String> = sqlx::query_scalar(
        "SELECT e.content->>'room_version' FROM room_current_state s
         JOIN events e ON e.event_id = s.event_id
         WHERE s.room_id = $1 AND s.type = 'm.room.create' AND s.state_key = ''",
    )
    .bind(&target.room_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(map_sqlx)?;
    let version = version.as_deref().and_then(|text| text.parse().ok()).unwrap_or(11);
    let pruned = conduit::room_version::redact_pdu(&target.pdu, version);
    if pruned.content == target.content && pruned.extensions == target.extensions {
        return Ok(());
    }
    let pdu_json = conduit::canonical_json::to_canonical_string(&pruned)
        .map_err(|error| Error::Storage(format!("redacted PDU is not canonical JSON: {error}")))?;
    let content = conduit::wire::project_nul(&pruned.content);
    sqlx::query(
        "UPDATE events SET content = $2, pdu_json = $3, id_integrity = 'redacted' WHERE event_id = $1",
    )
    .bind(&target.event_id)
    .bind(content)
    .bind(pdu_json)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

async fn redaction_auth(
    conn: &mut sqlx::PgConnection,
    redaction: &Event,
) -> Result<(Option<Event>, Option<String>)> {
    let mut power_levels = None;
    let mut creator = None;
    for id in &redaction.auth_events {
        let Some(event) = load_pdu(conn, id).await? else { continue };
        if event.event_type == "m.room.power_levels" {
            power_levels = Some(event);
        } else if event.event_type == "m.room.create" {
            creator = Some(event.sender.clone());
        }
    }
    Ok((power_levels, creator))
}

// ---------------------------------------------------------------------------
// Commit-ordered stream positions (conduit-y99.16)
// ---------------------------------------------------------------------------

/// A sync stream whose cursor is a PostgreSQL sequence position.
///
/// A `BIGSERIAL` value is allocated when the row is inserted, not when the
/// transaction commits: position N+1 can become visible while N is still in
/// flight, and a reader that advances its cursor to N+1 would skip N forever.
/// Every writer therefore takes the stream's transaction-scoped advisory lock
/// before allocating a position and holds it through commit. PostgreSQL makes
/// a commit visible before it releases the transaction's locks, so the next
/// writer allocates only after every lower position is visible: the highest
/// position a reader observes is a safe watermark. Each transaction takes at
/// most one stream lock, so the locks cannot deadlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Events,
    AccountData,
    Receipts,
    DeviceLists,
    ToDevice,
}

impl Stream {
    /// The advisory lock key (ASCII "cndt" + a per-stream discriminator).
    pub fn lock_key(self) -> i64 {
        0x636e_6474_0000_0000
            + match self {
                Stream::Events => 1,
                Stream::AccountData => 2,
                Stream::Receipts => 3,
                Stream::DeviceLists => 4,
                Stream::ToDevice => 5,
            }
    }
}

/// Serialise position allocation for `stream` with this transaction's commit.
pub async fn lock_stream(connection: &mut sqlx::PgConnection, stream: Stream) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(stream.lock_key())
        .execute(connection)
        .await
        .map_err(map_sqlx)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Storage impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Storage for PostgresStorage {
    async fn put_filter(&self, user: &str, id: &str, definition: &Value) -> Result<()> {
        sqlx::query!("INSERT INTO client_filters (user_id, filter_id, definition) VALUES ($1, $2, $3)", user, id, definition)
            .execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }
    async fn get_filter(&self, user: &str, id: &str) -> Result<Option<Value>> {
        let row = sqlx::query!("SELECT definition FROM client_filters WHERE user_id = $1 AND filter_id = $2", user, id)
            .fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        Ok(row.map(|row| row.definition))
    }

    async fn lock_transaction(&self, key: &conduit::storage::TransactionKey) -> Result<Box<dyn conduit::storage::TransactionGuard>> {
        use sha2::{Digest, Sha256};
        let identity = serde_json::json!(["conduit-replay", key.scope, key.owner, key.endpoint, key.txn_id]).to_string();
        let digest = Sha256::digest(identity.as_bytes());
        let lock_id = i64::from_be_bytes(digest[..8].try_into().expect("eight hash bytes"));
        let mut transaction = self.lock_pool.begin().await.map_err(map_sqlx)?;
        sqlx::query!("SELECT pg_advisory_xact_lock($1) IS NULL AS lock_held", lock_id)
            .fetch_one(&mut *transaction).await.map_err(map_sqlx)?;
        Ok(Box::new(PostgresTransactionGuard {_transaction: transaction}))
    }

    // Replay bodies and results are lossless JSON text (`*_text`, migration
    // 0091); rows written before it keep their JSONB columns, read as a
    // fallback. Text keeps U+0000 (`\u0000`) and floats, which JSONB or the
    // canonical encoder would refuse.

    async fn transaction_original(&self, key: &conduit::storage::TransactionKey) -> Result<Option<Value>> {
        let row = sqlx::query!("SELECT request_text, request FROM transactions WHERE scope = $1 AND owner = $2 AND endpoint = $3 AND txn_id = $4",
            key.scope, key.owner, key.endpoint, key.txn_id).fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        match row {
            Some(row) if row.request_text.is_some() || row.request.is_some() => Ok(Some(text_or_json(row.request_text, row.request)?)),
            _ => Ok(None),
        }
    }

    async fn transaction_request(&self, key: &conduit::storage::TransactionKey, request: &Value) -> Result<Value> {
        let row = sqlx::query!(
            r#"INSERT INTO transactions (scope, owner, endpoint, txn_id, request_text)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (scope, owner, endpoint, txn_id) DO UPDATE
                SET request_text = CASE WHEN transactions.request IS NULL
                    THEN COALESCE(transactions.request_text, EXCLUDED.request_text)
                    ELSE transactions.request_text END
            RETURNING request_text, request"#,
            key.scope, key.owner, key.endpoint, key.txn_id, json_text(request)
        ).fetch_one(&self.pool).await.map_err(map_sqlx)?;
        if row.request_text.is_none() && row.request.is_none() {
            return Err(Error::Storage("missing original transaction request".into()));
        }
        text_or_json(row.request_text, row.request)
    }

    async fn finish_transaction(&self, key: &conduit::storage::TransactionKey, result: &Value) -> Result<Value> {
        let row = sqlx::query!(
            r#"INSERT INTO transactions (scope, owner, endpoint, txn_id, result_text)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (scope, owner, endpoint, txn_id) DO UPDATE
                SET result_text = CASE WHEN transactions.result IS NULL
                    THEN COALESCE(transactions.result_text, EXCLUDED.result_text)
                    ELSE transactions.result_text END
            RETURNING result_text, result"#,
            key.scope, key.owner, key.endpoint, key.txn_id, json_text(result)
        ).fetch_one(&self.pool).await.map_err(map_sqlx)?;
        if row.result_text.is_none() && row.result.is_none() {
            return Err(Error::Storage("missing completed transaction result".into()));
        }
        text_or_json(row.result_text, row.result)
    }

    async fn transaction_result(&self, key: &conduit::storage::TransactionKey) -> Result<Option<Value>> {
        let row = sqlx::query!(
            "SELECT result_text, result FROM transactions WHERE scope = $1 AND owner = $2 AND endpoint = $3 AND txn_id = $4",
            key.scope, key.owner, key.endpoint, key.txn_id
        ).fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        match row {
            Some(row) if row.result_text.is_some() || row.result.is_some() => Ok(Some(text_or_json(row.result_text, row.result)?)),
            _ => Ok(None),
        }
    }

    async fn put_event_once(&self, key: &conduit::storage::TransactionKey, event: &Event) -> Result<(String, bool)> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        // The client event-transaction result is a fixed, NUL-free object
        // ({"event_id": "$<base64>"}); it is also kept in the JSONB column
        // for the 0051 event -> transaction_id lookup index.
        let result_json = serde_json::json!({"event_id": event.event_id});
        let result = json_text(&result_json);
        let inserted = sqlx::query!(
            "INSERT INTO transactions (scope, owner, endpoint, txn_id, result_text, result) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            key.scope, key.owner, key.endpoint, key.txn_id, result, result_json
        ).execute(&mut *transaction).await.map_err(map_sqlx)?.rows_affected() > 0;
        if !inserted {
            let row = sqlx::query!(
                "SELECT result_text, result FROM transactions WHERE scope = $1 AND owner = $2 AND endpoint = $3 AND txn_id = $4 FOR UPDATE",
                key.scope, key.owner, key.endpoint, key.txn_id
            ).fetch_one(&mut *transaction).await.map_err(map_sqlx)?;
            if row.result_text.is_some() || row.result.is_some() {
                let stored = text_or_json(row.result_text, row.result)?;
                let id = stored["event_id"].as_str().ok_or_else(|| Error::Storage("invalid stored event transaction".into()))?.to_owned();
                transaction.commit().await.map_err(map_sqlx)?;
                return Ok((id, false));
            }
            sqlx::query!("UPDATE transactions SET result_text = $5, result = $6 WHERE scope = $1 AND owner = $2 AND endpoint = $3 AND txn_id = $4",
                key.scope, key.owner, key.endpoint, key.txn_id, result, result_json).execute(&mut *transaction).await.map_err(map_sqlx)?;
        }
        if event.state_key.is_some() {
            return Err(Error::InvalidEvent("put_event_once accepts non-state events only".into()));
        }
        lock_stream(&mut transaction, Stream::Events).await?;
        insert_event(&mut transaction, event).await?;
        prune_after_insert(&mut transaction, event).await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok((event.event_id.clone(), true))
    }

    async fn deliver_to_device_once(&self, key: &conduit::storage::TransactionKey,
        local: &[conduit::storage::ToDeviceDelivery], remote: &[conduit::storage::OutboundDelivery]) -> Result<bool> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let result = json_text(&serde_json::json!({}));
        let inserted = sqlx::query!(
            "INSERT INTO transactions (scope, owner, endpoint, txn_id, result_text) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            key.scope, key.owner, key.endpoint, key.txn_id, result
        ).execute(&mut *transaction).await.map_err(map_sqlx)?.rows_affected() > 0;
        if !inserted {
            let row = sqlx::query!("SELECT result_text, result FROM transactions WHERE scope = $1 AND owner = $2 AND endpoint = $3 AND txn_id = $4 FOR UPDATE",
                key.scope, key.owner, key.endpoint, key.txn_id).fetch_one(&mut *transaction).await.map_err(map_sqlx)?;
            if row.result_text.is_some() || row.result.is_some() { transaction.commit().await.map_err(map_sqlx)?; return Ok(false); }
            sqlx::query!("UPDATE transactions SET result_text = $5 WHERE scope = $1 AND owner = $2 AND endpoint = $3 AND txn_id = $4",
                key.scope, key.owner, key.endpoint, key.txn_id, result).execute(&mut *transaction).await.map_err(map_sqlx)?;
        }
        if !local.is_empty() {
            lock_stream(&mut transaction, Stream::ToDevice).await?;
        }
        for message in local {
            sqlx::query!(
                r#"
                INSERT INTO to_device_queue (target_user, target_device, sender, event_type, content)
                SELECT user_id, device_id, $3, $4, $5 FROM devices
                WHERE user_id = $1 AND ($2 = '*' OR device_id = $2)
                "#,
                message.target_user, message.target_device, message.sender, message.event_type, message.content
            ).execute(&mut *transaction).await.map_err(map_sqlx)?;
        }
        for delivery in remote {
            sqlx::query!(
                r#"
                INSERT INTO fed_outbound_queue (destination, kind, txn_id, payload_text)
                VALUES ($1, 'transaction', $2, $3)
                "#,
                delivery.destination, delivery.txn_id, json_text(&delivery.payload)
            ).execute(&mut *transaction).await.map_err(map_sqlx)?;
        }
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    async fn get_event(&self, event_id: &str) -> Result<Option<Event>> {
        let row = sqlx::query!(
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth, pdu_json
            FROM events
            WHERE event_id = $1
            "#,
            event_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(r) = row else { return Ok(None) };

        let event = event_from_row(EventRow { event_id: r.event_id, pdu_json: r.pdu_json, room_id: r.room_id, sender: r.sender, event_type: r.event_type, state_key: r.state_key, content: r.content, origin_server_ts: r.origin_server_ts, auth_events: r.auth_events, prev_events: r.prev_events, hashes: r.hashes, signatures: r.signatures, depth: r.depth, unsigned: r.unsigned });
        Ok(Some(event))
    }

    async fn put_event(&self, event: &Event) -> Result<()> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        lock_stream(&mut transaction, Stream::Events).await?;
        insert_event(&mut transaction, event).await?;
        prune_after_insert(&mut transaction, event).await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn publish_event(&self, event: &Event) -> Result<()> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        lock_stream(&mut transaction, Stream::Events).await?;
        insert_event(&mut transaction, event).await?;
        prune_after_insert(&mut transaction, event).await?;
        if let Some(state_key) = &event.state_key {
            let room_id = if event.room_id.is_empty() {
                conduit::room_version::room_id_from_event_id(&event.event_id)
            } else {
                event.room_id.clone()
            };
            // Same statement as `set_state_entry`. It stays in this
            // transaction so a lock on the state row hides the event too.
            sqlx::query(
                "INSERT INTO room_current_state (room_id, type, state_key, event_id)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (room_id, type, state_key)
                 DO UPDATE SET event_id = EXCLUDED.event_id",
            )
            .bind(&room_id)
            .bind(&event.event_type)
            .bind(state_key)
            .bind(&event.event_id)
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        }
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn room_events(&self, room_id: &str) -> Result<Vec<Event>> {
        let rows = sqlx::query!(
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth, pdu_json
            FROM events
            WHERE room_id = $1
            ORDER BY stream_position
            "#,
            room_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let events = rows
            .into_iter()
            .map(|r| event_from_row(EventRow { event_id: r.event_id, pdu_json: r.pdu_json, room_id: r.room_id, sender: r.sender, event_type: r.event_type, state_key: r.state_key, content: r.content, origin_server_ts: r.origin_server_ts, auth_events: r.auth_events, prev_events: r.prev_events, hashes: r.hashes, signatures: r.signatures, depth: r.depth, unsigned: r.unsigned }))
            .collect();

        Ok(events)
    }

    // --- Federation wire integrity (add-pdu-wire) ---------------------------

    async fn get_wire_pdu_with_class(&self, event_id: &str) -> Result<Option<(IntegrityClass, Option<WirePdu>)>> {
        let row = sqlx::query!(
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth, pdu_json, id_integrity
            FROM events WHERE event_id = $1
            "#,
            event_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let Some(r) = row else { return Ok(None) };
        let stored = IntegrityClass::parse(&r.id_integrity);
        let had_pdu_json = r.pdu_json.is_some();
        let event = event_from_row(EventRow { event_id: r.event_id, pdu_json: r.pdu_json, room_id: r.room_id, sender: r.sender, event_type: r.event_type, state_key: r.state_key, content: r.content, origin_server_ts: r.origin_server_ts, auth_events: r.auth_events, prev_events: r.prev_events, hashes: r.hashes, signatures: r.signatures, depth: r.depth, unsigned: r.unsigned });
        let class = match stored {
            Some(class) => class,
            // Unchecked legacy row: classify its own bytes inline and persist.
            None => self.classify_legacy_row(&event, had_pdu_json).await?,
        };
        let wire = match class {
            IntegrityClass::IdMismatch => None,
            // Accepted redaction: the row already holds the room version's
            // pruned PDU. Do not run the v11 content-mismatch redaction over it.
            IntegrityClass::Redacted => WirePdu::retained(&event.event_id, event.pdu),
            // Redacted on receipt or lossy: `checked` yields the redaction,
            // computed now and never written back to retained history.
            _ => WirePdu::checked(&event.event_id, event.pdu),
        };
        Ok(Some((class, wire)))
    }

    async fn verify_legacy_event_ids(&self, batch: i64) -> Result<conduit::storage::LegacySweep> {
        use std::sync::atomic::Ordering;
        let cursor = self.sweep_cursor.load(Ordering::Relaxed);
        let rows = sqlx::query!(
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth, pdu_json, stream_position
            FROM events
            WHERE id_integrity = 'unchecked' AND stream_position > $1
            ORDER BY stream_position
            LIMIT $2
            "#,
            cursor, batch
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let mut sweep = conduit::storage::LegacySweep::default();
        for r in rows {
            self.sweep_cursor.fetch_max(r.stream_position, Ordering::Relaxed);
            let had_pdu_json = r.pdu_json.is_some();
            let event = event_from_row(EventRow { event_id: r.event_id, pdu_json: r.pdu_json, room_id: r.room_id, sender: r.sender, event_type: r.event_type, state_key: r.state_key, content: r.content, origin_server_ts: r.origin_server_ts, auth_events: r.auth_events, prev_events: r.prev_events, hashes: r.hashes, signatures: r.signatures, depth: r.depth, unsigned: r.unsigned });
            match self.classify_legacy_row(&event, had_pdu_json).await? {
                IntegrityClass::Verified => sweep.verified += 1,
                IntegrityClass::ContentMismatch => sweep.content_mismatch += 1,
                IntegrityClass::IdMismatch => sweep.id_mismatch += 1,
                // Legacy classification never writes this class.
                IntegrityClass::Redacted => {}
            }
        }
        Ok(sweep)
    }

    // -----------------------------------------------------------------------
    // Accounts
    // -----------------------------------------------------------------------

    async fn create_account(&self, user_id: &str, password_hash: Option<&str>) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO accounts (user_id, password_hash)
            VALUES ($1, $2)
            "#,
            user_id,
            password_hash
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref dbe) if dbe.code().as_deref() == Some("23505") => {
                Error::Storage(format!("account already exists: {user_id}"))
            }
            other => map_sqlx(other),
        })?;

        Ok(())
    }

    async fn get_account(&self, user_id: &str) -> Result<Option<Account>> {
        let row = sqlx::query!(
            r#"
            SELECT user_id, password_hash, is_admin, created_at, deactivated_at,
                   displayname, avatar_url, is_guest
            FROM accounts
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(r) = row else { return Ok(None) };

        Ok(Some(Account {
            user_id: r.user_id,
            password_hash: r.password_hash,
            is_admin: r.is_admin,
            created_at: r.created_at,
            deactivated_at: r.deactivated_at,
            displayname: r.displayname,
            avatar_url: r.avatar_url,
            is_guest: r.is_guest,
        }))
    }

    async fn deactivate_account(&self, user_id: &str) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE accounts
            SET deactivated_at = now()
            WHERE user_id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    async fn set_admin(&self, user_id: &str, is_admin: bool) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE accounts
            SET is_admin = $2
            WHERE user_id = $1
            "#,
            user_id,
            is_admin
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Devices
    // -----------------------------------------------------------------------

    async fn upsert_device(
        &self,
        user_id: &str,
        device_id: &str,
        display_name: Option<&str>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO devices (user_id, device_id, display_name, epoch)
            VALUES ($1, $2, $3, COALESCE(
                (SELECT epoch + 1 FROM retired_device_epochs
                 WHERE user_id = $1 AND device_id = $2), 0))
            ON CONFLICT (user_id, device_id)
            DO UPDATE SET display_name = EXCLUDED.display_name
            "#,
            user_id,
            device_id,
            display_name
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    async fn get_device(&self, user_id: &str, device_id: &str) -> Result<Option<Device>> {
        let row = sqlx::query!(
            r#"
            SELECT user_id, device_id, display_name, epoch, last_seen_ts,
                   host(last_seen_ip) AS last_seen_ip, last_seen_user_agent
            FROM devices
            WHERE user_id = $1 AND device_id = $2
            "#,
            user_id,
            device_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(r) = row else { return Ok(None) };

        Ok(Some(Device {
            user_id: r.user_id,
            device_id: r.device_id,
            display_name: r.display_name,
            epoch: r.epoch,
            last_seen_ts: r.last_seen_ts,
            last_seen_ip: r.last_seen_ip,
            last_seen_user_agent: r.last_seen_user_agent,
        }))
    }

    async fn list_devices_for_user(&self, user_id: &str) -> Result<Vec<Device>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_id, device_id, display_name, epoch, last_seen_ts,
                   host(last_seen_ip) AS last_seen_ip, last_seen_user_agent
            FROM devices
            WHERE user_id = $1
            ORDER BY device_id
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let devices = rows
            .into_iter()
            .map(|r| Device {
                user_id: r.user_id,
                device_id: r.device_id,
                display_name: r.display_name,
                epoch: r.epoch,
                last_seen_ts: r.last_seen_ts,
                last_seen_ip: r.last_seen_ip,
                last_seen_user_agent: r.last_seen_user_agent,
            })
            .collect();

        Ok(devices)
    }

    async fn device_epoch(&self, user_id: &str, device_id: &str) -> Result<Option<i64>> {
        let row = sqlx::query!(
            r#"
            SELECT epoch
            FROM devices
            WHERE user_id = $1 AND device_id = $2
            "#,
            user_id,
            device_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(row.map(|r| r.epoch))
    }

    async fn bump_device_epoch(&self, user_id: &str, device_id: &str) -> Result<i64> {
        let row = sqlx::query!(
            r#"
            UPDATE devices
            SET epoch = epoch + 1
            WHERE user_id = $1 AND device_id = $2
            RETURNING epoch
            "#,
            user_id,
            device_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        row.map(|r| r.epoch)
            .ok_or_else(|| Error::Storage(format!("unknown device {device_id}")))
    }

    async fn bump_all_device_epochs(&self, user_id: &str) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE devices
            SET epoch = epoch + 1
            WHERE user_id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    async fn link_identikey(&self, fingerprint: &str, user_id: &str) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO identikey_links (fingerprint, user_id)
            VALUES ($1, $2)
            ON CONFLICT (fingerprint) DO NOTHING
            "#,
            fingerprint,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    async fn user_for_identikey(&self, fingerprint: &str) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"
            SELECT user_id
            FROM identikey_links
            WHERE fingerprint = $1
            "#,
            fingerprint
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(row.map(|r| r.user_id))
    }

    async fn insert_minter_key(
        &self,
        key_id: &str,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO biscuit_minter_keys (key_id, private_key, public_key)
            VALUES ($1, $2, $3)
            "#,
            key_id,
            private_key,
            public_key
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    async fn current_minter_key(&self) -> Result<Option<SigningKey>> {
        let row = sqlx::query!(
            r#"
            SELECT key_id, private_key, public_key, created_at
            FROM biscuit_minter_keys
            ORDER BY created_at DESC
            LIMIT 1
            "#
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(row.map(|r| SigningKey {
            key_id: r.key_id,
            private_key: r.private_key,
            public_key: r.public_key,
            valid_until_ts: None,
            created_at: r.created_at,
        }))
    }

    // -----------------------------------------------------------------------
    // Access tokens
    // -----------------------------------------------------------------------

    async fn insert_token(
        &self,
        token_hash: &str,
        user_id: &str,
        device_id: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO access_tokens (token_hash, user_id, device_id, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
            token_hash,
            user_id,
            device_id,
            expires_at
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    async fn lookup_token(&self, token_hash: &str) -> Result<Option<TokenOwner>> {
        let row = sqlx::query!(
            r#"
            SELECT user_id, device_id
            FROM access_tokens
            WHERE token_hash = $1
              AND (expires_at IS NULL OR expires_at > now())
            "#,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(r) = row else { return Ok(None) };

        Ok(Some(TokenOwner {
            user_id: r.user_id,
            device_id: r.device_id,
        }))
    }

    async fn revoke_token(&self, token_hash: &str) -> Result<()> {
        sqlx::query!(
            r#"
            DELETE FROM access_tokens
            WHERE token_hash = $1
            "#,
            token_hash
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Server signing keys
    // -----------------------------------------------------------------------

    async fn insert_signing_key(
        &self,
        key_id: &str,
        private_key: &[u8],
        public_key: &[u8],
        valid_until_ts: Option<i64>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO server_signing_keys (key_id, private_key, public_key, valid_until_ts)
            VALUES ($1, $2, $3, $4)
            "#,
            key_id,
            private_key,
            public_key,
            valid_until_ts
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    async fn current_signing_key(&self) -> Result<Option<SigningKey>> {
        let row = sqlx::query!(
            r#"
            SELECT key_id, private_key, public_key, valid_until_ts, created_at
            FROM server_signing_keys
            ORDER BY created_at DESC
            LIMIT 1
            "#
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(r) = row else { return Ok(None) };

        Ok(Some(SigningKey {
            key_id: r.key_id,
            private_key: r.private_key,
            public_key: r.public_key,
            valid_until_ts: r.valid_until_ts,
            created_at: r.created_at,
        }))
    }

    async fn signing_keys_for_verification(&self) -> Result<Vec<SigningKey>> {
        let rows = sqlx::query!(
            r#"
            SELECT key_id, private_key, public_key, valid_until_ts, created_at
            FROM server_signing_keys
            ORDER BY created_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let keys = rows
            .into_iter()
            .map(|r| SigningKey {
                key_id: r.key_id,
                private_key: r.private_key,
                public_key: r.public_key,
                valid_until_ts: r.valid_until_ts,
                created_at: r.created_at,
            })
            .collect();

        Ok(keys)
    }

    async fn set_signing_key_expiry(&self, key_id: &str, valid_until_ts: i64) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE server_signing_keys
            SET valid_until_ts = $2
            WHERE key_id = $1
            "#,
            key_id,
            valid_until_ts
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Room current state
    // -----------------------------------------------------------------------

    async fn set_state_entry(
        &self,
        room_id: &str,
        event_type: &str,
        state_key: &str,
        event_id: &str,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO room_current_state (room_id, type, state_key, event_id)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (room_id, type, state_key)
            DO UPDATE SET event_id = EXCLUDED.event_id
            "#,
            room_id,
            event_type,
            state_key,
            event_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    async fn get_state_entry(
        &self,
        room_id: &str,
        event_type: &str,
        state_key: &str,
    ) -> Result<Option<Event>> {
        let row = sqlx::query!(
            r#"
            SELECT e.event_id, e.room_id, e.sender, e.type AS event_type,
                   e.state_key, e.content, e.auth_events, e.prev_events,
                   e.hashes, e.signatures, e.unsigned, e.origin_server_ts, e.depth, e.pdu_json
            FROM room_current_state rcs
            JOIN events e ON e.event_id = rcs.event_id
            WHERE rcs.room_id = $1 AND rcs.type = $2 AND rcs.state_key = $3
            "#,
            room_id,
            event_type,
            state_key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(r) = row else { return Ok(None) };

        Ok(Some(event_from_row(EventRow { event_id: r.event_id, pdu_json: r.pdu_json, room_id: r.room_id, sender: r.sender, event_type: r.event_type, state_key: r.state_key, content: r.content, origin_server_ts: r.origin_server_ts, auth_events: r.auth_events, prev_events: r.prev_events, hashes: r.hashes, signatures: r.signatures, depth: r.depth, unsigned: r.unsigned })))
    }

    async fn get_current_state(&self, room_id: &str) -> Result<Vec<Event>> {
        let rows = sqlx::query!(
            r#"
            SELECT e.event_id, e.room_id, e.sender, e.type AS event_type,
                   e.state_key, e.content, e.auth_events, e.prev_events,
                   e.hashes, e.signatures, e.unsigned, e.origin_server_ts, e.depth, e.pdu_json
            FROM room_current_state rcs
            JOIN events e ON e.event_id = rcs.event_id
            WHERE rcs.room_id = $1
            ORDER BY rcs.type, rcs.state_key
            "#,
            room_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let events = rows
            .into_iter()
            .map(|r| event_from_row(EventRow { event_id: r.event_id, pdu_json: r.pdu_json, room_id: r.room_id, sender: r.sender, event_type: r.event_type, state_key: r.state_key, content: r.content, origin_server_ts: r.origin_server_ts, auth_events: r.auth_events, prev_events: r.prev_events, hashes: r.hashes, signatures: r.signatures, depth: r.depth, unsigned: r.unsigned }))
            .collect();

        Ok(events)
    }

    async fn current_memberships(&self, user_id: &str) -> Result<Vec<Event>> {
        let rows = sqlx::query!(
            r#"SELECT e.event_id, e.room_id, e.sender, e.type AS event_type,
                e.state_key, e.content, e.auth_events, e.prev_events, e.hashes,
                e.signatures, e.unsigned, e.origin_server_ts, e.depth, e.pdu_json
            FROM room_current_state rcs JOIN events e ON e.event_id = rcs.event_id
            WHERE rcs.type = 'm.room.member' AND rcs.state_key = $1
            ORDER BY rcs.room_id"#,
            user_id
        ).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|row| event_from_row(EventRow { event_id: row.event_id, pdu_json: row.pdu_json, room_id: row.room_id, sender: row.sender, event_type: row.event_type, state_key: row.state_key, content: row.content, auth_events: row.auth_events, prev_events: row.prev_events, hashes: row.hashes, signatures: row.signatures, origin_server_ts: row.origin_server_ts, depth: row.depth, unsigned: row.unsigned })).collect())
    }

    async fn joined_rooms(&self, user_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT rcs.room_id
            FROM room_current_state rcs
            JOIN events e ON e.event_id = rcs.event_id
            WHERE rcs.type = 'm.room.member' AND rcs.state_key = $1
              AND e.content->>'membership' = 'join'
            ORDER BY rcs.room_id
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|row| row.room_id).collect())
    }

    async fn room_events_paginated(
        &self,
        room_id: &str,
        dir: char,
        from: i64,
        limit: i64,
    ) -> Result<(Vec<Event>, Option<i64>)> {
        // `from` is treated as an inclusive stream_position boundary.
        // For 'b' (backwards): fetch events with stream_position <= from,
        // ordered descending, limited to `limit`. The next cursor is the
        // stream_position of the last returned event minus one.
        // For 'f' (forwards): fetch events with stream_position >= from,
        // ordered ascending, limited to `limit`.
        struct Row {
            event_id: String,
            room_id: String,
            sender: String,
            event_type: String,
            state_key: Option<String>,
            content: serde_json::Value,
            auth_events: Vec<String>,
            prev_events: Vec<String>,
            hashes: serde_json::Value,
            signatures: serde_json::Value,
            unsigned: Option<serde_json::Value>,
            origin_server_ts: i64,
            depth: i64,
            stream_position: i64,
            pdu_json: Option<String>,
        }

        let rows: Vec<Row> = if dir == 'b' {
            sqlx::query!(
                r#"
                SELECT event_id, room_id, sender, type AS event_type, state_key,
                       content, auth_events, prev_events, hashes, signatures,
                       unsigned, origin_server_ts, depth, pdu_json, stream_position
                FROM events
                WHERE room_id = $1 AND stream_position <= $2
                ORDER BY stream_position DESC
                LIMIT $3
                "#,
                room_id,
                from,
                limit
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?
            .into_iter()
            .map(|r| Row {
                event_id: r.event_id,
                room_id: r.room_id,
                sender: r.sender,
                event_type: r.event_type,
                state_key: r.state_key,
                content: r.content,
                auth_events: r.auth_events,
                prev_events: r.prev_events,
                hashes: r.hashes,
                signatures: r.signatures,
                unsigned: r.unsigned,
                origin_server_ts: r.origin_server_ts,
                depth: r.depth,
                stream_position: r.stream_position,
                pdu_json: r.pdu_json,
            })
            .collect()
        } else {
            sqlx::query!(
                r#"
                SELECT event_id, room_id, sender, type AS event_type, state_key,
                       content, auth_events, prev_events, hashes, signatures,
                       unsigned, origin_server_ts, depth, pdu_json, stream_position
                FROM events
                WHERE room_id = $1 AND stream_position >= $2
                ORDER BY stream_position ASC
                LIMIT $3
                "#,
                room_id,
                from,
                limit
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?
            .into_iter()
            .map(|r| Row {
                event_id: r.event_id,
                room_id: r.room_id,
                sender: r.sender,
                event_type: r.event_type,
                state_key: r.state_key,
                content: r.content,
                auth_events: r.auth_events,
                prev_events: r.prev_events,
                hashes: r.hashes,
                signatures: r.signatures,
                unsigned: r.unsigned,
                origin_server_ts: r.origin_server_ts,
                depth: r.depth,
                stream_position: r.stream_position,
                pdu_json: r.pdu_json,
            })
            .collect()
        };

        // Determine next cursor from the last event's stream_position.
        let next: Option<i64> = rows.last().map(|r| {
            if dir == 'b' {
                r.stream_position - 1
            } else {
                r.stream_position + 1
            }
        });
        // If we got fewer rows than limit, there is no next page.
        let next = if (rows.len() as i64) < limit { None } else { next };

        let events = rows
            .into_iter()
            .map(|r| event_from_row(EventRow { event_id: r.event_id, pdu_json: r.pdu_json, room_id: r.room_id, sender: r.sender, event_type: r.event_type, state_key: r.state_key, content: r.content, origin_server_ts: r.origin_server_ts, auth_events: r.auth_events, prev_events: r.prev_events, hashes: r.hashes, signatures: r.signatures, depth: r.depth, unsigned: r.unsigned }))
            .collect();

        Ok((events, next))
    }

    async fn room_latest_stream_position(&self, room_id: &str) -> Result<Option<i64>> {
        let row = sqlx::query!(
            r#"
            SELECT MAX(stream_position) AS max_pos
            FROM events
            WHERE room_id = $1
            "#,
            room_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(row.max_pos)
    }

    async fn member_events_for_user(
        &self,
        room_id: &str,
        user_id: &str,
    ) -> Result<Vec<(i64, Event)>> {
        let rows = sqlx::query!(
            r#"
            SELECT stream_position, event_id, room_id, sender, type AS event_type,
                   state_key, content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth, pdu_json
            FROM events
            WHERE room_id = $1 AND type = 'm.room.member' AND state_key = $2
            ORDER BY stream_position ASC
            "#,
            room_id,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.stream_position,
                    event_from_row(EventRow { event_id: r.event_id, pdu_json: r.pdu_json, room_id: r.room_id, sender: r.sender, event_type: r.event_type, state_key: r.state_key, content: r.content, origin_server_ts: r.origin_server_ts, auth_events: r.auth_events, prev_events: r.prev_events, hashes: r.hashes, signatures: r.signatures, depth: r.depth, unsigned: r.unsigned }),
                )
            })
            .collect())
    }

    async fn member_events_for_server(
        &self,
        room_id: &str,
        server_name: &str,
    ) -> Result<Vec<(i64, Event)>> {
        let suffix = format!(":{server_name}");
        let rows = sqlx::query!(
            r#"
            SELECT stream_position, event_id, room_id, sender, type AS event_type,
                   state_key, content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth, pdu_json
            FROM events
            WHERE room_id = $1 AND type = 'm.room.member' AND state_key LIKE '%' || $2
            ORDER BY stream_position ASC
            "#,
            room_id,
            suffix
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.stream_position,
                    event_from_row(EventRow { event_id: r.event_id, pdu_json: r.pdu_json, room_id: r.room_id, sender: r.sender, event_type: r.event_type, state_key: r.state_key, content: r.content, origin_server_ts: r.origin_server_ts, auth_events: r.auth_events, prev_events: r.prev_events, hashes: r.hashes, signatures: r.signatures, depth: r.depth, unsigned: r.unsigned }),
                )
            })
            .collect())
    }

    async fn event_stream_positions(
        &self,
        event_ids: &[String],
    ) -> Result<std::collections::HashMap<String, i64>> {
        if event_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }

        let rows = sqlx::query!(
            r#"
            SELECT event_id, stream_position
            FROM events
            WHERE event_id = ANY($1)
            "#,
            event_ids
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows
            .into_iter()
            .map(|r| (r.event_id, r.stream_position))
            .collect())
    }

    async fn events_since(&self, since: i64, limit: i64) -> Result<Vec<Event>> {
        let rows = sqlx::query!(
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth, pdu_json
            FROM events
            WHERE stream_position > $1
            ORDER BY stream_position ASC
            LIMIT $2
            "#,
            since,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let events = rows
            .into_iter()
            .map(|r| event_from_row(EventRow { event_id: r.event_id, pdu_json: r.pdu_json, room_id: r.room_id, sender: r.sender, event_type: r.event_type, state_key: r.state_key, content: r.content, origin_server_ts: r.origin_server_ts, auth_events: r.auth_events, prev_events: r.prev_events, hashes: r.hashes, signatures: r.signatures, depth: r.depth, unsigned: r.unsigned }))
            .collect();

        Ok(events)
    }

    async fn global_max_stream_position(&self) -> Result<i64> {
        let row = sqlx::query!(
            r#"
            SELECT GREATEST(COALESCE(MAX(stream_position), 0),
                (SELECT position FROM retired_event_positions WHERE singleton)) AS max_pos
            FROM events
            "#
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(row.max_pos.unwrap_or(0))
    }

    // -----------------------------------------------------------------------
    // Device keys (mrm.1, mrm.2)
    // -----------------------------------------------------------------------

    async fn upsert_device_keys(&self, user_id: &str, device_id: &str, keys: &Value) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO device_keys (user_id, device_id, keys)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, device_id)
            DO UPDATE SET keys = EXCLUDED.keys
            "#,
            user_id,
            device_id,
            keys
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get_device_keys(&self, user_id: &str, device_id: &str) -> Result<Option<Value>> {
        let row = sqlx::query!(
            r#"SELECT keys FROM device_keys WHERE user_id = $1 AND device_id = $2"#,
            user_id,
            device_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| r.keys))
    }

    async fn get_device_keys_for_user(&self, user_id: &str) -> Result<HashMap<String, Value>> {
        let rows = sqlx::query!(
            r#"SELECT device_id, keys FROM device_keys WHERE user_id = $1"#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|r| (r.device_id, r.keys)).collect())
    }

    async fn delete_device_keys(&self, user_id: &str, device_id: &str) -> Result<()> {
        sqlx::query!(
            r#"DELETE FROM device_keys WHERE user_id = $1 AND device_id = $2"#,
            user_id,
            device_id,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // One-time keys (mrm.1, mrm.3)
    // -----------------------------------------------------------------------

    async fn insert_one_time_keys(
        &self,
        user_id: &str,
        device_id: &str,
        keys: Vec<(String, String, Value)>,
    ) -> Result<()> {
        for (key_id, algorithm, key_json) in keys {
            sqlx::query!(
                r#"
                INSERT INTO one_time_keys (user_id, device_id, key_id, algorithm, key_json)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (user_id, device_id, key_id) DO NOTHING
                "#,
                user_id,
                device_id,
                key_id,
                algorithm,
                key_json
            )
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        }
        Ok(())
    }

    async fn claim_one_time_key(
        &self,
        user_id: &str,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<(String, Value)>> {
        // Atomic DELETE ... RETURNING for exactly-once delivery.
        let row = sqlx::query!(
            r#"
            DELETE FROM one_time_keys
            WHERE (user_id, device_id, key_id) = (
                SELECT user_id, device_id, key_id
                FROM one_time_keys
                WHERE user_id = $1 AND device_id = $2 AND algorithm = $3
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING key_id, key_json
            "#,
            user_id,
            device_id,
            algorithm
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| (r.key_id, r.key_json)))
    }

    async fn one_time_key_counts(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<HashMap<String, i64>> {
        let rows = sqlx::query!(
            r#"
            SELECT algorithm, COUNT(*) AS count
            FROM one_time_keys
            WHERE user_id = $1 AND device_id = $2
            GROUP BY algorithm
            "#,
            user_id,
            device_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|r| (r.algorithm, r.count.unwrap_or(0)))
            .collect())
    }

    // -----------------------------------------------------------------------
    // Fallback keys (mrm.5)
    // -----------------------------------------------------------------------

    async fn upsert_fallback_key(
        &self,
        user_id: &str,
        device_id: &str,
        algorithm: &str,
        key_id: &str,
        key_json: &Value,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO fallback_keys (user_id, device_id, algorithm, key_id, key_json, used)
            VALUES ($1, $2, $3, $4, $5, false)
            ON CONFLICT (user_id, device_id, algorithm)
            DO UPDATE SET key_id = EXCLUDED.key_id,
                          key_json = EXCLUDED.key_json,
                          used = false
            "#,
            user_id,
            device_id,
            algorithm,
            key_id,
            key_json
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn claim_fallback_key(
        &self,
        user_id: &str,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<(String, Value)>> {
        let row = sqlx::query!(
            r#"
            UPDATE fallback_keys
            SET used = true
            WHERE user_id = $1 AND device_id = $2 AND algorithm = $3
            RETURNING key_id, key_json
            "#,
            user_id,
            device_id,
            algorithm
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| (r.key_id, r.key_json)))
    }

    // -----------------------------------------------------------------------
    // Cross-signing (mrm.8, mrm.9)
    // -----------------------------------------------------------------------

    async fn unused_fallback_key_types(&self, user_id: &str, device_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT algorithm FROM fallback_keys
            WHERE user_id = $1 AND device_id = $2 AND NOT used
            ORDER BY algorithm
            "#,
            user_id,
            device_id
        ).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|row| row.algorithm).collect())
    }

    async fn upsert_cross_signing_key(
        &self,
        user_id: &str,
        key_type: &str,
        key_json: &Value,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO cross_signing_keys (user_id, key_type, key_json)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, key_type)
            DO UPDATE SET key_json = EXCLUDED.key_json
            "#,
            user_id,
            key_type,
            key_json
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get_cross_signing_keys(&self, user_id: &str) -> Result<HashMap<String, Value>> {
        let rows = sqlx::query!(
            r#"SELECT key_type, key_json FROM cross_signing_keys WHERE user_id = $1"#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|r| (r.key_type, r.key_json)).collect())
    }

    async fn insert_cross_signing_signature(
        &self,
        signer_user: &str,
        signer_key: &str,
        target_user: &str,
        target_key: &str,
        signature: &str,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO cross_signing_signatures
                (signer_user_id, signer_key_id, target_user_id, target_key_id, signature)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (signer_user_id, signer_key_id, target_user_id, target_key_id)
            DO UPDATE SET signature = EXCLUDED.signature
            "#,
            signer_user,
            signer_key,
            target_user,
            target_key,
            signature
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // To-device queue (mrm.6, mrm.7, mrm.10)
    // -----------------------------------------------------------------------

    async fn enqueue_to_device(
        &self,
        target_user: &str,
        target_device: &str,
        sender: &str,
        event_type: &str,
        content: &Value,
    ) -> Result<i64> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        lock_stream(&mut transaction, Stream::ToDevice).await?;
        let row = sqlx::query!(
            r#"
            INSERT INTO to_device_queue (target_user, target_device, sender, event_type, content)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
            target_user,
            target_device,
            sender,
            event_type,
            content
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(row.id)
    }

    async fn drain_to_device(
        &self,
        target_user: &str,
        target_device: &str,
        since_id: i64,
        limit: i64,
    ) -> Result<Vec<ToDeviceMessage>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, sender, event_type, content
            FROM to_device_queue
            WHERE target_user = $1 AND target_device = $2 AND id > $3
            ORDER BY id ASC
            LIMIT $4
            "#,
            target_user,
            target_device,
            since_id,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|r| ToDeviceMessage {
                id: r.id,
                sender: r.sender,
                event_type: r.event_type,
                content: r.content,
            })
            .collect())
    }

    async fn delete_to_device_before(
        &self,
        target_user: &str,
        target_device: &str,
        up_to_id: i64,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            DELETE FROM to_device_queue
            WHERE target_user = $1 AND target_device = $2 AND id <= $3
            "#,
            target_user,
            target_device,
            up_to_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Device list changes (mrm.4, mrm.11, mrm.12)
    // -----------------------------------------------------------------------

    async fn record_device_list_change(&self, user_id: &str) -> Result<i64> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        lock_stream(&mut transaction, Stream::DeviceLists).await?;
        let row = sqlx::query!(
            r#"
            INSERT INTO device_list_changes (user_id)
            VALUES ($1)
            RETURNING id
            "#,
            user_id
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(row.id)
    }

    async fn device_list_changes_between(&self, since_pos: i64, through_pos: i64) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT user_id
            FROM device_list_changes
            WHERE id > $1 AND id <= $2
            ORDER BY user_id
            "#,
            since_pos,
            through_pos
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|r| r.user_id).collect())
    }

    async fn device_list_max_position(&self) -> Result<i64> {
        let row = sqlx::query!(
            r#"SELECT COALESCE(MAX(id), 0) AS max_id FROM device_list_changes"#
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.max_id.unwrap_or(0))
    }

    // -----------------------------------------------------------------------
    // Room key backup (mrm.13)
    // -----------------------------------------------------------------------

    async fn create_room_keys_version(
        &self,
        user_id: &str,
        version: &str,
        algorithm: &str,
        auth_data: &Value,
    ) -> Result<String> {
        let etag = format!("{}", chrono::Utc::now().timestamp_millis());
        sqlx::query!(
            r#"
            INSERT INTO room_keys_versions (user_id, version, algorithm, auth_data, count, etag)
            VALUES ($1, $2, $3, $4, 0, $5)
            "#,
            user_id,
            version,
            algorithm,
            auth_data,
            etag
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(etag)
    }

    async fn get_room_keys_version(
        &self,
        user_id: &str,
        version: Option<&str>,
    ) -> Result<Option<RoomKeyVersion>> {
        if let Some(v) = version {
            let row = sqlx::query!(
                r#"
                SELECT version, algorithm, auth_data, count, etag
                FROM room_keys_versions
                WHERE user_id = $1 AND version = $2 AND deleted = false
                "#,
                user_id,
                v
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
            Ok(row.map(|r| RoomKeyVersion {
                version: r.version,
                algorithm: r.algorithm,
                auth_data: r.auth_data,
                count: r.count,
                etag: r.etag,
            }))
        } else {
            let row = sqlx::query!(
                r#"
                SELECT version, algorithm, auth_data, count, etag
                FROM room_keys_versions
                WHERE user_id = $1 AND deleted = false
                ORDER BY version DESC
                LIMIT 1
                "#,
                user_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
            Ok(row.map(|r| RoomKeyVersion {
                version: r.version,
                algorithm: r.algorithm,
                auth_data: r.auth_data,
                count: r.count,
                etag: r.etag,
            }))
        }
    }

    async fn update_room_keys_version(
        &self,
        user_id: &str,
        version: &str,
        auth_data: &Value,
    ) -> Result<()> {
        // The etag represents stored keys, so an auth_data update keeps it.
        sqlx::query!(
            r#"
            UPDATE room_keys_versions
            SET auth_data = $3
            WHERE user_id = $1 AND version = $2 AND deleted = false
            "#,
            user_id,
            version,
            auth_data
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn delete_room_keys_version(&self, user_id: &str, version: &str) -> Result<()> {
        // Deleting a backup deletes its key data too (spec).
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        sqlx::query!(
            r#"
            UPDATE room_keys_versions SET deleted = true, count = 0
            WHERE user_id = $1 AND version = $2
            "#,
            user_id,
            version
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        sqlx::query!(
            "DELETE FROM room_keys_backup WHERE user_id = $1 AND version = $2",
            user_id,
            version
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn upsert_room_key(
        &self,
        user_id: &str,
        version: &str,
        room_id: &str,
        session_id: &str,
        key_data: &Value,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO room_keys_backup (user_id, version, room_id, session_id, key_data)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id, version, room_id, session_id)
            DO UPDATE SET key_data = EXCLUDED.key_data
            "#,
            user_id,
            version,
            room_id,
            session_id,
            key_data
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        // Update count and advance the etag counter (two writes in one
        // millisecond must still produce different etags).
        sqlx::query!(
            r#"
            UPDATE room_keys_versions
            SET count = (
                SELECT COUNT(*) FROM room_keys_backup
                WHERE user_id = $1 AND version = $2
            ),
            etag = (CASE WHEN etag ~ '^[0-9]{1,18}$' THEN etag::BIGINT + 1 ELSE 1 END)::TEXT
            WHERE user_id = $1 AND version = $2
            "#,
            user_id,
            version
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get_room_keys(
        &self,
        user_id: &str,
        version: &str,
        room_id: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<HashMap<String, HashMap<String, Value>>> {
        let rows = sqlx::query!(
            r#"
            SELECT room_id, session_id, key_data
            FROM room_keys_backup
            WHERE user_id = $1
              AND version = $2
              AND ($3::TEXT IS NULL OR room_id = $3)
              AND ($4::TEXT IS NULL OR session_id = $4)
            "#,
            user_id,
            version,
            room_id,
            session_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let mut result: HashMap<String, HashMap<String, Value>> = HashMap::new();
        for r in rows {
            result
                .entry(r.room_id)
                .or_default()
                .insert(r.session_id, r.key_data);
        }
        Ok(result)
    }

    async fn delete_room_keys(
        &self,
        user_id: &str,
        version: &str,
        room_id: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<i64> {
        let result = sqlx::query!(
            r#"
            DELETE FROM room_keys_backup
            WHERE user_id = $1
              AND version = $2
              AND ($3::TEXT IS NULL OR room_id = $3)
              AND ($4::TEXT IS NULL OR session_id = $4)
            "#,
            user_id,
            version,
            room_id,
            session_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let deleted = result.rows_affected() as i64;
        // Update count; the etag moves only when keys were removed.
        sqlx::query!(
            r#"
            UPDATE room_keys_versions
            SET count = (
                SELECT COUNT(*) FROM room_keys_backup
                WHERE user_id = $1 AND version = $2
            ),
            etag = CASE
                WHEN NOT $3 THEN etag
                WHEN etag ~ '^[0-9]{1,18}$' THEN (etag::BIGINT + 1)::TEXT
                ELSE '1'
            END
            WHERE user_id = $1 AND version = $2
            "#,
            user_id,
            version,
            deleted > 0
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(deleted)
    }

    // -----------------------------------------------------------------------
    // Profile (1mo.1, 1mo.2)
    // -----------------------------------------------------------------------

    async fn set_displayname(&self, user_id: &str, displayname: Option<&str>) -> Result<()> {
        sqlx::query!(
            r#"UPDATE accounts SET displayname = $2 WHERE user_id = $1"#,
            user_id,
            displayname
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn set_avatar_url(&self, user_id: &str, avatar_url: Option<&str>) -> Result<()> {
        sqlx::query!(
            r#"UPDATE accounts SET avatar_url = $2 WHERE user_id = $1"#,
            user_id,
            avatar_url
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Account data (1mo.3, 1mo.4)
    // -----------------------------------------------------------------------

    async fn set_account_data(
        &self,
        user_id: &str,
        room_id: Option<&str>,
        event_type: &str,
        content: &Value,
    ) -> Result<i64> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        lock_stream(&mut transaction, Stream::AccountData).await?;
        // Select the matching partial unique index before inserting.
        if room_id.is_none() {
            let row = sqlx::query!(
                r#"
                INSERT INTO account_data (user_id, room_id, event_type, content, updated_at)
                VALUES ($1, $2, $3, $4, now())
                ON CONFLICT (user_id, event_type) WHERE room_id IS NULL
                    DO UPDATE SET content = EXCLUDED.content, updated_at = now(),
                                  stream_pos = EXCLUDED.stream_pos
                RETURNING stream_pos
                "#,
                user_id,
                room_id as Option<&str>,
                event_type,
                content
            )
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(row.stream_pos);
        }

        // Per-room path (room_id IS NOT NULL).
        let row2 = sqlx::query!(
            r#"
            INSERT INTO account_data (user_id, room_id, event_type, content, updated_at)
            VALUES ($1, $2, $3, $4, now())
            ON CONFLICT (user_id, room_id, event_type) WHERE room_id IS NOT NULL
                DO UPDATE SET content = EXCLUDED.content, updated_at = now(),
                              stream_pos = EXCLUDED.stream_pos
            RETURNING stream_pos
            "#,
            user_id,
            room_id as Option<&str>,
            event_type,
            content
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(row2.stream_pos)
    }

    async fn get_account_data(
        &self,
        user_id: &str,
        room_id: Option<&str>,
        event_type: &str,
    ) -> Result<Option<Value>> {
        let row = sqlx::query!(
            r#"
            SELECT content
            FROM account_data
            WHERE user_id = $1
              AND event_type = $3
              AND (($2::TEXT IS NULL AND room_id IS NULL) OR room_id = $2)
            "#,
            user_id,
            room_id,
            event_type
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| r.content))
    }

    async fn account_data_since(
        &self,
        user_id: &str,
        since_pos: i64,
    ) -> Result<Vec<(Option<String>, String, Value, i64)>> {
        let rows = sqlx::query!(
            r#"
            SELECT room_id, event_type, content, stream_pos
            FROM account_data
            WHERE user_id = $1 AND stream_pos > $2
            ORDER BY stream_pos ASC
            "#,
            user_id,
            since_pos
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows
            .into_iter()
            .map(|r| (r.room_id, r.event_type, r.content, r.stream_pos))
            .collect())
    }

    // -----------------------------------------------------------------------
    // Receipts (1mo.6)
    // -----------------------------------------------------------------------

    async fn set_receipt(
        &self,
        room_id: &str,
        user_id: &str,
        receipt_type: &str,
        event_id: &str,
        ts: i64,
    ) -> Result<i64> {
        self.set_threaded_receipt(room_id, user_id, receipt_type, None, event_id, ts).await
    }

    async fn receipts_for_room(
        &self,
        room_id: &str,
    ) -> Result<Vec<(String, String, String, i64)>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_id, receipt_type, event_id, ts
            FROM receipts
            WHERE room_id = $1 AND thread_id = ''
            "#,
            room_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows
            .into_iter()
            .map(|r| (r.user_id, r.receipt_type, r.event_id, r.ts))
            .collect())
    }

    async fn receipts_since(
        &self,
        since_pos: i64,
    ) -> Result<Vec<(String, String, String, String, i64, i64)>> {
        let rows = sqlx::query!(
            r#"
            SELECT room_id, user_id, receipt_type, event_id, ts, stream_pos
            FROM receipts
            WHERE stream_pos > $1 AND thread_id = ''
            ORDER BY stream_pos ASC
            "#,
            since_pos
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows
            .into_iter()
            .map(|r| (r.room_id, r.user_id, r.receipt_type, r.event_id, r.ts, r.stream_pos))
            .collect())
    }

    // -----------------------------------------------------------------------
    // Media (E07)
    // -----------------------------------------------------------------------

    async fn insert_media(&self, m: &MediaMetadata) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO media
                (media_id, origin_server, uploader, content_type, upload_name,
                 file_size, sha256, storage_path, uploaded_at, last_accessed)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (media_id, origin_server) DO NOTHING
            "#,
            m.media_id,
            m.origin_server,
            m.uploader,
            m.content_type,
            m.upload_name,
            m.file_size,
            m.sha256,
            m.storage_path,
            m.uploaded_at,
            m.last_accessed,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get_media(&self, media_id: &str, origin_server: &str) -> Result<Option<MediaMetadata>> {
        let row = sqlx::query!(
            r#"
            SELECT media_id, origin_server, uploader, content_type, upload_name,
                   file_size, sha256, storage_path, uploaded_at, last_accessed
            FROM media
            WHERE media_id = $1 AND origin_server = $2
            "#,
            media_id,
            origin_server
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(r) = row else { return Ok(None) };
        Ok(Some(MediaMetadata {
            media_id: r.media_id,
            origin_server: r.origin_server,
            uploader: r.uploader,
            content_type: r.content_type,
            upload_name: r.upload_name,
            file_size: r.file_size,
            sha256: r.sha256,
            storage_path: r.storage_path,
            uploaded_at: r.uploaded_at,
            last_accessed: r.last_accessed,
        }))
    }

    async fn touch_media_access(&self, media_id: &str, origin_server: &str) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE media SET last_accessed = now()
            WHERE media_id = $1 AND origin_server = $2
            "#,
            media_id,
            origin_server
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn delete_media(&self, media_id: &str, origin_server: &str) -> Result<()> {
        sqlx::query!(
            r#"DELETE FROM media WHERE media_id = $1 AND origin_server = $2"#,
            media_id,
            origin_server
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn list_remote_media_older_than(&self, ts: DateTime<Utc>) -> Result<Vec<MediaMetadata>> {
        let rows = sqlx::query!(
            r#"
            SELECT media_id, origin_server, uploader, content_type, upload_name,
                   file_size, sha256, storage_path, uploaded_at, last_accessed
            FROM media
            WHERE uploader IS NULL AND last_accessed < $1
            "#,
            ts
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows
            .into_iter()
            .map(|r| MediaMetadata {
                media_id: r.media_id,
                origin_server: r.origin_server,
                uploader: r.uploader,
                content_type: r.content_type,
                upload_name: r.upload_name,
                file_size: r.file_size,
                sha256: r.sha256,
                storage_path: r.storage_path,
                uploaded_at: r.uploaded_at,
                last_accessed: r.last_accessed,
            })
            .collect())
    }

    async fn insert_thumbnail(&self, t: &ThumbnailMetadata) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO media_thumbnails
                (media_id, origin_server, width, height, method, content_type, file_size, storage_path)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (media_id, origin_server, width, height, method) DO NOTHING
            "#,
            t.media_id,
            t.origin_server,
            t.width,
            t.height,
            t.method,
            t.content_type,
            t.file_size,
            t.storage_path,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get_thumbnail(
        &self,
        media_id: &str,
        origin_server: &str,
        width: i32,
        height: i32,
        method: &str,
    ) -> Result<Option<ThumbnailMetadata>> {
        let row = sqlx::query!(
            r#"
            SELECT media_id, origin_server, width, height, method,
                   content_type, file_size, storage_path
            FROM media_thumbnails
            WHERE media_id = $1 AND origin_server = $2
              AND width = $3 AND height = $4 AND method = $5
            "#,
            media_id,
            origin_server,
            width,
            height,
            method,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(r) = row else { return Ok(None) };
        Ok(Some(ThumbnailMetadata {
            media_id: r.media_id,
            origin_server: r.origin_server,
            width: r.width,
            height: r.height,
            method: r.method,
            content_type: r.content_type,
            file_size: r.file_size,
            storage_path: r.storage_path,
        }))
    }

    // -----------------------------------------------------------------------
    // Media lane (conduit-y99.21): async upload, freeze, URL previews
    // -----------------------------------------------------------------------

    async fn create_pending_media(
        &self,
        p: &conduit::storage::PendingMedia,
        max_pending: i64,
    ) -> Result<conduit::storage::PendingMediaCreate> {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(format!("conduit-media-pending:{}", p.creator).as_bytes());
        let lock_id = i64::from_be_bytes(digest[..8].try_into().expect("eight hash bytes"));
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        // Serialize reservations per creator so the quota cannot be raced.
        sqlx::query!("SELECT pg_advisory_xact_lock($1) IS NULL AS lock_held", lock_id)
            .fetch_one(&mut *tx).await.map_err(map_sqlx)?;
        sqlx::query!(
            "DELETE FROM media_pending WHERE creator = $1 AND expires_at <= $2",
            p.creator, p.created_at
        ).execute(&mut *tx).await.map_err(map_sqlx)?;
        let held = sqlx::query!(
            r#"SELECT count(*) AS "count!", min(expires_at) AS earliest
               FROM media_pending WHERE creator = $1"#,
            p.creator
        ).fetch_one(&mut *tx).await.map_err(map_sqlx)?;
        if held.count >= max_pending {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(conduit::storage::PendingMediaCreate::LimitExceeded {
                earliest_expiry: held.earliest,
            });
        }
        sqlx::query!(
            r#"INSERT INTO media_pending (media_id, origin_server, creator, created_at, expires_at)
               VALUES ($1, $2, $3, $4, $5)"#,
            p.media_id, p.origin_server, p.creator, p.created_at, p.expires_at
        ).execute(&mut *tx).await.map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(conduit::storage::PendingMediaCreate::Created)
    }

    async fn get_pending_media(
        &self,
        media_id: &str,
        origin_server: &str,
    ) -> Result<Option<conduit::storage::PendingMedia>> {
        let row = sqlx::query!(
            r#"SELECT media_id, origin_server, creator, created_at, expires_at
               FROM media_pending WHERE media_id = $1 AND origin_server = $2"#,
            media_id, origin_server
        ).fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        Ok(row.map(|r| conduit::storage::PendingMedia {
            media_id: r.media_id,
            origin_server: r.origin_server,
            creator: r.creator,
            created_at: r.created_at,
            expires_at: r.expires_at,
        }))
    }

    async fn complete_pending_media(
        &self,
        m: &MediaMetadata,
        uploader: &str,
        now: DateTime<Utc>,
    ) -> Result<conduit::storage::PendingMediaCompletion> {
        use conduit::storage::PendingMediaCompletion as Outcome;
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let pending = sqlx::query!(
            r#"SELECT creator, expires_at FROM media_pending
               WHERE media_id = $1 AND origin_server = $2 FOR UPDATE"#,
            m.media_id, m.origin_server
        ).fetch_optional(&mut *tx).await.map_err(map_sqlx)?;
        let Some(pending) = pending else {
            let exists = sqlx::query!(
                r#"SELECT EXISTS (SELECT 1 FROM media WHERE media_id = $1 AND origin_server = $2) AS "exists!""#,
                m.media_id, m.origin_server
            ).fetch_one(&mut *tx).await.map_err(map_sqlx)?;
            return Ok(if exists.exists { Outcome::AlreadyUploaded } else { Outcome::NotFound });
        };
        if pending.creator != uploader {
            return Ok(Outcome::Forbidden);
        }
        sqlx::query!(
            "DELETE FROM media_pending WHERE media_id = $1 AND origin_server = $2",
            m.media_id, m.origin_server
        ).execute(&mut *tx).await.map_err(map_sqlx)?;
        if pending.expires_at <= now {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Outcome::NotFound);
        }
        let inserted = sqlx::query!(
            r#"
            INSERT INTO media
                (media_id, origin_server, uploader, content_type, upload_name,
                 file_size, sha256, storage_path, uploaded_at, last_accessed)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (media_id, origin_server) DO NOTHING
            "#,
            m.media_id,
            m.origin_server,
            m.uploader,
            m.content_type,
            m.upload_name,
            m.file_size,
            m.sha256,
            m.storage_path,
            m.uploaded_at,
            m.last_accessed,
        ).execute(&mut *tx).await.map_err(map_sqlx)?;
        if inserted.rows_affected() == 0 {
            return Ok(Outcome::AlreadyUploaded);
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(Outcome::Completed)
    }

    async fn media_unauthenticated_access(&self, media_id: &str, origin_server: &str) -> Result<bool> {
        let row = sqlx::query!(
            "SELECT unauthenticated_access FROM media WHERE media_id = $1 AND origin_server = $2",
            media_id, origin_server
        ).fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        Ok(row.is_some_and(|r| r.unauthenticated_access))
    }

    async fn set_media_unauthenticated_access(&self, media_id: &str, origin_server: &str, allowed: bool) -> Result<()> {
        sqlx::query!(
            "UPDATE media SET unauthenticated_access = $3 WHERE media_id = $1 AND origin_server = $2",
            media_id, origin_server, allowed
        ).execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn media_storage_path_in_use(&self, storage_path: &str) -> Result<bool> {
        let row = sqlx::query!(
            r#"SELECT (EXISTS (SELECT 1 FROM media WHERE storage_path = $1)
                    OR EXISTS (SELECT 1 FROM media_thumbnails WHERE storage_path = $1)) AS "in_use!""#,
            storage_path
        ).fetch_one(&self.pool).await.map_err(map_sqlx)?;
        Ok(row.in_use)
    }

    async fn insert_url_preview(&self, p: &conduit::storage::UrlPreview) -> Result<()> {
        sqlx::query!(
            r#"INSERT INTO url_previews (url, fetched_at, expires_at, og)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (url, fetched_at) DO UPDATE SET expires_at = EXCLUDED.expires_at, og = EXCLUDED.og"#,
            p.url, p.fetched_at, p.expires_at, p.og
        ).execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn latest_url_preview(
        &self,
        url: &str,
        fetched_at_or_before: Option<DateTime<Utc>>,
    ) -> Result<Option<conduit::storage::UrlPreview>> {
        let row = sqlx::query!(
            r#"SELECT url, fetched_at, expires_at, og FROM url_previews
               WHERE url = $1 AND ($2::timestamptz IS NULL OR fetched_at <= $2)
               ORDER BY fetched_at DESC LIMIT 1"#,
            url, fetched_at_or_before
        ).fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        Ok(row.map(|r| conduit::storage::UrlPreview {
            url: r.url,
            fetched_at: r.fetched_at,
            expires_at: r.expires_at,
            og: r.og,
        }))
    }

    // -----------------------------------------------------------------------
    // Push (E11 P1–P6)
    // -----------------------------------------------------------------------

    async fn upsert_pusher(&self, p: &Pusher) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO pushers
                (user_id, pushkey, app_id, app_display_name, device_display_name,
                 kind, lang, profile_tag, url, format, data, pushkey_ts)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (user_id, pushkey, app_id) DO UPDATE SET
                app_display_name    = EXCLUDED.app_display_name,
                device_display_name = EXCLUDED.device_display_name,
                kind                = EXCLUDED.kind,
                lang                = EXCLUDED.lang,
                profile_tag         = EXCLUDED.profile_tag,
                url                 = EXCLUDED.url,
                format              = EXCLUDED.format,
                data                = EXCLUDED.data,
                pushkey_ts          = EXCLUDED.pushkey_ts
            "#,
            p.user_id,
            p.pushkey,
            p.app_id,
            p.app_display_name,
            p.device_display_name,
            p.kind,
            p.lang,
            p.profile_tag,
            p.url,
            p.format,
            p.data,
            p.pushkey_ts,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn delete_pusher(&self, user_id: &str, pushkey: &str, app_id: &str) -> Result<()> {
        sqlx::query!(
            "DELETE FROM pushers WHERE user_id = $1 AND pushkey = $2 AND app_id = $3",
            user_id, pushkey, app_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn list_pushers(&self, user_id: &str) -> Result<Vec<Pusher>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_id, pushkey, app_id, app_display_name, device_display_name,
                   kind, lang, profile_tag, url, format, data, pushkey_ts
            FROM pushers
            WHERE user_id = $1
            ORDER BY created_at
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows.into_iter().map(|r| Pusher {
            user_id: r.user_id,
            pushkey: r.pushkey,
            app_id: r.app_id,
            app_display_name: r.app_display_name,
            device_display_name: r.device_display_name,
            kind: r.kind,
            lang: r.lang,
            profile_tag: r.profile_tag,
            url: r.url,
            format: r.format,
            data: r.data,
            pushkey_ts: r.pushkey_ts,
        }).collect())
    }

    async fn upsert_push_rule(&self, rule: &PushRule) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO push_rules
                (user_id, scope, kind, rule_id, priority, enabled, conditions, actions, pattern, is_default)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (user_id, scope, kind, rule_id) DO UPDATE SET
                priority   = EXCLUDED.priority,
                enabled    = EXCLUDED.enabled,
                conditions = EXCLUDED.conditions,
                actions    = EXCLUDED.actions,
                pattern    = EXCLUDED.pattern,
                is_default = EXCLUDED.is_default
            "#,
            rule.user_id,
            rule.scope,
            rule.kind,
            rule.rule_id,
            rule.priority,
            rule.enabled,
            rule.conditions,
            rule.actions,
            rule.pattern,
            rule.is_default,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn delete_push_rule(
        &self,
        user_id: &str,
        scope: &str,
        kind: &str,
        rule_id: &str,
    ) -> Result<()> {
        sqlx::query!(
            "DELETE FROM push_rules WHERE user_id = $1 AND scope = $2 AND kind = $3 AND rule_id = $4",
            user_id, scope, kind, rule_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn list_push_rules(&self, user_id: &str) -> Result<Vec<PushRule>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_id, scope, kind, rule_id, priority, enabled,
                   conditions, actions, pattern, is_default
            FROM push_rules
            WHERE user_id = $1
            ORDER BY priority
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows.into_iter().map(|r| PushRule {
            user_id: r.user_id,
            scope: r.scope,
            kind: r.kind,
            rule_id: r.rule_id,
            priority: r.priority,
            enabled: r.enabled,
            conditions: r.conditions,
            actions: r.actions,
            pattern: r.pattern,
            is_default: r.is_default,
        }).collect())
    }

    async fn set_push_rule_enabled(
        &self,
        user_id: &str,
        scope: &str,
        kind: &str,
        rule_id: &str,
        enabled: bool,
    ) -> Result<()> {
        sqlx::query!(
            "UPDATE push_rules SET enabled = $5 WHERE user_id = $1 AND scope = $2 AND kind = $3 AND rule_id = $4",
            user_id, scope, kind, rule_id, enabled
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn set_push_rule_actions(
        &self,
        user_id: &str,
        scope: &str,
        kind: &str,
        rule_id: &str,
        actions: Value,
    ) -> Result<()> {
        sqlx::query!(
            "UPDATE push_rules SET actions = $5 WHERE user_id = $1 AND scope = $2 AND kind = $3 AND rule_id = $4",
            user_id, scope, kind, rule_id, actions
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get_push_rule(
        &self,
        user_id: &str,
        scope: &str,
        kind: &str,
        rule_id: &str,
    ) -> Result<Option<PushRule>> {
        let row = sqlx::query!(
            r#"
            SELECT user_id, scope, kind, rule_id, priority, enabled,
                   conditions, actions, pattern, is_default
            FROM push_rules
            WHERE user_id = $1 AND scope = $2 AND kind = $3 AND rule_id = $4
            "#,
            user_id, scope, kind, rule_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(r) = row else { return Ok(None) };
        Ok(Some(PushRule {
            user_id: r.user_id,
            scope: r.scope,
            kind: r.kind,
            rule_id: r.rule_id,
            priority: r.priority,
            enabled: r.enabled,
            conditions: r.conditions,
            actions: r.actions,
            pattern: r.pattern,
            is_default: r.is_default,
        }))
    }

    // -----------------------------------------------------------------------
    // Push notifications and delivery (conduit-y99.30, conduit-y99.31)
    // -----------------------------------------------------------------------

    async fn push_cursor(&self) -> Result<i64> {
        sqlx::query_scalar!("SELECT stream_pos FROM push_cursor")
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx)
    }

    async fn commit_push_batch(
        &self,
        notifications: &[conduit::storage::PushNotification],
        read_marks: &[conduit::storage::PushReadMark],
        deliveries: &[conduit::storage::PushDelivery],
        cursor: i64,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        for m in read_marks {
            sqlx::query!(
                r#"
                INSERT INTO push_read_marks (user_id, room_id, scope, stream_pos)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (user_id, room_id, scope)
                DO UPDATE SET stream_pos = GREATEST(push_read_marks.stream_pos, EXCLUDED.stream_pos)
                "#,
                m.user_id, m.room_id, m.scope, m.stream_pos,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        }
        for n in notifications {
            sqlx::query!(
                r#"
                INSERT INTO push_notifications
                    (user_id, room_id, event_id, stream_pos, thread_id, actions, highlight, ts)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (user_id, event_id) DO NOTHING
                "#,
                n.user_id, n.room_id, n.event_id, n.stream_pos, n.thread_id, n.actions, n.highlight, n.ts,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        }
        for d in deliveries {
            sqlx::query!(
                r#"
                INSERT INTO push_outbox
                    (user_id, app_id, pushkey, room_id, event_id, actions, attempts, next_attempt_ms, created_ms)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (user_id, app_id, pushkey, event_id) DO NOTHING
                "#,
                d.user_id, d.app_id, d.pushkey, d.room_id, d.event_id, d.actions, d.attempts,
                d.next_attempt_ms, d.created_ms,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        }
        sqlx::query!(
            "UPDATE push_cursor SET stream_pos = GREATEST(stream_pos, $1)",
            cursor
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)
    }

    async fn push_read_marks(&self, user_id: &str, room_id: &str) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query!(
            "SELECT scope, stream_pos FROM push_read_marks WHERE user_id = $1 AND room_id = $2",
            user_id, room_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|r| (r.scope, r.stream_pos)).collect())
    }

    async fn unread_push_notifications(
        &self,
        user_id: &str,
        room_id: &str,
        after_pos: i64,
    ) -> Result<Vec<(Option<String>, i64, bool)>> {
        let rows = sqlx::query!(
            r#"
            SELECT thread_id, stream_pos, highlight FROM push_notifications
            WHERE user_id = $1 AND room_id = $2 AND stream_pos > $3
            ORDER BY stream_pos
            "#,
            user_id, room_id, after_pos
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|r| (r.thread_id, r.stream_pos, r.highlight)).collect())
    }

    async fn list_push_notifications(
        &self,
        user_id: &str,
        before_pos: Option<i64>,
        limit: i64,
        only_highlight: bool,
    ) -> Result<Vec<conduit::storage::PushNotification>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_id, room_id, event_id, stream_pos, thread_id, actions, highlight, ts
            FROM push_notifications
            WHERE user_id = $1
              AND ($2::BIGINT IS NULL OR stream_pos < $2)
              AND (NOT $3 OR highlight)
            ORDER BY stream_pos DESC
            LIMIT $4
            "#,
            user_id, before_pos, only_highlight, limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|r| conduit::storage::PushNotification {
                user_id: r.user_id,
                room_id: r.room_id,
                event_id: r.event_id,
                stream_pos: r.stream_pos,
                thread_id: r.thread_id,
                actions: r.actions,
                highlight: r.highlight,
                ts: r.ts,
            })
            .collect())
    }

    async fn due_push_deliveries(
        &self,
        now_ms: i64,
        limit: i64,
    ) -> Result<Vec<conduit::storage::PushDelivery>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, user_id, app_id, pushkey, room_id, event_id, actions, attempts,
                   next_attempt_ms, created_ms
            FROM push_outbox
            WHERE next_attempt_ms <= $1
            ORDER BY id
            LIMIT $2
            "#,
            now_ms, limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|r| conduit::storage::PushDelivery {
                id: r.id,
                user_id: r.user_id,
                app_id: r.app_id,
                pushkey: r.pushkey,
                room_id: r.room_id,
                event_id: r.event_id,
                actions: r.actions,
                attempts: r.attempts,
                next_attempt_ms: r.next_attempt_ms,
                created_ms: r.created_ms,
            })
            .collect())
    }

    async fn finish_push_delivery(&self, id: i64) -> Result<()> {
        sqlx::query!("DELETE FROM push_outbox WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn retry_push_delivery(&self, id: i64, attempts: i32, next_attempt_ms: i64) -> Result<()> {
        sqlx::query!(
            "UPDATE push_outbox SET attempts = $2, next_attempt_ms = $3 WHERE id = $1",
            id, attempts, next_attempt_ms
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn delete_pushers_for_key(
        &self,
        app_id: &str,
        pushkey: &str,
        keep_user: Option<&str>,
    ) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            DELETE FROM pushers
            WHERE app_id = $1 AND pushkey = $2 AND ($3::TEXT IS NULL OR user_id <> $3)
            "#,
            app_id, pushkey, keep_user
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(result.rows_affected())
    }

    // -----------------------------------------------------------------------
    // Admin (E11 AD1–AD6)
    // -----------------------------------------------------------------------

    async fn list_accounts(&self, from: i64, limit: i64) -> Result<Vec<Account>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_id, password_hash, is_admin, created_at, deactivated_at, displayname, avatar_url,
                   is_guest
            FROM accounts
            ORDER BY user_id
            LIMIT $2 OFFSET $1
            "#,
            from,
            limit,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows.into_iter().map(|r| Account {
            user_id: r.user_id,
            password_hash: r.password_hash,
            is_admin: r.is_admin,
            created_at: r.created_at,
            deactivated_at: r.deactivated_at,
            displayname: r.displayname,
            avatar_url: r.avatar_url,
            is_guest: r.is_guest,
        }).collect())
    }

    async fn set_password_hash(&self, user_id: &str, password_hash: &str) -> Result<()> {
        sqlx::query!(
            "UPDATE accounts SET password_hash = $2 WHERE user_id = $1",
            user_id, password_hash
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn append_audit_log(
        &self,
        admin_user: &str,
        action: &str,
        target: Option<&str>,
        detail: &Value,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO admin_audit (admin_user, action, target, detail) VALUES ($1, $2, $3, $4)",
            admin_user, action, target, detail
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn list_audit_log(&self, from: i64, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, admin_user, action, target, detail, ts
            FROM admin_audit
            ORDER BY ts DESC
            LIMIT $2 OFFSET $1
            "#,
            from,
            limit,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows.into_iter().map(|r| AuditEntry {
            id: r.id,
            admin_user: r.admin_user,
            action: r.action,
            target: r.target,
            detail: r.detail,
            ts: r.ts,
        }).collect())
    }

    async fn purge_room(&self, room_id: &str) -> Result<()> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        sqlx::query!("DELETE FROM room_current_state WHERE room_id = $1", room_id)
            .execute(&mut *transaction).await.map_err(map_sqlx)?;
        // Capture exactly the rows deleted by this statement, including any
        // insert committed before its snapshot. Retention and deletion commit together.
        sqlx::query!(
            r#"WITH deleted AS (
                DELETE FROM events WHERE room_id = $1 RETURNING stream_position
            ) UPDATE retired_event_positions
              SET position = GREATEST(position, (SELECT COALESCE(MAX(stream_position), 0) FROM deleted))
              WHERE singleton"#,
            room_id
        ).execute(&mut *transaction).await.map_err(map_sqlx)?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn list_rooms(&self, from: i64, limit: i64) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT room_id FROM events
            ORDER BY room_id
            LIMIT $2 OFFSET $1
            "#,
            from,
            limit,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows.into_iter().map(|r| r.room_id).collect())
    }

    async fn list_media(&self, from: i64, limit: i64) -> Result<Vec<MediaMetadata>> {
        let rows = sqlx::query!(
            r#"
            SELECT media_id, origin_server, uploader, content_type, upload_name,
                   file_size, sha256, storage_path, uploaded_at, last_accessed
            FROM media
            ORDER BY uploaded_at DESC
            LIMIT $2 OFFSET $1
            "#,
            from,
            limit,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows.into_iter().map(|r| MediaMetadata {
            media_id: r.media_id,
            origin_server: r.origin_server,
            uploader: r.uploader,
            content_type: r.content_type,
            upload_name: r.upload_name,
            file_size: r.file_size,
            sha256: r.sha256,
            storage_path: r.storage_path,
            uploaded_at: r.uploaded_at,
            last_accessed: r.last_accessed,
        }).collect())
    }

    // -----------------------------------------------------------------------
    // Outbound federation queue (conduit-5n3)
    // -----------------------------------------------------------------------

    async fn enqueue_outbound(
        &self,
        destination: &str,
        kind: &str,
        txn_id: &str,
        payload: &Value,
    ) -> Result<i64> {
        let payload_text = json_text(payload);
        let row = sqlx::query!(
            r#"
            INSERT INTO fed_outbound_queue (destination, kind, txn_id, payload_text)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
            destination,
            kind,
            txn_id,
            payload_text,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.id)
    }

    async fn outbound_destinations_with_pending(&self) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT destination
            FROM fed_outbound_queue
            WHERE status = 'pending'
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|r| r.destination).collect())
    }

    async fn next_pending_outbound(
        &self,
        destination: &str,
        limit: i64,
    ) -> Result<Vec<OutboundEntry>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, destination, kind, txn_id, payload, payload_text, attempts
            FROM fed_outbound_queue
            WHERE status = 'pending'
              AND destination = $1
              AND next_attempt_at <= now()
            ORDER BY next_attempt_at, id
            LIMIT $2
            "#,
            destination,
            limit,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        rows.into_iter()
            .map(|r| Ok(OutboundEntry {
                id: r.id,
                destination: r.destination,
                kind: r.kind,
                txn_id: r.txn_id,
                payload: text_or_json(r.payload_text, r.payload)?,
                attempts: r.attempts,
            }))
            .collect()
    }

    async fn record_legacy_snapshot_verdicts(&self, outbound_id: i64, verdicts: &Value, note: Option<&str>) -> Result<()> {
        sqlx::query!(
            "UPDATE fed_outbound_queue SET legacy_snapshot_verdicts = $2, last_error = COALESCE($3, last_error) WHERE id = $1",
            outbound_id, json_text(verdicts), note
        ).execute(&self.pool).await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn mark_outbound_sent(&self, id: i64) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE fed_outbound_queue
            SET status = 'sent', sent_at = now()
            WHERE id = $1
            "#,
            id,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn mark_outbound_failed(
        &self,
        id: i64,
        attempts: i32,
        next_attempt_at_ms: i64,
        last_error: &str,
    ) -> Result<()> {
        let next_attempt = DateTime::<Utc>::from_timestamp_millis(next_attempt_at_ms)
            .unwrap_or_else(Utc::now);
        sqlx::query!(
            r#"
            UPDATE fed_outbound_queue
            SET attempts = $2,
                next_attempt_at = $3,
                last_error = $4
            WHERE id = $1
            "#,
            id,
            attempts,
            next_attempt,
            last_error,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn mark_outbound_dead(&self, id: i64, last_error: &str) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE fed_outbound_queue
            SET status = 'dead', last_error = $2
            WHERE id = $1
            "#,
            id,
            last_error,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn outbound_next_eta_ms(
        &self,
        destination: &str,
    ) -> Result<Option<i64>> {
        let row = sqlx::query!(
            r#"
            SELECT MIN(next_attempt_at) AS eta
            FROM fed_outbound_queue
            WHERE status = 'pending' AND destination = $1
            "#,
            destination,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.eta.map(|ts| ts.timestamp_millis()))
    }

    async fn gc_outbound_queue(
        &self,
        sent_cutoff_ms: i64,
        dead_cutoff_ms: Option<i64>,
    ) -> Result<i64> {
        let sent_cut = DateTime::<Utc>::from_timestamp_millis(sent_cutoff_ms)
            .unwrap_or_else(Utc::now);
        let mut total = 0_i64;
        // Sent rows: prune those whose sent_at is older than the cutoff.
        let n = sqlx::query!(
            r#"
            DELETE FROM fed_outbound_queue
            WHERE status = 'sent' AND sent_at IS NOT NULL AND sent_at < $1
            "#,
            sent_cut,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?
        .rows_affected();
        total += n as i64;

        if let Some(dead_ms) = dead_cutoff_ms {
            let dead_cut = DateTime::<Utc>::from_timestamp_millis(dead_ms)
                .unwrap_or_else(Utc::now);
            let n = sqlx::query!(
                r#"
                DELETE FROM fed_outbound_queue
                WHERE status = 'dead' AND created_at < $1
                "#,
                dead_cut,
            )
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?
            .rows_affected();
            total += n as i64;
        }
        Ok(total)
    }

    async fn list_outbound_dlq(
        &self,
        from: i64,
        limit: i64,
    ) -> Result<Vec<DlqEntry>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, destination, kind, txn_id, attempts, last_error, created_at
            FROM fed_outbound_queue
            WHERE status = 'dead'
            ORDER BY id DESC
            LIMIT $2 OFFSET $1
            "#,
            from,
            limit,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|r| DlqEntry {
                id: r.id,
                destination: r.destination,
                kind: r.kind,
                txn_id: r.txn_id,
                attempts: r.attempts,
                last_error: r.last_error,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn replay_outbound_dlq(&self, id: i64) -> Result<bool> {
        let result = sqlx::query!(
            r#"
            UPDATE fed_outbound_queue
            SET status = 'pending',
                attempts = 0,
                next_attempt_at = now(),
                last_error = NULL
            WHERE id = $1 AND status = 'dead'
            "#,
            id,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(result.rows_affected() > 0)
    }

    async fn purge_outbound_dlq(&self, id: i64) -> Result<bool> {
        let result = sqlx::query!(
            r#"
            DELETE FROM fed_outbound_queue
            WHERE id = $1 AND status = 'dead'
            "#,
            id,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Room aliases (conduit-v0y)
    // -----------------------------------------------------------------------

    async fn upsert_alias(
        &self,
        alias: &str,
        room_id: &str,
        creator: &str,
    ) -> Result<()> {
        // No ON CONFLICT — we want the unique violation so callers get
        // a clear "already in use" error.
        let result = sqlx::query!(
            r#"
            INSERT INTO room_aliases (alias, room_id, creator)
            VALUES ($1, $2, $3)
            "#,
            alias,
            room_id,
            creator,
        )
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err))
                if db_err.constraint() == Some("room_aliases_pkey") =>
            {
                Err(Error::Storage(format!("alias already in use: {alias}")))
            }
            Err(e) => Err(map_sqlx(e)),
        }
    }

    async fn get_room_for_alias(&self, alias: &str) -> Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT room_id FROM room_aliases WHERE alias = $1"#,
            alias,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| r.room_id))
    }

    async fn delete_alias(&self, alias: &str) -> Result<()> {
        sqlx::query!(
            r#"DELETE FROM room_aliases WHERE alias = $1"#,
            alias,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn list_aliases_for_room(&self, room_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"SELECT alias FROM room_aliases WHERE room_id = $1 ORDER BY alias"#,
            room_id,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|r| r.alias).collect())
    }

    // -----------------------------------------------------------------------
    // Device list broadcast performance (conduit-e0e)
    // -----------------------------------------------------------------------

    async fn get_remote_servers_for_user(&self, user_id: &str, server_name: &str) -> Result<Vec<String>> {
        // Fast path: query the room_current_state table directly for all
        // m.room.member entries where the target user is joined, then
        // collect distinct remote servers from other join members in
        // the same rooms. This is O(user's rooms × members per room)
        // but only touches rooms the user is actually in.
        //
        // In a future migration this can be further optimized with
        // a materialized user_room_servers table that tracks the
        // (user_id -> remote_server) mapping incrementally.
        let rows = sqlx::query(
            r#"
            WITH user_rooms AS (
                SELECT rcs.room_id
                FROM room_current_state rcs
                WHERE rcs.type = 'm.room.member'
                  AND rcs.state_key = $1
                  AND (rcs.event_id IN (
                      SELECT event_id FROM events
                      WHERE room_id = rcs.room_id
                        AND type = 'm.room.member'
                        AND state_key = $1
                        AND content->>'membership' = 'join'
                  ))
            )
            SELECT DISTINCT SPLIT_PART(rcs.state_key, ':', 2) AS server
            FROM room_current_state rcs
            WHERE rcs.type = 'm.room.member'
              AND rcs.room_id IN (SELECT room_id FROM user_rooms)
              AND rcs.state_key != $1
              AND SPLIT_PART(rcs.state_key, ':', 2) != $2
              AND SPLIT_PART(rcs.state_key, ':', 2) != ''
              AND (rcs.event_id IN (
                  SELECT event_id FROM events
                  WHERE room_id = rcs.room_id
                    AND type = 'm.room.member'
                    AND state_key = rcs.state_key
                    AND content->>'membership' = 'join'
              ))
            "#,
        )
        .bind(user_id)
        .bind(server_name)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows.iter().map(|r| {
            use sqlx::Row;
            r.get::<Option<String>, _>("server").unwrap_or_default()
        }).collect())
    }

    async fn joined_remote_servers(&self, room_id: &str, server_name: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT substring(rcs.state_key from position(':' in rcs.state_key) + 1) AS server
            FROM room_current_state rcs
            JOIN events e ON e.event_id = rcs.event_id
            WHERE rcs.room_id = $1
              AND rcs.type = 'm.room.member'
              AND e.content->>'membership' = 'join'
              AND position(':' in rcs.state_key) > 1
              AND substring(rcs.state_key from position(':' in rcs.state_key) + 1) <> $2
            ORDER BY server
            "#,
        )
        .bind(room_id)
        .bind(server_name)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                use sqlx::Row;
                row.get::<Option<String>, _>("server")
            })
            .filter(|server| !server.is_empty())
            .collect())
    }

    // -----------------------------------------------------------------------
    // Published room directory & user directory (conduit-y99.20)
    // -----------------------------------------------------------------------

    async fn set_room_published(&self, room_id: &str, published: bool) -> Result<()> {
        if published {
            sqlx::query!(
                r#"INSERT INTO room_directory (room_id) VALUES ($1) ON CONFLICT (room_id) DO NOTHING"#,
                room_id,
            )
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        } else {
            sqlx::query!(r#"DELETE FROM room_directory WHERE room_id = $1"#, room_id)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx)?;
        }
        Ok(())
    }

    async fn is_room_published(&self, room_id: &str) -> Result<bool> {
        let row = sqlx::query!(
            r#"SELECT EXISTS (SELECT 1 FROM room_directory WHERE room_id = $1) AS "published!""#,
            room_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.published)
    }

    async fn set_appservice_room_published(
        &self,
        appservice_id: &str,
        network_id: &str,
        room_id: &str,
        published: bool,
    ) -> Result<()> {
        if published {
            sqlx::query!(
                r#"
                INSERT INTO appservice_room_directory (appservice_id, network_id, room_id)
                VALUES ($1, $2, $3)
                ON CONFLICT (appservice_id, network_id, room_id) DO NOTHING
                "#,
                appservice_id,
                network_id,
                room_id,
            )
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        } else {
            sqlx::query!(
                r#"
                DELETE FROM appservice_room_directory
                WHERE appservice_id = $1 AND network_id = $2 AND room_id = $3
                "#,
                appservice_id,
                network_id,
                room_id,
            )
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        }
        Ok(())
    }

    async fn published_rooms(&self, scope: &DirectoryScope) -> Result<Vec<String>> {
        let rows = match scope {
            DirectoryScope::Local => sqlx::query_scalar!(
                r#"SELECT room_id AS "room_id!" FROM room_directory ORDER BY room_id"#
            )
            .fetch_all(&self.pool)
            .await,
            DirectoryScope::AllNetworks => sqlx::query_scalar!(
                r#"
                SELECT room_id AS "room_id!" FROM room_directory
                UNION
                SELECT room_id FROM appservice_room_directory
                ORDER BY 1
                "#
            )
            .fetch_all(&self.pool)
            .await,
            DirectoryScope::Network { appservice_id, network_id } => sqlx::query_scalar!(
                r#"
                SELECT room_id AS "room_id!" FROM appservice_room_directory
                WHERE appservice_id = $1 AND network_id = $2
                ORDER BY room_id
                "#,
                appservice_id,
                network_id,
            )
            .fetch_all(&self.pool)
            .await,
        };
        rows.map_err(map_sqlx)
    }

    async fn alias_creator(&self, alias: &str) -> Result<Option<String>> {
        let row = sqlx::query!(r#"SELECT creator FROM room_aliases WHERE alias = $1"#, alias)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(row.map(|r| r.creator))
    }

    async fn search_user_directory(
        &self,
        requester: &str,
        term: &str,
        limit: i64,
    ) -> Result<Vec<UserDirectoryEntry>> {
        // Joined member state per room, the rooms the requester can "see"
        // members of (shared, public join rule, world-readable history),
        // then one row per user with the account profile preferred over
        // the per-room member event profile.
        let rows = sqlx::query!(
            r#"
            WITH joined AS (
                SELECT rcs.room_id, rcs.state_key AS user_id,
                       e.content->>'displayname' AS member_name,
                       e.content->>'avatar_url'  AS member_avatar
                FROM room_current_state rcs
                JOIN events e ON e.event_id = rcs.event_id
                WHERE rcs.type = 'm.room.member'
                  AND e.content->>'membership' = 'join'
            ),
            shared_rooms AS (
                SELECT room_id FROM joined WHERE user_id = $1
            ),
            visible_rooms AS (
                SELECT room_id FROM shared_rooms
                UNION
                SELECT rcs.room_id
                FROM room_current_state rcs
                JOIN events e ON e.event_id = rcs.event_id
                WHERE rcs.state_key = ''
                  AND ((rcs.type = 'm.room.join_rules'
                        AND e.content->>'join_rule' = 'public')
                    OR (rcs.type = 'm.room.history_visibility'
                        AND e.content->>'history_visibility' = 'world_readable'))
            ),
            candidates AS (
                SELECT j.user_id,
                       bool_or(j.room_id IN (SELECT room_id FROM shared_rooms)) AS shared,
                       min(j.member_name)   AS member_name,
                       min(j.member_avatar) AS member_avatar
                FROM joined j
                WHERE j.room_id IN (SELECT room_id FROM visible_rooms)
                GROUP BY j.user_id
            )
            SELECT c.user_id AS "user_id!",
                   COALESCE(a.displayname, c.member_name) AS display_name,
                   COALESCE(a.avatar_url, c.member_avatar) AS avatar_url
            FROM candidates c
            LEFT JOIN accounts a ON a.user_id = c.user_id
            WHERE a.deactivated_at IS NULL
              AND (strpos(lower(c.user_id), lower($2)) > 0
                   OR strpos(lower(COALESCE(a.displayname, c.member_name, '')), lower($2)) > 0)
            ORDER BY c.shared DESC, c.user_id
            LIMIT $3
            "#,
            requester,
            term,
            limit.max(0),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|r| UserDirectoryEntry {
                user_id: r.user_id,
                display_name: r.display_name,
                avatar_url: r.avatar_url,
            })
            .collect())
    }

    // -----------------------------------------------------------------------
    // Room content (conduit-y99.19)
    // -----------------------------------------------------------------------

    async fn room_events_with_positions(&self, room_id: &str) -> Result<Vec<(i64, Event)>> {
        let rows = sqlx::query_as!(
            PositionedEventRow,
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth, pdu_json, stream_position
            FROM events WHERE room_id = $1 ORDER BY stream_position
            "#,
            room_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(PositionedEventRow::into_pair).collect())
    }

    async fn state_events_through(&self, room_id: &str, through: i64) -> Result<Vec<(i64, Event)>> {
        let rows = sqlx::query_as!(
            PositionedEventRow,
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth, pdu_json, stream_position
            FROM events
            WHERE room_id = $1 AND state_key IS NOT NULL AND stream_position <= $2
            ORDER BY stream_position
            "#,
            room_id,
            through
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(PositionedEventRow::into_pair).collect())
    }

    async fn redactions_targeting(&self, room_id: &str, event_ids: &[String]) -> Result<Vec<Event>> {
        if event_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as!(
            PositionedEventRow,
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth, pdu_json, stream_position
            FROM events
            WHERE room_id = $1 AND type = 'm.room.redaction'
              AND content->>'redacts' = ANY($2)
            ORDER BY stream_position
            "#,
            room_id,
            event_ids
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|row| row.into_pair().1).collect())
    }

    async fn relation_children(&self, room_id: &str, parent_ids: &[String]) -> Result<Vec<(i64, Event)>> {
        if parent_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as!(
            PositionedEventRow,
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth, pdu_json, stream_position
            FROM events
            WHERE room_id = $1 AND content ? 'm.relates_to'
              AND content->'m.relates_to'->>'event_id' = ANY($2)
              AND content->'m.relates_to'->>'rel_type' IS NOT NULL
            ORDER BY stream_position
            "#,
            room_id,
            parent_ids
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(PositionedEventRow::into_pair).collect())
    }

    async fn thread_roots(&self, room_id: &str, user_id: &str) -> Result<Vec<(String, i64, bool)>> {
        let rows = sqlx::query!(
            r#"
            SELECT content->'m.relates_to'->>'event_id' AS "root!",
                   MAX(stream_position) AS "latest!",
                   BOOL_OR(sender = $2) AS "participated!"
            FROM events
            WHERE room_id = $1
              AND content->'m.relates_to'->>'rel_type' = 'm.thread'
              AND content->'m.relates_to'->>'event_id' IS NOT NULL
            GROUP BY 1
            ORDER BY 2 DESC
            "#,
            room_id,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|row| (row.root, row.latest, row.participated)).collect())
    }

    async fn events_near_timestamp(&self, room_id: &str, ts: i64, forward: bool, limit: i64) -> Result<Vec<Event>> {
        let rows = if forward {
            sqlx::query_as!(
                PositionedEventRow,
                r#"
                SELECT event_id, room_id, sender, type AS event_type, state_key,
                       content, auth_events, prev_events, hashes, signatures,
                       unsigned, origin_server_ts, depth, pdu_json, stream_position
                FROM events
                WHERE room_id = $1 AND origin_server_ts >= $2
                ORDER BY origin_server_ts ASC, stream_position ASC
                LIMIT $3
                "#,
                room_id,
                ts,
                limit
            )
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as!(
                PositionedEventRow,
                r#"
                SELECT event_id, room_id, sender, type AS event_type, state_key,
                       content, auth_events, prev_events, hashes, signatures,
                       unsigned, origin_server_ts, depth, pdu_json, stream_position
                FROM events
                WHERE room_id = $1 AND origin_server_ts <= $2
                ORDER BY origin_server_ts DESC, stream_position DESC
                LIMIT $3
                "#,
                room_id,
                ts,
                limit
            )
            .fetch_all(&self.pool)
            .await
        }
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|row| row.into_pair().1).collect())
    }

    async fn search_room_events(
        &self,
        rooms: &[String],
        term: &str,
        keys: conduit::room_content::SearchKeys,
        recent: bool,
        cap: i64,
    ) -> Result<Vec<conduit::room_content::SearchHit>> {
        if rooms.is_empty() {
            return Ok(Vec::new());
        }
        // websearch_to_tsquery accepts arbitrary user input without syntax
        // errors; each key is matched only on the event type defining it.
        let rows = sqlx::query!(
            r#"
            WITH q AS (SELECT websearch_to_tsquery('english', $2) AS query),
            hits AS (
                SELECT e.event_id, e.room_id, e.sender, e.type AS event_type, e.state_key,
                       e.content, e.auth_events, e.prev_events, e.hashes, e.signatures,
                       e.unsigned, e.origin_server_ts, e.depth, e.pdu_json, e.stream_position,
                       CASE e.type
                           WHEN 'm.room.message' THEN ts_rank(to_tsvector('english', e.content->>'body'), q.query)
                           WHEN 'm.room.name' THEN ts_rank(to_tsvector('english', e.content->>'name'), q.query)
                           ELSE ts_rank(to_tsvector('english', e.content->>'topic'), q.query)
                       END AS rank
                FROM events e, q
                WHERE e.room_id = ANY($1)
                  AND (
                      ($3 AND e.type = 'm.room.message' AND to_tsvector('english', e.content->>'body') @@ q.query)
                   OR ($4 AND e.type = 'm.room.name' AND to_tsvector('english', e.content->>'name') @@ q.query)
                   OR ($5 AND e.type = 'm.room.topic' AND to_tsvector('english', e.content->>'topic') @@ q.query)
                  )
            )
            SELECT event_id AS "event_id!", room_id AS "room_id!", sender AS "sender!",
                   event_type AS "event_type!", state_key, content AS "content!",
                   auth_events AS "auth_events!", prev_events AS "prev_events!",
                   hashes AS "hashes!", signatures AS "signatures!", unsigned, pdu_json,
                   origin_server_ts AS "origin_server_ts!", depth AS "depth!",
                   stream_position AS "stream_position!", rank AS "rank!"
            FROM hits
            ORDER BY CASE WHEN $6 THEN 0 ELSE rank END DESC, stream_position DESC
            LIMIT $7
            "#,
            rooms,
            term,
            keys.body,
            keys.name,
            keys.topic,
            recent,
            cap
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|r| conduit::room_content::SearchHit {
                rank: f64::from(r.rank),
                position: r.stream_position,
                event: event_from_row(EventRow { event_id: r.event_id, pdu_json: r.pdu_json, room_id: r.room_id, sender: r.sender, event_type: r.event_type, state_key: r.state_key, content: r.content, origin_server_ts: r.origin_server_ts, auth_events: r.auth_events, prev_events: r.prev_events, hashes: r.hashes, signatures: r.signatures, depth: r.depth, unsigned: r.unsigned }),
            })
            .collect())
    }

    async fn forget_room(&self, user_id: &str, room_id: &str, membership_event_id: &str) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO room_forgotten (user_id, room_id, membership_event_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, room_id) DO UPDATE
                SET membership_event_id = EXCLUDED.membership_event_id, forgotten_at = now()
            "#,
            user_id,
            room_id,
            membership_event_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn forgotten_rooms(&self, user_id: &str) -> Result<HashMap<String, String>> {
        let rows = sqlx::query!(
            "SELECT room_id, membership_event_id FROM room_forgotten WHERE user_id = $1",
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|row| (row.room_id, row.membership_event_id)).collect())
    }

    async fn insert_report(&self, report: &conduit::room_content::ContentReport) -> Result<i64> {
        let row = sqlx::query!(
            r#"
            INSERT INTO content_reports
                (kind, reporter, room_id, event_id, target_user_id, reason, received_ts)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
            report.kind,
            report.reporter,
            report.room_id,
            report.event_id,
            report.target_user_id,
            report.reason,
            report.received_ts
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.id)
    }

    async fn list_reports(&self, from: i64, limit: i64) -> Result<Vec<conduit::room_content::ContentReport>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, kind, reporter, room_id, event_id, target_user_id, reason, received_ts
            FROM content_reports WHERE id > $1 ORDER BY id LIMIT $2
            "#,
            from,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|row| conduit::room_content::ContentReport {
                id: row.id,
                kind: row.kind,
                reporter: row.reporter,
                room_id: row.room_id,
                event_id: row.event_id,
                target_user_id: row.target_user_id,
                reason: row.reason,
                received_ts: row.received_ts,
            })
            .collect())
    }

    // -----------------------------------------------------------------------
    // Account & device management (conduit-y99.18)
    // -----------------------------------------------------------------------

    async fn create_device_if_absent(
        &self,
        user_id: &str,
        device_id: &str,
        display_name: Option<&str>,
    ) -> Result<bool> {
        let result = sqlx::query!(
            r#"
            INSERT INTO devices (user_id, device_id, display_name, epoch)
            VALUES ($1, $2, $3, COALESCE(
                (SELECT epoch + 1 FROM retired_device_epochs
                 WHERE user_id = $1 AND device_id = $2), 0))
            ON CONFLICT (user_id, device_id) DO NOTHING
            "#,
            user_id,
            device_id,
            display_name
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(result.rows_affected() == 1)
    }

    async fn set_device_display_name(
        &self,
        user_id: &str,
        device_id: &str,
        display_name: Option<&str>,
    ) -> Result<bool> {
        let result = sqlx::query!(
            r#"
            UPDATE devices SET display_name = $3
            WHERE user_id = $1 AND device_id = $2
            "#,
            user_id,
            device_id,
            display_name
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete_device(&self, user_id: &str, device_id: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        sqlx::query!(
            "DELETE FROM access_tokens WHERE user_id = $1 AND device_id = $2",
            user_id,
            device_id
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        sqlx::query!(
            "DELETE FROM device_keys WHERE user_id = $1 AND device_id = $2",
            user_id,
            device_id
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        sqlx::query!(
            "DELETE FROM one_time_keys WHERE user_id = $1 AND device_id = $2",
            user_id,
            device_id
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        sqlx::query!(
            "DELETE FROM fallback_keys WHERE user_id = $1 AND device_id = $2",
            user_id,
            device_id
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        sqlx::query!(
            "DELETE FROM to_device_queue WHERE target_user = $1 AND target_device = $2",
            user_id,
            device_id
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        // refresh_tokens rows cascade with the device row.
        let retired = sqlx::query!(
            r#"
            DELETE FROM devices WHERE user_id = $1 AND device_id = $2
            RETURNING epoch
            "#,
            user_id,
            device_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        let Some(row) = retired else {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(false);
        };
        sqlx::query!(
            r#"
            INSERT INTO retired_device_epochs (user_id, device_id, epoch)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, device_id)
            DO UPDATE SET epoch = GREATEST(retired_device_epochs.epoch, EXCLUDED.epoch)
            "#,
            user_id,
            device_id,
            row.epoch
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(true)
    }

    async fn touch_device(
        &self,
        user_id: &str,
        device_id: &str,
        ts_ms: i64,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE devices
            SET last_seen_ts = $3,
                last_seen_ip = COALESCE($4::TEXT::INET, last_seen_ip),
                last_seen_user_agent = COALESCE($5, last_seen_user_agent)
            WHERE user_id = $1 AND device_id = $2
            "#,
            user_id,
            device_id,
            ts_ms,
            ip,
            user_agent
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn set_guest(&self, user_id: &str, is_guest: bool) -> Result<()> {
        sqlx::query!(
            "UPDATE accounts SET is_guest = $2 WHERE user_id = $1",
            user_id,
            is_guest
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn list_admin_user_ids(&self) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_id FROM accounts
            WHERE is_admin AND deactivated_at IS NULL
            ORDER BY user_id
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|r| r.user_id).collect())
    }

    async fn erase_account(&self, user_id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        sqlx::query!("DELETE FROM account_data WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        sqlx::query!("DELETE FROM profile_fields WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        sqlx::query!(
            r#"
            UPDATE accounts
            SET displayname = NULL, avatar_url = NULL, erased_at = now()
            WHERE user_id = $1
            "#,
            user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn insert_refresh_token(
        &self,
        token_hash: &str,
        user_id: &str,
        device_id: &str,
        epoch: i64,
        parent_hash: Option<&str>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO refresh_tokens (token_hash, user_id, device_id, epoch, parent_hash)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            token_hash,
            user_id,
            device_id,
            epoch,
            parent_hash
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get_refresh_token(&self, token_hash: &str) -> Result<Option<RefreshTokenRecord>> {
        let row = sqlx::query!(
            r#"
            SELECT user_id, device_id, epoch, parent_hash
            FROM refresh_tokens WHERE token_hash = $1
            "#,
            token_hash
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| RefreshTokenRecord {
            user_id: r.user_id,
            device_id: r.device_id,
            epoch: r.epoch,
            parent_hash: r.parent_hash,
        }))
    }

    async fn delete_refresh_token(&self, token_hash: &str) -> Result<()> {
        sqlx::query!("DELETE FROM refresh_tokens WHERE token_hash = $1", token_hash)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn delete_refresh_token_children(&self, parent_hash: &str) -> Result<()> {
        sqlx::query!("DELETE FROM refresh_tokens WHERE parent_hash = $1", parent_hash)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    // --- Application services & identity-server bindings (appservice lane) --

    async fn appservice_cursor(&self, as_id: &str) -> Result<conduit::storage::AppserviceCursor> {
        let existing = sqlx::query!(
            "SELECT event_pos, receipt_pos FROM appservice_stream WHERE as_id = $1",
            as_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if let Some(row) = existing {
            return Ok(conduit::storage::AppserviceCursor {
                event_pos: row.event_pos,
                receipt_pos: row.receipt_pos,
            });
        }
        let event_pos = self.global_max_stream_position().await?;
        // A first start inserts at the stream heads; a racing insert wins.
        let row = sqlx::query!(
            r#"
            WITH inserted AS (
                INSERT INTO appservice_stream (as_id, event_pos, receipt_pos)
                VALUES ($1, $2, (SELECT COALESCE(MAX(stream_pos), 0) FROM receipts))
                ON CONFLICT (as_id) DO NOTHING
                RETURNING event_pos, receipt_pos
            )
            SELECT event_pos AS "event_pos!", receipt_pos AS "receipt_pos!" FROM inserted
            UNION ALL
            SELECT event_pos, receipt_pos FROM appservice_stream WHERE as_id = $1
            LIMIT 1
            "#,
            as_id,
            event_pos
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(conduit::storage::AppserviceCursor {
            event_pos: row.event_pos,
            receipt_pos: row.receipt_pos,
        })
    }

    async fn appservice_pending_txn(&self, as_id: &str) -> Result<Option<(i64, Value)>> {
        let row = sqlx::query!(
            "SELECT txn_id, body FROM appservice_txns WHERE as_id = $1 ORDER BY txn_id LIMIT 1",
            as_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| (r.txn_id, r.body)))
    }

    async fn appservice_enqueue_txn(
        &self,
        as_id: &str,
        body: Option<&Value>,
        cursor: &conduit::storage::AppserviceCursor,
    ) -> Result<Option<i64>> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let next = sqlx::query_scalar!(
            "SELECT next_txn_id FROM appservice_stream WHERE as_id = $1 FOR UPDATE",
            as_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        .ok_or_else(|| Error::Storage(format!("no cursor for application service {as_id}")))?;
        let txn_id = match body {
            Some(body) => {
                sqlx::query!(
                    "INSERT INTO appservice_txns (as_id, txn_id, body) VALUES ($1, $2, $3)",
                    as_id,
                    next,
                    body
                )
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx)?;
                Some(next)
            }
            None => None,
        };
        sqlx::query!(
            r#"
            UPDATE appservice_stream
            SET event_pos = $2, receipt_pos = $3, next_txn_id = $4
            WHERE as_id = $1
            "#,
            as_id,
            cursor.event_pos,
            cursor.receipt_pos,
            next + i64::from(txn_id.is_some())
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(txn_id)
    }

    async fn appservice_complete_txn(&self, as_id: &str, txn_id: i64) -> Result<()> {
        sqlx::query!(
            "DELETE FROM appservice_txns WHERE as_id = $1 AND txn_id = $2",
            as_id,
            txn_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn add_threepid_binding(
        &self,
        user_id: &str,
        medium: &str,
        address: &str,
        id_server: &str,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO threepid_id_server_bindings (user_id, medium, address, id_server)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT DO NOTHING
            "#,
            user_id,
            medium,
            address,
            id_server
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn threepid_bindings(&self, user_id: &str) -> Result<Vec<(String, String, String)>> {
        let rows = sqlx::query!(
            r#"
            SELECT medium, address, id_server FROM threepid_id_server_bindings
            WHERE user_id = $1 ORDER BY medium, address, id_server
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|r| (r.medium, r.address, r.id_server)).collect())
    }

    async fn remove_threepid_binding(
        &self,
        user_id: &str,
        medium: &str,
        address: &str,
        id_server: Option<&str>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            DELETE FROM threepid_id_server_bindings
            WHERE user_id = $1 AND medium = $2 AND address = $3
              AND ($4::TEXT IS NULL OR id_server = $4)
            "#,
            user_id,
            medium,
            address,
            id_server
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn threepid_session_for_client(
        &self,
        medium: &str,
        address: &str,
        client_secret: &str,
    ) -> Result<Option<conduit::storage::ThreepidValidation>> {
        let row = sqlx::query!(
            r#"
            SELECT sid, client_secret, medium, address, purpose, send_attempt, token_hash, validated_at
            FROM threepid_validation_sessions
            WHERE medium = $1 AND address = $2 AND client_secret = $3
            "#,
            medium,
            address,
            client_secret
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| conduit::storage::ThreepidValidation {
            sid: r.sid,
            client_secret: r.client_secret,
            medium: r.medium,
            address: r.address,
            purpose: r.purpose,
            send_attempt: r.send_attempt,
            token_hash: r.token_hash,
            validated_at: r.validated_at,
        }))
    }

    async fn insert_threepid_session(&self, session: &conduit::storage::ThreepidValidation) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO threepid_validation_sessions
                (sid, client_secret, medium, address, purpose, send_attempt, token_hash, validated_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            session.sid,
            session.client_secret,
            session.medium,
            session.address,
            session.purpose,
            session.send_attempt,
            session.token_hash,
            session.validated_at,
            chrono::Utc::now().timestamp_millis()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn retarget_threepid_session(
        &self,
        sid: &str,
        purpose: &str,
        send_attempt: i32,
        token_hash: &str,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE threepid_validation_sessions
            SET purpose = $2, send_attempt = $3, token_hash = $4, validated_at = NULL
            WHERE sid = $1
            "#,
            sid,
            purpose,
            send_attempt,
            token_hash
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn threepid_session(&self, sid: &str) -> Result<Option<conduit::storage::ThreepidValidation>> {
        let row = sqlx::query!(
            r#"
            SELECT sid, client_secret, medium, address, purpose, send_attempt, token_hash, validated_at
            FROM threepid_validation_sessions
            WHERE sid = $1
            "#,
            sid
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| conduit::storage::ThreepidValidation {
            sid: r.sid,
            client_secret: r.client_secret,
            medium: r.medium,
            address: r.address,
            purpose: r.purpose,
            send_attempt: r.send_attempt,
            token_hash: r.token_hash,
            validated_at: r.validated_at,
        }))
    }

    async fn mark_threepid_validated(&self, sid: &str, validated_at: i64) -> Result<()> {
        sqlx::query!(
            "UPDATE threepid_validation_sessions SET validated_at = $2 WHERE sid = $1",
            sid,
            validated_at
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn account_threepid_owner(&self, medium: &str, address: &str) -> Result<Option<String>> {
        let row = sqlx::query!(
            "SELECT user_id FROM account_threepids WHERE medium = $1 AND address = $2",
            medium,
            address
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| r.user_id))
    }

    async fn list_account_threepids(&self, user_id: &str) -> Result<Vec<conduit::storage::AccountThreepid>> {
        let rows = sqlx::query!(
            r#"
            SELECT medium, address, added_at, validated_at
            FROM account_threepids
            WHERE user_id = $1
            ORDER BY added_at, medium, address
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|r| conduit::storage::AccountThreepid {
                medium: r.medium,
                address: r.address,
                added_at: r.added_at,
                validated_at: r.validated_at,
            })
            .collect())
    }

    async fn add_account_threepid(
        &self,
        user_id: &str,
        medium: &str,
        address: &str,
        added_at: i64,
        validated_at: i64,
    ) -> Result<bool> {
        let inserted = sqlx::query!(
            r#"
            INSERT INTO account_threepids (medium, address, user_id, added_at, validated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (medium, address) DO NOTHING
            "#,
            medium,
            address,
            user_id,
            added_at,
            validated_at
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if inserted.rows_affected() == 1 {
            return Ok(true);
        }
        let owner = self.account_threepid_owner(medium, address).await?;
        Ok(owner.as_deref() == Some(user_id))
    }

    async fn remove_account_threepid(&self, user_id: &str, medium: &str, address: &str) -> Result<()> {
        sqlx::query!(
            "DELETE FROM account_threepids WHERE user_id = $1 AND medium = $2 AND address = $3",
            user_id,
            medium,
            address
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn remove_account_threepids(&self, user_id: &str) -> Result<()> {
        sqlx::query!("DELETE FROM account_threepids WHERE user_id = $1", user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Sync & E2EE semantics (conduit-y99.14 / .15 / .16)
    // -----------------------------------------------------------------------

    async fn cross_signing_signatures_for(
        &self,
        target_user: &str,
    ) -> Result<Vec<(String, String, String, String)>> {
        let rows = sqlx::query!(
            r#"SELECT signer_user_id, signer_key_id, target_key_id, signature
               FROM cross_signing_signatures WHERE target_user_id = $1
               ORDER BY signer_user_id, signer_key_id, target_key_id"#,
            target_user
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|r| (r.signer_user_id, r.signer_key_id, r.target_key_id, r.signature))
            .collect())
    }

    async fn device_key_inventory(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<(HashMap<String, i64>, Vec<String>)> {
        // One statement is one snapshot: counts and fallback usage agree.
        let row = sqlx::query!(
            r#"SELECT
                 COALESCE((SELECT jsonb_object_agg(algorithm, n) FROM (
                     SELECT algorithm, COUNT(*) AS n FROM one_time_keys
                     WHERE user_id = $1 AND device_id = $2 GROUP BY algorithm) counts),
                   '{}'::jsonb) AS "counts!",
                 COALESCE((SELECT array_agg(algorithm ORDER BY algorithm) FROM fallback_keys
                     WHERE user_id = $1 AND device_id = $2 AND NOT used), '{}') AS "fallback!""#,
            user_id,
            device_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let counts = row
            .counts
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .filter_map(|(algorithm, n)| n.as_i64().map(|n| (algorithm.clone(), n)))
                    .collect()
            })
            .unwrap_or_default();
        Ok((counts, row.fallback))
    }

    async fn set_threaded_receipt(
        &self,
        room_id: &str,
        user_id: &str,
        receipt_type: &str,
        thread_id: Option<&str>,
        event_id: &str,
        ts: i64,
    ) -> Result<i64> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        lock_stream(&mut transaction, Stream::Receipts).await?;
        let row = sqlx::query!(
            r#"
            INSERT INTO receipts (room_id, user_id, receipt_type, thread_id, event_id, ts)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (room_id, user_id, receipt_type, thread_id)
                DO UPDATE SET event_id = EXCLUDED.event_id, ts = EXCLUDED.ts,
                              stream_pos = EXCLUDED.stream_pos
            RETURNING stream_pos
            "#,
            room_id,
            user_id,
            receipt_type,
            thread_id.unwrap_or_default(),
            event_id,
            ts
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(row.stream_pos)
    }

    async fn threaded_receipts_since(
        &self,
        since_pos: i64,
    ) -> Result<Vec<conduit::storage::ReceiptRecord>> {
        let rows = sqlx::query!(
            r#"SELECT room_id, user_id, receipt_type, thread_id, event_id, ts, stream_pos
               FROM receipts WHERE stream_pos > $1 ORDER BY stream_pos ASC"#,
            since_pos
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|r| conduit::storage::ReceiptRecord {
                room_id: r.room_id,
                user_id: r.user_id,
                receipt_type: r.receipt_type,
                thread_id: (!r.thread_id.is_empty()).then_some(r.thread_id),
                event_id: r.event_id,
                ts: r.ts,
                stream_pos: r.stream_pos,
            })
            .collect())
    }

    async fn client_transaction_ids(
        &self,
        user: &str,
        device: &str,
        event_ids: &[String],
    ) -> Result<HashMap<String, String>> {
        if event_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let owner = conduit::storage::TransactionKey::client(user, device, &[], "").owner;
        let rows = sqlx::query!(
            // Results moved to lossless `result_text` in 0091; older rows
            // keep JSONB `result`.  Read both without casting text to JSONB
            // (a stored U+0000 would make the cast fail).
            r#"SELECT event_id AS "event_id!", txn_id FROM (
                   SELECT COALESCE(result->>'event_id',
                                   substring(result_text from '"event_id":"([^"]+)"')) AS event_id,
                          txn_id
                   FROM transactions WHERE scope = 'client' AND owner = $1
               ) t WHERE event_id = ANY($2)"#,
            owner,
            event_ids
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|row| (row.event_id, row.txn_id)).collect())
    }

    async fn user_receipts_in_room(
        &self,
        room_id: &str,
        user_id: &str,
    ) -> Result<Vec<conduit::storage::ReceiptRecord>> {
        let rows = sqlx::query!(
            r#"SELECT room_id, user_id, receipt_type, thread_id, event_id, ts, stream_pos
               FROM receipts WHERE room_id = $1 AND user_id = $2 ORDER BY stream_pos ASC"#,
            room_id,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows
            .into_iter()
            .map(|r| conduit::storage::ReceiptRecord {
                room_id: r.room_id,
                user_id: r.user_id,
                receipt_type: r.receipt_type,
                thread_id: (!r.thread_id.is_empty()).then_some(r.thread_id),
                event_id: r.event_id,
                ts: r.ts,
                stream_pos: r.stream_pos,
            })
            .collect())
    }

    // --- Modules lane (conduit-y99.38/.39/.41/.43) --------------------------

    async fn profile_fields(&self, user_id: &str) -> Result<std::collections::BTreeMap<String, Value>> {
        let rows = sqlx::query!(
            "SELECT key, value FROM profile_fields WHERE user_id = $1",
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|r| (r.key, r.value)).collect())
    }

    async fn set_profile_field(&self, user_id: &str, key: &str, value: Option<&Value>) -> Result<()> {
        match value {
            Some(value) => {
                sqlx::query!(
                    r#"
                    INSERT INTO profile_fields (user_id, key, value) VALUES ($1, $2, $3)
                    ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value
                    "#,
                    user_id,
                    key,
                    value
                )
                .execute(&self.pool)
                .await
                .map_err(map_sqlx)?;
            }
            None => {
                sqlx::query!(
                    "DELETE FROM profile_fields WHERE user_id = $1 AND key = $2",
                    user_id,
                    key
                )
                .execute(&self.pool)
                .await
                .map_err(map_sqlx)?;
            }
        }
        Ok(())
    }

    async fn account_moderation(&self, user_id: &str) -> Result<conduit::storage::AccountModeration> {
        let row = sqlx::query!(
            r#"
            SELECT locked_at IS NOT NULL AS "locked!", suspended_at IS NOT NULL AS "suspended!"
            FROM account_moderation WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row
            .map(|r| conduit::storage::AccountModeration { locked: r.locked, suspended: r.suspended })
            .unwrap_or_default())
    }

    async fn set_account_locked(&self, user_id: &str, locked: bool) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO account_moderation (user_id, locked_at)
            VALUES ($1, CASE WHEN $2 THEN now() END)
            ON CONFLICT (user_id) DO UPDATE SET locked_at = CASE
                WHEN NOT $2 THEN NULL
                ELSE COALESCE(account_moderation.locked_at, now())
            END
            "#,
            user_id,
            locked
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn set_account_suspended(&self, user_id: &str, suspended: bool) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO account_moderation (user_id, suspended_at)
            VALUES ($1, CASE WHEN $2 THEN now() END)
            ON CONFLICT (user_id) DO UPDATE SET suspended_at = CASE
                WHEN NOT $2 THEN NULL
                ELSE COALESCE(account_moderation.suspended_at, now())
            END
            "#,
            user_id,
            suspended
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn room_keys_version_deleted(&self, user_id: &str, version: &str) -> Result<Option<bool>> {
        let row = sqlx::query!(
            "SELECT deleted FROM room_keys_versions WHERE user_id = $1 AND version = $2",
            user_id,
            version
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| r.deleted))
    }

    async fn server_notice_room(&self, user_id: &str) -> Result<Option<String>> {
        let row = sqlx::query!(
            "SELECT room_id FROM server_notice_rooms WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(|r| r.room_id))
    }

    async fn set_server_notice_room(&self, user_id: &str, room_id: &str) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO server_notice_rooms (user_id, room_id) VALUES ($1, $2)
            ON CONFLICT (user_id) DO UPDATE SET room_id = EXCLUDED.room_id
            "#,
            user_id,
            room_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn is_server_notice_room(&self, room_id: &str) -> Result<bool> {
        let row = sqlx::query!(
            r#"SELECT EXISTS (SELECT 1 FROM server_notice_rooms WHERE room_id = $1) AS "found!""#,
            room_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.found)
    }

    async fn account_erased_at(&self, user_id: &str) -> Result<Option<i64>> {
        let row = sqlx::query!(
            r#"SELECT (EXTRACT(EPOCH FROM erased_at) * 1000)::BIGINT AS "erased_at" FROM accounts WHERE user_id = $1"#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.and_then(|r| r.erased_at))
    }
}

/// An `events` row with its stream position (conduit-y99.19 queries).
struct PositionedEventRow {
    event_id: String,
    room_id: String,
    sender: String,
    event_type: String,
    state_key: Option<String>,
    content: Value,
    auth_events: Vec<String>,
    prev_events: Vec<String>,
    hashes: Value,
    signatures: Value,
    unsigned: Option<Value>,
    origin_server_ts: i64,
    depth: i64,
    stream_position: i64,
    pdu_json: Option<String>,
}

impl PositionedEventRow {
    fn into_pair(self) -> (i64, Event) {
        (
            self.stream_position,
            event_from_row(EventRow { event_id: self.event_id, pdu_json: self.pdu_json, room_id: self.room_id, sender: self.sender, event_type: self.event_type, state_key: self.state_key, content: self.content, origin_server_ts: self.origin_server_ts, auth_events: self.auth_events, prev_events: self.prev_events, hashes: self.hashes, signatures: self.signatures, depth: self.depth, unsigned: self.unsigned }),
        )
    }
}
