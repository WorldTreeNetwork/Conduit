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
    event::Event,
    storage::{
        Account, AuditEntry, Device, MediaMetadata, OutboundEntry, Pusher, PushRule,
        RoomKeyVersion, SigningKey, Storage, ThumbnailMetadata, ToDeviceMessage, TokenOwner,
    },
};

// ---------------------------------------------------------------------------
// PostgresStorage
// ---------------------------------------------------------------------------

pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Convenience constructor that wraps self in `Arc<dyn Storage>`.
    pub fn into_arc(self) -> Arc<dyn Storage> {
        Arc::new(self)
    }
}

// ---------------------------------------------------------------------------
// Helper: map sqlx errors to conduit::Error
// ---------------------------------------------------------------------------

fn map_sqlx(e: sqlx::Error) -> Error {
    Error::Storage(e.to_string())
}

// ---------------------------------------------------------------------------
// Storage impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Storage for PostgresStorage {
    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    async fn get_event(&self, event_id: &str) -> Result<Option<Event>> {
        let row = sqlx::query!(
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth
            FROM events
            WHERE event_id = $1
            "#,
            event_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let Some(r) = row else { return Ok(None) };

        let event = Event {
            event_id: r.event_id,
            room_id: r.room_id,
            sender: r.sender,
            event_type: r.event_type,
            state_key: r.state_key,
            content: r.content,
            origin_server_ts: r.origin_server_ts as u64,
            auth_events: r.auth_events,
            prev_events: r.prev_events,
            hashes: r.hashes,
            signatures: r.signatures,
            depth: r.depth,
            unsigned: r.unsigned,
        };
        Ok(Some(event))
    }

    async fn put_event(&self, event: &Event) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO events
                (event_id, room_id, sender, type, state_key, content,
                 auth_events, prev_events, signatures, hashes, unsigned,
                 origin_server_ts, depth)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (event_id) DO NOTHING
            "#,
            event.event_id,
            event.room_id,
            event.sender,
            event.event_type,
            event.state_key,
            event.content,
            &event.auth_events,
            &event.prev_events,
            event.signatures,
            event.hashes,
            event.unsigned,
            event.origin_server_ts as i64,
            event.depth
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    async fn room_events(&self, room_id: &str) -> Result<Vec<Event>> {
        let rows = sqlx::query!(
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth
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
            .map(|r| Event {
                event_id: r.event_id,
                room_id: r.room_id,
                sender: r.sender,
                event_type: r.event_type,
                state_key: r.state_key,
                content: r.content,
                origin_server_ts: r.origin_server_ts as u64,
                auth_events: r.auth_events,
                prev_events: r.prev_events,
                hashes: r.hashes,
                signatures: r.signatures,
                depth: r.depth,
                unsigned: r.unsigned,
            })
            .collect();

        Ok(events)
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
                   displayname, avatar_url
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
            INSERT INTO devices (user_id, device_id, display_name)
            VALUES ($1, $2, $3)
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
            SELECT user_id, device_id, display_name, last_seen_ts,
                   last_seen_ip::TEXT AS last_seen_ip
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
            last_seen_ts: r.last_seen_ts,
            last_seen_ip: r.last_seen_ip,
        }))
    }

    async fn list_devices_for_user(&self, user_id: &str) -> Result<Vec<Device>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_id, device_id, display_name, last_seen_ts,
                   last_seen_ip::TEXT AS last_seen_ip
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
                last_seen_ts: r.last_seen_ts,
                last_seen_ip: r.last_seen_ip,
            })
            .collect();

        Ok(devices)
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
                   e.hashes, e.signatures, e.unsigned, e.origin_server_ts, e.depth
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

        Ok(Some(Event {
            event_id: r.event_id,
            room_id: r.room_id,
            sender: r.sender,
            event_type: r.event_type,
            state_key: r.state_key,
            content: r.content,
            origin_server_ts: r.origin_server_ts as u64,
            auth_events: r.auth_events,
            prev_events: r.prev_events,
            hashes: r.hashes,
            signatures: r.signatures,
            depth: r.depth,
            unsigned: r.unsigned,
        }))
    }

    async fn get_current_state(&self, room_id: &str) -> Result<Vec<Event>> {
        let rows = sqlx::query!(
            r#"
            SELECT e.event_id, e.room_id, e.sender, e.type AS event_type,
                   e.state_key, e.content, e.auth_events, e.prev_events,
                   e.hashes, e.signatures, e.unsigned, e.origin_server_ts, e.depth
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
            .map(|r| Event {
                event_id: r.event_id,
                room_id: r.room_id,
                sender: r.sender,
                event_type: r.event_type,
                state_key: r.state_key,
                content: r.content,
                origin_server_ts: r.origin_server_ts as u64,
                auth_events: r.auth_events,
                prev_events: r.prev_events,
                hashes: r.hashes,
                signatures: r.signatures,
                depth: r.depth,
                unsigned: r.unsigned,
            })
            .collect();

        Ok(events)
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
        }

        let rows: Vec<Row> = if dir == 'b' {
            sqlx::query!(
                r#"
                SELECT event_id, room_id, sender, type AS event_type, state_key,
                       content, auth_events, prev_events, hashes, signatures,
                       unsigned, origin_server_ts, depth, stream_position
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
            })
            .collect()
        } else {
            sqlx::query!(
                r#"
                SELECT event_id, room_id, sender, type AS event_type, state_key,
                       content, auth_events, prev_events, hashes, signatures,
                       unsigned, origin_server_ts, depth, stream_position
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
            .map(|r| Event {
                event_id: r.event_id,
                room_id: r.room_id,
                sender: r.sender,
                event_type: r.event_type,
                state_key: r.state_key,
                content: r.content,
                origin_server_ts: r.origin_server_ts as u64,
                auth_events: r.auth_events,
                prev_events: r.prev_events,
                hashes: r.hashes,
                signatures: r.signatures,
                depth: r.depth,
                unsigned: r.unsigned,
            })
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

    async fn events_since(&self, since: i64, limit: i64) -> Result<Vec<Event>> {
        let rows = sqlx::query!(
            r#"
            SELECT event_id, room_id, sender, type AS event_type, state_key,
                   content, auth_events, prev_events, hashes, signatures,
                   unsigned, origin_server_ts, depth
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
            .map(|r| Event {
                event_id: r.event_id,
                room_id: r.room_id,
                sender: r.sender,
                event_type: r.event_type,
                state_key: r.state_key,
                content: r.content,
                origin_server_ts: r.origin_server_ts as u64,
                auth_events: r.auth_events,
                prev_events: r.prev_events,
                hashes: r.hashes,
                signatures: r.signatures,
                depth: r.depth,
                unsigned: r.unsigned,
            })
            .collect();

        Ok(events)
    }

    async fn global_max_stream_position(&self) -> Result<i64> {
        let row = sqlx::query!(
            r#"
            SELECT COALESCE(MAX(stream_position), 0) AS max_pos
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
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
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
        let row = sqlx::query!(
            r#"
            INSERT INTO device_list_changes (user_id)
            VALUES ($1)
            RETURNING id
            "#,
            user_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.id)
    }

    async fn device_list_changes_since(&self, since_pos: i64) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT user_id
            FROM device_list_changes
            WHERE id > $1
            ORDER BY user_id
            "#,
            since_pos
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
        let etag = format!("{}", chrono::Utc::now().timestamp_millis());
        sqlx::query!(
            r#"
            UPDATE room_keys_versions
            SET auth_data = $3, etag = $4
            WHERE user_id = $1 AND version = $2 AND deleted = false
            "#,
            user_id,
            version,
            auth_data,
            etag
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn delete_room_keys_version(&self, user_id: &str, version: &str) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE room_keys_versions SET deleted = true
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
        // Update count + etag.
        let etag = format!("{}", chrono::Utc::now().timestamp_millis());
        sqlx::query!(
            r#"
            UPDATE room_keys_versions
            SET count = (
                SELECT COUNT(*) FROM room_keys_backup
                WHERE user_id = $1 AND version = $2
            ),
            etag = $3
            WHERE user_id = $1 AND version = $2
            "#,
            user_id,
            version,
            etag
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
        // Update count.
        sqlx::query!(
            r#"
            UPDATE room_keys_versions
            SET count = (
                SELECT COUNT(*) FROM room_keys_backup
                WHERE user_id = $1 AND version = $2
            )
            WHERE user_id = $1 AND version = $2
            "#,
            user_id,
            version
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
        // PostgreSQL partial unique indexes cannot be referenced by name in
        // ON CONFLICT clauses — we must use the DELETE + INSERT pattern or
        // a direct UPDATE + INSERT dance instead.
        let row = sqlx::query!(
            r#"
            INSERT INTO account_data (user_id, room_id, event_type, content, updated_at)
            VALUES ($1, $2, $3, $4, now())
            ON CONFLICT (user_id, event_type) WHERE room_id IS NULL
                DO UPDATE SET content = EXCLUDED.content, updated_at = now()
            RETURNING stream_pos
            "#,
            user_id,
            room_id as Option<&str>,
            event_type,
            content
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;

        if let Some(r) = row {
            return Ok(r.stream_pos);
        }

        // Per-room path (room_id IS NOT NULL).
        let row2 = sqlx::query!(
            r#"
            INSERT INTO account_data (user_id, room_id, event_type, content, updated_at)
            VALUES ($1, $2, $3, $4, now())
            ON CONFLICT (user_id, room_id, event_type) WHERE room_id IS NOT NULL
                DO UPDATE SET content = EXCLUDED.content, updated_at = now()
            RETURNING stream_pos
            "#,
            user_id,
            room_id as Option<&str>,
            event_type,
            content
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;

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
    ) -> Result<Vec<(Option<String>, String, Value)>> {
        let rows = sqlx::query!(
            r#"
            SELECT room_id, event_type, content
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
            .map(|r| (r.room_id, r.event_type, r.content))
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
        let row = sqlx::query!(
            r#"
            INSERT INTO receipts (room_id, user_id, receipt_type, event_id, ts)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (room_id, user_id, receipt_type)
                DO UPDATE SET event_id = EXCLUDED.event_id, ts = EXCLUDED.ts
            RETURNING stream_pos
            "#,
            room_id,
            user_id,
            receipt_type,
            event_id,
            ts
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.stream_pos)
    }

    async fn receipts_for_room(
        &self,
        room_id: &str,
    ) -> Result<Vec<(String, String, String, i64)>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_id, receipt_type, event_id, ts
            FROM receipts
            WHERE room_id = $1
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
    ) -> Result<Vec<(String, String, String, String, i64)>> {
        let rows = sqlx::query!(
            r#"
            SELECT room_id, user_id, receipt_type, event_id, ts
            FROM receipts
            WHERE stream_pos > $1
            ORDER BY stream_pos ASC
            "#,
            since_pos
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        Ok(rows
            .into_iter()
            .map(|r| (r.room_id, r.user_id, r.receipt_type, r.event_id, r.ts))
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
    // Push (E11 P1–P6)
    // -----------------------------------------------------------------------

    async fn upsert_pusher(&self, p: &Pusher) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO pushers
                (user_id, pushkey, app_id, app_display_name, device_display_name,
                 kind, lang, profile_tag, url, format, data)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (user_id, pushkey, app_id) DO UPDATE SET
                app_display_name    = EXCLUDED.app_display_name,
                device_display_name = EXCLUDED.device_display_name,
                kind                = EXCLUDED.kind,
                lang                = EXCLUDED.lang,
                profile_tag         = EXCLUDED.profile_tag,
                url                 = EXCLUDED.url,
                format              = EXCLUDED.format,
                data                = EXCLUDED.data
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
                   kind, lang, profile_tag, url, format, data
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
    // Admin (E11 AD1–AD6)
    // -----------------------------------------------------------------------

    async fn list_accounts(&self, from: i64, limit: i64) -> Result<Vec<Account>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_id, password_hash, is_admin, created_at, deactivated_at, displayname, avatar_url
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
        // Delete state first (FK to events).
        sqlx::query!("DELETE FROM room_current_state WHERE room_id = $1", room_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        // Delete events.
        sqlx::query!("DELETE FROM events WHERE room_id = $1", room_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
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
        let row = sqlx::query!(
            r#"
            INSERT INTO fed_outbound_queue (destination, kind, txn_id, payload)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
            destination,
            kind,
            txn_id,
            payload,
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
            SELECT id, destination, kind, txn_id, payload, attempts
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
        Ok(rows
            .into_iter()
            .map(|r| OutboundEntry {
                id: r.id,
                destination: r.destination,
                kind: r.kind,
                txn_id: r.txn_id,
                payload: r.payload,
                attempts: r.attempts,
            })
            .collect())
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
}
