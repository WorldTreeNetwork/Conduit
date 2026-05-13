//! PostgreSQL implementation of [`conduit::storage::Storage`].
//!
//! `PostgresStorage` wraps a `sqlx::PgPool` and implements every method of
//! the `Storage` trait using compile-time-checked `sqlx::query!` macros.
//! Requires `DATABASE_URL` to be set at build time for macro expansion.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;

use conduit::{
    Error, Result,
    event::Event,
    storage::{Account, Device, SigningKey, Storage, TokenOwner},
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
            SELECT user_id, password_hash, is_admin, created_at, deactivated_at
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
}
