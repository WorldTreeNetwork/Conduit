//! Storage abstraction.
//!
//! `conduit` doesn't bind to a particular database. Implement the
//! [`Storage`] trait on top of whatever you like — sqlite, rocksdb,
//! postgres, an in-memory map for tests — and pass it in at startup.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use crate::event::Event;
use crate::Result;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A registered local user account.
#[derive(Debug, Clone)]
pub struct Account {
    pub user_id: String,
    /// Argon2 / bcrypt hash; `None` means the account has no password
    /// (e.g. guest or SSO-only).
    pub password_hash: Option<String>,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    /// `Some` when the account has been deactivated.
    pub deactivated_at: Option<DateTime<Utc>>,
}

/// A client device registered to a user.
#[derive(Debug, Clone)]
pub struct Device {
    pub user_id: String,
    pub device_id: String,
    pub display_name: Option<String>,
    /// Unix-ms timestamp of last activity, if recorded.
    pub last_seen_ts: Option<i64>,
    pub last_seen_ip: Option<String>,
}

/// The (user_id, device_id) pair that owns an access token.
#[derive(Debug, Clone)]
pub struct TokenOwner {
    pub user_id: String,
    pub device_id: String,
}

/// A server signing key (ed25519 or similar).
#[derive(Debug, Clone)]
pub struct SigningKey {
    pub key_id: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    /// Unix-ms timestamp after which this key should not be used for
    /// signing new events.  `None` means no expiry declared.
    pub valid_until_ts: Option<i64>,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Storage trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait Storage: Send + Sync + 'static {
    // --- Events (unchanged) -------------------------------------------------

    async fn get_event(&self, event_id: &str) -> Result<Option<Event>>;
    async fn put_event(&self, event: &Event) -> Result<()>;
    async fn room_events(&self, room_id: &str) -> Result<Vec<Event>>;

    // --- Accounts -----------------------------------------------------------

    /// Create a new user account.  Fails if `user_id` already exists.
    async fn create_account(
        &self,
        user_id: &str,
        password_hash: Option<&str>,
    ) -> Result<()>;

    async fn get_account(&self, user_id: &str) -> Result<Option<Account>>;

    /// Mark the account as deactivated (soft-delete).
    async fn deactivate_account(&self, user_id: &str) -> Result<()>;

    async fn set_admin(&self, user_id: &str, is_admin: bool) -> Result<()>;

    // --- Devices ------------------------------------------------------------

    /// Insert or update a device record (upsert on (user_id, device_id)).
    async fn upsert_device(
        &self,
        user_id: &str,
        device_id: &str,
        display_name: Option<&str>,
    ) -> Result<()>;

    async fn get_device(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<Device>>;

    async fn list_devices_for_user(&self, user_id: &str) -> Result<Vec<Device>>;

    // --- Access tokens ------------------------------------------------------

    async fn insert_token(
        &self,
        token_hash: &str,
        user_id: &str,
        device_id: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()>;

    async fn lookup_token(&self, token_hash: &str) -> Result<Option<TokenOwner>>;

    async fn revoke_token(&self, token_hash: &str) -> Result<()>;

    // --- Server signing keys ------------------------------------------------

    async fn insert_signing_key(
        &self,
        key_id: &str,
        private_key: &[u8],
        public_key: &[u8],
        valid_until_ts: Option<i64>,
    ) -> Result<()>;

    /// The most-recently inserted signing key, if any.
    async fn current_signing_key(&self) -> Result<Option<SigningKey>>;

    /// All keys — current and retired-but-still-valid — suitable for
    /// verification of inbound federation events.
    async fn signing_keys_for_verification(&self) -> Result<Vec<SigningKey>>;

    /// Mark a signing key as retired by setting its `valid_until_ts`.
    ///
    /// After this, the key is no longer "current" (won't be returned by
    /// `current_signing_key` once a newer key exists) but stays in
    /// `signing_keys_for_verification` until callers filter by ts.
    async fn set_signing_key_expiry(&self, key_id: &str, valid_until_ts: i64) -> Result<()>;

    // --- Room current state -------------------------------------------------

    /// Upsert a (room_id, type, state_key) → event_id mapping.
    async fn set_state_entry(
        &self,
        room_id: &str,
        event_type: &str,
        state_key: &str,
        event_id: &str,
    ) -> Result<()>;

    /// Look up a single current-state event.
    async fn get_state_entry(
        &self,
        room_id: &str,
        event_type: &str,
        state_key: &str,
    ) -> Result<Option<Event>>;

    /// All current-state events for a room.
    async fn get_current_state(&self, room_id: &str) -> Result<Vec<Event>>;

    /// Paginated room timeline.
    ///
    /// `dir` is `'f'` (forward / chronological) or `'b'` (backward).
    /// `from` is an inclusive stream_position cursor (0 = start of room).
    /// Returns at most `limit` events ordered by stream_position in the
    /// requested direction, together with the next cursor (or `None` if
    /// the end has been reached).
    async fn room_events_paginated(
        &self,
        room_id: &str,
        dir: char,
        from: i64,
        limit: i64,
    ) -> Result<(Vec<Event>, Option<i64>)>;

    /// The highest stream_position for events in `room_id`, or `None` if the
    /// room has no events yet.
    async fn room_latest_stream_position(&self, room_id: &str) -> Result<Option<i64>>;
}

// ---------------------------------------------------------------------------
// MemoryStorage — in-memory backend for tests and demos.  Not durable.
// ---------------------------------------------------------------------------

/// An in-memory [`Storage`] for tests and demos. Not durable.
#[derive(Default)]
pub struct MemoryStorage {
    inner: RwLock<MemoryInner>,
}

#[derive(Default)]
struct MemoryInner {
    events: HashMap<String, Event>,
    accounts: HashMap<String, Account>,
    /// (user_id, device_id) → Device
    devices: HashMap<(String, String), Device>,
    /// token_hash → (user_id, device_id, expires_at)
    tokens: HashMap<String, (String, String, Option<DateTime<Utc>>)>,
    /// Ordered list of signing keys (push_back = newest).
    signing_keys: Vec<SigningKey>,
    /// (room_id, type, state_key) → event_id
    room_state: HashMap<(String, String, String), String>,
}

#[async_trait]
impl Storage for MemoryStorage {
    // --- Events -------------------------------------------------------------

    async fn get_event(&self, event_id: &str) -> Result<Option<Event>> {
        Ok(self.inner.read().await.events.get(event_id).cloned())
    }

    async fn put_event(&self, event: &Event) -> Result<()> {
        self.inner
            .write()
            .await
            .events
            .insert(event.event_id.clone(), event.clone());
        Ok(())
    }

    async fn room_events(&self, room_id: &str) -> Result<Vec<Event>> {
        Ok(self
            .inner
            .read()
            .await
            .events
            .values()
            .filter(|e| e.room_id == room_id)
            .cloned()
            .collect())
    }

    // --- Accounts -----------------------------------------------------------

    async fn create_account(
        &self,
        user_id: &str,
        password_hash: Option<&str>,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.accounts.contains_key(user_id) {
            return Err(crate::Error::Storage(format!(
                "account already exists: {user_id}"
            )));
        }
        inner.accounts.insert(
            user_id.to_owned(),
            Account {
                user_id: user_id.to_owned(),
                password_hash: password_hash.map(|s| s.to_owned()),
                is_admin: false,
                created_at: Utc::now(),
                deactivated_at: None,
            },
        );
        Ok(())
    }

    async fn get_account(&self, user_id: &str) -> Result<Option<Account>> {
        Ok(self.inner.read().await.accounts.get(user_id).cloned())
    }

    async fn deactivate_account(&self, user_id: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(acct) = inner.accounts.get_mut(user_id) {
            acct.deactivated_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn set_admin(&self, user_id: &str, is_admin: bool) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(acct) = inner.accounts.get_mut(user_id) {
            acct.is_admin = is_admin;
        }
        Ok(())
    }

    // --- Devices ------------------------------------------------------------

    async fn upsert_device(
        &self,
        user_id: &str,
        device_id: &str,
        display_name: Option<&str>,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        let key = (user_id.to_owned(), device_id.to_owned());
        let entry = inner.devices.entry(key).or_insert_with(|| Device {
            user_id: user_id.to_owned(),
            device_id: device_id.to_owned(),
            display_name: None,
            last_seen_ts: None,
            last_seen_ip: None,
        });
        entry.display_name = display_name.map(|s| s.to_owned());
        Ok(())
    }

    async fn get_device(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<Device>> {
        let key = (user_id.to_owned(), device_id.to_owned());
        Ok(self.inner.read().await.devices.get(&key).cloned())
    }

    async fn list_devices_for_user(&self, user_id: &str) -> Result<Vec<Device>> {
        Ok(self
            .inner
            .read()
            .await
            .devices
            .values()
            .filter(|d| d.user_id == user_id)
            .cloned()
            .collect())
    }

    // --- Access tokens ------------------------------------------------------

    async fn insert_token(
        &self,
        token_hash: &str,
        user_id: &str,
        device_id: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        self.inner.write().await.tokens.insert(
            token_hash.to_owned(),
            (user_id.to_owned(), device_id.to_owned(), expires_at),
        );
        Ok(())
    }

    async fn lookup_token(&self, token_hash: &str) -> Result<Option<TokenOwner>> {
        let inner = self.inner.read().await;
        let Some((user_id, device_id, expires_at)) = inner.tokens.get(token_hash)
        else {
            return Ok(None);
        };
        // Treat expired tokens as absent.
        if let Some(exp) = expires_at {
            if Utc::now() > *exp {
                return Ok(None);
            }
        }
        Ok(Some(TokenOwner {
            user_id: user_id.clone(),
            device_id: device_id.clone(),
        }))
    }

    async fn revoke_token(&self, token_hash: &str) -> Result<()> {
        self.inner.write().await.tokens.remove(token_hash);
        Ok(())
    }

    // --- Server signing keys ------------------------------------------------

    async fn insert_signing_key(
        &self,
        key_id: &str,
        private_key: &[u8],
        public_key: &[u8],
        valid_until_ts: Option<i64>,
    ) -> Result<()> {
        let key = SigningKey {
            key_id: key_id.to_owned(),
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            valid_until_ts,
            created_at: Utc::now(),
        };
        self.inner.write().await.signing_keys.push(key);
        Ok(())
    }

    async fn current_signing_key(&self) -> Result<Option<SigningKey>> {
        Ok(self.inner.read().await.signing_keys.last().cloned())
    }

    async fn signing_keys_for_verification(&self) -> Result<Vec<SigningKey>> {
        // Return all keys.  Callers filter by valid_until_ts as needed.
        Ok(self.inner.read().await.signing_keys.clone())
    }

    async fn set_signing_key_expiry(&self, key_id: &str, valid_until_ts: i64) -> Result<()> {
        let mut inner = self.inner.write().await;
        for key in inner.signing_keys.iter_mut() {
            if key.key_id == key_id {
                key.valid_until_ts = Some(valid_until_ts);
                return Ok(());
            }
        }
        Ok(())
    }

    // --- Room current state -------------------------------------------------

    async fn set_state_entry(
        &self,
        room_id: &str,
        event_type: &str,
        state_key: &str,
        event_id: &str,
    ) -> Result<()> {
        let map_key = (
            room_id.to_owned(),
            event_type.to_owned(),
            state_key.to_owned(),
        );
        self.inner
            .write()
            .await
            .room_state
            .insert(map_key, event_id.to_owned());
        Ok(())
    }

    async fn get_state_entry(
        &self,
        room_id: &str,
        event_type: &str,
        state_key: &str,
    ) -> Result<Option<Event>> {
        let inner = self.inner.read().await;
        let map_key = (
            room_id.to_owned(),
            event_type.to_owned(),
            state_key.to_owned(),
        );
        let Some(event_id) = inner.room_state.get(&map_key) else {
            return Ok(None);
        };
        Ok(inner.events.get(event_id).cloned())
    }

    async fn get_current_state(&self, room_id: &str) -> Result<Vec<Event>> {
        let inner = self.inner.read().await;
        let event_ids: Vec<String> = inner
            .room_state
            .iter()
            .filter(|((rid, _, _), _)| rid == room_id)
            .map(|(_, eid)| eid.clone())
            .collect();
        let events = event_ids
            .iter()
            .filter_map(|eid| inner.events.get(eid).cloned())
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
        let inner = self.inner.read().await;
        // MemoryStorage doesn't have stream_position; use insertion order via
        // the events map. We simulate stream_position as the index in a sorted
        // Vec of room events.
        let mut room_evs: Vec<Event> = inner
            .events
            .values()
            .filter(|e| e.room_id == room_id)
            .cloned()
            .collect();
        // Stable sort by depth as a proxy for stream_position in memory tests.
        room_evs.sort_by_key(|e| e.depth);

        let total = room_evs.len() as i64;
        let (slice, next): (Vec<Event>, Option<i64>) = match dir {
            'b' => {
                // backwards from `from` (inclusive)
                let end = (from + 1).min(total) as usize;
                let start = (end as i64 - limit).max(0) as usize;
                let chunk: Vec<Event> = room_evs[start..end]
                    .iter()
                    .rev()
                    .cloned()
                    .collect();
                let next = if start > 0 { Some(start as i64 - 1) } else { None };
                (chunk, next)
            }
            _ => {
                // forwards from `from` (inclusive)
                let start = from.max(0) as usize;
                let end = (start as i64 + limit).min(total) as usize;
                let chunk: Vec<Event> = room_evs[start..end].to_vec();
                let next = if (end as i64) < total { Some(end as i64) } else { None };
                (chunk, next)
            }
        };
        Ok((slice, next))
    }

    async fn room_latest_stream_position(&self, room_id: &str) -> Result<Option<i64>> {
        let inner = self.inner.read().await;
        let max_depth = inner
            .events
            .values()
            .filter(|e| e.room_id == room_id)
            .map(|e| e.depth)
            .max();
        // In MemoryStorage depth serves as stream_position proxy.
        Ok(max_depth)
    }
}

// ---------------------------------------------------------------------------
// Tests for MemoryStorage
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_signing_key_expiry_updates_existing() {
        let store = MemoryStorage::default();

        store
            .insert_signing_key("ed25519:abc", b"priv", b"pub", None)
            .await
            .unwrap();

        // Confirm no expiry yet.
        let keys = store.signing_keys_for_verification().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].valid_until_ts.is_none());

        store
            .set_signing_key_expiry("ed25519:abc", 12345)
            .await
            .unwrap();

        let keys = store.signing_keys_for_verification().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].valid_until_ts, Some(12345));
    }
}
