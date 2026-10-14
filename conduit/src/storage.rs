//! Storage abstraction.
//!
//! `conduit` doesn't bind to a particular database. Implement the
//! [`Storage`] trait on top of whatever you like — sqlite, rocksdb,
//! postgres, an in-memory map for tests — and pass it in at startup.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::event::Event;
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Media domain types (E07)
// ---------------------------------------------------------------------------

/// Metadata for a locally-uploaded or remotely-cached media item.
#[derive(Debug, Clone)]
pub struct MediaMetadata {
    pub media_id: String,
    pub origin_server: String,
    pub uploader: Option<String>,
    pub content_type: Option<String>,
    pub upload_name: Option<String>,
    pub file_size: i64,
    pub sha256: String,
    pub storage_path: String,
    pub uploaded_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
}

/// Metadata for a cached thumbnail.
#[derive(Debug, Clone)]
pub struct ThumbnailMetadata {
    pub media_id: String,
    pub origin_server: String,
    pub width: i32,
    pub height: i32,
    pub method: String,
    pub content_type: String,
    pub file_size: i64,
    pub storage_path: String,
}

/// An `mxc://` URI reserved by `POST /_matrix/media/v1/create` whose
/// content has not been uploaded yet.
#[derive(Debug, Clone)]
pub struct PendingMedia {
    pub media_id: String,
    pub origin_server: String,
    pub creator: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Outcome of reserving a pending media ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingMediaCreate {
    Created,
    /// The creator already holds the maximum number of unexpired
    /// reservations; the earliest one expires at `earliest_expiry`.
    LimitExceeded { earliest_expiry: Option<DateTime<Utc>> },
}

/// Outcome of attaching content to a pending media ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingMediaCompletion {
    Completed,
    /// Never created, or the reservation expired.
    NotFound,
    /// Reserved by a different user.
    Forbidden,
    /// Content already exists for this ID.
    AlreadyUploaded,
}

/// A cached URL preview (OpenGraph object) generated at `fetched_at`.
#[derive(Debug, Clone)]
pub struct UrlPreview {
    pub url: String,
    pub fetched_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub og: Value,
}

// ---------------------------------------------------------------------------
// E2EE domain types
// ---------------------------------------------------------------------------

/// A pending to-device message from the queue.
#[derive(Debug, Clone)]
pub struct ToDeviceMessage {
    pub id: i64,
    pub sender: String,
    pub event_type: String,
    pub content: Value,
}

/// One entry in the durable outbound federation queue (conduit-5n3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundEntry {
    pub id: i64,
    pub destination: String,
    /// `"transaction"` for a PDU+EDU batch, `"to_device"` for federated
    /// to-device delivery.
    pub kind: String,
    pub txn_id: String,
    pub payload: Value,
    pub attempts: i32,
}

/// A row that hit `status='dead'` — exposed to admin for inspection / replay
/// (conduit-4l9).
#[derive(Debug, Clone)]
pub struct DlqEntry {
    pub id: i64,
    pub destination: String,
    pub kind: String,
    pub txn_id: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A room key backup version record.
#[derive(Debug, Clone)]
pub struct RoomKeyVersion {
    pub version: String,
    pub algorithm: String,
    pub auth_data: Value,
    pub count: i64,
    pub etag: String,
}

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
    /// Display name set via `PUT /profile/{userId}/displayname`.
    pub displayname: Option<String>,
    /// Avatar URL set via `PUT /profile/{userId}/avatar_url`.
    pub avatar_url: Option<String>,
    /// Guest accounts (`POST /register?kind=guest`) may only use the
    /// guest subset of the client-server API.
    pub is_guest: bool,
}

/// A client device registered to a user.
#[derive(Debug, Clone)]
pub struct Device {
    pub user_id: String,
    pub device_id: String,
    pub display_name: Option<String>,
    /// Session epoch.  Capability tokens carry the epoch they were
    /// minted at; bumping this row invalidates every one of them
    /// without a denylist.  See [`crate::agency`].
    pub epoch: i64,
    /// Unix-ms timestamp of last activity, if recorded.
    pub last_seen_ts: Option<i64>,
    pub last_seen_ip: Option<String>,
    /// User agent of the most recent authenticated request.
    pub last_seen_user_agent: Option<String>,
}

/// A stored refresh token (only its hash is kept).
#[derive(Debug, Clone)]
pub struct RefreshTokenRecord {
    pub user_id: String,
    pub device_id: String,
    /// Device epoch the token was issued at; a later epoch (logout,
    /// re-login with the same device ID) invalidates it.
    pub epoch: i64,
    /// The refresh token this one was issued in exchange for.  It stays
    /// usable until this token is used, then it is revoked.
    pub parent_hash: Option<String>,
}

/// The (user_id, device_id) pair that owns an access token.
#[derive(Debug, Clone)]
pub struct TokenOwner {
    pub user_id: String,
    pub device_id: String,
}

/// Collision-free domain identity for a retried client request or federation EDU.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionKey {
    pub scope: String,
    pub owner: String,
    pub endpoint: String,
    pub txn_id: String,
}

/// Lifetime guard for a single transaction identity. Cancellation releases it.
/// The kernel exposes no transport or database types through this guard.
pub trait TransactionGuard: Send {}

impl TransactionGuard for tokio::sync::OwnedMutexGuard<()> {}

impl TransactionKey {
    pub fn client(user: &str, device: &str, endpoint: &[&str], txn_id: &str) -> Self {
        Self {
            scope: "client".into(),
            owner: serde_json::json!([user, device]).to_string(),
            endpoint: serde_json::json!(endpoint).to_string(),
            txn_id: txn_id.to_owned(),
        }
    }

    pub fn federation(origin: &str, message_id: &str) -> Self {
        Self {
            scope: "federation".into(),
            owner: origin.to_owned(),
            endpoint: "m.direct_to_device".into(),
            txn_id: message_id.to_owned(),
        }
    }

    pub fn federation_request(origin: &str, txn_id: &str) -> Self {
        Self { scope: "federation_request".into(), owner: origin.into(),
            endpoint: "send".into(), txn_id: txn_id.into() }
    }
}

/// A local delivery; `target_device == "*"` is expanded atomically on commit.
#[derive(Debug, Clone)]
pub struct ToDeviceDelivery {
    pub target_user: String,
    pub target_device: String,
    pub sender: String,
    pub event_type: String,
    pub content: Value,
}

/// An already-framed standard federation transaction for the durable outbox.
#[derive(Debug, Clone)]
pub struct OutboundDelivery {
    pub destination: String,
    pub txn_id: String,
    pub payload: Value,
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
// Push domain types (E11 P1–P6)
// ---------------------------------------------------------------------------

/// A registered push notification destination for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pusher {
    pub user_id: String,
    pub pushkey: String,
    pub app_id: String,
    pub app_display_name: Option<String>,
    pub device_display_name: Option<String>,
    pub kind: String,
    pub lang: String,
    pub profile_tag: Option<String>,
    pub url: Option<String>,
    pub format: Option<String>,
    pub data: Value,
}

/// A push rule stored for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRule {
    pub user_id: String,
    pub scope: String,
    pub kind: String,
    pub rule_id: String,
    pub priority: i32,
    pub enabled: bool,
    pub conditions: Value,
    pub actions: Value,
    pub pattern: Option<String>,
    pub is_default: bool,
}

// ---------------------------------------------------------------------------
// Admin domain types (E11 AD6)
// ---------------------------------------------------------------------------

/// An admin audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub admin_user: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Value,
    pub ts: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Storage trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait Storage: Send + Sync + 'static {
    async fn put_filter(&self, user: &str, id: &str, definition: &Value) -> Result<()>;
    async fn get_filter(&self, user: &str, id: &str) -> Result<Option<Value>>;
    async fn lock_transaction(&self, key: &TransactionKey) -> Result<Box<dyn TransactionGuard>>;

    async fn transaction_original(&self, key: &TransactionKey) -> Result<Option<Value>>;

    /// Insert the first request if absent; return that immutable original.
    async fn transaction_request(&self, key: &TransactionKey, request: &Value) -> Result<Value>;

    /// Complete an operation without replacing an already committed result.
    async fn finish_transaction(&self, key: &TransactionKey, result: &Value) -> Result<Value>;
    /// Original successful result, scoped to a device/endpoint or origin/EDU ID.
    async fn transaction_result(&self, key: &TransactionKey) -> Result<Option<Value>>;

    /// Atomically persist a non-state event and its transaction result.
    /// Returns the original event ID and whether this call inserted it.
    async fn put_event_once(&self, key: &TransactionKey, event: &Event) -> Result<(String, bool)>;

    /// Atomically record deduplication, local deliveries, and remote outbox rows.
    /// Returns false for a successful request that was already committed.
    async fn deliver_to_device_once(&self, key: &TransactionKey,
        local: &[ToDeviceDelivery], remote: &[OutboundDelivery]) -> Result<bool>;
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

    /// The device's current session epoch, or `None` when the device
    /// row does not exist (which fails every token for it).
    async fn device_epoch(&self, user_id: &str, device_id: &str) -> Result<Option<i64>>;

    /// Advance one device's epoch, returning the new value.  This is
    /// logout and device revocation: outstanding capability tokens for
    /// that device stop verifying immediately.
    async fn bump_device_epoch(&self, user_id: &str, device_id: &str) -> Result<i64>;

    /// Advance every device epoch for a user.  This is `logout_all`.
    async fn bump_all_device_epochs(&self, user_id: &str) -> Result<()>;

    // --- IdentiKey identity links -------------------------------------------

    /// Link an identikey-auth fingerprint to a local MXID.  Callers go
    /// through [`crate::identity`], which enforces the policy that an
    /// unlinked fingerprint never creates an account.
    async fn link_identikey(&self, fingerprint: &str, user_id: &str) -> Result<()>;

    /// The MXID linked to a fingerprint, if any.
    async fn user_for_identikey(&self, fingerprint: &str) -> Result<Option<String>>;

    // --- Biscuit minter key -------------------------------------------------

    /// Persist the Biscuit minter key.  Stored the way a signing key is
    /// stored — raw private bytes — because a key we sign with cannot
    /// be a digest.  It is deliberately not a Matrix server signing key
    /// and must never be published as one.
    async fn insert_minter_key(
        &self,
        key_id: &str,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<()>;

    /// The newest minter key, or `None` before first boot.
    async fn current_minter_key(&self) -> Result<Option<SigningKey>>;

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

    /// Rooms where the current membership of `user_id` is join.
    async fn joined_rooms(&self, user_id: &str) -> Result<Vec<String>>;

    /// Current memberships across rooms, including invitations and departures.
    async fn current_memberships(&self, user_id: &str) -> Result<Vec<Event>> {
        let mut offset = 0;
        let mut memberships = Vec::new();
        loop {
            let rooms = self.list_rooms(offset, 1000).await?;
            for room in &rooms {
                if let Some(event) = self.get_state_entry(room, "m.room.member", user_id).await? { memberships.push(event); }
            }
            if rooms.len() < 1000 { break; }
            offset += rooms.len() as i64;
        }
        Ok(memberships)
    }


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

    /// Every `m.room.member` event whose state_key is `user_id` in
    /// `room_id`, paired with its stream_position, ordered ascending.
    ///
    /// This is the one walk history visibility needs: it is how
    /// [`crate::auth::user_event_position`] decides where a user stood
    /// relative to an event.  Federation backfill uses the same walk
    /// over any member of the requesting origin.
    async fn member_events_for_user(
        &self,
        room_id: &str,
        user_id: &str,
    ) -> Result<Vec<(i64, Event)>>;

    /// Every `m.room.member` event in `room_id` whose state_key belongs
    /// to `server_name`, paired with its stream_position, ordered
    /// ascending.  Federation backfill's half of the same walk.
    async fn member_events_for_server(
        &self,
        room_id: &str,
        server_name: &str,
    ) -> Result<Vec<(i64, Event)>>;

    /// Stream positions for a batch of event ids.  One query per page
    /// of timeline, rather than one per event.
    async fn event_stream_positions(&self, event_ids: &[String]) -> Result<HashMap<String, i64>>;

    /// All events across all rooms whose stream_position is strictly greater
    /// than `since`, ordered by stream_position ascending, up to `limit`.
    ///
    /// Used by the `/sync` incremental path.
    async fn events_since(&self, since: i64, limit: i64) -> Result<Vec<Event>>;

    /// The maximum stream_position across all rooms, or 0 if there are no events.
    async fn global_max_stream_position(&self) -> Result<i64>;

    // --- Device keys (E2EE mrm.1, mrm.2) ------------------------------------

    /// Upsert the full device keys JSON for (user_id, device_id).
    async fn upsert_device_keys(&self, user_id: &str, device_id: &str, keys: &Value) -> Result<()>;

    async fn get_device_keys(&self, user_id: &str, device_id: &str) -> Result<Option<Value>>;

    /// All devices for a user: device_id → keys JSON.
    async fn get_device_keys_for_user(&self, user_id: &str) -> Result<HashMap<String, Value>>;

    /// Remove the device-keys entry for a (user_id, device_id) tuple.
    /// Idempotent: a missing row is a no-op (returns Ok).
    /// Used when a remote `m.device_list_update` EDU carries `deleted=true`
    /// (E10 follow-up conduit-ub5).
    async fn delete_device_keys(&self, user_id: &str, device_id: &str) -> Result<()>;

    // --- One-time keys (mrm.1, mrm.3) ----------------------------------------

    /// Insert a batch of OTKs. Each tuple is (key_id, algorithm, key_json).
    async fn insert_one_time_keys(
        &self,
        user_id: &str,
        device_id: &str,
        keys: Vec<(String, String, Value)>,
    ) -> Result<()>;

    /// Atomically claim one OTK for the given algorithm.
    /// Returns `None` if no key is available (fallback should be consulted next).
    async fn claim_one_time_key(
        &self,
        user_id: &str,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<(String, Value)>>;

    /// Count available OTKs per algorithm for a device.
    async fn one_time_key_counts(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<HashMap<String, i64>>;

    // --- Fallback keys (mrm.5) -----------------------------------------------

    /// Upsert the single fallback key for (user_id, device_id, algorithm).
    async fn upsert_fallback_key(
        &self,
        user_id: &str,
        device_id: &str,
        algorithm: &str,
        key_id: &str,
        key_json: &Value,
    ) -> Result<()>;

    /// Claim the fallback key for a device algorithm (marks it used, returns it).
    async fn claim_fallback_key(
        &self,
        user_id: &str,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<(String, Value)>>;

    /// Algorithms whose current fallback key has not been claimed.
    async fn unused_fallback_key_types(&self, user_id: &str, device_id: &str) -> Result<Vec<String>>;

    // --- Cross-signing (mrm.8, mrm.9) ----------------------------------------

    async fn upsert_cross_signing_key(
        &self,
        user_id: &str,
        key_type: &str,
        key_json: &Value,
    ) -> Result<()>;

    /// Returns map: key_type → key_json.
    async fn get_cross_signing_keys(&self, user_id: &str) -> Result<HashMap<String, Value>>;

    async fn insert_cross_signing_signature(
        &self,
        signer_user: &str,
        signer_key: &str,
        target_user: &str,
        target_key: &str,
        signature: &str,
    ) -> Result<()>;

    // --- To-device queue (mrm.6, mrm.7, mrm.10) ------------------------------

    /// Enqueue a to-device message. Returns the assigned queue id.
    async fn enqueue_to_device(
        &self,
        target_user: &str,
        target_device: &str,
        sender: &str,
        event_type: &str,
        content: &Value,
    ) -> Result<i64>;

    /// Drain up to `limit` messages for a device with id > since_id.
    async fn drain_to_device(
        &self,
        target_user: &str,
        target_device: &str,
        since_id: i64,
        limit: i64,
    ) -> Result<Vec<ToDeviceMessage>>;

    /// Delete all messages for a device with id <= up_to_id.
    async fn delete_to_device_before(
        &self,
        target_user: &str,
        target_device: &str,
        up_to_id: i64,
    ) -> Result<()>;

    // --- Device list changes (mrm.4, mrm.11, mrm.12) -------------------------

    /// Record that user_id's device list changed. Returns the new stream position.
    async fn record_device_list_change(&self, user_id: &str) -> Result<i64>;

    /// Return distinct user_ids that have changed since stream position `since_pos`.
    async fn device_list_changes_since(&self, since_pos: i64) -> Result<Vec<String>> {
        self.device_list_changes_between(since_pos, i64::MAX).await
    }

    /// Device-list changes bounded by the position captured for this batch.
    async fn device_list_changes_between(&self, since_pos: i64, through_pos: i64) -> Result<Vec<String>>;

    /// The maximum device list stream position, or 0 if none.
    async fn device_list_max_position(&self) -> Result<i64>;

    // --- Room key backup (mrm.13) ---------------------------------------------

    /// Create a new backup version. Returns the etag.
    async fn create_room_keys_version(
        &self,
        user_id: &str,
        version: &str,
        algorithm: &str,
        auth_data: &Value,
    ) -> Result<String>;

    /// Get a backup version. If version is None, returns the latest non-deleted one.
    async fn get_room_keys_version(
        &self,
        user_id: &str,
        version: Option<&str>,
    ) -> Result<Option<RoomKeyVersion>>;

    /// Update the auth_data of a backup version.
    async fn update_room_keys_version(
        &self,
        user_id: &str,
        version: &str,
        auth_data: &Value,
    ) -> Result<()>;

    /// Mark a backup version as deleted.
    async fn delete_room_keys_version(&self, user_id: &str, version: &str) -> Result<()>;

    /// Upsert a single room key into a backup.
    async fn upsert_room_key(
        &self,
        user_id: &str,
        version: &str,
        room_id: &str,
        session_id: &str,
        key_data: &Value,
    ) -> Result<()>;

    /// Get room keys. room_id=None means all rooms; session_id=None means all sessions.
    /// Returns nested map: room_id → session_id → key_data.
    async fn get_room_keys(
        &self,
        user_id: &str,
        version: &str,
        room_id: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<HashMap<String, HashMap<String, Value>>>;

    /// Delete room keys. Returns count deleted.
    async fn delete_room_keys(
        &self,
        user_id: &str,
        version: &str,
        room_id: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<i64>;

    // --- Profile (1mo.1, 1mo.2) ----------------------------------------------

    async fn set_displayname(&self, user_id: &str, displayname: Option<&str>) -> Result<()>;
    async fn set_avatar_url(&self, user_id: &str, avatar_url: Option<&str>) -> Result<()>;

    // --- Account data (1mo.3, 1mo.4) -----------------------------------------

    /// Upsert account data. Returns the new stream_pos.
    async fn set_account_data(
        &self,
        user_id: &str,
        room_id: Option<&str>,
        event_type: &str,
        content: &Value,
    ) -> Result<i64>;

    async fn get_account_data(
        &self,
        user_id: &str,
        room_id: Option<&str>,
        event_type: &str,
    ) -> Result<Option<Value>>;

    /// All account data (global + per-room) changed since `since_pos`.
    /// Returns `(room_id, event_type, content, stream_pos)`; global room IDs are `None`.
    async fn account_data_since(
        &self,
        user_id: &str,
        since_pos: i64,
    ) -> Result<Vec<(Option<String>, String, Value, i64)>>;

    // --- Media (E07) ---------------------------------------------------------

    async fn insert_media(&self, m: &MediaMetadata) -> Result<()>;
    async fn get_media(&self, media_id: &str, origin_server: &str) -> Result<Option<MediaMetadata>>;
    async fn touch_media_access(&self, media_id: &str, origin_server: &str) -> Result<()>;
    async fn delete_media(&self, media_id: &str, origin_server: &str) -> Result<()>;
    async fn list_remote_media_older_than(&self, ts: DateTime<Utc>) -> Result<Vec<MediaMetadata>>;

    async fn insert_thumbnail(&self, t: &ThumbnailMetadata) -> Result<()>;
    async fn get_thumbnail(
        &self,
        media_id: &str,
        origin_server: &str,
        width: i32,
        height: i32,
        method: &str,
    ) -> Result<Option<ThumbnailMetadata>>;

    // --- Media lane (conduit-y99.21): async upload, freeze, previews ------

    /// Reserve `p` unless its creator already holds `max_pending`
    /// unexpired reservations. Expired reservations of the creator are
    /// discarded first. Atomic per creator.
    async fn create_pending_media(&self, p: &PendingMedia, max_pending: i64) -> Result<PendingMediaCreate>;
    /// The unexpired-or-not reservation for an ID, if one exists.
    async fn get_pending_media(&self, media_id: &str, origin_server: &str) -> Result<Option<PendingMedia>>;
    /// Atomically consume the reservation for `m` (checking creator and
    /// expiry against `now`) and insert `m`.
    async fn complete_pending_media(
        &self,
        m: &MediaMetadata,
        uploader: &str,
        now: DateTime<Utc>,
    ) -> Result<PendingMediaCompletion>;
    /// Whether the deprecated unauthenticated endpoints may serve this
    /// media (stored before the freeze). False for unknown media.
    async fn media_unauthenticated_access(&self, media_id: &str, origin_server: &str) -> Result<bool>;
    async fn set_media_unauthenticated_access(&self, media_id: &str, origin_server: &str, allowed: bool) -> Result<()>;
    /// Whether any media or thumbnail row still references a
    /// content-addressed blob path (blobs are deduplicated by sha256).
    async fn media_storage_path_in_use(&self, storage_path: &str) -> Result<bool>;
    async fn insert_url_preview(&self, p: &UrlPreview) -> Result<()>;
    /// Newest cached preview for `url`, restricted to previews fetched at
    /// or before `fetched_at_or_before` when given.
    async fn latest_url_preview(
        &self,
        url: &str,
        fetched_at_or_before: Option<DateTime<Utc>>,
    ) -> Result<Option<UrlPreview>>;

    // --- Receipts (1mo.6) ----------------------------------------------------

    /// Upsert a read receipt. Returns the new stream_pos.
    async fn set_receipt(
        &self,
        room_id: &str,
        user_id: &str,
        receipt_type: &str,
        event_id: &str,
        ts: i64,
    ) -> Result<i64>;

    /// All receipts for a room (current snapshot, any type).
    /// Returns `(user_id, receipt_type, event_id, ts)`.
    async fn receipts_for_room(
        &self,
        room_id: &str,
    ) -> Result<Vec<(String, String, String, i64)>>;

    /// Receipts whose stream_pos is strictly greater than `since_pos`.
    /// Returns `(room_id, user_id, receipt_type, event_id, ts, stream_pos)`.
    async fn receipts_since(
        &self,
        since_pos: i64,
    ) -> Result<Vec<(String, String, String, String, i64, i64)>>;

    // --- Push (E11 P1–P6) -----------------------------------------------------

    /// Upsert a pusher.
    async fn upsert_pusher(&self, pusher: &Pusher) -> Result<()>;
    /// Delete a pusher by (user_id, pushkey, app_id).
    async fn delete_pusher(&self, user_id: &str, pushkey: &str, app_id: &str) -> Result<()>;
    /// List all pushers for a user.
    async fn list_pushers(&self, user_id: &str) -> Result<Vec<Pusher>>;

    /// Upsert a push rule.
    async fn upsert_push_rule(&self, rule: &PushRule) -> Result<()>;
    /// Delete a push rule.
    async fn delete_push_rule(
        &self,
        user_id: &str,
        scope: &str,
        kind: &str,
        rule_id: &str,
    ) -> Result<()>;
    /// List all push rules for a user (across all scopes/kinds).
    async fn list_push_rules(&self, user_id: &str) -> Result<Vec<PushRule>>;
    /// Enable/disable a push rule.
    async fn set_push_rule_enabled(
        &self,
        user_id: &str,
        scope: &str,
        kind: &str,
        rule_id: &str,
        enabled: bool,
    ) -> Result<()>;
    /// Update a push rule's actions.
    async fn set_push_rule_actions(
        &self,
        user_id: &str,
        scope: &str,
        kind: &str,
        rule_id: &str,
        actions: Value,
    ) -> Result<()>;
    /// Get a single push rule.
    async fn get_push_rule(
        &self,
        user_id: &str,
        scope: &str,
        kind: &str,
        rule_id: &str,
    ) -> Result<Option<PushRule>>;

    // --- Admin (E11 AD1–AD6) -------------------------------------------------

    /// List all accounts, paginated. Returns (user_id, is_admin, deactivated_at, created_at).
    async fn list_accounts(&self, from: i64, limit: i64) -> Result<Vec<Account>>;

    /// Set password hash for an account.
    async fn set_password_hash(&self, user_id: &str, password_hash: &str) -> Result<()>;

    /// Append an admin audit log entry.
    async fn append_audit_log(
        &self,
        admin_user: &str,
        action: &str,
        target: Option<&str>,
        detail: &Value,
    ) -> Result<()>;

    /// Paginated audit log. Returns entries ordered by ts desc.
    async fn list_audit_log(&self, from: i64, limit: i64) -> Result<Vec<AuditEntry>>;

    /// Purge all events and state for a room (admin destructive op).
    async fn purge_room(&self, room_id: &str) -> Result<()>;

    /// List all rooms (distinct room_ids from events).
    async fn list_rooms(&self, from: i64, limit: i64) -> Result<Vec<String>>;

    /// List all local media (paginated).
    async fn list_media(&self, from: i64, limit: i64) -> Result<Vec<MediaMetadata>>;

    // --- Outbound federation queue (conduit-5n3) -----------------------------

    /// Insert a new pending entry. Returns the assigned id.
    async fn enqueue_outbound(
        &self,
        destination: &str,
        kind: &str,
        txn_id: &str,
        payload: &Value,
    ) -> Result<i64>;

    /// Distinct destinations that have at least one pending entry — used
    /// on boot to know which per-destination workers to spawn.
    async fn outbound_destinations_with_pending(&self) -> Result<Vec<String>>;

    /// The next pending entries for `destination` whose `next_attempt_at`
    /// is in the past (i.e., ready to send now), oldest first. Caller is
    /// the single worker for the destination — no row-level locking
    /// required since per-destination workers don't compete.
    async fn next_pending_outbound(
        &self,
        destination: &str,
        limit: i64,
    ) -> Result<Vec<OutboundEntry>>;

    async fn mark_outbound_sent(&self, id: i64) -> Result<()>;

    /// Record a failed attempt. `attempts` and `next_attempt_at_ms` are
    /// computed by the caller (worker) using its own backoff policy so
    /// the Storage trait remains backoff-policy-agnostic.
    async fn mark_outbound_failed(
        &self,
        id: i64,
        attempts: i32,
        next_attempt_at_ms: i64,
        last_error: &str,
    ) -> Result<()>;

    async fn mark_outbound_dead(&self, id: i64, last_error: &str) -> Result<()>;

    /// Smallest `next_attempt_at` (as ms since epoch) among pending rows for
    /// `destination`, including rows scheduled in the future. Workers use
    /// this to sleep precisely until the next retry instead of polling.
    async fn outbound_next_eta_ms(
        &self,
        destination: &str,
    ) -> Result<Option<i64>>;

    /// Delete sent rows older than `sent_cutoff_ms` and (optionally) dead
    /// rows older than `dead_cutoff_ms`. Returns the total number of rows
    /// removed (conduit-cgl).
    async fn gc_outbound_queue(
        &self,
        sent_cutoff_ms: i64,
        dead_cutoff_ms: Option<i64>,
    ) -> Result<i64>;

    /// List dead-lettered rows, paginated by created_at desc (conduit-4l9).
    async fn list_outbound_dlq(&self, from: i64, limit: i64) -> Result<Vec<DlqEntry>>;

    /// Reset a dead row back to pending with attempts=0 and
    /// next_attempt_at=now. Returns true if a matching row was found.
    async fn replay_outbound_dlq(&self, id: i64) -> Result<bool>;

    /// Permanently delete a dead row. Returns true if it existed.
    async fn purge_outbound_dlq(&self, id: i64) -> Result<bool>;

    // --- Room aliases (conduit-v0y) -----------------------------------------

    /// Create an alias pointing at `room_id`. Fails if the alias already
    /// exists (regardless of which room it points at).
    async fn upsert_alias(&self, alias: &str, room_id: &str, creator: &str)
        -> Result<()>;

    /// Resolve an alias → room_id.
    async fn get_room_for_alias(&self, alias: &str) -> Result<Option<String>>;

    /// Remove an alias (idempotent — missing alias is Ok).
    async fn delete_alias(&self, alias: &str) -> Result<()>;

    /// List every alias that currently points at `room_id`.
    async fn list_aliases_for_room(&self, room_id: &str) -> Result<Vec<String>>;

    // --- Device list broadcast performance (conduit-e0e) --------------------

    /// Return all remote servers that share a room with `user_id` via the
    /// member state. This is an O(1) lookup backed by a materialized view
    /// in the Postgres backend, or falls back to the O(rooms × members)
    /// walk in the default implementation.
    async fn get_remote_servers_for_user(&self, user_id: &str, server_name: &str) -> Result<Vec<String>>;

    // --- Published room directory & user directory (conduit-y99.20) --------

    /// Publish (`true`) or unpublish a room in the server's main room
    /// directory (`PUT /directory/list/room/{roomId}`, `createRoom`
    /// with `visibility: public`). Idempotent.
    async fn set_room_published(&self, room_id: &str, published: bool) -> Result<()>;

    /// Whether the room is published in the main room directory.
    async fn is_room_published(&self, room_id: &str) -> Result<bool>;

    /// Publish or unpublish a room in an application service's
    /// third-party network directory
    /// (`PUT /directory/list/appservice/{networkId}/{roomId}`).
    async fn set_appservice_room_published(
        &self,
        appservice_id: &str,
        network_id: &str,
        room_id: &str,
        published: bool,
    ) -> Result<()>;

    /// Room IDs listed in the given directory scope, deduplicated, in
    /// no particular order (the handler sorts).
    async fn published_rooms(&self, scope: &DirectoryScope) -> Result<Vec<String>>;

    /// The creator of an alias binding, if the alias exists.
    async fn alias_creator(&self, alias: &str) -> Result<Option<String>>;

    /// Case-insensitive substring search over user IDs and display names
    /// of users visible to `requester`: anyone joined to a room the
    /// requester is joined to, or joined to a room whose join rule is
    /// `public` or whose history visibility is `world_readable`.
    /// Deactivated local accounts are excluded. Returns at most `limit`
    /// entries, users sharing a room with the requester first, then by
    /// user ID.
    async fn search_user_directory(
        &self,
        requester: &str,
        term: &str,
        limit: i64,
    ) -> Result<Vec<UserDirectoryEntry>>;

    // --- Room content (conduit-y99.19) --------------------------------------
    //
    // Defaults derive everything from the event log so any backend is
    // correct; PostgreSQL overrides the scans with indexed queries.

    /// Every event in a room with its stream position, ascending.
    async fn room_events_with_positions(&self, room_id: &str) -> Result<Vec<(i64, Event)>> {
        let events = self.room_events(room_id).await?;
        let ids: Vec<String> = events.iter().map(|event| event.event_id.clone()).collect();
        let positions = self.event_stream_positions(&ids).await?;
        let mut rows: Vec<_> = events
            .into_iter()
            .filter_map(|event| positions.get(&event.event_id).map(|position| (*position, event)))
            .collect();
        rows.sort_by_key(|(position, _)| *position);
        Ok(rows)
    }

    /// State events at or before stream position `through`, ascending.
    /// Folding them yields the room state as of that position.
    async fn state_events_through(&self, room_id: &str, through: i64) -> Result<Vec<(i64, Event)>> {
        Ok(self
            .room_events_with_positions(room_id)
            .await?
            .into_iter()
            .filter(|(position, event)| *position <= through && event.state_key.is_some())
            .collect())
    }

    /// `m.room.redaction` events in `room_id` whose target is in `event_ids`.
    async fn redactions_targeting(&self, room_id: &str, event_ids: &[String]) -> Result<Vec<Event>> {
        Ok(self
            .room_events(room_id)
            .await?
            .into_iter()
            .filter(|event| {
                crate::room_content::redaction_target(event)
                    .is_some_and(|target| event_ids.iter().any(|id| id == target))
            })
            .collect())
    }

    /// Events in `room_id` whose cleartext `m.relates_to.event_id` is one of
    /// `parent_ids`, with stream positions, ascending.
    async fn relation_children(&self, room_id: &str, parent_ids: &[String]) -> Result<Vec<(i64, Event)>> {
        Ok(self
            .room_events_with_positions(room_id)
            .await?
            .into_iter()
            .filter(|(_, event)| {
                crate::room_content::relation(event)
                    .is_some_and(|(_, parent)| parent_ids.iter().any(|id| id == parent))
            })
            .collect())
    }

    /// Thread roots in a room: `(root_event_id, latest_child_position,
    /// user_sent_a_child)`, most recently active first.
    async fn thread_roots(&self, room_id: &str, user_id: &str) -> Result<Vec<(String, i64, bool)>> {
        let mut roots: HashMap<String, (i64, bool)> = HashMap::new();
        for (position, event) in self.room_events_with_positions(room_id).await? {
            if let Some(("m.thread", parent)) = crate::room_content::relation(&event) {
                let entry = roots.entry(parent.to_owned()).or_insert((position, false));
                entry.0 = entry.0.max(position);
                entry.1 |= event.sender == user_id;
            }
        }
        let mut roots: Vec<_> = roots.into_iter().map(|(id, (pos, mine))| (id, pos, mine)).collect();
        roots.sort_by_key(|root| std::cmp::Reverse(root.1));
        Ok(roots)
    }

    /// Up to `limit` events nearest `ts`: at or after it ascending when
    /// `forward`, at or before it descending otherwise. Ties on timestamp
    /// follow stream order.
    async fn events_near_timestamp(&self, room_id: &str, ts: i64, forward: bool, limit: i64) -> Result<Vec<Event>> {
        let mut rows: Vec<_> = self
            .room_events_with_positions(room_id)
            .await?
            .into_iter()
            .filter(|(_, event)| {
                let at = event.origin_server_ts as i64;
                if forward { at >= ts } else { at <= ts }
            })
            .collect();
        rows.sort_by_key(|(position, event)| (event.origin_server_ts, *position));
        if !forward {
            rows.reverse();
        }
        rows.truncate(limit.max(0) as usize);
        Ok(rows.into_iter().map(|(_, event)| event).collect())
    }

    /// Full-text search across `rooms`, best first (`recent`: newest
    /// first), at most `cap` hits. Visibility is the caller's job.
    async fn search_room_events(
        &self,
        rooms: &[String],
        term: &str,
        keys: crate::room_content::SearchKeys,
        recent: bool,
        cap: i64,
    ) -> Result<Vec<crate::room_content::SearchHit>> {
        let query = crate::room_content::search_tokens(term);
        let mut hits = Vec::new();
        for room in rooms {
            for (position, event) in self.room_events_with_positions(room).await? {
                if let Some(rank) = keys.text(&event).and_then(|text| crate::room_content::naive_rank(text, &query)) {
                    hits.push(crate::room_content::SearchHit { rank, position, event });
                }
            }
        }
        hits.sort_by(|a, b| {
            if recent {
                b.position.cmp(&a.position)
            } else {
                b.rank.total_cmp(&a.rank).then(b.position.cmp(&a.position))
            }
        });
        hits.truncate(cap.max(0) as usize);
        Ok(hits)
    }

    /// Record that `user_id` forgot `room_id` as of their departure event.
    async fn forget_room(&self, user_id: &str, room_id: &str, membership_event_id: &str) -> Result<()>;

    /// Forgotten rooms: room_id → the membership event that was forgotten.
    /// A room stays forgotten only while that event is still current.
    async fn forgotten_rooms(&self, user_id: &str) -> Result<HashMap<String, String>>;

    /// Store a report; returns its id.
    async fn insert_report(&self, report: &crate::room_content::ContentReport) -> Result<i64>;

    /// Reports with id > `from`, ascending, at most `limit`.
    async fn list_reports(&self, from: i64, limit: i64) -> Result<Vec<crate::room_content::ContentReport>>;

    // --- Account & device management (conduit-y99.18) -------------------------

    /// Create the device when absent, returning `true` if it was created.
    /// A known device keeps its display name (the spec ignores
    /// `initial_device_display_name` for known devices).  A device ID that
    /// was deleted earlier resumes past its retired epoch, so capability
    /// tokens minted for the old device never verify again.
    async fn create_device_if_absent(
        &self,
        user_id: &str,
        device_id: &str,
        display_name: Option<&str>,
    ) -> Result<bool>;

    /// Rename an existing device.  `false` when the device does not exist.
    async fn set_device_display_name(
        &self,
        user_id: &str,
        device_id: &str,
        display_name: Option<&str>,
    ) -> Result<bool>;

    /// Delete a device and everything bound to it: OpenID and refresh
    /// tokens, device keys, one-time and fallback keys, and queued
    /// to-device messages.  Its epoch is retired so a recreated device
    /// with the same ID cannot resurrect old tokens.  Returns whether the
    /// device existed.
    async fn delete_device(&self, user_id: &str, device_id: &str) -> Result<bool>;

    /// Record last-seen activity for a device.
    async fn touch_device(
        &self,
        user_id: &str,
        device_id: &str,
        ts_ms: i64,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<()>;

    /// Mark or clear the guest flag on an account.
    async fn set_guest(&self, user_id: &str, is_guest: bool) -> Result<()>;

    /// Local, active server administrators.
    async fn list_admin_user_ids(&self) -> Result<Vec<String>>;

    /// Erase non-event data for a deactivating account (account data,
    /// profile) and remember that erasure was requested.
    async fn erase_account(&self, user_id: &str) -> Result<()>;

    async fn insert_refresh_token(
        &self,
        token_hash: &str,
        user_id: &str,
        device_id: &str,
        epoch: i64,
        parent_hash: Option<&str>,
    ) -> Result<()>;

    async fn get_refresh_token(&self, token_hash: &str) -> Result<Option<RefreshTokenRecord>>;

    async fn delete_refresh_token(&self, token_hash: &str) -> Result<()>;

    /// Revoke every token issued in exchange for `parent_hash`.
    async fn delete_refresh_token_children(&self, parent_hash: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Directory domain types (conduit-y99.20)
// ---------------------------------------------------------------------------

/// Which published-room list `POST /publicRooms` reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryScope {
    /// The server's own directory only (the default).
    Local,
    /// The server's directory plus every application-service network.
    AllNetworks,
    /// One application service network (`third_party_instance_id`).
    Network { appservice_id: String, network_id: String },
}

/// One row of `POST /user_directory/search`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDirectoryEntry {
    pub user_id: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// In-memory published-room directory for [`MemoryStorage`].
#[derive(Default)]
struct MemoryDirectory {
    local: std::collections::HashSet<String>,
    /// (appservice_id, network_id, room_id)
    appservice: std::collections::HashSet<(String, String, String)>,
}

// ---------------------------------------------------------------------------
// MemoryStorage — in-memory backend for tests and demos.  Not durable.
// ---------------------------------------------------------------------------

/// An in-memory [`Storage`] for tests and demos. Not durable.
#[derive(Default)]
pub struct MemoryStorage {
    transaction_locks: std::sync::Mutex<HashMap<TransactionKey, std::sync::Weak<tokio::sync::Mutex<()>>>>,
    inner: RwLock<MemoryInner>,
    room_content: RwLock<MemoryRoomContent>,
    directory: RwLock<MemoryDirectory>,
}

#[derive(Debug, Clone)]
struct OutboundRow {
    entry: OutboundEntry,
    status: String,
    next_attempt_at_ms: i64,
    last_error: Option<String>,
}

#[derive(Default)]
struct MemoryOutbound {
    rows: Vec<OutboundRow>,
    next_id: i64,
}

struct MemoryInner {
    filters: HashMap<(String, String), Value>,
    requests: HashMap<TransactionKey, Value>,
    transactions: HashMap<TransactionKey, Value>,
    events: HashMap<String, Event>,
    event_positions: HashMap<String, i64>,
    event_next_position: i64,
    accounts: HashMap<String, Account>,
    /// (user_id, device_id) → Device
    devices: HashMap<(String, String), Device>,
    /// token_hash → (user_id, device_id, expires_at)
    tokens: HashMap<String, (String, String, Option<DateTime<Utc>>)>,
    /// Ordered list of signing keys (push_back = newest).
    signing_keys: Vec<SigningKey>,
    /// identikey-auth fingerprint → MXID
    identikey_links: HashMap<String, String>,
    /// Biscuit minter keys (push_back = newest).
    minter_keys: Vec<SigningKey>,
    /// (room_id, type, state_key) → event_id
    room_state: HashMap<(String, String, String), String>,
    // E2EE
    /// (user_id, device_id) → keys JSON
    device_keys: HashMap<(String, String), Value>,
    /// (user_id, device_id, key_id) → (algorithm, key_json)
    one_time_keys: HashMap<(String, String, String), (String, Value)>,
    /// (user_id, device_id, algorithm) → (key_id, key_json, used)
    fallback_keys: HashMap<(String, String, String), (String, Value, bool)>,
    /// (user_id, key_type) → key_json
    cross_signing_keys: HashMap<(String, String), Value>,
    /// (signer_user, signer_key, target_user, target_key) → signature
    cross_signing_sigs: HashMap<(String, String, String, String), String>,
    /// to-device queue entries (id, target_user, target_device, sender, event_type, content)
    to_device_queue: Vec<(i64, String, String, String, String, Value)>,
    to_device_next_id: i64,
    /// device list change log (id, user_id)
    device_list_changes: Vec<(i64, String)>,
    device_list_next_id: i64,
    /// (user_id, version) → RoomKeyVersion + deleted flag
    room_key_versions: HashMap<(String, String), (RoomKeyVersion, bool)>,
    /// (user_id, version, room_id, session_id) → key_data
    room_keys: HashMap<(String, String, String, String), Value>,
    // Presence layer (1mo.3–1mo.6)
    /// (user_id, room_id_or_empty, event_type) → (stream_pos, content)
    account_data: HashMap<(String, Option<String>, String), (i64, Value)>,
    account_data_next_pos: i64,
    /// (room_id, user_id, receipt_type) → (event_id, ts, stream_pos)
    receipts: HashMap<(String, String, String), (String, i64, i64)>,
    receipts_next_pos: i64,
    // Media (E07)
    media: HashMap<(String, String), MediaMetadata>,
    thumbnails: HashMap<(String, String, i32, i32, String), ThumbnailMetadata>,
    // Media lane (conduit-y99.21)
    pending_media: HashMap<(String, String), PendingMedia>,
    media_legacy_access: std::collections::HashSet<(String, String)>,
    url_previews: Vec<UrlPreview>,
    // Push (E11)
    pushers: HashMap<(String, String, String), Pusher>,
    push_rules: HashMap<(String, String, String, String), PushRule>,
    // Admin audit log (E11)
    audit_log: Vec<AuditEntry>,
    audit_log_next_id: i64,
    // Outbound federation queue (conduit-5n3)
    outbound_queue: MemoryOutbound,
    // Room aliases (conduit-v0y): alias → (room_id, creator, created_at)
    aliases: HashMap<String, (String, String, DateTime<Utc>)>,
    // Account & device management (conduit-y99.18)
    account_lane: AccountLaneMemory,
}

#[derive(Default)]
struct AccountLaneMemory {
    /// (user_id, device_id) → last epoch of a deleted device
    retired_epochs: HashMap<(String, String), i64>,
    /// token_hash → record
    refresh_tokens: HashMap<String, RefreshTokenRecord>,
    erased: std::collections::HashSet<String>,
}

impl Default for MemoryInner {
    fn default() -> Self {
        Self {
            events: HashMap::new(),
            filters: HashMap::new(),
            event_positions: HashMap::new(),
            event_next_position: 0,
            requests: HashMap::new(),
            transactions: HashMap::new(),
            accounts: HashMap::new(),
            devices: HashMap::new(),
            tokens: HashMap::new(),
            signing_keys: Vec::new(),
            identikey_links: HashMap::new(),
            minter_keys: Vec::new(),
            room_state: HashMap::new(),
            device_keys: HashMap::new(),
            one_time_keys: HashMap::new(),
            fallback_keys: HashMap::new(),
            cross_signing_keys: HashMap::new(),
            cross_signing_sigs: HashMap::new(),
            to_device_queue: Vec::new(),
            to_device_next_id: 0,
            device_list_changes: Vec::new(),
            device_list_next_id: 0,
            room_key_versions: HashMap::new(),
            room_keys: HashMap::new(),
            account_data: HashMap::new(),
            account_data_next_pos: 0,
            receipts: HashMap::new(),
            receipts_next_pos: 0,
            media: HashMap::new(),
            thumbnails: HashMap::new(),
            pending_media: HashMap::new(),
            media_legacy_access: std::collections::HashSet::new(),
            url_previews: Vec::new(),
            pushers: HashMap::new(),
            push_rules: HashMap::new(),
            audit_log: Vec::new(),
            audit_log_next_id: 0,
            outbound_queue: MemoryOutbound::default(),
            aliases: HashMap::new(),
            account_lane: AccountLaneMemory::default(),
        }
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn put_filter(&self, user: &str, id: &str, definition: &Value) -> Result<()> {
        let mut inner = self.inner.write().await;
        let key = (user.into(), id.into());
        if inner.filters.contains_key(&key) { return Err(crate::Error::Storage("filter ID already exists".into())); }
        inner.filters.insert(key, definition.clone());
        Ok(())
    }
    async fn get_filter(&self, user: &str, id: &str) -> Result<Option<Value>> {
        Ok(self.inner.read().await.filters.get(&(user.into(), id.into())).cloned())
    }
    async fn lock_transaction(&self, key: &TransactionKey) -> Result<Box<dyn TransactionGuard>> {
        let lock = {
            let mut locks = self.transaction_locks.lock().map_err(|_| crate::Error::Storage("transaction lock registry poisoned".into()))?;
            locks.retain(|_, value| value.strong_count() > 0);
            let lock = locks.get(key).and_then(std::sync::Weak::upgrade)
                .unwrap_or_else(|| std::sync::Arc::new(tokio::sync::Mutex::new(())));
            locks.insert(key.clone(), std::sync::Arc::downgrade(&lock));
            lock
        };
        Ok(Box::new(lock.lock_owned().await))
    }

    async fn transaction_original(&self, key: &TransactionKey) -> Result<Option<Value>> {
        Ok(self.inner.read().await.requests.get(key).cloned())
    }

    async fn transaction_request(&self, key: &TransactionKey, request: &Value) -> Result<Value> {
        Ok(self.inner.write().await.requests.entry(key.clone()).or_insert_with(|| request.clone()).clone())
    }

    async fn finish_transaction(&self, key: &TransactionKey, result: &Value) -> Result<Value> {
        Ok(self.inner.write().await.transactions.entry(key.clone()).or_insert_with(|| result.clone()).clone())
    }

    async fn transaction_result(&self, key: &TransactionKey) -> Result<Option<Value>> {
        Ok(self.inner.read().await.transactions.get(key).cloned())
    }

    async fn put_event_once(&self, key: &TransactionKey, event: &Event) -> Result<(String, bool)> {
        let mut inner = self.inner.write().await;
        if let Some(result) = inner.transactions.get(key) {
            return result["event_id"].as_str().map(|id| (id.to_owned(), false))
                .ok_or_else(|| crate::Error::Storage("invalid stored event transaction".into()));
        }
        if event.state_key.is_some() {
            return Err(crate::Error::InvalidEvent("put_event_once accepts non-state events only".into()));
        }
        if !inner.events.contains_key(&event.event_id) {
            inner.event_next_position += 1;
            let position = inner.event_next_position;
            inner.event_positions.insert(event.event_id.clone(), position);
            inner.events.insert(event.event_id.clone(), event.clone());
        }
        inner.transactions.insert(key.clone(), serde_json::json!({"event_id": event.event_id}));
        Ok((event.event_id.clone(), true))
    }

    async fn deliver_to_device_once(&self, key: &TransactionKey, local: &[ToDeviceDelivery], remote: &[OutboundDelivery]) -> Result<bool> {
        let mut inner = self.inner.write().await;
        if inner.transactions.contains_key(key) { return Ok(false); }
        for message in local {
            let targets: Vec<_> = inner.devices.keys()
                .filter(|(user, device)| user == &message.target_user && (message.target_device == "*" || device == &message.target_device))
                .map(|(_, device)| device.clone()).collect();
            for device in targets {
                inner.to_device_next_id += 1;
                let id = inner.to_device_next_id;
                inner.to_device_queue.push((id, message.target_user.clone(), device,
                    message.sender.clone(), message.event_type.clone(), message.content.clone()));
            }
        }
        for delivery in remote {
            inner.outbound_queue.next_id += 1;
            let id = inner.outbound_queue.next_id;
            inner.outbound_queue.rows.push(OutboundRow {
                entry: OutboundEntry {id, destination: delivery.destination.clone(), kind: "transaction".into(), txn_id: delivery.txn_id.clone(), payload: delivery.payload.clone(), attempts: 0},
                status: "pending".into(), next_attempt_at_ms: chrono::Utc::now().timestamp_millis(), last_error: None,
            });
        }
        inner.transactions.insert(key.clone(), serde_json::json!({}));
        Ok(true)
    }

    // --- Events -------------------------------------------------------------

    async fn get_event(&self, event_id: &str) -> Result<Option<Event>> {
        Ok(self.inner.read().await.events.get(event_id).cloned())
    }

    async fn put_event(&self, event: &Event) -> Result<()> {
        let mut inner = self.inner.write().await;
        if !inner.events.contains_key(&event.event_id) {
            inner.event_next_position += 1;
            let position = inner.event_next_position;
            inner.event_positions.insert(event.event_id.clone(), position);
            inner.events.insert(event.event_id.clone(), event.clone());
        }
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
                displayname: None,
                avatar_url: None,
                is_guest: false,
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
        let epoch = inner
            .account_lane
            .retired_epochs
            .get(&key)
            .map(|e| e + 1)
            .unwrap_or(0);
        let entry = inner.devices.entry(key).or_insert_with(|| Device {
            user_id: user_id.to_owned(),
            device_id: device_id.to_owned(),
            display_name: None,
            epoch,
            last_seen_ts: None,
            last_seen_ip: None,
            last_seen_user_agent: None,
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

    async fn device_epoch(&self, user_id: &str, device_id: &str) -> Result<Option<i64>> {
        let key = (user_id.to_owned(), device_id.to_owned());
        Ok(self.inner.read().await.devices.get(&key).map(|d| d.epoch))
    }

    async fn bump_device_epoch(&self, user_id: &str, device_id: &str) -> Result<i64> {
        let mut inner = self.inner.write().await;
        let key = (user_id.to_owned(), device_id.to_owned());
        let device = inner
            .devices
            .get_mut(&key)
            .ok_or_else(|| Error::Storage(format!("unknown device {device_id}")))?;
        device.epoch += 1;
        Ok(device.epoch)
    }

    async fn bump_all_device_epochs(&self, user_id: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        for device in inner.devices.values_mut() {
            if device.user_id == user_id {
                device.epoch += 1;
            }
        }
        Ok(())
    }

    async fn insert_minter_key(
        &self,
        key_id: &str,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<()> {
        self.inner.write().await.minter_keys.push(SigningKey {
            key_id: key_id.to_owned(),
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            valid_until_ts: None,
            created_at: Utc::now(),
        });
        Ok(())
    }

    async fn current_minter_key(&self) -> Result<Option<SigningKey>> {
        Ok(self.inner.read().await.minter_keys.last().cloned())
    }

    async fn link_identikey(&self, fingerprint: &str, user_id: &str) -> Result<()> {
        self.inner
            .write()
            .await
            .identikey_links
            .insert(fingerprint.to_owned(), user_id.to_owned());
        Ok(())
    }

    async fn user_for_identikey(&self, fingerprint: &str) -> Result<Option<String>> {
        Ok(self
            .inner
            .read()
            .await
            .identikey_links
            .get(fingerprint)
            .cloned())
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

    async fn current_memberships(&self, user_id: &str) -> Result<Vec<Event>> {
        let inner = self.inner.read().await;
        Ok(inner.room_state.iter().filter(|((_, kind, key), _)| kind == "m.room.member" && key == user_id)
            .filter_map(|(_, id)| inner.events.get(id).cloned()).collect())
    }

    async fn joined_rooms(&self, user_id: &str) -> Result<Vec<String>> {
        let inner = self.inner.read().await;
        let mut rooms: Vec<_> = inner.room_state.iter()
            .filter(|((_, event_type, state_key), _)| event_type == "m.room.member" && state_key == user_id)
            .filter_map(|((room_id, _, _), event_id)| {
                inner.events.get(event_id)
                    .filter(|event| event.content.get("membership").and_then(Value::as_str) == Some("join"))
                    .map(|_| room_id.clone())
            }).collect();
        rooms.sort();
        Ok(rooms)
    }

    async fn room_events_paginated(&self, room_id: &str, dir: char, from: i64, limit: i64)
        -> Result<(Vec<Event>, Option<i64>)> {
        let inner = self.inner.read().await;
        let mut rows: Vec<_> = inner.events.values().filter(|event| event.room_id == room_id)
            .filter_map(|event| inner.event_positions.get(&event.event_id).map(|position| (*position, event.clone())))
            .filter(|(position, _)| if dir == 'b' { *position <= from } else { *position >= from }).collect();
        rows.sort_by_key(|(position, _)| if dir == 'b' { -*position } else { *position });
        rows.truncate(limit.max(0) as usize);
        let next = rows.last().map(|(position, _)| if dir == 'b' { position.saturating_sub(1) } else { position.saturating_add(1) });
        let next = if (rows.len() as i64) < limit { None } else { next };
        Ok((rows.into_iter().map(|(_, event)| event).collect(), next))
    }

    async fn room_latest_stream_position(&self, room_id: &str) -> Result<Option<i64>> {
        let inner = self.inner.read().await;
        Ok(inner.events.values().filter(|event| event.room_id == room_id)
            .filter_map(|event| inner.event_positions.get(&event.event_id).copied()).max())
    }

    async fn member_events_for_user(
        &self,
        room_id: &str,
        user_id: &str,
    ) -> Result<Vec<(i64, Event)>> {
        let inner = self.inner.read().await;
        let mut rows: Vec<(i64, Event)> = inner
            .events
            .values()
            .filter(|e| {
                e.room_id == room_id
                    && e.event_type == "m.room.member"
                    && e.state_key.as_deref() == Some(user_id)
            })
            .filter_map(|e| inner.event_positions.get(&e.event_id).map(|position| (*position, e.clone())))
            .collect();
        rows.sort_by_key(|(pos, _)| *pos);
        Ok(rows)
    }

    async fn member_events_for_server(
        &self,
        room_id: &str,
        server_name: &str,
    ) -> Result<Vec<(i64, Event)>> {
        let inner = self.inner.read().await;
        let suffix = format!(":{server_name}");
        let mut rows: Vec<(i64, Event)> = inner
            .events
            .values()
            .filter(|e| {
                e.room_id == room_id
                    && e.event_type == "m.room.member"
                    && e.state_key
                        .as_deref()
                        .is_some_and(|sk| sk.ends_with(&suffix))
            })
            .filter_map(|e| inner.event_positions.get(&e.event_id).map(|position| (*position, e.clone())))
            .collect();
        rows.sort_by_key(|(pos, _)| *pos);
        Ok(rows)
    }

    async fn event_stream_positions(&self, event_ids: &[String]) -> Result<HashMap<String, i64>> {
        let inner = self.inner.read().await;
        Ok(event_ids
            .iter()
            .filter_map(|id| inner.event_positions.get(id).map(|position| (id.clone(), *position)))
            .collect())
    }

    async fn events_since(&self, since: i64, limit: i64) -> Result<Vec<Event>> {
        let inner = self.inner.read().await;
        let mut rows: Vec<_> = inner.events.values()
            .filter_map(|event| inner.event_positions.get(&event.event_id).map(|position| (*position, event.clone())))
            .filter(|(position, _)| *position > since).collect();
        rows.sort_by_key(|(position, _)| *position);
        rows.truncate(limit.max(0) as usize);
        Ok(rows.into_iter().map(|(_, event)| event).collect())
    }

    async fn global_max_stream_position(&self) -> Result<i64> {
        Ok(self.inner.read().await.event_next_position)
    }

    // --- Device keys ----------------------------------------------------------

    async fn upsert_device_keys(&self, user_id: &str, device_id: &str, keys: &Value) -> Result<()> {
        self.inner
            .write()
            .await
            .device_keys
            .insert((user_id.to_owned(), device_id.to_owned()), keys.clone());
        Ok(())
    }

    async fn get_device_keys(&self, user_id: &str, device_id: &str) -> Result<Option<Value>> {
        Ok(self
            .inner
            .read()
            .await
            .device_keys
            .get(&(user_id.to_owned(), device_id.to_owned()))
            .cloned())
    }

    async fn get_device_keys_for_user(&self, user_id: &str) -> Result<HashMap<String, Value>> {
        let inner = self.inner.read().await;
        let map = inner
            .device_keys
            .iter()
            .filter(|((u, _), _)| u == user_id)
            .map(|((_, d), v)| (d.clone(), v.clone()))
            .collect();
        Ok(map)
    }

    async fn delete_device_keys(&self, user_id: &str, device_id: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner
            .device_keys
            .remove(&(user_id.to_owned(), device_id.to_owned()));
        Ok(())
    }

    // --- One-time keys --------------------------------------------------------

    async fn insert_one_time_keys(
        &self,
        user_id: &str,
        device_id: &str,
        keys: Vec<(String, String, Value)>,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        for (key_id, algorithm, key_json) in keys {
            inner.one_time_keys.insert(
                (user_id.to_owned(), device_id.to_owned(), key_id),
                (algorithm, key_json),
            );
        }
        Ok(())
    }

    async fn claim_one_time_key(
        &self,
        user_id: &str,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<(String, Value)>> {
        let mut inner = self.inner.write().await;
        // Find first key matching user/device/algorithm.
        let found_key = inner
            .one_time_keys
            .iter()
            .find(|((u, d, _), (alg, _))| u == user_id && d == device_id && alg == algorithm)
            .map(|((_, _, kid), _)| kid.clone());
        if let Some(kid) = found_key {
            let map_key = (user_id.to_owned(), device_id.to_owned(), kid.clone());
            if let Some((_, key_json)) = inner.one_time_keys.remove(&map_key) {
                return Ok(Some((kid, key_json)));
            }
        }
        Ok(None)
    }

    async fn one_time_key_counts(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<HashMap<String, i64>> {
        let inner = self.inner.read().await;
        let mut counts: HashMap<String, i64> = HashMap::new();
        for ((u, d, _), (alg, _)) in &inner.one_time_keys {
            if u == user_id && d == device_id {
                *counts.entry(alg.clone()).or_insert(0) += 1;
            }
        }
        Ok(counts)
    }

    // --- Fallback keys --------------------------------------------------------

    async fn upsert_fallback_key(
        &self,
        user_id: &str,
        device_id: &str,
        algorithm: &str,
        key_id: &str,
        key_json: &Value,
    ) -> Result<()> {
        self.inner.write().await.fallback_keys.insert(
            (user_id.to_owned(), device_id.to_owned(), algorithm.to_owned()),
            (key_id.to_owned(), key_json.clone(), false),
        );
        Ok(())
    }

    async fn claim_fallback_key(
        &self,
        user_id: &str,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<(String, Value)>> {
        let mut inner = self.inner.write().await;
        let map_key = (user_id.to_owned(), device_id.to_owned(), algorithm.to_owned());
        if let Some((kid, key_json, used)) = inner.fallback_keys.get_mut(&map_key) {
            *used = true;
            return Ok(Some((kid.clone(), key_json.clone())));
        }
        Ok(None)
    }

    // --- Cross-signing --------------------------------------------------------

    async fn unused_fallback_key_types(&self, user_id: &str, device_id: &str) -> Result<Vec<String>> {
        let inner = self.inner.read().await;
        let mut algorithms: Vec<_> = inner.fallback_keys.iter()
            .filter(|((user, device, _), (_, _, used))| user == user_id && device == device_id && !used)
            .map(|((_, _, algorithm), _)| algorithm.clone()).collect();
        algorithms.sort();
        Ok(algorithms)
    }

    async fn upsert_cross_signing_key(
        &self,
        user_id: &str,
        key_type: &str,
        key_json: &Value,
    ) -> Result<()> {
        self.inner
            .write()
            .await
            .cross_signing_keys
            .insert((user_id.to_owned(), key_type.to_owned()), key_json.clone());
        Ok(())
    }

    async fn get_cross_signing_keys(&self, user_id: &str) -> Result<HashMap<String, Value>> {
        let inner = self.inner.read().await;
        let map = inner
            .cross_signing_keys
            .iter()
            .filter(|((u, _), _)| u == user_id)
            .map(|((_, kt), v)| (kt.clone(), v.clone()))
            .collect();
        Ok(map)
    }

    async fn insert_cross_signing_signature(
        &self,
        signer_user: &str,
        signer_key: &str,
        target_user: &str,
        target_key: &str,
        signature: &str,
    ) -> Result<()> {
        self.inner.write().await.cross_signing_sigs.insert(
            (
                signer_user.to_owned(),
                signer_key.to_owned(),
                target_user.to_owned(),
                target_key.to_owned(),
            ),
            signature.to_owned(),
        );
        Ok(())
    }

    // --- To-device queue ------------------------------------------------------

    async fn enqueue_to_device(
        &self,
        target_user: &str,
        target_device: &str,
        sender: &str,
        event_type: &str,
        content: &Value,
    ) -> Result<i64> {
        let mut inner = self.inner.write().await;
        inner.to_device_next_id += 1;
        let id = inner.to_device_next_id;
        inner.to_device_queue.push((
            id,
            target_user.to_owned(),
            target_device.to_owned(),
            sender.to_owned(),
            event_type.to_owned(),
            content.clone(),
        ));
        Ok(id)
    }

    async fn drain_to_device(
        &self,
        target_user: &str,
        target_device: &str,
        since_id: i64,
        limit: i64,
    ) -> Result<Vec<ToDeviceMessage>> {
        let inner = self.inner.read().await;
        let msgs = inner
            .to_device_queue
            .iter()
            .filter(|(id, tu, td, _, _, _)| {
                *id > since_id && tu == target_user && td == target_device
            })
            .take(limit as usize)
            .map(|(id, _, _, sender, event_type, content)| ToDeviceMessage {
                id: *id,
                sender: sender.clone(),
                event_type: event_type.clone(),
                content: content.clone(),
            })
            .collect();
        Ok(msgs)
    }

    async fn delete_to_device_before(
        &self,
        target_user: &str,
        target_device: &str,
        up_to_id: i64,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.to_device_queue.retain(|(id, tu, td, _, _, _)| {
            !(*id <= up_to_id && tu == target_user && td == target_device)
        });
        Ok(())
    }

    // --- Device list changes --------------------------------------------------

    async fn record_device_list_change(&self, user_id: &str) -> Result<i64> {
        let mut inner = self.inner.write().await;
        inner.device_list_next_id += 1;
        let id = inner.device_list_next_id;
        inner.device_list_changes.push((id, user_id.to_owned()));
        Ok(id)
    }

    async fn device_list_changes_between(&self, since_pos: i64, through_pos: i64) -> Result<Vec<String>> {
        let inner = self.inner.read().await;
        let mut users: Vec<String> = inner
            .device_list_changes
            .iter()
            .filter(|(id, _)| *id > since_pos && *id <= through_pos)
            .map(|(_, u)| u.clone())
            .collect();
        users.dedup();
        Ok(users)
    }

    async fn device_list_max_position(&self) -> Result<i64> {
        Ok(self.inner.read().await.device_list_next_id)
    }

    // --- Room key backup ------------------------------------------------------

    async fn create_room_keys_version(
        &self,
        user_id: &str,
        version: &str,
        algorithm: &str,
        auth_data: &Value,
    ) -> Result<String> {
        let etag = format!("{}", chrono::Utc::now().timestamp_millis());
        let rv = RoomKeyVersion {
            version: version.to_owned(),
            algorithm: algorithm.to_owned(),
            auth_data: auth_data.clone(),
            count: 0,
            etag: etag.clone(),
        };
        self.inner
            .write()
            .await
            .room_key_versions
            .insert((user_id.to_owned(), version.to_owned()), (rv, false));
        Ok(etag)
    }

    async fn get_room_keys_version(
        &self,
        user_id: &str,
        version: Option<&str>,
    ) -> Result<Option<RoomKeyVersion>> {
        let inner = self.inner.read().await;
        if let Some(v) = version {
            Ok(inner
                .room_key_versions
                .get(&(user_id.to_owned(), v.to_owned()))
                .and_then(|(rv, deleted)| if *deleted { None } else { Some(rv.clone()) }))
        } else {
            // Return latest non-deleted version.
            Ok(inner
                .room_key_versions
                .iter()
                .filter(|((u, _), (_, deleted))| u == user_id && !*deleted)
                .max_by(|((_, va), _), ((_, vb), _)| va.cmp(vb))
                .map(|(_, (rv, _))| rv.clone()))
        }
    }

    async fn update_room_keys_version(
        &self,
        user_id: &str,
        version: &str,
        auth_data: &Value,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        let key = (user_id.to_owned(), version.to_owned());
        if let Some((rv, _)) = inner.room_key_versions.get_mut(&key) {
            rv.auth_data = auth_data.clone();
            rv.etag = format!("{}", chrono::Utc::now().timestamp_millis());
        }
        Ok(())
    }

    async fn delete_room_keys_version(&self, user_id: &str, version: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        let key = (user_id.to_owned(), version.to_owned());
        if let Some((_, deleted)) = inner.room_key_versions.get_mut(&key) {
            *deleted = true;
        }
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
        let mut inner = self.inner.write().await;
        inner.room_keys.insert(
            (
                user_id.to_owned(),
                version.to_owned(),
                room_id.to_owned(),
                session_id.to_owned(),
            ),
            key_data.clone(),
        );
        // Update count — compute before the mutable borrow.
        let vk = (user_id.to_owned(), version.to_owned());
        let count = inner
            .room_keys
            .keys()
            .filter(|(u, v, _, _)| u == user_id && v == version)
            .count() as i64;
        if let Some((rv, _)) = inner.room_key_versions.get_mut(&vk) {
            rv.count = count;
        }
        Ok(())
    }

    async fn get_room_keys(
        &self,
        user_id: &str,
        version: &str,
        room_id: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<HashMap<String, HashMap<String, Value>>> {
        let inner = self.inner.read().await;
        let mut result: HashMap<String, HashMap<String, Value>> = HashMap::new();
        for ((u, v, r, s), kd) in &inner.room_keys {
            if u != user_id || v != version {
                continue;
            }
            if let Some(rid) = room_id {
                if r != rid {
                    continue;
                }
            }
            if let Some(sid) = session_id {
                if s != sid {
                    continue;
                }
            }
            result
                .entry(r.clone())
                .or_default()
                .insert(s.clone(), kd.clone());
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
        let mut inner = self.inner.write().await;
        let before = inner.room_keys.len();
        inner.room_keys.retain(|(u, v, r, s), _| {
            if u != user_id || v != version {
                return true;
            }
            if let Some(rid) = room_id {
                if r != rid {
                    return true;
                }
            }
            if let Some(sid) = session_id {
                if s != sid {
                    return true;
                }
            }
            false
        });
        let deleted = (before - inner.room_keys.len()) as i64;
        // Update count — compute before the mutable borrow.
        let vk = (user_id.to_owned(), version.to_owned());
        let count = inner
            .room_keys
            .keys()
            .filter(|(u, v, _, _)| u == user_id && v == version)
            .count() as i64;
        if let Some((rv, _)) = inner.room_key_versions.get_mut(&vk) {
            rv.count = count;
        }
        Ok(deleted)
    }

    // --- Profile --------------------------------------------------------------

    async fn set_displayname(&self, user_id: &str, displayname: Option<&str>) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(acct) = inner.accounts.get_mut(user_id) {
            acct.displayname = displayname.map(|s| s.to_owned());
        }
        Ok(())
    }

    async fn set_avatar_url(&self, user_id: &str, avatar_url: Option<&str>) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(acct) = inner.accounts.get_mut(user_id) {
            acct.avatar_url = avatar_url.map(|s| s.to_owned());
        }
        Ok(())
    }

    // --- Account data ---------------------------------------------------------

    async fn set_account_data(
        &self,
        user_id: &str,
        room_id: Option<&str>,
        event_type: &str,
        content: &Value,
    ) -> Result<i64> {
        let mut inner = self.inner.write().await;
        inner.account_data_next_pos += 1;
        let pos = inner.account_data_next_pos;
        inner.account_data.insert(
            (user_id.to_owned(), room_id.map(|s| s.to_owned()), event_type.to_owned()),
            (pos, content.clone()),
        );
        Ok(pos)
    }

    async fn get_account_data(
        &self,
        user_id: &str,
        room_id: Option<&str>,
        event_type: &str,
    ) -> Result<Option<Value>> {
        let inner = self.inner.read().await;
        let key = (user_id.to_owned(), room_id.map(|s| s.to_owned()), event_type.to_owned());
        Ok(inner.account_data.get(&key).map(|(_, v)| v.clone()))
    }

    async fn account_data_since(
        &self,
        user_id: &str,
        since_pos: i64,
    ) -> Result<Vec<(Option<String>, String, Value, i64)>> {
        let inner = self.inner.read().await;
        let mut results: Vec<(Option<String>, String, Value, i64)> = inner
            .account_data
            .iter()
            .filter(|((u, _, _), (pos, _))| u == user_id && *pos > since_pos)
            .map(|((_, room_id, event_type), (pos, content))| {
                (room_id.clone(), event_type.clone(), content.clone(), *pos)
            })
            .collect();
        results.sort_by_key(|(_, _, _, pos)| *pos);
        Ok(results)
    }

    // --- Receipts -------------------------------------------------------------

    async fn set_receipt(
        &self,
        room_id: &str,
        user_id: &str,
        receipt_type: &str,
        event_id: &str,
        ts: i64,
    ) -> Result<i64> {
        let mut inner = self.inner.write().await;
        inner.receipts_next_pos += 1;
        let pos = inner.receipts_next_pos;
        inner.receipts.insert(
            (room_id.to_owned(), user_id.to_owned(), receipt_type.to_owned()),
            (event_id.to_owned(), ts, pos),
        );
        Ok(pos)
    }

    async fn receipts_for_room(
        &self,
        room_id: &str,
    ) -> Result<Vec<(String, String, String, i64)>> {
        let inner = self.inner.read().await;
        Ok(inner
            .receipts
            .iter()
            .filter(|((r, _, _), _)| r == room_id)
            .map(|((_, user_id, receipt_type), (event_id, ts, _))| {
                (user_id.clone(), receipt_type.clone(), event_id.clone(), *ts)
            })
            .collect())
    }

    async fn receipts_since(
        &self,
        since_pos: i64,
    ) -> Result<Vec<(String, String, String, String, i64, i64)>> {
        let inner = self.inner.read().await;
        let mut results: Vec<(String, String, String, String, i64, i64)> = inner
            .receipts
            .iter()
            .filter(|(_, (_, _, pos))| *pos > since_pos)
            .map(|((room_id, user_id, receipt_type), (event_id, ts, pos))| {
                (room_id.clone(), user_id.clone(), receipt_type.clone(), event_id.clone(), *ts, *pos)
            })
            .collect();
        results.sort_by_key(|(_, _, _, _, _, pos)| *pos);
        Ok(results)
    }

    // --- Media (E07) ----------------------------------------------------------

    async fn insert_media(&self, m: &MediaMetadata) -> Result<()> {
        self.inner
            .write()
            .await
            .media
            .insert((m.media_id.clone(), m.origin_server.clone()), m.clone());
        Ok(())
    }

    async fn get_media(&self, media_id: &str, origin_server: &str) -> Result<Option<MediaMetadata>> {
        Ok(self
            .inner
            .read()
            .await
            .media
            .get(&(media_id.to_owned(), origin_server.to_owned()))
            .cloned())
    }

    async fn touch_media_access(&self, media_id: &str, origin_server: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(m) = inner.media.get_mut(&(media_id.to_owned(), origin_server.to_owned())) {
            m.last_accessed = Utc::now();
        }
        Ok(())
    }

    async fn delete_media(&self, media_id: &str, origin_server: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.media.remove(&(media_id.to_owned(), origin_server.to_owned()));
        inner.media_legacy_access.remove(&(media_id.to_owned(), origin_server.to_owned()));
        // Cascade: remove thumbnails too.
        inner.thumbnails.retain(|(mid, orig, _, _, _), _| {
            !(mid == media_id && orig == origin_server)
        });
        Ok(())
    }

    async fn list_remote_media_older_than(&self, ts: DateTime<Utc>) -> Result<Vec<MediaMetadata>> {
        let inner = self.inner.read().await;
        Ok(inner
            .media
            .values()
            .filter(|m| m.uploader.is_none() && m.last_accessed < ts)
            .cloned()
            .collect())
    }

    async fn insert_thumbnail(&self, t: &ThumbnailMetadata) -> Result<()> {
        let key = (
            t.media_id.clone(),
            t.origin_server.clone(),
            t.width,
            t.height,
            t.method.clone(),
        );
        self.inner.write().await.thumbnails.insert(key, t.clone());
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
        let key = (
            media_id.to_owned(),
            origin_server.to_owned(),
            width,
            height,
            method.to_owned(),
        );
        Ok(self.inner.read().await.thumbnails.get(&key).cloned())
    }

    // --- Media lane (conduit-y99.21) ----------------------------------------

    async fn create_pending_media(&self, p: &PendingMedia, max_pending: i64) -> Result<PendingMediaCreate> {
        let mut inner = self.inner.write().await;
        let now = p.created_at;
        inner
            .pending_media
            .retain(|_, existing| existing.creator != p.creator || existing.expires_at > now);
        let mine: Vec<DateTime<Utc>> = inner
            .pending_media
            .values()
            .filter(|existing| existing.creator == p.creator)
            .map(|existing| existing.expires_at)
            .collect();
        if mine.len() as i64 >= max_pending {
            return Ok(PendingMediaCreate::LimitExceeded {
                earliest_expiry: mine.into_iter().min(),
            });
        }
        inner
            .pending_media
            .insert((p.media_id.clone(), p.origin_server.clone()), p.clone());
        Ok(PendingMediaCreate::Created)
    }

    async fn get_pending_media(&self, media_id: &str, origin_server: &str) -> Result<Option<PendingMedia>> {
        Ok(self
            .inner
            .read()
            .await
            .pending_media
            .get(&(media_id.to_owned(), origin_server.to_owned()))
            .cloned())
    }

    async fn complete_pending_media(
        &self,
        m: &MediaMetadata,
        uploader: &str,
        now: DateTime<Utc>,
    ) -> Result<PendingMediaCompletion> {
        let mut inner = self.inner.write().await;
        let key = (m.media_id.clone(), m.origin_server.clone());
        let Some(pending) = inner.pending_media.get(&key).cloned() else {
            return Ok(if inner.media.contains_key(&key) {
                PendingMediaCompletion::AlreadyUploaded
            } else {
                PendingMediaCompletion::NotFound
            });
        };
        if pending.creator != uploader {
            return Ok(PendingMediaCompletion::Forbidden);
        }
        inner.pending_media.remove(&key);
        if pending.expires_at <= now {
            return Ok(PendingMediaCompletion::NotFound);
        }
        if inner.media.contains_key(&key) {
            return Ok(PendingMediaCompletion::AlreadyUploaded);
        }
        inner.media.insert(key, m.clone());
        Ok(PendingMediaCompletion::Completed)
    }

    async fn media_unauthenticated_access(&self, media_id: &str, origin_server: &str) -> Result<bool> {
        Ok(self
            .inner
            .read()
            .await
            .media_legacy_access
            .contains(&(media_id.to_owned(), origin_server.to_owned())))
    }

    async fn set_media_unauthenticated_access(&self, media_id: &str, origin_server: &str, allowed: bool) -> Result<()> {
        let mut inner = self.inner.write().await;
        let key = (media_id.to_owned(), origin_server.to_owned());
        if allowed && inner.media.contains_key(&key) {
            inner.media_legacy_access.insert(key);
        } else if !allowed {
            inner.media_legacy_access.remove(&key);
        }
        Ok(())
    }

    async fn media_storage_path_in_use(&self, storage_path: &str) -> Result<bool> {
        let inner = self.inner.read().await;
        Ok(inner.media.values().any(|m| m.storage_path == storage_path)
            || inner.thumbnails.values().any(|t| t.storage_path == storage_path))
    }

    async fn insert_url_preview(&self, p: &UrlPreview) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner
            .url_previews
            .retain(|existing| !(existing.url == p.url && existing.fetched_at == p.fetched_at));
        inner.url_previews.push(p.clone());
        Ok(())
    }

    async fn latest_url_preview(
        &self,
        url: &str,
        fetched_at_or_before: Option<DateTime<Utc>>,
    ) -> Result<Option<UrlPreview>> {
        Ok(self
            .inner
            .read()
            .await
            .url_previews
            .iter()
            .filter(|p| p.url == url && fetched_at_or_before.is_none_or(|ts| p.fetched_at <= ts))
            .max_by_key(|p| p.fetched_at)
            .cloned())
    }

    // --- Push (E11) ----------------------------------------------------------

    async fn upsert_pusher(&self, pusher: &Pusher) -> Result<()> {
        let key = (pusher.user_id.clone(), pusher.pushkey.clone(), pusher.app_id.clone());
        self.inner.write().await.pushers.insert(key, pusher.clone());
        Ok(())
    }

    async fn delete_pusher(&self, user_id: &str, pushkey: &str, app_id: &str) -> Result<()> {
        let key = (user_id.to_owned(), pushkey.to_owned(), app_id.to_owned());
        self.inner.write().await.pushers.remove(&key);
        Ok(())
    }

    async fn list_pushers(&self, user_id: &str) -> Result<Vec<Pusher>> {
        let inner = self.inner.read().await;
        Ok(inner
            .pushers
            .iter()
            .filter(|((u, _, _), _)| u == user_id)
            .map(|(_, p)| p.clone())
            .collect())
    }

    async fn upsert_push_rule(&self, rule: &PushRule) -> Result<()> {
        let key = (
            rule.user_id.clone(),
            rule.scope.clone(),
            rule.kind.clone(),
            rule.rule_id.clone(),
        );
        self.inner.write().await.push_rules.insert(key, rule.clone());
        Ok(())
    }

    async fn delete_push_rule(
        &self,
        user_id: &str,
        scope: &str,
        kind: &str,
        rule_id: &str,
    ) -> Result<()> {
        let key = (user_id.to_owned(), scope.to_owned(), kind.to_owned(), rule_id.to_owned());
        self.inner.write().await.push_rules.remove(&key);
        Ok(())
    }

    async fn list_push_rules(&self, user_id: &str) -> Result<Vec<PushRule>> {
        let inner = self.inner.read().await;
        let mut rules: Vec<PushRule> = inner
            .push_rules
            .iter()
            .filter(|((u, _, _, _), _)| u == user_id)
            .map(|(_, r)| r.clone())
            .collect();
        rules.sort_by_key(|r| r.priority);
        Ok(rules)
    }

    async fn set_push_rule_enabled(
        &self,
        user_id: &str,
        scope: &str,
        kind: &str,
        rule_id: &str,
        enabled: bool,
    ) -> Result<()> {
        let key = (user_id.to_owned(), scope.to_owned(), kind.to_owned(), rule_id.to_owned());
        let mut inner = self.inner.write().await;
        if let Some(rule) = inner.push_rules.get_mut(&key) {
            rule.enabled = enabled;
        }
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
        let key = (user_id.to_owned(), scope.to_owned(), kind.to_owned(), rule_id.to_owned());
        let mut inner = self.inner.write().await;
        if let Some(rule) = inner.push_rules.get_mut(&key) {
            rule.actions = actions;
        }
        Ok(())
    }

    async fn get_push_rule(
        &self,
        user_id: &str,
        scope: &str,
        kind: &str,
        rule_id: &str,
    ) -> Result<Option<PushRule>> {
        let key = (user_id.to_owned(), scope.to_owned(), kind.to_owned(), rule_id.to_owned());
        Ok(self.inner.read().await.push_rules.get(&key).cloned())
    }

    // --- Admin (E11) ---------------------------------------------------------

    async fn list_accounts(&self, from: i64, limit: i64) -> Result<Vec<Account>> {
        let inner = self.inner.read().await;
        let mut accounts: Vec<Account> = inner.accounts.values().cloned().collect();
        accounts.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        let start = from.max(0) as usize;
        Ok(accounts.into_iter().skip(start).take(limit as usize).collect())
    }

    async fn set_password_hash(&self, user_id: &str, password_hash: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(acct) = inner.accounts.get_mut(user_id) {
            acct.password_hash = Some(password_hash.to_owned());
        }
        Ok(())
    }

    async fn append_audit_log(
        &self,
        admin_user: &str,
        action: &str,
        target: Option<&str>,
        detail: &Value,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.audit_log_next_id += 1;
        let id = inner.audit_log_next_id;
        inner.audit_log.push(AuditEntry {
            id,
            admin_user: admin_user.to_owned(),
            action: action.to_owned(),
            target: target.map(|s| s.to_owned()),
            detail: detail.clone(),
            ts: Utc::now(),
        });
        Ok(())
    }

    async fn list_audit_log(&self, from: i64, limit: i64) -> Result<Vec<AuditEntry>> {
        let inner = self.inner.read().await;
        let mut entries = inner.audit_log.clone();
        entries.sort_by(|a, b| b.ts.cmp(&a.ts));
        let start = from.max(0) as usize;
        Ok(entries.into_iter().skip(start).take(limit as usize).collect())
    }

    async fn purge_room(&self, room_id: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.events.retain(|_, e| e.room_id != room_id);
        let surviving: std::collections::HashSet<_> = inner.events.keys().cloned().collect();
        inner.event_positions.retain(|id, _| surviving.contains(id));
        inner.room_state.retain(|(r, _, _), _| r != room_id);
        Ok(())
    }

    async fn list_rooms(&self, from: i64, limit: i64) -> Result<Vec<String>> {
        let inner = self.inner.read().await;
        let mut rooms: Vec<String> = inner
            .events
            .values()
            .map(|e| e.room_id.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        rooms.sort();
        let start = from.max(0) as usize;
        Ok(rooms.into_iter().skip(start).take(limit as usize).collect())
    }

    async fn list_media(&self, from: i64, limit: i64) -> Result<Vec<MediaMetadata>> {
        let inner = self.inner.read().await;
        let mut items: Vec<MediaMetadata> = inner.media.values().cloned().collect();
        items.sort_by(|a, b| a.media_id.cmp(&b.media_id));
        let start = from.max(0) as usize;
        Ok(items.into_iter().skip(start).take(limit as usize).collect())
    }

    // --- Outbound federation queue ------------------------------------------

    async fn enqueue_outbound(
        &self,
        destination: &str,
        kind: &str,
        txn_id: &str,
        payload: &Value,
    ) -> Result<i64> {
        let mut inner = self.inner.write().await;
        inner.outbound_queue.next_id += 1;
        let id = inner.outbound_queue.next_id;
        inner.outbound_queue.rows.push(OutboundRow {
            entry: OutboundEntry {
                id,
                destination: destination.to_owned(),
                kind: kind.to_owned(),
                txn_id: txn_id.to_owned(),
                payload: payload.clone(),
                attempts: 0,
            },
            status: "pending".to_owned(),
            next_attempt_at_ms: Utc::now().timestamp_millis(),
            last_error: None,
        });
        Ok(id)
    }

    async fn outbound_destinations_with_pending(&self) -> Result<Vec<String>> {
        let inner = self.inner.read().await;
        let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
        for row in &inner.outbound_queue.rows {
            if row.status == "pending" {
                set.insert(row.entry.destination.clone());
            }
        }
        Ok(set.into_iter().collect())
    }

    async fn next_pending_outbound(
        &self,
        destination: &str,
        limit: i64,
    ) -> Result<Vec<OutboundEntry>> {
        let inner = self.inner.read().await;
        let now_ms = Utc::now().timestamp_millis();
        let mut rows: Vec<&OutboundRow> = inner
            .outbound_queue
            .rows
            .iter()
            .filter(|r| {
                r.status == "pending"
                    && r.entry.destination == destination
                    && r.next_attempt_at_ms <= now_ms
            })
            .collect();
        rows.sort_by_key(|r| (r.next_attempt_at_ms, r.entry.id));
        Ok(rows
            .into_iter()
            .take(limit as usize)
            .map(|r| r.entry.clone())
            .collect())
    }

    async fn mark_outbound_sent(&self, id: i64) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(row) = inner
            .outbound_queue
            .rows
            .iter_mut()
            .find(|r| r.entry.id == id)
        {
            row.status = "sent".to_owned();
        }
        Ok(())
    }

    async fn mark_outbound_failed(
        &self,
        id: i64,
        attempts: i32,
        next_attempt_at_ms: i64,
        last_error: &str,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(row) = inner
            .outbound_queue
            .rows
            .iter_mut()
            .find(|r| r.entry.id == id)
        {
            row.entry.attempts = attempts;
            row.next_attempt_at_ms = next_attempt_at_ms;
            row.last_error = Some(last_error.to_owned());
        }
        Ok(())
    }

    async fn mark_outbound_dead(&self, id: i64, last_error: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(row) = inner
            .outbound_queue
            .rows
            .iter_mut()
            .find(|r| r.entry.id == id)
        {
            row.status = "dead".to_owned();
            row.last_error = Some(last_error.to_owned());
        }
        Ok(())
    }

    async fn outbound_next_eta_ms(
        &self,
        destination: &str,
    ) -> Result<Option<i64>> {
        let inner = self.inner.read().await;
        Ok(inner
            .outbound_queue
            .rows
            .iter()
            .filter(|r| r.status == "pending" && r.entry.destination == destination)
            .map(|r| r.next_attempt_at_ms)
            .min())
    }

    async fn gc_outbound_queue(
        &self,
        sent_cutoff_ms: i64,
        dead_cutoff_ms: Option<i64>,
    ) -> Result<i64> {
        let mut inner = self.inner.write().await;
        let before = inner.outbound_queue.rows.len();
        inner.outbound_queue.rows.retain(|row| {
            let too_old_sent =
                row.status == "sent" && row.next_attempt_at_ms < sent_cutoff_ms;
            let too_old_dead = match dead_cutoff_ms {
                Some(cut) => row.status == "dead" && row.next_attempt_at_ms < cut,
                None => false,
            };
            !(too_old_sent || too_old_dead)
        });
        Ok((before - inner.outbound_queue.rows.len()) as i64)
    }

    async fn list_outbound_dlq(&self, from: i64, limit: i64) -> Result<Vec<DlqEntry>> {
        let inner = self.inner.read().await;
        let mut rows: Vec<&OutboundRow> = inner
            .outbound_queue
            .rows
            .iter()
            .filter(|r| r.status == "dead")
            .collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.entry.id));
        Ok(rows
            .into_iter()
            .skip(from.max(0) as usize)
            .take(limit as usize)
            .map(|r| DlqEntry {
                id: r.entry.id,
                destination: r.entry.destination.clone(),
                kind: r.entry.kind.clone(),
                txn_id: r.entry.txn_id.clone(),
                attempts: r.entry.attempts,
                last_error: r.last_error.clone(),
                created_at: Utc::now(),
            })
            .collect())
    }

    async fn replay_outbound_dlq(&self, id: i64) -> Result<bool> {
        let mut inner = self.inner.write().await;
        if let Some(row) = inner
            .outbound_queue
            .rows
            .iter_mut()
            .find(|r| r.entry.id == id && r.status == "dead")
        {
            row.status = "pending".to_owned();
            row.entry.attempts = 0;
            row.next_attempt_at_ms = Utc::now().timestamp_millis();
            row.last_error = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn purge_outbound_dlq(&self, id: i64) -> Result<bool> {
        let mut inner = self.inner.write().await;
        let before = inner.outbound_queue.rows.len();
        inner
            .outbound_queue
            .rows
            .retain(|r| !(r.entry.id == id && r.status == "dead"));
        Ok(before != inner.outbound_queue.rows.len())
    }

    // --- Room aliases -------------------------------------------------------

    async fn upsert_alias(
        &self,
        alias: &str,
        room_id: &str,
        creator: &str,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        if inner.aliases.contains_key(alias) {
            return Err(crate::Error::Storage(format!(
                "alias already in use: {alias}"
            )));
        }
        inner.aliases.insert(
            alias.to_owned(),
            (room_id.to_owned(), creator.to_owned(), Utc::now()),
        );
        Ok(())
    }

    async fn get_room_for_alias(&self, alias: &str) -> Result<Option<String>> {
        let inner = self.inner.read().await;
        Ok(inner.aliases.get(alias).map(|(rid, _, _)| rid.clone()))
    }

    async fn delete_alias(&self, alias: &str) -> Result<()> {
        self.inner.write().await.aliases.remove(alias);
        Ok(())
    }

    async fn list_aliases_for_room(&self, room_id: &str) -> Result<Vec<String>> {
        let inner = self.inner.read().await;
        let mut out: Vec<String> = inner
            .aliases
            .iter()
            .filter(|(_, (rid, _, _))| rid == room_id)
            .map(|(a, _)| a.clone())
            .collect();
        out.sort();
        Ok(out)
    }

    async fn get_remote_servers_for_user(&self, user_id: &str, server_name: &str) -> Result<Vec<String>> {
        // Fallback implementation: walk all rooms × members (O(rooms × members)).
        // This mirrors the old approach in remote_servers_sharing_room_with.
        let mut servers = std::collections::HashSet::new();
        let inner = self.inner.read().await;
        for (_key, event_id) in &inner.room_state {
            if let Some(event) = inner.events.get(event_id) {
                if event.event_type == "m.room.member"
                    && event.state_key.as_deref() == Some(user_id)
                {
                    // Found a room where user is a member — check membership = join
                    if event.content.get("membership").and_then(|v| v.as_str()) != Some("join") {
                        continue;
                    }
                    // Collect remote servers from other join members in this room
                    let room_id = &event.room_id;
                    for ((rid, etype, skey), eid) in &inner.room_state {
                        if rid != room_id || etype != "m.room.member" {
                            continue;
                        }
                        if let Some(ev) = inner.events.get(eid) {
                            if ev.content.get("membership").and_then(|v| v.as_str()) != Some("join") {
                                continue;
                            }
                            let other = skey.as_str();
                            let srv = other.split(':').nth(1).unwrap_or("");
                            if !srv.is_empty() && srv != server_name {
                                servers.insert(srv.to_owned());
                            }
                        }
                    }
                }
            }
        }
        let mut out: Vec<String> = servers.into_iter().collect();
        out.sort();
        Ok(out)
    }

    // --- Published room directory & user directory (conduit-y99.20) --------

    async fn set_room_published(&self, room_id: &str, published: bool) -> Result<()> {
        let mut directory = self.directory.write().await;
        if published {
            directory.local.insert(room_id.to_owned());
        } else {
            directory.local.remove(room_id);
        }
        Ok(())
    }

    async fn is_room_published(&self, room_id: &str) -> Result<bool> {
        Ok(self.directory.read().await.local.contains(room_id))
    }

    async fn set_appservice_room_published(
        &self,
        appservice_id: &str,
        network_id: &str,
        room_id: &str,
        published: bool,
    ) -> Result<()> {
        let key = (appservice_id.to_owned(), network_id.to_owned(), room_id.to_owned());
        let mut directory = self.directory.write().await;
        if published {
            directory.appservice.insert(key);
        } else {
            directory.appservice.remove(&key);
        }
        Ok(())
    }

    async fn published_rooms(&self, scope: &DirectoryScope) -> Result<Vec<String>> {
        let directory = self.directory.read().await;
        let mut rooms: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        match scope {
            DirectoryScope::Local => rooms.extend(directory.local.iter().cloned()),
            DirectoryScope::AllNetworks => {
                rooms.extend(directory.local.iter().cloned());
                rooms.extend(directory.appservice.iter().map(|(_, _, room)| room.clone()));
            }
            DirectoryScope::Network { appservice_id, network_id } => rooms.extend(
                directory
                    .appservice
                    .iter()
                    .filter(|(a, n, _)| a == appservice_id && n == network_id)
                    .map(|(_, _, room)| room.clone()),
            ),
        }
        Ok(rooms.into_iter().collect())
    }

    async fn alias_creator(&self, alias: &str) -> Result<Option<String>> {
        Ok(self.inner.read().await.aliases.get(alias).map(|(_, creator, _)| creator.clone()))
    }

    async fn search_user_directory(
        &self,
        requester: &str,
        term: &str,
        limit: i64,
    ) -> Result<Vec<UserDirectoryEntry>> {
        let inner = self.inner.read().await;
        let state = |room: &str, kind: &str, key: &str| {
            inner
                .room_state
                .get(&(room.to_owned(), kind.to_owned(), key.to_owned()))
                .and_then(|id| inner.events.get(id))
        };
        // room → joined members (with their member event)
        let mut joined: HashMap<&str, Vec<&Event>> = HashMap::new();
        for ((room, kind, _), id) in &inner.room_state {
            if kind != "m.room.member" {
                continue;
            }
            if let Some(event) = inner.events.get(id) {
                if event.content["membership"] == "join" {
                    joined.entry(room.as_str()).or_default().push(event);
                }
            }
        }
        let needle = term.to_lowercase();
        // user → (shares a room with requester, entry)
        let mut found: HashMap<String, (bool, UserDirectoryEntry)> = HashMap::new();
        for (room, members) in &joined {
            let shared = members.iter().any(|m| m.state_key.as_deref() == Some(requester));
            let public = state(room, "m.room.join_rules", "")
                .is_some_and(|e| e.content["join_rule"] == "public");
            let world_readable = state(room, "m.room.history_visibility", "")
                .is_some_and(|e| e.content["history_visibility"] == "world_readable");
            if !(shared || public || world_readable) {
                continue;
            }
            for member in members {
                let Some(user) = member.state_key.as_deref() else { continue };
                let account = inner.accounts.get(user);
                if account.is_some_and(|a| a.deactivated_at.is_some()) {
                    continue;
                }
                let display_name = account
                    .and_then(|a| a.displayname.clone())
                    .or_else(|| member.content["displayname"].as_str().map(str::to_owned));
                let avatar_url = account
                    .and_then(|a| a.avatar_url.clone())
                    .or_else(|| member.content["avatar_url"].as_str().map(str::to_owned));
                let matches = user.to_lowercase().contains(&needle)
                    || display_name.as_deref().is_some_and(|d| d.to_lowercase().contains(&needle));
                if !matches {
                    continue;
                }
                let slot = found.entry(user.to_owned()).or_insert_with(|| {
                    (
                        false,
                        UserDirectoryEntry { user_id: user.to_owned(), display_name, avatar_url },
                    )
                });
                slot.0 |= shared;
            }
        }
        let mut rows: Vec<_> = found.into_values().collect();
        rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.user_id.cmp(&b.1.user_id)));
        Ok(rows
            .into_iter()
            .take(limit.max(0) as usize)
            .map(|(_, entry)| entry)
            .collect())
    }

    // --- Room content (conduit-y99.19) --------------------------------------

    async fn forget_room(&self, user_id: &str, room_id: &str, membership_event_id: &str) -> Result<()> {
        self.room_content.write().await.forgotten.insert(
            (user_id.to_owned(), room_id.to_owned()),
            membership_event_id.to_owned(),
        );
        Ok(())
    }

    async fn forgotten_rooms(&self, user_id: &str) -> Result<HashMap<String, String>> {
        Ok(self
            .room_content
            .read()
            .await
            .forgotten
            .iter()
            .filter(|((user, _), _)| user == user_id)
            .map(|((_, room), event)| (room.clone(), event.clone()))
            .collect())
    }

    async fn insert_report(&self, report: &crate::room_content::ContentReport) -> Result<i64> {
        let mut content = self.room_content.write().await;
        let id = content.reports.len() as i64 + 1;
        content.reports.push(crate::room_content::ContentReport { id, ..report.clone() });
        Ok(id)
    }

    async fn list_reports(&self, from: i64, limit: i64) -> Result<Vec<crate::room_content::ContentReport>> {
        Ok(self
            .room_content
            .read()
            .await
            .reports
            .iter()
            .filter(|report| report.id > from)
            .take(limit.max(0) as usize)
            .cloned()
            .collect())
    }

    // --- Account & device management (conduit-y99.18) -------------------------

    async fn create_device_if_absent(
        &self,
        user_id: &str,
        device_id: &str,
        display_name: Option<&str>,
    ) -> Result<bool> {
        let mut inner = self.inner.write().await;
        let key = (user_id.to_owned(), device_id.to_owned());
        if inner.devices.contains_key(&key) {
            return Ok(false);
        }
        let epoch = inner
            .account_lane
            .retired_epochs
            .get(&key)
            .map(|e| e + 1)
            .unwrap_or(0);
        inner.devices.insert(
            key,
            Device {
                user_id: user_id.to_owned(),
                device_id: device_id.to_owned(),
                display_name: display_name.map(str::to_owned),
                epoch,
                last_seen_ts: None,
                last_seen_ip: None,
                last_seen_user_agent: None,
            },
        );
        Ok(true)
    }

    async fn set_device_display_name(
        &self,
        user_id: &str,
        device_id: &str,
        display_name: Option<&str>,
    ) -> Result<bool> {
        let mut inner = self.inner.write().await;
        match inner.devices.get_mut(&(user_id.to_owned(), device_id.to_owned())) {
            Some(d) => {
                d.display_name = display_name.map(str::to_owned);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn delete_device(&self, user_id: &str, device_id: &str) -> Result<bool> {
        let mut inner = self.inner.write().await;
        let key = (user_id.to_owned(), device_id.to_owned());
        let Some(device) = inner.devices.remove(&key) else {
            return Ok(false);
        };
        inner.account_lane.retired_epochs.insert(key.clone(), device.epoch);
        inner.tokens.retain(|_, (u, d, _)| !(u == user_id && d == device_id));
        inner
            .account_lane
            .refresh_tokens
            .retain(|_, r| !(r.user_id == user_id && r.device_id == device_id));
        inner.device_keys.remove(&key);
        inner
            .one_time_keys
            .retain(|(u, d, _), _| !(u == user_id && d == device_id));
        inner
            .fallback_keys
            .retain(|(u, d, _), _| !(u == user_id && d == device_id));
        inner
            .to_device_queue
            .retain(|(_, u, d, _, _, _)| !(u == user_id && d == device_id));
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
        let mut inner = self.inner.write().await;
        if let Some(d) = inner.devices.get_mut(&(user_id.to_owned(), device_id.to_owned())) {
            d.last_seen_ts = Some(ts_ms);
            if ip.is_some() {
                d.last_seen_ip = ip.map(str::to_owned);
            }
            if user_agent.is_some() {
                d.last_seen_user_agent = user_agent.map(str::to_owned);
            }
        }
        Ok(())
    }

    async fn set_guest(&self, user_id: &str, is_guest: bool) -> Result<()> {
        let mut inner = self.inner.write().await;
        if let Some(acct) = inner.accounts.get_mut(user_id) {
            acct.is_guest = is_guest;
        }
        Ok(())
    }

    async fn list_admin_user_ids(&self) -> Result<Vec<String>> {
        let inner = self.inner.read().await;
        let mut out: Vec<String> = inner
            .accounts
            .values()
            .filter(|a| a.is_admin && a.deactivated_at.is_none())
            .map(|a| a.user_id.clone())
            .collect();
        out.sort();
        Ok(out)
    }

    async fn erase_account(&self, user_id: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.account_data.retain(|(u, _, _), _| u != user_id);
        if let Some(acct) = inner.accounts.get_mut(user_id) {
            acct.displayname = None;
            acct.avatar_url = None;
        }
        inner.account_lane.erased.insert(user_id.to_owned());
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
        self.inner.write().await.account_lane.refresh_tokens.insert(
            token_hash.to_owned(),
            RefreshTokenRecord {
                user_id: user_id.to_owned(),
                device_id: device_id.to_owned(),
                epoch,
                parent_hash: parent_hash.map(str::to_owned),
            },
        );
        Ok(())
    }

    async fn get_refresh_token(&self, token_hash: &str) -> Result<Option<RefreshTokenRecord>> {
        Ok(self.inner.read().await.account_lane.refresh_tokens.get(token_hash).cloned())
    }

    async fn delete_refresh_token(&self, token_hash: &str) -> Result<()> {
        self.inner.write().await.account_lane.refresh_tokens.remove(token_hash);
        Ok(())
    }

    async fn delete_refresh_token_children(&self, parent_hash: &str) -> Result<()> {
        self.inner
            .write()
            .await
            .account_lane
            .refresh_tokens
            .retain(|_, r| r.parent_hash.as_deref() != Some(parent_hash));
        Ok(())
    }
}

/// MemoryStorage room-content tables (conduit-y99.19).
#[derive(Default)]
struct MemoryRoomContent {
    /// (user_id, room_id) → forgotten membership event id
    forgotten: HashMap<(String, String), String>,
    reports: Vec<crate::room_content::ContentReport>,
}

// ---------------------------------------------------------------------------
// Tests for MemoryStorage
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stream_event(id: &str, room: &str, depth: i64) -> Event {
        Event { event_id: id.into(), room_id: room.into(), sender: "@a:test".into(),
            event_type: "m.room.message".into(), content: json!({"body": id}), state_key: None,
            origin_server_ts: 1, auth_events: vec![], prev_events: vec![], hashes: json!({}),
            signatures: json!({}), depth, unsigned: None }
    }

    #[tokio::test]
    async fn event_stream_positions_are_independent_of_depth_room_and_duplicates() {
        let store = MemoryStorage::default();
        let first = stream_event("$first", "!one:test", 10);
        let second = stream_event("$second", "!two:test", 2);
        let third = stream_event("$third", "!one:test", 2);
        for event in [&first, &second, &third] { store.put_event(event).await.unwrap(); }
        assert_eq!(store.global_max_stream_position().await.unwrap(), 3);
        assert_eq!(store.events_since(1, 100).await.unwrap(), vec![second.clone(), third.clone()]);
        let mut duplicate = first.clone();
        duplicate.content = json!({"body": "wrong replacement"});
        store.put_event(&duplicate).await.unwrap();
        assert_eq!(store.get_event("$first").await.unwrap(), Some(first.clone()));
        assert_eq!(store.global_max_stream_position().await.unwrap(), 3);
        let (page, next) = store.room_events_paginated("!one:test", 'b', 3, 1).await.unwrap();
        assert_eq!(page, vec![third]);
        assert_eq!(next, Some(2));
        let (page, _) = store.room_events_paginated("!one:test", 'b', 2, 10).await.unwrap();
        assert_eq!(page, vec![first]);
        store.purge_room("!one:test").await.unwrap();
        assert_eq!(store.global_max_stream_position().await.unwrap(), 3);
        store.put_event(&stream_event("$new", "!new:test", 1)).await.unwrap();
        assert_eq!(store.global_max_stream_position().await.unwrap(), 4);
        let key = TransactionKey::client("@a:test", "A", &["room_send", "!new:test", "m.room.message"], "atomic");
        let atomic = stream_event("$atomic", "!new:test", 1);
        assert_eq!(store.put_event_once(&key, &atomic).await.unwrap(), ("$atomic".into(), true));
        assert_eq!(store.event_stream_positions(&["$atomic".into()]).await.unwrap()["$atomic"], 5);
        assert_eq!(store.put_event_once(&key, &stream_event("$ignored", "!new:test", 1)).await.unwrap(), ("$atomic".into(), false));
        assert_eq!(store.global_max_stream_position().await.unwrap(), 5);
    }

    #[tokio::test]
    async fn replay_lock_cancellation_retains_original_request_and_result() {
        let store = std::sync::Arc::new(MemoryStorage::default());
        let key = TransactionKey::federation_request("peer.test", "once");
        let guard = store.lock_transaction(&key).await.unwrap();
        assert_eq!(store.transaction_request(&key, &json!({"first": 1})).await.unwrap(), json!({"first": 1}));
        let other = store.clone();
        let other_key = key.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(async move {
            started.send(()).unwrap();
            other.lock_transaction(&other_key).await.unwrap()
        });
        ready.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        waiter.abort();
        assert!(waiter.await.is_err());
        drop(guard);
        let _guard = tokio::time::timeout(std::time::Duration::from_secs(1), store.lock_transaction(&key)).await.unwrap().unwrap();
        assert_eq!(store.transaction_request(&key, &json!({"changed": 2})).await.unwrap(), json!({"first": 1}));
        store.finish_transaction(&key, &json!({"original": 3})).await.unwrap();
        assert_eq!(store.finish_transaction(&key, &json!({"changed": 4})).await.unwrap(), json!({"original": 3}));
    }

    #[tokio::test]
    async fn atomic_to_device_delivery_is_scoped_and_does_not_reexpand_retries() {
        let store = MemoryStorage::default();
        store.upsert_device("@bob:test", "ONE", None).await.unwrap();
        store.upsert_device("@bob:test", "TWO", None).await.unwrap();
        let key = TransactionKey::client("@alice:test", "A", &["send_to_device", "m.test"], "once");
        let local = vec![ToDeviceDelivery {target_user: "@bob:test".into(), target_device: "*".into(),
            sender: "@alice:test".into(), event_type: "m.test".into(), content: json!({"body": "once"})}];
        assert!(store.deliver_to_device_once(&key, &local, &[]).await.unwrap());
        store.upsert_device("@bob:test", "NEW", None).await.unwrap();
        assert!(!store.deliver_to_device_once(&key, &local, &[]).await.unwrap());
        for device in ["ONE", "TWO"] { assert_eq!(store.drain_to_device("@bob:test", device, 0, 100).await.unwrap().len(), 1); }
        assert!(store.drain_to_device("@bob:test", "NEW", 0, 100).await.unwrap().is_empty());
        let other = TransactionKey::client("@alice:test", "SECOND", &["send_to_device", "m.test"], "once");
        assert!(store.deliver_to_device_once(&other, &local, &[]).await.unwrap());
        assert_eq!(store.drain_to_device("@bob:test", "NEW", 0, 100).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn account_data_cursor_uses_observed_positions_across_overwrites_and_gaps() {
        let store = MemoryStorage::default();
        store.set_account_data("@other:test", None, "m.test", &json!({"v": 1})).await.unwrap();
        store.set_account_data("@a:test", None, "m.test", &json!({"v": 1})).await.unwrap();
        store.set_account_data("@other:test", None, "m.test", &json!({"v": 2})).await.unwrap();
        let position = store.set_account_data("@a:test", None, "m.test", &json!({"v": 2})).await.unwrap();
        let rows = store.account_data_since("@a:test", 0).await.unwrap();
        assert_eq!(rows, vec![(None, "m.test".into(), json!({"v": 2}), position)]);
        assert!(position > rows.len() as i64);
        assert!(store.account_data_since("@a:test", position).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn receipt_cursor_advances_on_overwrite_and_preserves_other_users() {
        let store = MemoryStorage::default();
        store.set_receipt("!room:test", "@a:test", "m.read", "$first", 1).await.unwrap();
        store.set_receipt("!room:test", "@b:test", "m.read", "$first", 1).await.unwrap();
        let position = store.set_receipt("!room:test", "@a:test", "m.read", "$second", 2).await.unwrap();
        let rows = store.receipts_since(0).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows.last().unwrap().3, "$second");
        assert_eq!(rows.last().unwrap().5, position);
        assert!(store.receipts_since(position).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn device_list_boundary_excludes_later_changes() {
        let store = MemoryStorage::default();
        let boundary = store.record_device_list_change("@a:test").await.unwrap();
        store.record_device_list_change("@b:test").await.unwrap();
        assert_eq!(store.device_list_changes_between(0, boundary).await.unwrap(), vec!["@a:test"]);
        assert_eq!(store.device_list_changes_since(boundary).await.unwrap(), vec!["@b:test"]);
    }

    #[tokio::test]
    async fn aliases_round_trip() {
        let store = MemoryStorage::default();
        // upsert + resolve.
        store
            .upsert_alias("#dev:local", "!abc:local", "@a:local")
            .await
            .unwrap();
        assert_eq!(
            store.get_room_for_alias("#dev:local").await.unwrap(),
            Some("!abc:local".to_owned())
        );
        // duplicate fails.
        let dup = store
            .upsert_alias("#dev:local", "!xyz:local", "@b:local")
            .await;
        assert!(dup.is_err());
        // reverse lookup.
        store
            .upsert_alias("#dev2:local", "!abc:local", "@a:local")
            .await
            .unwrap();
        let mut aliases = store
            .list_aliases_for_room("!abc:local")
            .await
            .unwrap();
        aliases.sort();
        assert_eq!(aliases, vec!["#dev2:local".to_owned(), "#dev:local".to_owned()]);
        // delete is idempotent.
        store.delete_alias("#dev:local").await.unwrap();
        store.delete_alias("#dev:local").await.unwrap();
        assert!(store
            .get_room_for_alias("#dev:local")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn outbound_queue_lifecycle() {
        let store = MemoryStorage::default();
        // enqueue two destinations.
        let id_a = store
            .enqueue_outbound("a.example", "to_device", "t1", &json!({"x": 1}))
            .await
            .unwrap();
        let id_b = store
            .enqueue_outbound("b.example", "transaction", "t2", &json!({"y": 2}))
            .await
            .unwrap();
        assert!(id_a < id_b);

        let dests = store.outbound_destinations_with_pending().await.unwrap();
        assert_eq!(dests.len(), 2);
        assert!(dests.contains(&"a.example".to_owned()));
        assert!(dests.contains(&"b.example".to_owned()));

        // next_pending returns ready rows for the dest.
        let ready = store.next_pending_outbound("a.example", 10).await.unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, id_a);
        assert_eq!(ready[0].destination, "a.example");
        assert_eq!(ready[0].kind, "to_device");
        assert_eq!(ready[0].attempts, 0);

        // mark sent — vanishes from pending.
        store.mark_outbound_sent(id_a).await.unwrap();
        let ready = store.next_pending_outbound("a.example", 10).await.unwrap();
        assert!(ready.is_empty());
        let dests = store.outbound_destinations_with_pending().await.unwrap();
        assert_eq!(dests, vec!["b.example".to_owned()]);

        // mark failed with future eta — vanishes from ready, but eta query sees it.
        let future = chrono::Utc::now().timestamp_millis() + 60_000;
        store
            .mark_outbound_failed(id_b, 1, future, "boom")
            .await
            .unwrap();
        let ready = store.next_pending_outbound("b.example", 10).await.unwrap();
        assert!(ready.is_empty());
        let eta = store.outbound_next_eta_ms("b.example").await.unwrap();
        assert_eq!(eta, Some(future));

        // mark dead — vanishes from pending entirely.
        store.mark_outbound_dead(id_b, "exhausted").await.unwrap();
        assert!(store
            .outbound_destinations_with_pending()
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            store.outbound_next_eta_ms("b.example").await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn delete_device_keys_tombstones_device() {
        let store = MemoryStorage::default();
        store
            .upsert_device_keys("@alice:srv", "DEV1", &json!({"keys": {"x": "y"}}))
            .await
            .unwrap();
        store
            .upsert_device_keys("@alice:srv", "DEV2", &json!({"keys": {"a": "b"}}))
            .await
            .unwrap();

        // Both present.
        let all = store.get_device_keys_for_user("@alice:srv").await.unwrap();
        assert_eq!(all.len(), 2);

        // Tombstone DEV1.
        store
            .delete_device_keys("@alice:srv", "DEV1")
            .await
            .unwrap();
        assert!(store
            .get_device_keys("@alice:srv", "DEV1")
            .await
            .unwrap()
            .is_none());
        // DEV2 still present.
        assert!(store
            .get_device_keys("@alice:srv", "DEV2")
            .await
            .unwrap()
            .is_some());
        let all = store.get_device_keys_for_user("@alice:srv").await.unwrap();
        assert_eq!(all.len(), 1);

        // Deleting absent device is a no-op.
        store
            .delete_device_keys("@alice:srv", "NOPE")
            .await
            .unwrap();
    }

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
