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
use crate::Result;

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
    async fn device_list_changes_since(&self, since_pos: i64) -> Result<Vec<String>>;

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
    /// Returns `(room_id, event_type, content)` — `room_id` is `None` for global entries.
    async fn account_data_since(
        &self,
        user_id: &str,
        since_pos: i64,
    ) -> Result<Vec<(Option<String>, String, Value)>>;

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
    /// Returns `(room_id, user_id, receipt_type, event_id, ts)`.
    async fn receipts_since(
        &self,
        since_pos: i64,
    ) -> Result<Vec<(String, String, String, String, i64)>>;

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
}

// ---------------------------------------------------------------------------
// MemoryStorage — in-memory backend for tests and demos.  Not durable.
// ---------------------------------------------------------------------------

/// An in-memory [`Storage`] for tests and demos. Not durable.
#[derive(Default)]
pub struct MemoryStorage {
    inner: RwLock<MemoryInner>,
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
}

impl Default for MemoryInner {
    fn default() -> Self {
        Self {
            events: HashMap::new(),
            accounts: HashMap::new(),
            devices: HashMap::new(),
            tokens: HashMap::new(),
            signing_keys: Vec::new(),
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
            pushers: HashMap::new(),
            push_rules: HashMap::new(),
            audit_log: Vec::new(),
            audit_log_next_id: 0,
            outbound_queue: MemoryOutbound::default(),
            aliases: HashMap::new(),
        }
    }
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
                displayname: None,
                avatar_url: None,
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

    async fn events_since(&self, since: i64, limit: i64) -> Result<Vec<Event>> {
        let inner = self.inner.read().await;
        // In MemoryStorage, depth is used as stream_position proxy.
        let mut evs: Vec<Event> = inner
            .events
            .values()
            .filter(|e| e.depth > since)
            .cloned()
            .collect();
        evs.sort_by_key(|e| e.depth);
        evs.truncate(limit as usize);
        Ok(evs)
    }

    async fn global_max_stream_position(&self) -> Result<i64> {
        let inner = self.inner.read().await;
        Ok(inner.events.values().map(|e| e.depth).max().unwrap_or(0))
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

    async fn device_list_changes_since(&self, since_pos: i64) -> Result<Vec<String>> {
        let inner = self.inner.read().await;
        let mut users: Vec<String> = inner
            .device_list_changes
            .iter()
            .filter(|(id, _)| *id > since_pos)
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
    ) -> Result<Vec<(Option<String>, String, Value)>> {
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
        Ok(results.into_iter().map(|(r, e, c, _)| (r, e, c)).collect())
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
    ) -> Result<Vec<(String, String, String, String, i64)>> {
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
        Ok(results.into_iter().map(|(r, u, t, e, ts, _)| (r, u, t, e, ts)).collect())
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
}

// ---------------------------------------------------------------------------
// Tests for MemoryStorage
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
