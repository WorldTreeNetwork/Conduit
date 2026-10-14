//! Application service transaction push (conduit-y99.34).
//!
//! <https://spec.matrix.org/v1.19/application-service-api/#pushing-events>
//!
//! One worker per registered AS with a URL.  The worker linearises the
//! event stream (and, with `receive_ephemeral`, receipts, typing and
//! presence) into transactions:
//!
//! * The next transaction is *frozen* in storage together with the cursor
//!   advance, under a durable, strictly increasing txnId.  A restart
//!   resends the frozen body under the same txnId; nothing is lost or
//!   re-batched, and a retry never alters a transaction's contents.
//! * Only one transaction is in flight per AS, so order is preserved.
//! * Delivery uses `Authorization: Bearer {hs_token}` with a legacy route
//!   fallback ([`crate::app_service::as_request`]), retried with
//!   exponential backoff while the AS is unreachable or failing.
//!
//! Interest (spec "namespaces"): an event is pushed when its room ID is in
//! a `rooms` namespace, one of the room's aliases is in an `aliases`
//! namespace, a local user in a `users` namespace (or the AS sender) sent
//! it, is its `m.room.member` target, or is joined to its room.
//!
//! Typing and presence are process-local (`TypingStore`/`PresenceStore`),
//! so their push cursors start at the current head after a restart; the
//! receipt cursor is durable with the event cursor.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use conduit::event::Event;
use conduit::storage::{AppserviceCursor, Storage};

use crate::api::client::{PresenceStore, TypingStore};
use crate::app_service::{as_request, AppService};

/// Maximum number of room events in one transaction.
const MAX_EVENTS_PER_TXN: i64 = 100;
/// Longest wait between retries of a failing transaction.
const MAX_BACKOFF: Duration = Duration::from_secs(10 * 60);
/// Idle poll interval (receipts and missed wake-ups are picked up here).
const IDLE_POLL: Duration = Duration::from_millis(500);

/// What the push workers need from the host.
#[derive(Clone)]
pub struct PushContext {
    pub storage: Arc<dyn Storage>,
    pub server_name: Arc<str>,
    pub http: reqwest::Client,
    pub typing: Arc<TypingStore>,
    pub presence: Arc<PresenceStore>,
    /// First retry delay; doubles per consecutive failure up to
    /// [`MAX_BACKOFF`].  `CONDUIT_AS_BACKOFF_BASE_MS` (default 1000).
    pub backoff_base: Duration,
}

impl PushContext {
    /// Read `CONDUIT_AS_BACKOFF_BASE_MS` (default one second).
    pub fn backoff_from_env() -> Duration {
        std::env::var("CONDUIT_AS_BACKOFF_BASE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_secs(1))
    }
}

/// Spawn one transaction worker per AS that has a URL (`url: null` ASes
/// receive nothing).
pub fn spawn_workers(
    services: &[AppService],
    ctx: PushContext,
    events_tx: &broadcast::Sender<i64>,
) {
    for svc in services.iter().filter(|s| !s.url.is_empty()) {
        let worker = Worker {
            svc: svc.clone(),
            ctx: ctx.clone(),
            typing_pos: 0,
            presence_pos: 0,
        };
        tokio::spawn(worker.run(events_tx.subscribe()));
    }
}

/// Outcome of one worker step.
enum Step {
    /// A transaction was delivered or frozen, or the cursor moved: go again.
    Progress,
    /// Nothing to do: wait for a wake-up.
    Idle,
    /// Delivery failed: back off.
    Failed,
}

struct Worker {
    svc: AppService,
    ctx: PushContext,
    typing_pos: i64,
    presence_pos: i64,
}

impl Worker {
    async fn run(mut self, mut events_rx: broadcast::Receiver<i64>) {
        let mut typing_rx = self.ctx.typing.subscribe();
        let mut presence_rx = self.ctx.presence.subscribe();
        // Ephemeral streams are not durable: start at their current heads.
        self.typing_pos = self.ctx.typing.snapshot(None).await.0;
        self.presence_pos = self.ctx.presence.snapshot(None).await.0;
        info!(as_id = self.svc.id, "AS transaction worker started");
        let mut backoff = self.ctx.backoff_base;
        loop {
            match self.step().await {
                Ok(Step::Progress) => backoff = self.ctx.backoff_base,
                Ok(Step::Idle) => {
                    backoff = self.ctx.backoff_base;
                    tokio::select! {
                        _ = events_rx.recv() => {}
                        _ = typing_rx.changed() => {}
                        _ = presence_rx.changed() => {}
                        _ = tokio::time::sleep(IDLE_POLL) => {}
                    }
                }
                Ok(Step::Failed) => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                Err(e) => {
                    warn!(as_id = self.svc.id, error = %e, "AS worker storage error");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    async fn step(&mut self) -> conduit::Result<Step> {
        let storage = Arc::clone(&self.ctx.storage);
        if let Some((txn_id, body)) = storage.appservice_pending_txn(&self.svc.id).await? {
            return Ok(if self.deliver(txn_id, &body).await {
                storage.appservice_complete_txn(&self.svc.id, txn_id).await?;
                Step::Progress
            } else {
                Step::Failed
            });
        }

        let cursor = storage.appservice_cursor(&self.svc.id).await?;
        let mut next = cursor;
        let mut interest = Interest::new(&self.svc, &self.ctx);

        // Room events, linearised by stream position.
        let events = storage.events_since(cursor.event_pos, MAX_EVENTS_PER_TXN).await?;
        if let Some(last) = events.last() {
            let positions = storage.event_stream_positions(&[last.event_id.clone()]).await?;
            next.event_pos = positions
                .get(&last.event_id)
                .copied()
                .unwrap_or(cursor.event_pos)
                .max(cursor.event_pos);
        }
        let now = now_ms();
        let mut pushed = Vec::new();
        for event in &events {
            if interest.event(event).await? {
                pushed.push(format_event(event, now));
            }
        }

        // Ephemeral data.
        let receipts = storage.receipts_since(cursor.receipt_pos).await?;
        if let Some(max) = receipts.iter().map(|r| r.5).max() {
            next.receipt_pos = max.max(cursor.receipt_pos);
        }
        let mut ephemeral = Vec::new();
        let (typing_pos, typing, _) = self.ctx.typing.snapshot(Some(self.typing_pos)).await;
        let (presence_pos, presence, _) = self.ctx.presence.snapshot(Some(self.presence_pos)).await;
        let ephemeral_moved = typing_pos != self.typing_pos || presence_pos != self.presence_pos;
        self.typing_pos = typing_pos;
        self.presence_pos = presence_pos;
        if self.svc.receive_ephemeral {
            ephemeral.extend(interest.receipts(&receipts).await?);
            let mut rooms: Vec<_> = typing.into_iter().collect();
            rooms.sort();
            for (room_id, user_ids) in rooms {
                if interest.room(&room_id).await? {
                    ephemeral.push(json!({
                        "type": "m.typing",
                        "room_id": room_id,
                        "content": {"user_ids": user_ids},
                    }));
                }
            }
            for (user_id, entry) in presence {
                if interest.presence(&user_id).await? {
                    let mut content = json!({
                        "presence": entry.effective_presence(),
                        "last_active_ago": entry.last_changed_at.elapsed().as_millis() as u64,
                        "currently_active": entry.effective_presence() == "online",
                    });
                    if let Some(msg) = &entry.status_msg {
                        content["status_msg"] = json!(msg);
                    }
                    ephemeral.push(json!({
                        "type": "m.presence",
                        "sender": user_id,
                        "content": content,
                    }));
                }
            }
        }

        if pushed.is_empty() && ephemeral.is_empty() {
            if next != cursor {
                storage.appservice_enqueue_txn(&self.svc.id, None, &next).await?;
                return Ok(Step::Progress);
            }
            return Ok(if ephemeral_moved { Step::Progress } else { Step::Idle });
        }
        let mut body = json!({ "events": pushed });
        if self.svc.receive_ephemeral {
            body["ephemeral"] = Value::Array(ephemeral);
        }
        let txn_id = storage.appservice_enqueue_txn(&self.svc.id, Some(&body), &next).await?;
        debug!(as_id = self.svc.id, ?txn_id, "AS transaction frozen");
        Ok(Step::Progress)
    }

    /// `PUT /_matrix/app/v1/transactions/{txnId}`; true on 2xx.
    async fn deliver(&self, txn_id: i64, body: &Value) -> bool {
        let path = format!("transactions/{txn_id}");
        match as_request(&self.ctx.http, &self.svc, reqwest::Method::PUT, &path, Some(body)).await {
            Ok(status) if (200..300).contains(&status) => {
                debug!(as_id = self.svc.id, txn_id, "AS transaction delivered");
                true
            }
            Ok(status) => {
                warn!(as_id = self.svc.id, txn_id, status, "AS transaction rejected; will retry");
                false
            }
            Err(e) => {
                warn!(as_id = self.svc.id, txn_id, error = %e, "AS unreachable; will retry");
                false
            }
        }
    }
}

/// Client-format event for the AS: the sending client's `transaction_id`
/// is not the AS's business.
fn format_event(event: &Event, now: u64) -> Value {
    let mut value = conduit::room_content::client_event(event, now);
    if let Some(unsigned) = value.get_mut("unsigned").and_then(Value::as_object_mut) {
        unsigned.remove("transaction_id");
    }
    value
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The server part of a user ID (`@local:server` -> `server`).
fn user_domain(user_id: &str) -> Option<&str> {
    user_id.strip_prefix('@')?.split_once(':').map(|(_, d)| d)
}

/// Interest evaluation with a per-step room cache.
struct Interest<'a> {
    svc: &'a AppService,
    ctx: &'a PushContext,
    rooms: HashMap<String, bool>,
}

impl<'a> Interest<'a> {
    fn new(svc: &'a AppService, ctx: &'a PushContext) -> Self {
        Self { svc, ctx, rooms: HashMap::new() }
    }

    /// A *local* user the AS cares about.  "Application services can only
    /// register interest in local users."
    fn user(&self, user_id: &str) -> bool {
        user_domain(user_id) == Some(&*self.ctx.server_name)
            && self.svc.is_interested_in_user(user_id, &self.ctx.server_name)
    }

    async fn event(&mut self, event: &Event) -> conduit::Result<bool> {
        if self.user(&event.sender) {
            return Ok(true);
        }
        if event.event_type == "m.room.member" {
            if let Some(target) = &event.state_key {
                if self.user(target) {
                    return Ok(true);
                }
            }
        }
        self.room(&event.room_id).await
    }

    /// Room-level interest: room ID, any alias, or a joined interesting user.
    async fn room(&mut self, room_id: &str) -> conduit::Result<bool> {
        if let Some(hit) = self.rooms.get(room_id) {
            return Ok(*hit);
        }
        let hit = self.compute_room(room_id).await?;
        self.rooms.insert(room_id.to_owned(), hit);
        Ok(hit)
    }

    async fn compute_room(&self, room_id: &str) -> conduit::Result<bool> {
        if self.svc.is_interested_in_room_id(room_id) {
            return Ok(true);
        }
        let storage = &self.ctx.storage;
        let mut aliases = storage.list_aliases_for_room(room_id).await?;
        let state = storage.get_current_state(room_id).await?;
        for event in &state {
            if event.event_type == "m.room.canonical_alias" {
                if let Some(alias) = event.content.get("alias").and_then(Value::as_str) {
                    aliases.push(alias.to_owned());
                }
                if let Some(alt) = event.content.get("alt_aliases").and_then(Value::as_array) {
                    aliases.extend(alt.iter().filter_map(Value::as_str).map(str::to_owned));
                }
            }
        }
        if aliases.iter().any(|a| self.svc.is_interested_in_alias(a)) {
            return Ok(true);
        }
        Ok(state.iter().any(|event| {
            event.event_type == "m.room.member"
                && event.content.get("membership").and_then(Value::as_str) == Some("join")
                && event.state_key.as_deref().is_some_and(|u| self.user(u))
        }))
    }

    /// `m.receipt` EDUs per room.  Private receipts only for namespace users.
    async fn receipts(
        &mut self,
        receipts: &[(String, String, String, String, i64, i64)],
    ) -> conduit::Result<Vec<Value>> {
        let mut by_room: Vec<(String, Map<String, Value>)> = Vec::new();
        for (room_id, user_id, receipt_type, event_id, ts, _) in receipts {
            if receipt_type == "m.read.private" && !self.user(user_id) {
                continue;
            }
            if !self.room(room_id).await? {
                continue;
            }
            let index = match by_room.iter().position(|(r, _)| r == room_id) {
                Some(i) => i,
                None => {
                    by_room.push((room_id.clone(), Map::new()));
                    by_room.len() - 1
                }
            };
            let content = &mut by_room[index].1;
            let per_event = content
                .entry(event_id.clone())
                .or_insert_with(|| json!({}));
            let per_type = per_event
                .as_object_mut()
                .expect("object")
                .entry(receipt_type.clone())
                .or_insert_with(|| json!({}));
            per_type[user_id.as_str()] = json!({ "ts": ts });
        }
        Ok(by_room
            .into_iter()
            .map(|(room_id, content)| {
                json!({"type": "m.receipt", "room_id": room_id, "content": content})
            })
            .collect())
    }

    /// Presence applies contextually: the user is interesting, or shares a
    /// room the AS is interested in.
    async fn presence(&mut self, user_id: &str) -> conduit::Result<bool> {
        if self.user(user_id) {
            return Ok(true);
        }
        for room_id in self.ctx.storage.joined_rooms(user_id).await? {
            if self.room(&room_id).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Cursor helper for tests and diagnostics.
pub async fn cursor(storage: &dyn Storage, as_id: &str) -> conduit::Result<AppserviceCursor> {
    storage.appservice_cursor(as_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit::storage::MemoryStorage;
    use regex::Regex;

    fn svc(users: &str, rooms: &[&str], aliases: &[&str]) -> AppService {
        AppService {
            id: "bridge".into(),
            url: "http://127.0.0.1:1".into(),
            as_token: "as".into(),
            hs_token: "hs".into(),
            sender_localpart: "bridgebot".into(),
            rate_limited: false,
            user_namespaces: vec![(true, Regex::new(users).unwrap())],
            alias_namespaces: aliases.iter().map(|a| (true, Regex::new(a).unwrap())).collect(),
            room_namespaces: rooms.iter().map(|r| (false, Regex::new(r).unwrap())).collect(),
            protocols: vec![],
            receive_ephemeral: true,
        }
    }

    fn ctx(storage: Arc<dyn Storage>) -> PushContext {
        PushContext {
            storage,
            server_name: "hs.test".into(),
            http: reqwest::Client::new(),
            typing: TypingStore::new().0,
            presence: PresenceStore::new(),
            backoff_base: Duration::from_millis(1),
        }
    }

    fn event(id: &str, room: &str, sender: &str, ty: &str, state_key: Option<&str>, content: Value) -> Event {
        Event {
            event_id: id.into(),
            room_id: room.into(),
            sender: sender.into(),
            event_type: ty.into(),
            content,
            state_key: state_key.map(str::to_owned),
            origin_server_ts: 1,
            auth_events: vec![],
            prev_events: vec![],
            hashes: json!({}),
            signatures: json!({}),
            depth: 1,
            unsigned: Some(json!({"transaction_id": "secret"})),
        }
    }

    async fn put_state(storage: &Arc<dyn Storage>, ev: Event) {
        storage.put_event(&ev).await.unwrap();
        storage
            .set_state_entry(&ev.room_id, &ev.event_type, ev.state_key.as_deref().unwrap(), &ev.event_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn interest_covers_sender_target_room_alias_and_joined_members() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::default());
        let svc = svc(r"^@irc_.*:hs\.test$", &[r"^!bridged:"], &[r"^#irc_.*:hs\.test$"]);
        let ctx = ctx(Arc::clone(&storage));
        let mut interest = Interest::new(&svc, &ctx);
        let msg = |room: &str, sender: &str| event("$m", room, sender, "m.room.message", None, json!({}));

        // Sender in the users namespace; remote look-alikes are not ours.
        assert!(interest.event(&msg("!a:hs.test", "@irc_bob:hs.test")).await.unwrap());
        assert!(!interest.event(&msg("!a:hs.test", "@irc_bob:remote.test")).await.unwrap());
        // The AS sender user counts too.
        assert!(interest.event(&msg("!a:hs.test", "@bridgebot:hs.test")).await.unwrap());
        // Member target.
        let invite = event("$i", "!b:hs.test", "@alice:hs.test", "m.room.member", Some("@irc_carol:hs.test"), json!({"membership": "invite"}));
        assert!(interest.event(&invite).await.unwrap());
        // Rooms namespace.
        assert!(interest.event(&msg("!bridged:hs.test", "@alice:hs.test")).await.unwrap());
        // Unrelated.
        assert!(!interest.event(&msg("!c:hs.test", "@alice:hs.test")).await.unwrap());

        // Alias namespace via the directory and via canonical alt_aliases.
        storage.upsert_alias("#irc_chan:hs.test", "!d:hs.test", "@alice:hs.test").await.unwrap();
        put_state(&storage, event("$ca", "!e:hs.test", "@alice:hs.test", "m.room.canonical_alias", Some(""), json!({"alt_aliases": ["#irc_other:hs.test"]}))).await;
        let mut fresh = Interest::new(&svc, &ctx);
        assert!(fresh.event(&msg("!d:hs.test", "@alice:hs.test")).await.unwrap());
        assert!(fresh.event(&msg("!e:hs.test", "@alice:hs.test")).await.unwrap());

        // A joined namespace user makes every event in the room interesting.
        put_state(&storage, event("$j", "!f:hs.test", "@irc_dave:hs.test", "m.room.member", Some("@irc_dave:hs.test"), json!({"membership": "join"}))).await;
        let mut fresh = Interest::new(&svc, &ctx);
        assert!(fresh.event(&msg("!f:hs.test", "@alice:hs.test")).await.unwrap());
        // ...but not after they left.
        put_state(&storage, event("$l", "!g:hs.test", "@irc_dave:hs.test", "m.room.member", Some("@irc_dave:hs.test"), json!({"membership": "leave"}))).await;
        assert!(!fresh.event(&msg("!g:hs.test", "@alice:hs.test")).await.unwrap());
    }

    #[tokio::test]
    async fn private_receipts_only_for_namespace_users() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::default());
        let svc = svc(r"^@irc_.*:hs\.test$", &[r"^!bridged:"], &[]);
        let ctx = ctx(Arc::clone(&storage));
        let mut interest = Interest::new(&svc, &ctx);
        let rows = vec![
            ("!bridged:hs.test".to_owned(), "@alice:hs.test".to_owned(), "m.read".to_owned(), "$e".to_owned(), 5, 1),
            ("!bridged:hs.test".to_owned(), "@alice:hs.test".to_owned(), "m.read.private".to_owned(), "$e".to_owned(), 6, 2),
            ("!bridged:hs.test".to_owned(), "@irc_x:hs.test".to_owned(), "m.read.private".to_owned(), "$e".to_owned(), 7, 3),
            ("!other:hs.test".to_owned(), "@irc_x:hs.test".to_owned(), "m.read".to_owned(), "$o".to_owned(), 8, 4),
        ];
        let edus = interest.receipts(&rows).await.unwrap();
        assert_eq!(edus.len(), 1);
        assert_eq!(edus[0]["room_id"], "!bridged:hs.test");
        let content = &edus[0]["content"]["$e"];
        assert_eq!(content["m.read"]["@alice:hs.test"]["ts"], 5);
        assert!(content["m.read.private"].get("@alice:hs.test").is_none());
        assert_eq!(content["m.read.private"]["@irc_x:hs.test"]["ts"], 7);
    }

    #[test]
    fn pushed_events_drop_the_client_transaction_id() {
        let ev = event("$m", "!r:hs.test", "@a:hs.test", "m.room.message", None, json!({"body": "x"}));
        let value = format_event(&ev, 10);
        assert!(value["unsigned"].get("transaction_id").is_none());
        assert_eq!(value["unsigned"]["age"], 9);
        assert!(value.get("hashes").is_none());
    }

    #[tokio::test]
    async fn memory_cursor_freezes_transactions_with_durable_ids() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::default());
        let c = cursor(storage.as_ref(), "x").await.unwrap();
        assert_eq!(c, AppserviceCursor::default());
        let advanced = AppserviceCursor { event_pos: 3, receipt_pos: 1 };
        assert_eq!(storage.appservice_enqueue_txn("x", None, &advanced).await.unwrap(), None);
        let one = storage.appservice_enqueue_txn("x", Some(&json!({"n": 1})), &advanced).await.unwrap();
        let two = storage.appservice_enqueue_txn("x", Some(&json!({"n": 2})), &advanced).await.unwrap();
        assert_eq!((one, two), (Some(1), Some(2)));
        assert_eq!(storage.appservice_pending_txn("x").await.unwrap(), Some((1, json!({"n": 1}))));
        storage.appservice_complete_txn("x", 1).await.unwrap();
        assert_eq!(storage.appservice_pending_txn("x").await.unwrap(), Some((2, json!({"n": 2}))));
        assert_eq!(cursor(storage.as_ref(), "x").await.unwrap(), advanced);
    }
}
