//! Durable per-destination outbound federation send queue (conduit-5n3).
//!
//! ## Design
//!
//! - Every enqueued batch is persisted to the `fed_outbound_queue` Postgres
//!   table before any in-memory state is touched, so restarts never drop
//!   undelivered work.
//! - One async worker task per destination owns dispatching for that dest.
//!   Workers are spawned on first enqueue and on boot for any destination
//!   that already has pending rows.
//! - Workers consume a [`tokio::sync::Notify`] wake-signal AND poll
//!   periodically (default 30 s) so retries fire even when no new enqueues
//!   arrive.
//! - On send failure the worker computes `backoff = min(2^attempts s, 300 s)`,
//!   updates the row's `attempts` + `next_attempt_at`, and loops. After
//!   `MAX_ATTEMPTS` attempts the row is marked `dead` for manual inspection.
//!
//! ## Public API
//!
//! [`Queue::enqueue`] preserves the legacy `(dest, pdus, edus)` shape for
//! callers that send transactions. [`Queue::enqueue_to_device`] is the
//! durable path used by remote sendToDevice (conduit-0t6).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::{json, Value};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};
use uuid::Uuid;

use conduit::event::Event;
use conduit::storage::{OutboundEntry, Storage};

use super::client::Client;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Max retries before a row is dead-lettered. With 2^attempts backoff capped
/// at 300 s, 20 attempts ≈ 1 h cumulative wait.
const MAX_ATTEMPTS: i32 = 20;
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const WORKER_POLL_INTERVAL: Duration = Duration::from_secs(30);
const DRAIN_BATCH_SIZE: i64 = 32;

// ---------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------

/// Per-destination Notify + the worker JoinHandle that consumes it.
/// Storing the handle lets `ensure_worker` detect dead tasks (panic or
/// normal exit) and respawn (conduit-5l9).
struct WorkerSlot {
    notify: Arc<Notify>,
    handle: JoinHandle<()>,
}

/// Per-destination workers + their wake signals.
pub struct Queue {
    client: Arc<Client>,
    storage: Arc<dyn Storage>,
    workers: Mutex<HashMap<String, WorkerSlot>>,
}

impl Queue {
    /// Create a new Queue. Call [`Queue::start`] once at boot to spawn
    /// workers for any destinations with pending rows left over from a
    /// previous run.
    pub fn new(client: Arc<Client>, storage: Arc<dyn Storage>) -> Self {
        Self {
            client,
            storage,
            workers: Mutex::new(HashMap::new()),
        }
    }

    /// Spawn workers for every destination with at least one pending row.
    /// Idempotent — repeated calls are safe.
    pub async fn start(&self) {
        let dests = match self.storage.outbound_destinations_with_pending().await {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "outbound queue: boot recovery query failed");
                return;
            }
        };
        if dests.is_empty() {
            debug!("outbound queue: no pending rows at boot");
            return;
        }
        debug!(count = dests.len(), "outbound queue: spawning recovery workers");
        for dest in dests {
            self.ensure_worker(&dest).await;
        }
    }

    /// Legacy API: persist + dispatch a PDU + EDU batch.
    pub async fn enqueue(&self, dest: &str, pdus: Vec<Event>, edus: Vec<Value>) {
        let payload = json!({ "pdus": pdus, "edus": edus });
        self.persist_and_signal(dest, "transaction", &payload).await;
    }

    /// Persist + dispatch a federation /sendToDevice payload (conduit-0t6).
    pub async fn enqueue_to_device(
        &self,
        dest: &str,
        event_type: &str,
        messages: Value,
    ) {
        let payload = json!({ "event_type": event_type, "messages": messages });
        self.persist_and_signal(dest, "to_device", &payload).await;
    }

    async fn persist_and_signal(&self, dest: &str, kind: &str, payload: &Value) {
        let txn_id = Uuid::new_v4().to_string();
        match self
            .storage
            .enqueue_outbound(dest, kind, &txn_id, payload)
            .await
        {
            Ok(id) => {
                debug!(dest = dest, id, kind, "outbound queue: row persisted");
            }
            Err(e) => {
                error!(dest = dest, kind, error = %e, "outbound queue: persist failed");
                return;
            }
        }
        self.ensure_worker(dest).await.notify_one();
    }

    /// Get or create the Notify handle for `dest`, spawning the worker if
    /// it isn't already running OR if the previous one died (panic, normal
    /// exit, or runtime shutdown). conduit-5l9.
    async fn ensure_worker(&self, dest: &str) -> Arc<Notify> {
        let mut guard = self.workers.lock().await;
        // Live worker? Reuse.
        if let Some(slot) = guard.get(dest) {
            if !slot.handle.is_finished() {
                return Arc::clone(&slot.notify);
            }
            // Stale entry — fall through to respawn.
            warn!(dest, "outbound worker had exited; respawning");
        }
        let notify = Arc::new(Notify::new());
        let client = Arc::clone(&self.client);
        let storage = Arc::clone(&self.storage);
        let notify_for_worker = Arc::clone(&notify);
        let dest_owned = dest.to_owned();
        let handle = tokio::spawn(async move {
            worker_loop(client, storage, dest_owned, notify_for_worker).await;
        });
        guard.insert(
            dest.to_owned(),
            WorkerSlot {
                notify: Arc::clone(&notify),
                handle,
            },
        );
        notify
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

async fn worker_loop(
    client: Arc<Client>,
    storage: Arc<dyn Storage>,
    dest: String,
    notify: Arc<Notify>,
) {
    debug!(dest = %dest, "outbound worker started");
    loop {
        // Drain ready rows.
        match storage.next_pending_outbound(&dest, DRAIN_BATCH_SIZE).await {
            Ok(rows) if !rows.is_empty() => {
                for row in rows {
                    dispatch_one(&client, &storage, &dest, row).await;
                }
                // Loop back immediately to check for more.
                continue;
            }
            Ok(_) => {} // empty — fall through to sleep
            Err(e) => {
                error!(dest = %dest, error = %e, "outbound worker: next_pending query failed");
            }
        }

        // Sleep until the soonest scheduled retry, or until a wake signal,
        // or until the safety poll interval — whichever comes first.
        let sleep_dur = match storage.outbound_next_eta_ms(&dest).await {
            Ok(Some(eta_ms)) => {
                let now_ms = Utc::now().timestamp_millis();
                if eta_ms <= now_ms {
                    Duration::from_millis(0)
                } else {
                    Duration::from_millis((eta_ms - now_ms) as u64)
                }
            }
            Ok(None) => WORKER_POLL_INTERVAL,
            Err(e) => {
                error!(dest = %dest, error = %e, "outbound worker: eta query failed");
                WORKER_POLL_INTERVAL
            }
        };
        // Cap so a wildly-future eta doesn't make us miss a signal.
        let sleep_dur = sleep_dur.min(WORKER_POLL_INTERVAL);
        tokio::select! {
            _ = notify.notified() => {}
            _ = tokio::time::sleep(sleep_dur) => {}
        }
    }
}

async fn dispatch_one(
    client: &Arc<Client>,
    storage: &Arc<dyn Storage>,
    dest: &str,
    entry: OutboundEntry,
) {
    let result: Result<(), String> = match entry.kind.as_str() {
        "transaction" => send_transaction(client, dest, &entry).await,
        "to_device" => send_to_device(client, dest, &entry).await,
        other => {
            error!(dest, id = entry.id, kind = other, "unknown outbound queue kind");
            // Dead-letter unknown kinds — they cannot be retried productively.
            let _ = storage
                .mark_outbound_dead(entry.id, &format!("unknown kind: {other}"))
                .await;
            return;
        }
    };

    match result {
        Ok(()) => {
            debug!(dest, id = entry.id, kind = entry.kind, "outbound delivered");
            if let Err(e) = storage.mark_outbound_sent(entry.id).await {
                warn!(dest, id = entry.id, error = %e, "mark_outbound_sent failed");
            }
        }
        Err(err) => {
            let attempts = entry.attempts + 1;
            if attempts >= MAX_ATTEMPTS {
                warn!(
                    dest,
                    id = entry.id,
                    attempts,
                    error = %err,
                    "outbound: max attempts reached, dead-lettering"
                );
                let _ = storage.mark_outbound_dead(entry.id, &err).await;
            } else {
                let backoff = backoff_for(attempts);
                let next_ms =
                    Utc::now().timestamp_millis() + backoff.as_millis() as i64;
                warn!(
                    dest,
                    id = entry.id,
                    attempts,
                    backoff_secs = backoff.as_secs(),
                    error = %err,
                    "outbound: scheduling retry"
                );
                let _ = storage
                    .mark_outbound_failed(entry.id, attempts, next_ms, &err)
                    .await;
            }
        }
    }
}

async fn send_transaction(
    client: &Arc<Client>,
    dest: &str,
    entry: &OutboundEntry,
) -> Result<(), String> {
    let pdus_val = entry.payload.get("pdus").cloned().unwrap_or_else(|| json!([]));
    let edus_val = entry.payload.get("edus").cloned().unwrap_or_else(|| json!([]));

    let pdus: Vec<Event> = serde_json::from_value(pdus_val).map_err(|e| e.to_string())?;
    let edus: Vec<Value> = serde_json::from_value(edus_val).map_err(|e| e.to_string())?;

    match client.send_transaction(dest, &entry.txn_id, pdus, edus).await {
        Ok(resp) => {
            // Log per-PDU errors but treat the call as successful so the row
            // is retired — the remote chose to reject specific PDUs and
            // retrying the whole batch won't help.
            let rejected: Vec<&str> = resp
                .pdus
                .iter()
                .filter(|(_, v)| v.is_object() && v.get("error").is_some())
                .map(|(id, _)| id.as_str())
                .collect();
            if !rejected.is_empty() {
                warn!(
                    dest,
                    txn_id = %entry.txn_id,
                    "remote rejected {} PDU(s): {:?}",
                    rejected.len(),
                    rejected
                );
            }
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

async fn send_to_device(
    client: &Arc<Client>,
    dest: &str,
    entry: &OutboundEntry,
) -> Result<(), String> {
    let event_type = entry
        .payload
        .get("event_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "to_device payload missing event_type".to_owned())?;
    let messages = entry
        .payload
        .get("messages")
        .cloned()
        .ok_or_else(|| "to_device payload missing messages".to_owned())?;
    client
        .send_to_device(dest, &entry.txn_id, event_type, messages)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Backoff: 2^attempts seconds, capped at `MAX_BACKOFF`.
/// attempts=1 → 2s, attempts=8 → 256s, attempts≥9 → 300s.
fn backoff_for(attempts: i32) -> Duration {
    let secs = 1u64.checked_shl(attempts.min(20) as u32).unwrap_or(u64::MAX);
    Duration::from_secs(secs).min(MAX_BACKOFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_then_caps() {
        assert_eq!(backoff_for(1).as_secs(), 2);
        assert_eq!(backoff_for(2).as_secs(), 4);
        assert_eq!(backoff_for(3).as_secs(), 8);
        assert_eq!(backoff_for(8).as_secs(), 256);
        // 2^9 = 512 → capped at 300
        assert_eq!(backoff_for(9).as_secs(), 300);
        assert_eq!(backoff_for(20).as_secs(), 300);
    }
}
