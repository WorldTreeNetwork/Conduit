//! Per-destination outbound federation send queue with exponential backoff.
//!
//! ## Design
//!
//! - One async worker task per destination server.
//! - Each worker drains a [`tokio::sync::mpsc`] channel.
//! - On `send_transaction` failure the worker backs off exponentially
//!   (1 s → 2 s → 4 s … capped at 5 minutes) before retrying the same batch.
//! - On success, the backoff resets and the worker moves to the next batch.
//! - The queue does **not** persist across restarts (tracked as a follow-up).
//!
//! ## Usage
//!
//! ```ignore
//! let queue = Arc::new(Queue::new(Arc::clone(&federation_client)));
//! queue.enqueue("matrix.org", vec![event], vec![]).await;
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, warn};
use uuid::Uuid;

use conduit::event::Event;

use super::client::Client;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(300); // 5 minutes
const CHANNEL_CAPACITY: usize = 1024;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single batch of PDUs + EDUs destined for one remote server.
struct Batch {
    txn_id: String,
    pdus: Vec<Event>,
    edus: Vec<Value>,
}

// ---------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------

/// A map of per-destination send queues.
///
/// New destination workers are spawned on demand when [`Queue::enqueue`] is
/// called for a previously-unseen server name.
pub struct Queue {
    client: Arc<Client>,
    /// Sender halves keyed by destination server name.
    senders: Mutex<HashMap<String, mpsc::Sender<Batch>>>,
}

impl Queue {
    /// Create a new `Queue` backed by the given `Client`.
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            senders: Mutex::new(HashMap::new()),
        }
    }

    /// Enqueue a batch of PDUs and EDUs for delivery to `dest`.
    ///
    /// If no worker exists for `dest`, one is spawned.  The call returns
    /// immediately without waiting for delivery.
    pub async fn enqueue(&self, dest: &str, pdus: Vec<Event>, edus: Vec<Value>) {
        let mut guard = self.senders.lock().await;

        // Get or create the sender for this destination.
        let sender = guard.entry(dest.to_owned()).or_insert_with(|| {
            let (tx, rx) = mpsc::channel::<Batch>(CHANNEL_CAPACITY);
            let client = Arc::clone(&self.client);
            let destination = dest.to_owned();
            tokio::spawn(async move {
                worker(client, destination, rx).await;
            });
            tx
        });

        let batch = Batch {
            txn_id: Uuid::new_v4().to_string(),
            pdus,
            edus,
        };

        if let Err(e) = sender.send(batch).await {
            error!(dest = dest, "failed to enqueue federation batch: {}", e);
        }
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// Long-running worker task for a single destination.
///
/// Reads batches from `rx`, attempts delivery via `client.send_transaction`,
/// and retries with exponential backoff on failure.
async fn worker(client: Arc<Client>, dest: String, mut rx: mpsc::Receiver<Batch>) {
    debug!(dest = %dest, "federation worker started");

    while let Some(batch) = rx.recv().await {
        let mut backoff = INITIAL_BACKOFF;

        loop {
            match client
                .send_transaction(&dest, &batch.txn_id, batch.pdus.clone(), batch.edus.clone())
                .await
            {
                Ok(resp) => {
                    // Check for per-PDU errors in the response.
                    let failed: Vec<_> = resp
                        .pdus
                        .iter()
                        .filter(|(_, v)| v.is_object() && v.get("error").is_some())
                        .map(|(id, _)| id.as_str())
                        .collect();
                    if !failed.is_empty() {
                        warn!(
                            dest = %dest,
                            txn_id = %batch.txn_id,
                            "remote rejected {} PDU(s): {:?}",
                            failed.len(),
                            failed
                        );
                    }
                    debug!(dest = %dest, txn_id = %batch.txn_id, "transaction delivered");
                    break; // success — move to next batch
                }
                Err(e) => {
                    warn!(
                        dest = %dest,
                        txn_id = %batch.txn_id,
                        backoff_secs = backoff.as_secs(),
                        "send_transaction failed: {e}; retrying after backoff"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    debug!(dest = %dest, "federation worker exiting (channel closed)");
}
