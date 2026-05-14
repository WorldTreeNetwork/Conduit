//! Bounded in-memory cache of recently-processed event IDs (conduit-3qj).
//!
//! Used by [`super::pipeline::process_incoming_pdu`] as a cheap pre-filter to
//! short-circuit duplicate PDUs without a storage round-trip. False negatives
//! (cache misses on events we *have* seen) just fall through to the existing
//! `storage.get_event` dedup — they cost a DB hit but are otherwise correct.

use std::collections::{HashSet, VecDeque};

use tokio::sync::Mutex;

const DEFAULT_CAPACITY: usize = 10_000;

/// FIFO-eviction set of recently-seen event IDs.
///
/// Cheap stand-in for a true bloom filter — exact membership (no false
/// positives) at the cost of `O(capacity)` memory and per-entry hashing.
pub struct RecentEventCache {
    inner: Mutex<Inner>,
    capacity: usize,
}

struct Inner {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl RecentEventCache {
    /// Create a cache with the default capacity (10,000 entries).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                set: HashSet::with_capacity(capacity),
                order: VecDeque::with_capacity(capacity),
            }),
            capacity,
        }
    }

    /// Returns `true` when `event_id` was previously inserted and not yet evicted.
    pub async fn contains(&self, event_id: &str) -> bool {
        self.inner.lock().await.set.contains(event_id)
    }

    /// Insert `event_id`; evict the oldest entry if at capacity.
    pub async fn insert(&self, event_id: &str) {
        let mut g = self.inner.lock().await;
        if g.set.contains(event_id) {
            return;
        }
        if g.order.len() >= self.capacity {
            if let Some(victim) = g.order.pop_front() {
                g.set.remove(&victim);
            }
        }
        g.order.push_back(event_id.to_owned());
        g.set.insert(event_id.to_owned());
    }
}

impl Default for RecentEventCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn insert_then_contains() {
        let c = RecentEventCache::new();
        assert!(!c.contains("$a").await);
        c.insert("$a").await;
        assert!(c.contains("$a").await);
    }

    #[tokio::test]
    async fn duplicate_insert_is_a_no_op() {
        let c = RecentEventCache::with_capacity(3);
        c.insert("$a").await;
        c.insert("$a").await;
        c.insert("$a").await;
        assert!(c.contains("$a").await);
        // Other slots are still free.
        c.insert("$b").await;
        c.insert("$c").await;
        assert!(c.contains("$a").await);
        assert!(c.contains("$b").await);
        assert!(c.contains("$c").await);
    }

    #[tokio::test]
    async fn fifo_eviction_drops_oldest() {
        let c = RecentEventCache::with_capacity(3);
        c.insert("$a").await;
        c.insert("$b").await;
        c.insert("$c").await;
        c.insert("$d").await; // evicts $a
        assert!(!c.contains("$a").await);
        assert!(c.contains("$b").await);
        assert!(c.contains("$c").await);
        assert!(c.contains("$d").await);
    }
}
