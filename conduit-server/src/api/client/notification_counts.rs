//! Unread notification counts for `/sync`, push gateways and
//! `/notifications` (conduit-y99.13.4, conduit-y99.30).
//!
//! Push rules are evaluated once per event by the push engine
//! (`push::notifications::process_pending`), which stores the notifying
//! events per user. An event counts as unread when it is after the user's
//! read-up-to point for its thread scope: the later of the unthreaded
//! receipt and the scope's own threaded receipt (`m.read` or
//! `m.read.private`, whichever is ahead). The user's own latest event in a
//! scope also marks it read. Highlights are the notifying events whose
//! actions set the `highlight` tweak.

use std::collections::HashMap;

use serde_json::{json, Value};

use conduit::storage::{PushNotification, Storage};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub notification_count: u64,
    pub highlight_count: u64,
}

impl Counts {
    pub fn to_json(self) -> Value {
        json!({"notification_count": self.notification_count, "highlight_count": self.highlight_count})
    }

    fn add(&mut self, highlight: bool) {
        self.notification_count += 1;
        if highlight {
            self.highlight_count += 1;
        }
    }
}

/// Counts for one room: the main-timeline counts and, keyed by thread
/// root, the per-thread counts.
#[derive(Debug, Default, Clone)]
pub struct RoomCounts {
    pub main: Counts,
    pub threads: HashMap<String, Counts>,
}

impl RoomCounts {
    /// Whole-room counts when the client did not ask for thread partitioning.
    pub fn total(&self) -> Counts {
        self.threads.values().fold(self.main, |sum, counts| Counts {
            notification_count: sum.notification_count + counts.notification_count,
            highlight_count: sum.highlight_count + counts.highlight_count,
        })
    }
}

/// Where a user has read up to in a room: the unthreaded point and, per
/// scope (`main` or a thread root), the scope's own point.
#[derive(Debug, Default, Clone)]
pub struct ReadPoints {
    pub unthreaded: i64,
    pub scoped: HashMap<String, i64>,
}

impl ReadPoints {
    /// The read-up-to position for events in `thread` (`None` = main).
    pub fn for_thread(&self, thread: Option<&str>) -> i64 {
        let scope = thread.unwrap_or("main");
        self.unthreaded.max(self.scoped.get(scope).copied().unwrap_or(0))
    }
}

/// Read points from receipts and the user's own events.
pub async fn read_points(storage: &dyn Storage, user: &str, room: &str) -> conduit::Result<ReadPoints> {
    let receipts: Vec<_> = storage
        .user_receipts_in_room(room, user)
        .await?
        .into_iter()
        .filter(|r| matches!(r.receipt_type.as_str(), "m.read" | "m.read.private"))
        .collect();
    let ids: Vec<_> = receipts.iter().map(|r| r.event_id.clone()).collect();
    let positions = storage.event_stream_positions(&ids).await?;
    let mut points = ReadPoints::default();
    for receipt in receipts {
        let Some(&pos) = positions.get(&receipt.event_id) else { continue };
        match receipt.thread_id {
            None => points.unthreaded = points.unthreaded.max(pos),
            Some(scope) => {
                let entry = points.scoped.entry(scope).or_insert(0);
                *entry = (*entry).max(pos);
            }
        }
    }
    for (scope, pos) in storage.push_read_marks(user, room).await? {
        let entry = points.scoped.entry(scope).or_insert(0);
        *entry = (*entry).max(pos);
    }
    Ok(points)
}

/// Unread counts for `user` in `room`. Call
/// `push::notifications::process_pending` first so the newest events are
/// included.
pub async fn room_counts(storage: &dyn Storage, user: &str, room: &str) -> conduit::Result<RoomCounts> {
    let points = read_points(storage, user, room).await?;
    let mut counts = RoomCounts::default();
    for (thread, pos, highlight) in storage.unread_push_notifications(user, room, points.unthreaded).await? {
        if pos <= points.for_thread(thread.as_deref()) {
            continue;
        }
        match thread {
            None => counts.main.add(highlight),
            Some(root) => counts.threads.entry(root).or_default().add(highlight),
        }
    }
    Ok(counts)
}

/// Total unread notifications across the user's joined rooms (the push
/// gateway's `counts.unread` badge).
pub async fn total_unread(storage: &dyn Storage, user: &str) -> conduit::Result<u64> {
    let mut total = 0;
    for room in storage.joined_rooms(user).await? {
        total += room_counts(storage, user, &room).await?.total().notification_count;
    }
    Ok(total)
}

/// Whether a stored notification is covered by the user's read points
/// (`read` in `/notifications`). `cache` holds read points per room.
pub async fn is_read(
    storage: &dyn Storage,
    cache: &mut HashMap<String, ReadPoints>,
    user: &str,
    notification: &PushNotification,
) -> conduit::Result<bool> {
    if !cache.contains_key(&notification.room_id) {
        let points = read_points(storage, user, &notification.room_id).await?;
        cache.insert(notification.room_id.clone(), points);
    }
    Ok(notification.stream_pos <= cache[&notification.room_id].for_thread(notification.thread_id.as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_fold_threads_into_main() {
        let mut counts = RoomCounts::default();
        counts.main.add(false);
        counts.threads.entry("$t".into()).or_default().add(true);
        counts.threads.entry("$t".into()).or_default().add(false);
        assert_eq!(counts.total(), Counts { notification_count: 3, highlight_count: 1 });
    }

    #[test]
    fn read_points_take_the_later_of_unthreaded_and_scope() {
        let points = ReadPoints {
            unthreaded: 5,
            scoped: HashMap::from([("main".to_owned(), 9), ("$t".to_owned(), 3)]),
        };
        assert_eq!(points.for_thread(None), 9);
        assert_eq!(points.for_thread(Some("$t")), 5);
        assert_eq!(points.for_thread(Some("$other")), 5);
    }
}
