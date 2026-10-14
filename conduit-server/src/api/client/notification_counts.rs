//! Unread notification counts for `/sync` (conduit-y99.13.4).
//!
//! An event counts as an unread notification for a user when the user's push
//! rules give it the `notify` action, it was not sent by the user, and it is
//! after the user's read-up-to point for its thread scope. The read-up-to
//! point is the later of the unthreaded receipt and the scope's own threaded
//! receipt (`m.read` or `m.read.private`, whichever is ahead), and the user's
//! own latest event in that scope also marks it read. Highlights are the
//! notifying events whose actions set the `highlight` tweak.

use std::collections::HashMap;

use serde_json::{json, Value};

use conduit::event::Event;
use conduit::storage::{PushRule, Storage};

use super::push::rules::{default_push_rules, evaluate_rule, EvalContext};

/// Upper bound on events examined per room; counts saturate beyond it.
const MAX_SCANNED_EVENTS: i64 = 1000;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub notification_count: u64,
    pub highlight_count: u64,
}

impl Counts {
    pub fn to_json(self) -> Value {
        json!({"notification_count": self.notification_count, "highlight_count": self.highlight_count})
    }
}

/// Counts for one room: the main-timeline (or whole-room) counts and, keyed
/// by thread root, the per-thread counts.
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

/// The user's effective push rules: stored rules plus any default rule the
/// user has not stored, evaluated by kind then priority.
pub async fn effective_push_rules(storage: &dyn Storage, user: &str) -> conduit::Result<Vec<PushRule>> {
    let mut rules = storage.list_push_rules(user).await?;
    for default in default_push_rules(user) {
        if !rules.iter().any(|rule| rule.kind == default.kind && rule.rule_id == default.rule_id) {
            rules.push(default);
        }
    }
    let rank = |kind: &str| match kind {
        "override" => 0,
        "content" => 1,
        "room" => 2,
        "sender" => 3,
        "underride" => 4,
        _ => 5,
    };
    rules.sort_by_key(|rule| (rank(&rule.kind), rule.priority));
    Ok(rules)
}

/// Compute unread counts for `user` in `room`.
pub async fn room_counts(
    storage: &dyn Storage,
    user: &str,
    room: &str,
    rules: &[PushRule],
    displayname: Option<&str>,
) -> conduit::Result<RoomCounts> {
    // Read-up-to positions per scope ("" = unthreaded).
    let receipts = storage.user_receipts_in_room(room, user).await?;
    let receipt_ids: Vec<_> = receipts.iter().map(|receipt| receipt.event_id.clone()).collect();
    let receipt_positions = storage.event_stream_positions(&receipt_ids).await?;
    let mut read: HashMap<String, i64> = HashMap::new();
    for receipt in &receipts {
        if !matches!(receipt.receipt_type.as_str(), "m.read" | "m.read.private") {
            continue;
        }
        if let Some(position) = receipt_positions.get(&receipt.event_id) {
            let scope = receipt.thread_id.clone().unwrap_or_default();
            let entry = read.entry(scope).or_insert(0);
            *entry = (*entry).max(*position);
        }
    }
    let unthreaded = read.get("").copied().unwrap_or(0);
    // Every scope's read point is at least the unthreaded one.
    let floor = read.values().copied().min().unwrap_or(0).min(unthreaded);

    let (events, _) = storage
        .room_events_paginated(room, 'f', floor.saturating_add(1), MAX_SCANNED_EVENTS)
        .await?;
    let ids: Vec<_> = events.iter().map(|event| event.event_id.clone()).collect();
    let positions = storage.event_stream_positions(&ids).await?;

    let state = storage.get_current_state(room).await?;
    let member_count = state
        .iter()
        .filter(|event| event.event_type == "m.room.member" && event.content["membership"] == "join")
        .count();
    let power_levels = state
        .iter()
        .find(|event| event.event_type == "m.room.power_levels" && event.state_key.as_deref() == Some(""))
        .map(|event| event.content.clone());

    // Classify events by scope; the user's own events also mark their scope read.
    let mut scoped: Vec<(i64, Option<String>, &Event)> = Vec::new();
    for event in &events {
        let Some(position) = positions.get(&event.event_id).copied() else { continue };
        let thread = super::receipts::thread_of(storage, event).await?;
        if event.sender == user {
            let scope = thread.clone().unwrap_or_else(|| "main".to_owned());
            let entry = read.entry(scope).or_insert(0);
            *entry = (*entry).max(position);
        }
        scoped.push((position, thread, event));
    }

    let mut counts = RoomCounts::default();
    for (position, thread, event) in scoped {
        if event.sender == user {
            continue;
        }
        let scope = thread.clone().unwrap_or_else(|| "main".to_owned());
        let read_up_to = unthreaded.max(read.get(&scope).copied().unwrap_or(0));
        if position <= read_up_to {
            continue;
        }
        let json = serde_json::to_value(event).unwrap_or(Value::Null);
        let context = EvalContext {
            event: &json,
            displayname,
            member_count,
            power_levels: power_levels.as_ref(),
            sender: &event.sender,
        };
        let Some(actions) = rules.iter().find_map(|rule| evaluate_rule(rule, &context)) else { continue };
        if !actions.should_notify {
            continue;
        }
        let slot = match thread {
            Some(root) => counts.threads.entry(root).or_default(),
            None => &mut counts.main,
        };
        slot.notification_count += 1;
        if actions.highlight {
            slot.highlight_count += 1;
        }
    }
    Ok(counts)
}
