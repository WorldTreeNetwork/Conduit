//! Room summaries and lazy-loading redundancy for `/sync` (conduit-y99.13.4).

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};

use conduit::storage::Storage;

/// Maximum number of heroes reported (the spec suggests clients use five).
const MAX_HEROES: usize = 5;

/// `RoomSummary` for `room` as seen by `user`, plus the hero user IDs.
///
/// Counts come from current membership. Heroes are reported when the room has
/// no non-empty `m.room.name` or `m.room.canonical_alias`: up to five other
/// joined or invited members in membership order, or, when there are none,
/// members who left or were banned.
pub async fn summary(storage: &dyn Storage, room: &str, user: &str) -> conduit::Result<(Value, Vec<String>)> {
    let state = storage.get_current_state(room).await?;
    let named = state.iter().any(|event| {
        event.state_key.as_deref() == Some("")
            && ((event.event_type == "m.room.name"
                && event.content["name"].as_str().is_some_and(|name| !name.is_empty()))
                || (event.event_type == "m.room.canonical_alias"
                    && event.content["alias"].as_str().is_some_and(|alias| !alias.is_empty())))
    });
    let members: Vec<_> = state
        .iter()
        .filter(|event| event.event_type == "m.room.member")
        .filter_map(|event| {
            event
                .state_key
                .clone()
                .map(|member| (member, event.content["membership"].as_str().unwrap_or_default().to_owned(), event.event_id.clone()))
        })
        .collect();
    let joined = members.iter().filter(|(_, membership, _)| membership == "join").count();
    let invited = members.iter().filter(|(_, membership, _)| membership == "invite").count();
    let mut body = json!({"m.joined_member_count": joined, "m.invited_member_count": invited});
    let mut heroes = Vec::new();
    if !named {
        let ids: Vec<_> = members.iter().map(|(_, _, id)| id.clone()).collect();
        let positions = storage.event_stream_positions(&ids).await?;
        let mut ordered: Vec<_> = members.iter().filter(|(member, _, _)| member != user).collect();
        ordered.sort_by_key(|(member, _, id)| (positions.get(id).copied().unwrap_or(i64::MAX), member.clone()));
        let pick = |wanted: &[&str]| -> Vec<String> {
            ordered
                .iter()
                .filter(|(_, membership, _)| wanted.contains(&membership.as_str()))
                .take(MAX_HEROES)
                .map(|(member, _, _)| member.clone())
                .collect()
        };
        heroes = pick(&["join", "invite"]);
        if heroes.is_empty() {
            heroes = pick(&["leave", "ban"]);
        }
        body["m.heroes"] = json!(heroes);
    }
    Ok((body, heroes))
}

/// Member events already sent to a device under lazy loading: per
/// `(user, device)`, `(room, member) -> (event ID, events position of the
/// response that carried it)`. A member event counts as known only when the
/// client's `since` is at or after that response, so a lost response is
/// re-sent rather than assumed. Process-local: a restart only causes
/// (permitted) redundant membership events.
type SentMembers = HashMap<(String, String), (String, i64)>;

static LAZY_SENT: Mutex<Option<HashMap<(String, String), SentMembers>>> = Mutex::new(None);

/// Bound on tracked devices; the cache is cleared rather than grown past it.
const MAX_TRACKED_DEVICES: usize = 10_000;

fn with_cache<R>(f: impl FnOnce(&mut HashMap<(String, String), SentMembers>) -> R) -> R {
    let mut guard = LAZY_SENT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(guard.get_or_insert_with(HashMap::new))
}

/// Forget everything sent to a device (initial or full-state sync).
pub fn forget_device(user: &str, device: &str) {
    with_cache(|cache| {
        cache.remove(&(user.to_owned(), device.to_owned()));
    });
}

/// Has this exact member event already reached the client at `since`?
pub fn already_sent(user: &str, device: &str, room: &str, member: &str, event_id: &str, since: i64) -> bool {
    with_cache(|cache| {
        cache
            .get(&(user.to_owned(), device.to_owned()))
            .and_then(|sent| sent.get(&(room.to_owned(), member.to_owned())))
            .is_some_and(|(id, position)| id == event_id && *position <= since)
    })
}

/// Record member events carried by a response whose events cursor is `position`.
pub fn record_sent(user: &str, device: &str, entries: Vec<(String, String, String)>, position: i64) {
    if entries.is_empty() {
        return;
    }
    with_cache(|cache| {
        if cache.len() >= MAX_TRACKED_DEVICES && !cache.contains_key(&(user.to_owned(), device.to_owned())) {
            cache.clear();
        }
        let sent = cache.entry((user.to_owned(), device.to_owned())).or_default();
        for (room, member, event_id) in entries {
            let key = (room, member);
            // Keep the earliest delivery of the same event.
            if sent.get(&key).is_some_and(|(id, _)| *id == event_id) {
                continue;
            }
            sent.insert(key, (event_id, position));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_events_are_known_only_after_the_carrying_response() {
        let (user, device) = ("@lazy-test:x", "DEV");
        forget_device(user, device);
        record_sent(user, device, vec![("!r".into(), "@m:x".into(), "$e1".into())], 10);
        assert!(!already_sent(user, device, "!r", "@m:x", "$e1", 9), "response at 10 may have been lost");
        assert!(already_sent(user, device, "!r", "@m:x", "$e1", 10));
        assert!(!already_sent(user, device, "!r", "@m:x", "$e2", 10), "a changed membership is not redundant");
        record_sent(user, device, vec![("!r".into(), "@m:x".into(), "$e1".into())], 20);
        assert!(already_sent(user, device, "!r", "@m:x", "$e1", 10), "re-sending keeps the earliest delivery");
        forget_device(user, device);
        assert!(!already_sent(user, device, "!r", "@m:x", "$e1", 10));
    }
}
