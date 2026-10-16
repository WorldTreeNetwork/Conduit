//! Guest access revocation (Matrix v1.19 §Guest access; conduit-y99.18.4).
//!
//! When `m.room.guest_access` stops being `can_join`, the server MUST set
//! its guest members' membership to `leave`.  Each guest leaves on its
//! own behalf (a self-leave always passes auth), right after the state
//! change is persisted.

use serde_json::Value;

use conduit::room::{Room, RoomEventSender};
use conduit::storage::Storage;

use super::session::may_be_guest;

/// Whether a `m.room.guest_access` content still admits guests.
pub fn admits_guests(content: &Value) -> bool {
    content.get("guest_access").and_then(Value::as_str) == Some("can_join")
}

/// Called after a state event is persisted, including one accepted over
/// federation: when guest access was revoked, every local guest still
/// joined leaves the room.
pub async fn after_state_event(
    storage: &dyn Storage,
    server_name: &str,
    sender: &dyn RoomEventSender,
    room_id: &str,
    event_type: &str,
    content: &Value,
) {
    if event_type != "m.room.guest_access" || admits_guests(content) {
        return;
    }
    let members = match storage.get_current_state(room_id).await {
        Ok(events) => events,
        Err(e) => {
            tracing::warn!(room_id, error = %e, "guest revocation: state lookup failed");
            return;
        }
    };
    let suffix = format!(":{server_name}");
    for member in members {
        if member.event_type != "m.room.member"
            || member.content.get("membership").and_then(Value::as_str) != Some("join")
        {
            continue;
        }
        let Some(user_id) = member.state_key.as_deref() else { continue };
        if !user_id.ends_with(&suffix) || !may_be_guest(user_id) {
            continue;
        }
        let is_guest = matches!(storage.get_account(user_id).await, Ok(Some(a)) if a.is_guest);
        if !is_guest {
            continue;
        }
        // The kernel call goes through the boxed RoomEventSender, which
        // breaks the async recursion back into the event pipeline.
        if let Err(e) = Room::new(room_id)
            .leave(user_id, Some("Guest access was disabled"), sender)
            .await
        {
            tracing::warn!(room_id, user_id, error = %e, "guest revocation: leave failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_can_join_admits_guests() {
        assert!(admits_guests(&json!({"guest_access": "can_join"})));
        assert!(!admits_guests(&json!({"guest_access": "forbidden"})));
        assert!(!admits_guests(&json!({})));
    }
}
