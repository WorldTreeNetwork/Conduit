//! Device-list tracking visibility (conduit-y99.14).
//!
//! `/sync` `device_lists` and `GET /keys/changes` must not leak key activity
//! globally. A user appears in `changed` when they updated device or
//! cross-signing keys and share a joined room with the requester (or are the
//! requester), or when they newly share an encrypted room with the requester.
//! A user appears in `left` when the requester no longer shares any encrypted
//! room with them after a membership change in the window.

use std::collections::{BTreeSet, HashMap, HashSet};

use conduit::event::Event;
use conduit::storage::Storage;

/// Membership of one room the requester is currently joined to.
#[derive(Debug, Default, Clone)]
pub struct RoomPeers {
    pub encrypted: bool,
    pub members: HashSet<String>,
}

/// The requester's currently joined rooms and their joined members.
#[derive(Debug, Default, Clone)]
pub struct JoinedRoomIndex {
    pub rooms: HashMap<String, RoomPeers>,
}

impl JoinedRoomIndex {
    pub async fn load(storage: &dyn Storage, user: &str) -> conduit::Result<Self> {
        let mut rooms = HashMap::new();
        for room in storage.joined_rooms(user).await? {
            rooms.insert(room.clone(), room_peers(storage, &room).await?);
        }
        Ok(Self { rooms })
    }

    /// Users sharing at least one joined room (any encryption).
    pub fn peers(&self) -> HashSet<String> {
        self.rooms.values().flat_map(|room| room.members.iter().cloned()).collect()
    }

    /// Users sharing at least one encrypted joined room.
    pub fn encrypted_peers(&self) -> HashSet<String> {
        self.rooms
            .values()
            .filter(|room| room.encrypted)
            .flat_map(|room| room.members.iter().cloned())
            .collect()
    }
}

/// Current encryption flag and joined members of `room`.
pub async fn room_peers(storage: &dyn Storage, room: &str) -> conduit::Result<RoomPeers> {
    let mut peers = RoomPeers::default();
    for event in storage.get_current_state(room).await? {
        if event.event_type == "m.room.encryption" && event.state_key.as_deref() == Some("") {
            peers.encrypted = true;
        }
        if event.event_type == "m.room.member" && event.content["membership"] == "join" {
            if let Some(member) = event.pdu.state_key {
                peers.members.insert(member);
            }
        }
    }
    Ok(peers)
}

/// Compute `(changed, left)` for `user`.
///
/// `key_updates` are the users whose device lists changed in the window;
/// `window_events` are the room events committed in the same window.
pub async fn device_list_delta(
    storage: &dyn Storage,
    user: &str,
    index: &JoinedRoomIndex,
    key_updates: &[String],
    window_events: &[Event],
) -> conduit::Result<(Vec<String>, Vec<String>)> {
    let encrypted_peers = index.encrypted_peers();
    // Key updates are visible to anyone sharing a joined room, as for
    // `/keys/changes`; clients track the members of their encrypted rooms.
    let visible = index.peers();
    let mut changed: BTreeSet<String> = key_updates
        .iter()
        .filter(|updated| updated.as_str() == user || visible.contains(updated.as_str()))
        .cloned()
        .collect();
    let mut left = BTreeSet::new();
    let mut departed_rooms: HashMap<String, RoomPeers> = HashMap::new();
    for event in window_events {
        let joined_now = index.rooms.get(&event.room_id);
        match event.event_type.as_str() {
            // Encryption enabled: every member now shares an encrypted room.
            "m.room.encryption" if event.state_key.as_deref() == Some("") => {
                if let Some(room) = joined_now.filter(|room| room.encrypted) {
                    changed.extend(room.members.iter().cloned());
                }
            }
            "m.room.member" => {
                let Some(target) = event.state_key.as_deref() else { continue };
                let membership = event.content["membership"].as_str().unwrap_or_default();
                if membership == "join" {
                    let Some(room) = joined_now.filter(|room| room.encrypted) else { continue };
                    if target == user {
                        // We joined: everyone in the room is newly shared.
                        changed.extend(room.members.iter().cloned());
                    } else if room.members.contains(target) {
                        changed.insert(target.to_owned());
                    }
                } else if matches!(membership, "leave" | "ban") {
                    if target == user {
                        if joined_now.is_some() {
                            continue; // Rejoined later in the window.
                        }
                        if !departed_rooms.contains_key(&event.room_id) {
                            let peers = room_peers(storage, &event.room_id).await?;
                            departed_rooms.insert(event.room_id.clone(), peers);
                        }
                        let room = &departed_rooms[&event.room_id];
                        if room.encrypted {
                            left.extend(
                                room.members
                                    .iter()
                                    .filter(|member| !encrypted_peers.contains(*member))
                                    .cloned(),
                            );
                        }
                    } else if joined_now.is_some_and(|room| room.encrypted)
                        && !encrypted_peers.contains(target)
                    {
                        left.insert(target.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    left.remove(user);
    for user in &left {
        changed.remove(user);
    }
    Ok((changed.into_iter().collect(), left.into_iter().collect()))
}
