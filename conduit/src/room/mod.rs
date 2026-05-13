//! Rooms — the unit of conversation in Matrix.
//!
//! A room is a DAG of events replicated across all participating
//! homeservers. The current state of a room is computed by resolving
//! the DAG; see [`state_res`].

pub mod state_res;

use std::collections::HashMap;

use crate::auth::StateMap;
use crate::event::Event;

/// A handle onto a room. Storage of the actual DAG lives in
/// [`crate::storage`]; this is a lightweight identifier + helpers.
#[derive(Debug, Clone)]
pub struct Room {
    pub room_id: String,
}

impl Room {
    pub fn new(room_id: impl Into<String>) -> Self {
        Self { room_id: room_id.into() }
    }
}

/// Compute the current state of a room from a collection of state set snapshots.
///
/// `state_sets` — each element is a `(event_type, state_key) → Event` map
/// representing a branch tip.
///
/// `auth_chain` — the union of all auth-chain events (event_id → Event) for
/// all events in all state sets.
///
/// Returns `Ok(resolved_state)` or a [`state_res::StateResError`].
pub fn current_state(
    state_sets: Vec<StateMap<Event>>,
    auth_chain: HashMap<String, Event>,
) -> Result<StateMap<Event>, state_res::StateResError> {
    state_res::resolve(state_sets, auth_chain)
}
