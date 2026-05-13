//! Rooms — the unit of conversation in Matrix.
//!
//! A room is a DAG of events replicated across all participating
//! homeservers. The current state of a room is computed by resolving
//! the DAG; see [`state_res`].

pub mod state_res;

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

/// Compute the current state of a room from a set of state events.
/// Hands off to [`state_res::resolve`].
pub fn current_state(state_sets: &[Vec<Event>]) -> Vec<Event> {
    state_res::resolve(state_sets)
}
