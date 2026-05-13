//! State resolution.
//!
//! Matrix uses an algorithm called State Resolution v2 to compute the
//! current state of a room from its event DAG. The algorithm is
//! defined in the spec:
//! <https://spec.matrix.org/latest/rooms/v11/#state-resolution>.
//!
//! This module is currently a stub. The algorithm has three phases:
//!
//! 1. Separate "conflicted" state from "unconflicted" state.
//! 2. Linearize conflicted power-events via reverse topological power
//!    ordering and apply them in order, picking auth-check passers.
//! 3. Apply the remaining conflicted events in mainline-ordered fashion.

use crate::event::Event;

/// Resolve a set of state sets down to the room's current state.
pub fn resolve(_state_sets: &[Vec<Event>]) -> Vec<Event> {
    // TODO: implement state resolution v2.
    Vec::new()
}
