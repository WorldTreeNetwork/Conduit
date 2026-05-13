//! Matrix event types.
//!
//! Currently a thin placeholder. The eventual choice is between
//! fleshing these out against the spec or pulling in [`ruma`] for the
//! canonical Rust bindings; see the Events section of the Matrix spec:
//! <https://spec.matrix.org/latest/#events>.
//!
//! [`ruma`]: https://docs.rs/ruma

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A Matrix room event in its persisted ("PDU") shape.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Event {
    pub event_id: String,
    pub room_id: String,
    pub sender: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub content: Value,
    #[serde(default)]
    pub state_key: Option<String>,
    pub origin_server_ts: u64,
}
