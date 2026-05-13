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
///
/// Field layout follows the v11 PDU wire format:
/// <https://spec.matrix.org/latest/rooms/v11/>
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
    /// Event IDs of events required for this event to be valid.
    pub auth_events: Vec<String>,
    /// Event IDs of the most recent events in the room at the time this was sent.
    pub prev_events: Vec<String>,
    /// Content hashes of the PDU, e.g. `{ "sha256": "..." }`.
    pub hashes: Value,
    /// Server signatures over the PDU, e.g. `{ "example.org": { "ed25519:abc": "..." } }`.
    pub signatures: Value,
    /// Topological ordering depth within the room DAG.
    pub depth: i64,
    /// Optional ephemeral data not included in the event hash.
    pub unsigned: Option<Value>,
}
