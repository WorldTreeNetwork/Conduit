//! Room content endpoints (conduit-y99.19), Matrix spec v1.19.
//!
//! Implements:
//!   GET    /_matrix/client/v3/rooms/:roomId/event/:eventId
//!   GET    /_matrix/client/v3/rooms/:roomId/members
//!   GET    /_matrix/client/v3/rooms/:roomId/context/:eventId
//!   PUT    /_matrix/client/v3/rooms/:roomId/redact/:eventId/:txnId
//!   GET    /_matrix/client/v3/joined_rooms
//!   POST   /_matrix/client/v3/rooms/:roomId/forget
//!   POST   /_matrix/client/v3/rooms/:roomId/read_markers
//!   GET    /_matrix/client/v3/user/:userId/rooms/:roomId/tags
//!   PUT    /_matrix/client/v3/user/:userId/rooms/:roomId/tags/:tag
//!   DELETE /_matrix/client/v3/user/:userId/rooms/:roomId/tags/:tag
//!   GET    /_matrix/client/v1/rooms/:roomId/relations/:eventId[/:relType[/:eventType]]
//!   GET    /_matrix/client/v1/rooms/:roomId/threads
//!   GET    /_matrix/client/v1/rooms/:roomId/timestamp_to_event
//!   POST   /_matrix/client/v3/search
//!   POST   /_matrix/client/v3/rooms/:roomId/report/:eventId
//!   POST   /_matrix/client/v3/rooms/:roomId/report
//!   POST   /_matrix/client/v3/users/:userId/report
//!   GET    /_matrix/conduit/admin/v1/reports
//!   POST   /_matrix/client/v3/rooms/:roomId/upgrade
//!   GET    /_matrix/client/v1/rooms/:roomId/hierarchy
//!
//! Serving rules shared with `/sync` and `/messages` (redactions with
//! `unsigned.redacted_because`, bundled `m.relations`, ignored users) live
//! in [`serve`].

// Handlers return `Response` as the error type throughout, as elsewhere in
// this crate.
#![allow(clippy::result_large_err)]

pub mod events;
pub mod hierarchy;
pub mod redact;
pub mod relations;
pub mod reports;
pub mod search;
pub mod serve;
pub mod upgrade;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde_json::json;

use conduit::event::Event;
use conduit::state_events::HistoryVisibility;
use conduit::storage::Storage;

use super::{AuthState, MatrixError};

/// Every room-content route. Mounted once from `main.rs`.
pub fn router<S: AuthState>() -> Router<S> {
    let v3 = "/_matrix/client/v3";
    let v1 = "/_matrix/client/v1";
    Router::new()
        .route(&format!("{v3}/rooms/:roomId/event/:eventId"), get(events::get_event::<S>))
        .route(&format!("{v3}/rooms/:roomId/members"), get(events::get_members::<S>))
        .route(&format!("{v3}/rooms/:roomId/context/:eventId"), get(events::get_context::<S>))
        .route(&format!("{v3}/rooms/:roomId/redact/:eventId/:txnId"), put(redact::redact_event::<S>))
        .route(&format!("{v3}/joined_rooms"), get(events::joined_rooms::<S>))
        .route(&format!("{v3}/rooms/:roomId/forget"), post(events::forget_room::<S>))
        .route(&format!("{v3}/rooms/:roomId/read_markers"), post(events::read_markers::<S>))
        .route(&format!("{v3}/user/:userId/rooms/:roomId/tags"), get(events::get_tags::<S>))
        .route(
            &format!("{v3}/user/:userId/rooms/:roomId/tags/:tag"),
            put(events::put_tag::<S>).delete(events::delete_tag::<S>),
        )
        .route(&format!("{v1}/rooms/:roomId/relations/:eventId"), get(relations::relations::<S>))
        .route(
            &format!("{v1}/rooms/:roomId/relations/:eventId/:relType"),
            get(relations::relations_by_type::<S>),
        )
        .route(
            &format!("{v1}/rooms/:roomId/relations/:eventId/:relType/:eventType"),
            get(relations::relations_by_type_and_event_type::<S>),
        )
        .route(&format!("{v1}/rooms/:roomId/threads"), get(relations::threads::<S>))
        .route(
            &format!("{v1}/rooms/:roomId/timestamp_to_event"),
            get(events::timestamp_to_event::<S>),
        )
        .route(&format!("{v3}/search"), post(search::search::<S>))
        .route(&format!("{v3}/rooms/:roomId/report/:eventId"), post(reports::report_event::<S>))
        .route(&format!("{v3}/rooms/:roomId/report"), post(reports::report_room::<S>))
        .route(&format!("{v3}/users/:userId/report"), post(reports::report_user::<S>))
        .route("/_matrix/conduit/admin/v1/reports", get(reports::list_reports::<S>))
        .route(&format!("{v3}/rooms/:roomId/upgrade"), post(upgrade::upgrade_room::<S>))
        .route(&format!("{v1}/rooms/:roomId/hierarchy"), get(hierarchy::hierarchy::<S>))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A Matrix error response with an arbitrary errcode.
pub(crate) fn error(status: StatusCode, errcode: &str, message: impl Into<String>) -> Response {
    (status, Json(json!({"errcode": errcode, "error": message.into()}))).into_response()
}

pub(crate) fn not_found(message: &str) -> Response {
    error(StatusCode::NOT_FOUND, "M_NOT_FOUND", message)
}

pub(crate) fn invalid_param(message: impl Into<String>) -> Response {
    error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", message)
}

pub(crate) fn storage_error(error: conduit::Error) -> Response {
    MatrixError::unknown(error.to_string()).into_response()
}

/// Parse a stream-position token: `/messages` (`123`, `s123`), `/sync`
/// (`s123_d4_…`) and this module's own tokens all start with the position.
pub(crate) fn parse_position(token: &str) -> Option<i64> {
    token
        .strip_prefix('s')
        .unwrap_or(token)
        .split('_')
        .next()?
        .parse::<i64>()
        .ok()
        .filter(|position| *position >= 0)
}

pub(crate) fn position_token(position: i64) -> String {
    format!("s{}", position.max(0))
}

/// Parse an optional positive integer query parameter.
pub(crate) fn limit_param(
    query: &HashMap<String, String>,
    name: &str,
    default: usize,
    max: usize,
) -> Result<usize, Response> {
    match query.get(name) {
        None => Ok(default),
        Some(raw) => match raw.parse::<i64>() {
            Ok(value) if value > 0 => Ok((value as usize).min(max)),
            _ => Err(invalid_param(format!("{name} must be a positive integer"))),
        },
    }
}

/// Where the requesting user stands in a room, for read access.
///
/// Spec: a joined user reads current state and all visible history; a user
/// who left (or was banned) keeps the history they could see up to their
/// departure, unless they forgot the room; anyone may read a
/// `world_readable` room.
pub(crate) struct RoomAccess {
    /// Current membership event of the user, if any.
    pub member: Option<Event>,
    pub membership: Option<String>,
    /// Stream position of `member`.
    pub member_position: Option<i64>,
    pub world_readable: bool,
    /// The user forgot the room after this departure.
    pub forgotten: bool,
}

impl RoomAccess {
    pub async fn load(storage: &dyn Storage, room_id: &str, user_id: &str) -> conduit::Result<Self> {
        let state = conduit::auth::current_state_map(storage, room_id).await?;
        let world_readable =
            conduit::auth::history_visibility_of(&state) == HistoryVisibility::WorldReadable;
        let member = state.get(&("m.room.member".to_owned(), user_id.to_owned())).cloned();
        let membership = member
            .as_ref()
            .and_then(|event| event.content.get("membership"))
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        let member_position = match &member {
            Some(event) => storage
                .event_stream_positions(std::slice::from_ref(&event.event_id))
                .await?
                .get(&event.event_id)
                .copied(),
            None => None,
        };
        let forgotten = match &member {
            Some(event) => storage
                .forgotten_rooms(user_id)
                .await?
                .get(room_id)
                .is_some_and(|forgotten| *forgotten == event.event_id),
            None => false,
        };
        Ok(Self { member, membership, member_position, world_readable, forgotten })
    }

    pub fn is_joined(&self) -> bool {
        self.membership.as_deref() == Some("join")
    }

    /// Left or banned, and the departure was not forgotten.
    pub fn departed(&self) -> bool {
        matches!(self.membership.as_deref(), Some("leave" | "ban")) && !self.forgotten
    }

    /// May the user read anything of this room's history at all?
    pub fn may_read_history(&self) -> bool {
        self.world_readable
            || (!self.forgotten && matches!(self.membership.as_deref(), Some("join" | "invite" | "leave" | "ban")))
    }

    /// The last stream position whose state this user may see: `None` for
    /// "current"; the departure position for a user who left.
    pub fn state_horizon(&self) -> Option<i64> {
        if self.is_joined() || self.world_readable {
            None
        } else if self.departed() {
            self.member_position
        } else {
            None
        }
    }
}

/// Events from `room_id` the user may see: history visibility at each
/// event, plus the forget rule.
pub(crate) async fn visible_events(
    storage: &dyn Storage,
    access: &RoomAccess,
    room_id: &str,
    user_id: &str,
    events: Vec<Event>,
) -> conduit::Result<Vec<Event>> {
    if !access.may_read_history() {
        return Ok(Vec::new());
    }
    conduit::auth::filter_visible_for_user(storage, room_id, user_id, events).await
}

/// Room state folded from state events, as of `through` (`None`: current).
pub(crate) async fn state_at(
    storage: &dyn Storage,
    room_id: &str,
    through: Option<i64>,
) -> conduit::Result<Vec<Event>> {
    match through {
        None => storage.get_current_state(room_id).await,
        Some(position) => {
            let mut state: HashMap<(String, String), Event> = HashMap::new();
            for (_, event) in storage.state_events_through(room_id, position).await? {
                let key = (event.event_type.clone(), event.state_key.clone().unwrap_or_default());
                state.insert(key, event);
            }
            Ok(state.into_values().collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_tokens_accept_messages_and_sync_forms() {
        assert_eq!(parse_position("12"), Some(12));
        assert_eq!(parse_position("s12"), Some(12));
        assert_eq!(parse_position("s12_d3_a4"), Some(12));
        assert_eq!(parse_position("s-1"), None);
        assert_eq!(parse_position("x"), None);
        assert_eq!(position_token(-4), "s0");
    }

    #[test]
    fn limits_must_be_positive() {
        let mut query = HashMap::new();
        assert_eq!(limit_param(&query, "limit", 7, 10).unwrap(), 7);
        query.insert("limit".into(), "50".into());
        assert_eq!(limit_param(&query, "limit", 7, 10).unwrap(), 10);
        query.insert("limit".into(), "0".into());
        assert!(limit_param(&query, "limit", 7, 10).is_err());
    }
}
