//! Trailing-slash state paths (conduit-y99.47).
//!
//! When the state key is empty the trailing slash is optional, so
//! `/rooms/{roomId}/state/{eventType}/` must behave exactly like
//! `/rooms/{roomId}/state/{eventType}` for both PUT and GET.

use axum::routing::put;

use super::{rooms, AuthState};

pub fn router<S: AuthState>() -> axum::Router<S> {
    axum::Router::new().route(
        "/_matrix/client/v3/rooms/:roomId/state/:eventType/",
        put(rooms::send_state_event::<S>).get(rooms::get_state_event_no_key::<S>),
    )
}
