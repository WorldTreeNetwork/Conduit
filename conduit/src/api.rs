//! HTTP API surfaces.
//!
//! Two distinct APIs in the Matrix spec:
//!
//! - [`client`] — the Client-Server API, used by Matrix clients to
//!   talk to their homeserver (login, send messages, sync, ...).
//! - [`federation`] — the Server-Server API, used by homeservers to
//!   talk to each other (federated send, state queries, ...).
//!
//! This crate only exposes handler functions and types — it does not
//! mount routes on a webserver. The `conduit-server` crate does that
//! against `axum`; if you want a different host, build your own.

pub mod client {
    //! Client-Server API. <https://spec.matrix.org/latest/client-server-api/>
    //!
    //! TODO: handler types for login, sync, send, register, ...

    /// The set of Matrix client-server API versions this server speaks.
    /// Returned from `GET /_matrix/client/versions`.
    pub const SUPPORTED_VERSIONS: &[&str] = &["v1.11"];
}

pub mod federation {
    //! Server-Server (federation) API.
    //! <https://spec.matrix.org/latest/server-server-api/>
    //!
    //! TODO: handler types for federated send, state, backfill, ...
}
