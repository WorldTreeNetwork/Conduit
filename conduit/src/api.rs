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

    /// The set of Matrix client-server API versions this server speaks,
    /// oldest first. Returned from `GET /_matrix/client/versions`.
    /// v1.1 is the first versioned release; later ones are additive.
    pub const SUPPORTED_VERSIONS: &[&str] = &[
        "v1.1", "v1.2", "v1.3", "v1.4", "v1.5", "v1.6", "v1.7", "v1.8", "v1.9", "v1.10",
        "v1.11", "v1.12", "v1.13", "v1.14", "v1.15", "v1.16", "v1.17", "v1.18", "v1.19",
    ];
}

pub mod federation {
    //! Server-Server (federation) API.
    //! <https://spec.matrix.org/latest/server-server-api/>
    //!
    //! TODO: handler types for federated send, state, backfill, ...
}
