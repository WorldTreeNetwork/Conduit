//! Conduit — a Matrix homeserver, as a pure library.
//!
//! This crate is the Matrix **kernel**: events, rooms, v11 auth, storage
//! trait, agency tokens. It is tokio-hosted. It does not depend on
//! `axum`. Public API has no HTTP types. See `docs/architecture.md`.
//! The companion `conduit-server` crate is the HTTP/Postgres host.
//!
//! ## Lineage
//!
//! The name "Conduit" is reused on purpose. The original Conduit was
//! the first serious Rust Matrix homeserver; after it was archived the
//! work continued as `conduwuit`, and the actively maintained successor
//! is now [continuwuity]. This crate is an independent reimplementation
//! that points at that lineage; we work primarily from the
//! [Matrix specification] and only occasionally glance at prior
//! implementations for layout cues.
//!
//! [continuwuity]: https://forgejo.ellis.link/continuwuation/continuwuity
//! [Matrix specification]: https://spec.matrix.org/

pub mod agency;
pub mod api;
pub mod auth;
pub mod canonical_json;
pub mod config;
pub mod error;
pub mod event;
pub mod hashing;
pub mod identity;
pub mod keys;
pub mod redaction;
pub mod room;
pub mod signing;
pub mod state_events;
pub mod storage;
pub mod transport;

pub use config::Config;
pub use error::{require_room_version, Error, Result, ROOM_VERSION};
