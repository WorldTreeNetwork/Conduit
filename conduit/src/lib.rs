//! Conduit — a Matrix homeserver, as a pure library.
//!
//! This crate exposes the machinery of a Matrix homeserver — events,
//! rooms, state, storage abstraction, transports — without imposing a
//! particular HTTP server or I/O loop. To run it, see the companion
//! `conduit-server` crate, or embed it in your own host.
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

pub mod api;
pub mod config;
pub mod error;
pub mod event;
pub mod room;
pub mod storage;
pub mod transport;

pub use config::Config;
pub use error::{Error, Result};
