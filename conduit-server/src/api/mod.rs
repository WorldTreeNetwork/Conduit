//! HTTP API modules for conduit-server.
//!
//! Organises route handlers by spec sub-API.
//! Routes are mounted in `main.rs`; this module only provides the handlers.

pub mod admin;
pub mod client;
