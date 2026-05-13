//! Public library surface for `conduit-server`.
//!
//! Exposes [`PostgresStorage`] so that integration tests in `tests/` can
//! instantiate it directly.  Application entry-point lives in `main.rs`.

pub mod api;
pub mod federation;
pub mod keys;
pub mod media_storage;
pub mod remote_keys;
pub mod storage_pg;

pub use media_storage::BlobStore;
pub use remote_keys::RemoteKeyCache;
pub use storage_pg::PostgresStorage;
