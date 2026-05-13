//! Top-level error type.

use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(String),

    #[error("invalid event: {0}")]
    InvalidEvent(String),

    #[error("not found")]
    NotFound,

    #[error("forbidden")]
    Forbidden,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
