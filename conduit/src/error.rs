//! Top-level error type.

use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(String),

    /// The database refused a value as a data exception (PostgreSQL SQLSTATE
    /// class 22, e.g. U+0000 in JSONB/TEXT). Deterministic: retrying the same
    /// bytes fails the same way, so callers may drop the item instead of
    /// failing a whole request.
    #[error("storage data error: {0}")]
    StorageData(String),

    #[error("invalid event: {0}")]
    InvalidEvent(String),

    #[error("not found")]
    NotFound,

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("unsupported room version: {0}")]
    UnsupportedRoomVersion(String),

    #[error("too large: {0}")]
    TooLarge(String),
}

impl Error {
    /// Matrix `errcode` for this error. The host maps this to HTTP status.
    pub fn errcode(&self) -> &'static str {
        match self {
            Error::NotFound => "M_NOT_FOUND",
            Error::Forbidden(_) => "M_FORBIDDEN",
            Error::UnsupportedRoomVersion(_) => "M_UNSUPPORTED_ROOM_VERSION",
            Error::TooLarge(_) => "M_TOO_LARGE",
            Error::InvalidEvent(_) => "M_BAD_JSON",
            Error::Storage(_) | Error::StorageData(_) | Error::Io(_) | Error::Serde(_) => "M_UNKNOWN",
        }
    }
}

/// Room version used when a client omits `room_version` on create.
pub const ROOM_VERSION: &str = "12";

pub fn require_room_version(version: &str) -> Result<()> {
    if crate::room_version::parse(version).is_some() {
        Ok(())
    } else {
        Err(Error::UnsupportedRoomVersion(version.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_one_through_twelve_are_accepted() {
        for version in ["1", "6", "10", "11", "12"] {
            require_room_version(version).unwrap();
        }
        assert_eq!(ROOM_VERSION, "12");
    }

    #[test]
    fn unknown_room_version_is_rejected() {
        let e = require_room_version("13").unwrap_err();
        assert_eq!(e.errcode(), "M_UNSUPPORTED_ROOM_VERSION");
    }

    #[test]
    fn conduit_manifest_has_no_axum() {
        let toml = include_str!("../Cargo.toml");
        assert!(
            !toml.contains("axum"),
            "conduit must not depend on axum"
        );
    }
}
