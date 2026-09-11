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

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("unsupported room version: {0}")]
    UnsupportedRoomVersion(String),
}

impl Error {
    /// Matrix `errcode` for this error. The host maps this to HTTP status.
    pub fn errcode(&self) -> &'static str {
        match self {
            Error::NotFound => "M_NOT_FOUND",
            Error::Forbidden(_) => "M_FORBIDDEN",
            Error::UnsupportedRoomVersion(_) => "M_UNSUPPORTED_ROOM_VERSION",
            Error::InvalidEvent(_) => "M_BAD_JSON",
            Error::Storage(_) | Error::Io(_) | Error::Serde(_) => "M_UNKNOWN",
        }
    }
}

/// Room version this kernel speaks. Create and inbound reject anything else.
pub const ROOM_VERSION: &str = "11";

pub fn require_room_version(version: &str) -> Result<()> {
    if version == ROOM_VERSION {
        Ok(())
    } else {
        Err(Error::UnsupportedRoomVersion(version.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v11_ok() {
        require_room_version("11").unwrap();
    }

    #[test]
    fn v10_rejected() {
        let e = require_room_version("10").unwrap_err();
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
