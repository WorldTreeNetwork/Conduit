//! Server configuration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// The Matrix server name (the part after `@user:` in MXIDs).
    pub server_name: String,

    /// Whether federation is enabled.
    #[serde(default = "default_true")]
    pub federation_enabled: bool,

    /// Whether new accounts can be registered without an invite.
    #[serde(default)]
    pub registration_open: bool,
}

impl Config {
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            federation_enabled: true,
            registration_open: false,
        }
    }
}

fn default_true() -> bool {
    true
}
