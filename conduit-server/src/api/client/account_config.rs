//! Deployment knobs for registration, sessions and discovery
//! (conduit-y99.18).  Read once from the environment.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `CONDUIT_ALLOW_REGISTRATION` | `true` | Open `kind=user` registration |
//! | `CONDUIT_REGISTRATION_TOKENS` | unset | Comma-separated tokens; when set, registration requires `m.login.registration_token` |
//! | `CONDUIT_ALLOW_GUEST_ACCESS` | `false` | Allow `kind=guest` registration |
//! | `CONDUIT_REFRESH_TOKEN_ACCESS_LIFETIME_MS` | `300000` | Lifetime of access tokens issued with a refresh token |
//! | `CONDUIT_WELL_KNOWN_CLIENT_BASE_URL` | request origin | `m.homeserver.base_url` in `/.well-known/matrix/client` |
//! | `CONDUIT_WELL_KNOWN_IDENTITY_SERVER` | unset | `m.identity_server.base_url` |
//! | `CONDUIT_WELL_KNOWN_SERVER` | unset (404) | `m.server` delegation in `/.well-known/matrix/server` |
//! | `CONDUIT_SUPPORT_PAGE` | unset | `support_page` in `/.well-known/matrix/support` |
//! | `CONDUIT_SUPPORT_CONTACTS` | local admins | JSON array of contact objects |
//! | `CONDUIT_THREEPID_SINK` | unset | HTTP endpoint that receives validation tokens; unset disables 3PID changes |

use std::sync::OnceLock;

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct AccountConfig {
    pub allow_registration: bool,
    pub registration_tokens: Vec<String>,
    pub allow_guest_access: bool,
    pub refresh_access_token_lifetime_ms: i64,
    pub client_base_url: Option<String>,
    pub identity_server: Option<String>,
    pub server_delegation: Option<String>,
    pub support_page: Option<String>,
    pub support_contacts: Option<Value>,
    /// Where validation tokens are delivered. Unset means this server
    /// does not validate email or phone numbers.
    pub threepid_sink: Option<String>,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            allow_registration: true,
            registration_tokens: Vec::new(),
            allow_guest_access: false,
            refresh_access_token_lifetime_ms: 300_000,
            client_base_url: None,
            identity_server: None,
            server_delegation: None,
            support_page: None,
            support_contacts: None,
            threepid_sink: None,
        }
    }
}

fn flag(raw: Option<String>, default: bool) -> bool {
    match raw.as_deref().map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("1" | "true" | "yes" | "on") => true,
        Some("0" | "false" | "no" | "off") => false,
        _ => default,
    }
}

fn non_empty(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

impl AccountConfig {
    /// Build from an arbitrary variable lookup (the environment in
    /// production, a map in unit tests).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let d = Self::default();
        Self {
            allow_registration: flag(get("CONDUIT_ALLOW_REGISTRATION"), d.allow_registration),
            registration_tokens: get("CONDUIT_REGISTRATION_TOKENS")
                .map(|v| {
                    v.split(',')
                        .map(|t| t.trim().to_owned())
                        .filter(|t| !t.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            allow_guest_access: flag(get("CONDUIT_ALLOW_GUEST_ACCESS"), d.allow_guest_access),
            refresh_access_token_lifetime_ms: get("CONDUIT_REFRESH_TOKEN_ACCESS_LIFETIME_MS")
                .and_then(|v| v.trim().parse::<i64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(d.refresh_access_token_lifetime_ms),
            client_base_url: non_empty(get("CONDUIT_WELL_KNOWN_CLIENT_BASE_URL")),
            identity_server: non_empty(get("CONDUIT_WELL_KNOWN_IDENTITY_SERVER")),
            server_delegation: non_empty(get("CONDUIT_WELL_KNOWN_SERVER")),
            support_page: non_empty(get("CONDUIT_SUPPORT_PAGE")),
            support_contacts: non_empty(get("CONDUIT_SUPPORT_CONTACTS"))
                .and_then(|v| serde_json::from_str::<Value>(&v).ok())
                .filter(Value::is_array),
            threepid_sink: non_empty(get("CONDUIT_THREEPID_SINK")),
        }
    }

    /// The process-wide configuration, read from the environment once.
    pub fn get() -> &'static AccountConfig {
        static CONFIG: OnceLock<AccountConfig> = OnceLock::new();
        CONFIG.get_or_init(|| Self::from_lookup(|k| std::env::var(k).ok()))
    }

    pub fn registration_token_valid(&self, token: &str) -> bool {
        self.registration_tokens.iter().any(|t| t == token)
    }

    pub fn threepid_enabled(&self) -> bool {
        self.threepid_sink.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> AccountConfig {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        AccountConfig::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn defaults_are_open_registration_without_guests() {
        let c = cfg(&[]);
        assert!(c.allow_registration);
        assert!(!c.allow_guest_access);
        assert!(c.registration_tokens.is_empty());
        assert_eq!(c.refresh_access_token_lifetime_ms, 300_000);
        assert!(c.server_delegation.is_none());
    }

    #[test]
    fn parses_flags_tokens_and_contacts() {
        let c = cfg(&[
            ("CONDUIT_ALLOW_REGISTRATION", "off"),
            ("CONDUIT_ALLOW_GUEST_ACCESS", "1"),
            ("CONDUIT_REGISTRATION_TOKENS", " abc , ,def"),
            ("CONDUIT_REFRESH_TOKEN_ACCESS_LIFETIME_MS", "1500"),
            ("CONDUIT_SUPPORT_CONTACTS", r#"[{"role":"m.role.admin","email_address":"a@b.c"}]"#),
        ]);
        assert!(!c.allow_registration);
        assert!(c.allow_guest_access);
        assert_eq!(c.registration_tokens, vec!["abc", "def"]);
        assert!(c.registration_token_valid("def"));
        assert!(!c.registration_token_valid("xyz"));
        assert_eq!(c.refresh_access_token_lifetime_ms, 1500);
        assert!(c.support_contacts.unwrap().is_array());
    }

    #[test]
    fn rejects_nonsense_values() {
        let c = cfg(&[
            ("CONDUIT_REFRESH_TOKEN_ACCESS_LIFETIME_MS", "-5"),
            ("CONDUIT_SUPPORT_CONTACTS", r#"{"not":"an array"}"#),
        ]);
        assert_eq!(c.refresh_access_token_lifetime_ms, 300_000);
        assert!(c.support_contacts.is_none());
    }
}
