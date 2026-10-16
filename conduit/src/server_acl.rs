//! `m.room.server_acl` matching (Matrix v1.19).
//!
//! ACLs are a network check, not an authorization rule. No event in the
//! room allows every server. Otherwise: IP literals, then deny globs, then
//! allow globs, then deny.

use serde_json::Value;

use crate::storage::Storage;

/// Whether `server_name` may participate in a room with this ACL content.
/// `None` means the room has no `m.room.server_acl` event.
pub fn server_allowed(acl: Option<&Value>, server_name: &str) -> bool {
    let Some(acl) = acl else { return true };
    let name = host_without_port(server_name);
    let allow_ip = match acl.get("allow_ip_literals") {
        Some(Value::Bool(value)) => *value,
        _ => true,
    };
    if !allow_ip && is_ip_literal(name) {
        return false;
    }
    let deny = patterns(acl.get("deny"));
    if deny.iter().any(|pattern| glob_match(pattern, name)) {
        return false;
    }
    let allow = patterns(acl.get("allow"));
    allow.iter().any(|pattern| glob_match(pattern, name))
}

/// The room's current ACL, defaulting to allow when the event is absent.
pub async fn server_allowed_by_room(
    storage: &dyn Storage,
    room_id: &str,
    server_name: &str,
) -> crate::Result<bool> {
    let event = storage.get_state_entry(room_id, "m.room.server_acl", "").await?;
    Ok(server_allowed(event.as_ref().map(|event| &event.content), server_name))
}

fn patterns(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|entries| entries.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Drop a trailing numeric port. Bracketed IPv6 keeps its brackets and
/// drops `]:port`.
fn host_without_port(server_name: &str) -> &str {
    if let Some(end) = server_name.find(']') {
        return &server_name[..=end];
    }
    match server_name.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => host,
        _ => server_name,
    }
}

fn is_ip_literal(name: &str) -> bool {
    if name.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    if let Some(inner) = name.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    false
}

/// Case-insensitive glob: `*` is any run of characters, `?` is one.
fn glob_match(pattern: &str, value: &str) -> bool {
    fn rec(pattern: &[char], value: &[char]) -> bool {
        let Some(head) = pattern.first() else {
            return value.is_empty();
        };
        if *head == '*' {
            rec(&pattern[1..], value) || (!value.is_empty() && rec(pattern, &value[1..]))
        } else if value.is_empty() {
            false
        } else if *head == '?' || head.eq_ignore_ascii_case(&value[0]) {
            rec(&pattern[1..], &value[1..])
        } else {
            false
        }
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    rec(&pattern, &value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn acl_order_globs_ports_and_ip_literals() {
        assert!(server_allowed(None, "remote.test"));
        let open = json!({"allow": ["*"], "deny": ["evil.com", "*.spam.test"]});
        assert!(!server_allowed(Some(&open), "evil.com"));
        assert!(!server_allowed(Some(&open), "EVIL.COM:8448"));
        assert!(!server_allowed(Some(&open), "a.spam.test"));
        assert!(server_allowed(Some(&open), "good.test"));
        // Deny is checked before allow, so `*` in both lists denies everyone.
        let blocked = json!({"allow": ["*"], "deny": ["*"]});
        assert!(!server_allowed(Some(&blocked), "good.test"));
        // An absent allow list denies every server.
        assert!(!server_allowed(Some(&json!({})), "good.test"));
        assert!(server_allowed(Some(&json!({"allow": ["a?c.com"]})), "abc.com"));
        assert!(!server_allowed(Some(&json!({"allow": ["a?c.com"]})), "ac.com"));
        // `*` is zero or more characters; `?` is exactly one.
        assert!(server_allowed(Some(&json!({"allow": ["*spam.test"]})), "spam.test"));
        assert!(!server_allowed(Some(&json!({"allow": ["?spam.test"]})), "spam.test"));
        let no_ip = json!({"allow": ["*"], "allow_ip_literals": false});
        assert!(!server_allowed(Some(&no_ip), "1.2.3.4"));
        assert!(!server_allowed(Some(&no_ip), "1.2.3.4:443"));
        assert!(!server_allowed(Some(&no_ip), "[2001:db8::1]"));
        assert!(!server_allowed(Some(&no_ip), "[2001:db8::1]:8448"));
        assert!(server_allowed(Some(&no_ip), "letters.test"));
        // A non-boolean allow_ip_literals falls back to true.
        let ips = json!({"allow": ["*"], "allow_ip_literals": "false"});
        assert!(server_allowed(Some(&ips), "1.2.3.4"));
    }
}
