//! Matrix identifier grammar.
//!
//! <https://spec.matrix.org/v1.19/appendices/#identifier-grammar>

use std::net::Ipv6Addr;

/// Common Namespaced Identifier Grammar: 1–255 characters, starting with
/// `[a-z]`, then `[a-z0-9._-]`.
pub fn valid_namespaced_identifier(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    let mut count = 1usize;
    for char in chars {
        if count == 255 || !(char.is_ascii_lowercase() || char.is_ascii_digit() || matches!(char, '-' | '_' | '.')) {
            return false;
        }
        count += 1;
    }
    true
}

/// Opaque Identifier Grammar: 1–255 characters from `[0-9A-Za-z._~-]`.
pub fn valid_opaque_identifier(id: &str) -> bool {
    let mut count = 0usize;
    for char in id.chars() {
        if count == 255 || !(char.is_ascii_alphanumeric() || matches!(char, '-' | '.' | '_' | '~')) {
            return false;
        }
        count += 1;
    }
    count >= 1
}

/// Server name: DNS name, IPv4 literal, or bracketed IPv6 literal, with an
/// optional numeric port of 1–5 digits.
pub fn valid_server_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let (host, port) = if name.starts_with('[') {
        let Some(end) = name.find(']') else {
            return false;
        };
        let host = &name[..=end];
        let after = &name[end + 1..];
        if after.is_empty() {
            (host, None)
        } else {
            let Some(port) = after.strip_prefix(':') else {
                return false;
            };
            (host, Some(port))
        }
    } else if let Some((host, port)) = name.rsplit_once(':') {
        (host, Some(port))
    } else {
        (name, None)
    };
    if let Some(port) = port {
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|host| host.strip_suffix(']')) {
        return (2..=45).contains(&inner.len()) && inner.parse::<Ipv6Addr>().is_ok();
    }
    if host.split('.').count() == 4 && host.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.') {
        return host.split('.').all(|octet| octet.parse::<u16>().is_ok_and(|n| n <= 255) && !octet.is_empty());
    }
    (1..=255).contains(&host.len())
        && host.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
}

/// A user id that must be accepted on a federation event.
///
/// The localpart may be empty or any Unicode scalar except `:` and NUL.
/// Surrogates cannot occur in a Rust string. The server name is non-empty
/// and the whole id is at most 255 bytes.
pub fn acceptable_historical_user_id(id: &str) -> bool {
    if id.len() > 255 || id.contains('\0') {
        return false;
    }
    let Some(rest) = id.strip_prefix('@') else {
        return false;
    };
    let Some((local, server)) = rest.split_once(':') else {
        return false;
    };
    !server.is_empty() && !local.contains(':')
}

/// A user id that may be shown to clients outside an event.
///
/// The localpart is non-empty and every character is in U+0021..=U+007E.
/// An empty localpart, or any character outside that range, is a
/// non-compliant historical id: events still carry it, and device-list
/// updates must be dropped.
pub fn forwardable_user_id(id: &str) -> bool {
    if !acceptable_historical_user_id(id) {
        return false;
    }
    let local = id.strip_prefix('@').and_then(|rest| rest.split_once(':')).map(|(local, _)| local);
    local.is_some_and(|local| !local.is_empty() && local.chars().all(|c| ('\u{0021}'..='\u{007E}').contains(&c)))
}

/// `#localpart:server`. The localpart is any non-empty string without `:` or
/// U+0000. The whole alias is at most 255 bytes.
pub fn valid_room_alias(alias: &str) -> bool {
    let Some(rest) = alias.strip_prefix('#') else {
        return false;
    };
    let Some((local, server)) = rest.split_once(':') else {
        return false;
    };
    !local.is_empty() && !local.contains(':') && !local.contains('\0') && valid_server_name(server) && alias.len() <= 255
}

/// Alias localpart used by `createRoom`'s `room_alias_name`.
pub fn valid_alias_localpart(local: &str) -> bool {
    !local.is_empty() && !local.contains(':') && !local.contains('\0')
}

/// `!opaque:server`, or a domain-less id whose body is an event-id hash.
pub fn valid_room_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix('!') else {
        return false;
    };
    if rest.is_empty() || id.len() > 255 || rest.contains('\0') {
        return false;
    }
    if let Some((local, server)) = rest.split_once(':') {
        return !local.is_empty() && !local.contains(':') && !local.contains('\0') && valid_server_name(server);
    }
    valid_id_hash(rest)
}

/// `$opaque:server` (room versions 1–2), or `$` plus an unpadded base64 hash
/// (standard alphabet for version 3, URL-safe for versions 4+).
pub fn valid_event_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix('$') else {
        return false;
    };
    if rest.is_empty() || id.len() > 255 || rest.contains('\0') {
        return false;
    }
    if let Some((local, server)) = rest.split_once(':') {
        return !local.is_empty() && !local.contains(':') && !local.contains('\0') && valid_server_name(server);
    }
    valid_id_hash(rest)
}

fn valid_id_hash(body: &str) -> bool {
    !body.is_empty()
        && body.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaced_identifiers_are_lowercase_and_bounded() {
        assert!(valid_namespaced_identifier("m.room.message"));
        assert!(valid_namespaced_identifier("com.example.identifier"));
        assert!(valid_namespaced_identifier("a"));
        assert!(!valid_namespaced_identifier(""));
        assert!(!valid_namespaced_identifier("Bad"));
        assert!(!valid_namespaced_identifier("1abc"));
        assert!(!valid_namespaced_identifier("has space"));
        assert!(!valid_namespaced_identifier(&"a".repeat(256)));
        assert!(valid_namespaced_identifier(&"a".repeat(255)));
    }

    #[test]
    fn opaque_identifiers_use_the_unreserved_set() {
        assert!(valid_opaque_identifier("Phone_1"));
        assert!(valid_opaque_identifier("ok~id"));
        assert!(valid_opaque_identifier("A.Z-9"));
        assert!(!valid_opaque_identifier(""));
        assert!(!valid_opaque_identifier("bad id"));
        assert!(!valid_opaque_identifier("plus+"));
        assert!(!valid_opaque_identifier("slash/"));
        assert!(!valid_opaque_identifier(&"a".repeat(256)));
    }

    #[test]
    fn server_names_match_the_spec_examples() {
        for name in ["matrix.org", "matrix.org:8888", "1.2.3.4", "1.2.3.4:1234", "[1234:5678::abcd]", "[1234:5678::abcd]:5678"] {
            assert!(valid_server_name(name), "{name}");
        }
        assert!(valid_server_name("MATRIX.ORG"));
        assert!(!valid_server_name(""));
        assert!(!valid_server_name("matrix.org:"));
        assert!(!valid_server_name("matrix.org:123456"));
        assert!(!valid_server_name("999.1.1.1"));
        assert!(!valid_server_name("[::1"));
        assert!(!valid_server_name("has space"));
    }

    #[test]
    fn historical_user_ids_accept_any_localpart_and_forward_only_printable_ones() {
        assert!(acceptable_historical_user_id("@:remote.test"));
        assert!(acceptable_historical_user_id("@世界:remote.test"));
        assert!(acceptable_historical_user_id("@a b:remote.test"));
        assert!(acceptable_historical_user_id("@Bob:remote.test"));
        assert!(!acceptable_historical_user_id("@a\u{0}b:remote.test"));
        assert!(!acceptable_historical_user_id("bob:remote.test"));
        assert!(!acceptable_historical_user_id("@bob"));
        assert!(forwardable_user_id("@Bob:remote.test"));
        assert!(forwardable_user_id("@a*b:remote.test"));
        assert!(!forwardable_user_id("@:remote.test"));
        assert!(!forwardable_user_id("@世界:remote.test"));
        assert!(!forwardable_user_id("@a b:remote.test"));
        assert!(!forwardable_user_id("@a\u{0}b:remote.test"));
    }

    #[test]
    fn room_alias_room_id_and_event_id_grammars() {
        assert!(valid_room_alias("#room:matrix.org"));
        assert!(valid_room_alias("#room:matrix.org:8888"));
        assert!(valid_room_alias("#café:matrix.org"));
        assert!(!valid_room_alias("room:matrix.org"));
        assert!(!valid_room_alias("#:matrix.org"));
        assert!(!valid_room_alias("#room:999.1.1.1"));
        assert!(!valid_room_alias(&format!("#{}:matrix.org", "a".repeat(250))));
        assert!(valid_alias_localpart("ok"));
        assert!(!valid_alias_localpart(""));
        assert!(!valid_alias_localpart("a:b"));
        assert!(!valid_alias_localpart("a\u{0}b"));

        assert!(valid_room_id("!opaque:matrix.org"));
        assert!(valid_room_id("!opaque:1.2.3.4:1234"));
        assert!(valid_room_id("!abcDEF12-_"));
        assert!(!valid_room_id("!"));
        assert!(!valid_room_id("opaque:matrix.org"));
        assert!(!valid_room_id("!opaque:999.1.1.1"));

        assert!(valid_event_id("$0:domain"));
        assert!(valid_event_id("$abc+/DEF"));
        assert!(valid_event_id("$Zm9vYmFy"));
        assert!(valid_event_id("$abc-DEF_09"));
        assert!(!valid_event_id("0:domain"));
        assert!(!valid_event_id("$"));
        assert!(!valid_event_id("$0:999.1.1.1"));
        assert!(!valid_event_id(&format!("${}", "a".repeat(255))));
    }
}
