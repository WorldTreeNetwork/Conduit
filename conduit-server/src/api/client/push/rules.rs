//! Push rule evaluator and default rule set (E11 P3, P4).
//!
//! Implements:
//!   - Default push rules per spec (P3)
//!   - Condition evaluators: event_match, contains_display_name,
//!     room_member_count, sender_notification_permission (P4)
//!   - Action parsing helpers

use regex::Regex;
use serde_json::Value;

use conduit::storage::PushRule;

// ---------------------------------------------------------------------------
// Default push rules (P3)
// ---------------------------------------------------------------------------

/// Build the default push rules for a new user.
/// These are marked `is_default = true` so user overrides take precedence.
pub fn default_push_rules(user_id: &str) -> Vec<PushRule> {
    vec![
        // .m.rule.master — catch-all at highest priority (override kind)
        PushRule {
            user_id: user_id.to_owned(),
            scope: "global".to_owned(),
            kind: "override".to_owned(),
            rule_id: ".m.rule.master".to_owned(),
            priority: 0,
            enabled: false, // disabled by default — user enables to mute everything
            conditions: serde_json::json!([]),
            actions: serde_json::json!(["dont_notify"]),
            pattern: None,
            is_default: true,
        },
        // .m.rule.suppress_notices — suppress bot notices
        PushRule {
            user_id: user_id.to_owned(),
            scope: "global".to_owned(),
            kind: "override".to_owned(),
            rule_id: ".m.rule.suppress_notices".to_owned(),
            priority: 1,
            enabled: true,
            conditions: serde_json::json!([{
                "kind": "event_match",
                "key": "content.msgtype",
                "pattern": "m.notice"
            }]),
            actions: serde_json::json!(["dont_notify"]),
            pattern: None,
            is_default: true,
        },
        // .m.rule.invite_for_me — notify when invited
        PushRule {
            user_id: user_id.to_owned(),
            scope: "global".to_owned(),
            kind: "override".to_owned(),
            rule_id: ".m.rule.invite_for_me".to_owned(),
            priority: 2,
            enabled: true,
            conditions: serde_json::json!([
                {
                    "kind": "event_match",
                    "key": "type",
                    "pattern": "m.room.member"
                },
                {
                    "kind": "event_match",
                    "key": "content.membership",
                    "pattern": "invite"
                },
                {
                    "kind": "event_match",
                    "key": "state_key",
                    "pattern": user_id
                }
            ]),
            actions: serde_json::json!(["notify", { "set_tweak": "sound", "value": "default" }, { "set_tweak": "highlight" }]),
            pattern: None,
            is_default: true,
        },
        // .m.rule.member_event — suppress member events (not self-invite)
        PushRule {
            user_id: user_id.to_owned(),
            scope: "global".to_owned(),
            kind: "override".to_owned(),
            rule_id: ".m.rule.member_event".to_owned(),
            priority: 3,
            enabled: true,
            conditions: serde_json::json!([{
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.member"
            }]),
            actions: serde_json::json!(["dont_notify"]),
            pattern: None,
            is_default: true,
        },
        // .m.rule.contains_display_name — notify when display name appears
        PushRule {
            user_id: user_id.to_owned(),
            scope: "global".to_owned(),
            kind: "override".to_owned(),
            rule_id: ".m.rule.contains_display_name".to_owned(),
            priority: 4,
            enabled: true,
            conditions: serde_json::json!([{ "kind": "contains_display_name" }]),
            actions: serde_json::json!(["notify", { "set_tweak": "sound", "value": "default" }, { "set_tweak": "highlight" }]),
            pattern: None,
            is_default: true,
        },
        // .m.rule.tombstone — notify on room tombstone
        PushRule {
            user_id: user_id.to_owned(),
            scope: "global".to_owned(),
            kind: "override".to_owned(),
            rule_id: ".m.rule.tombstone".to_owned(),
            priority: 5,
            enabled: true,
            conditions: serde_json::json!([{
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.tombstone"
            }]),
            actions: serde_json::json!(["notify", { "set_tweak": "highlight" }]),
            pattern: None,
            is_default: true,
        },
        // .m.rule.reaction — suppress reactions
        PushRule {
            user_id: user_id.to_owned(),
            scope: "global".to_owned(),
            kind: "override".to_owned(),
            rule_id: ".m.rule.reaction".to_owned(),
            priority: 6,
            enabled: true,
            conditions: serde_json::json!([{
                "kind": "event_match",
                "key": "type",
                "pattern": "m.reaction"
            }]),
            actions: serde_json::json!(["dont_notify"]),
            pattern: None,
            is_default: true,
        },
        // .m.rule.room_one_to_one — notify for messages in 1:1 rooms
        PushRule {
            user_id: user_id.to_owned(),
            scope: "global".to_owned(),
            kind: "underride".to_owned(),
            rule_id: ".m.rule.room_one_to_one".to_owned(),
            priority: 10,
            enabled: true,
            conditions: serde_json::json!([
                { "kind": "room_member_count", "is": "2" },
                { "kind": "event_match", "key": "type", "pattern": "m.room.message" }
            ]),
            actions: serde_json::json!(["notify", { "set_tweak": "sound", "value": "default" }]),
            pattern: None,
            is_default: true,
        },
        // .m.rule.encrypted_room_one_to_one — same for encrypted 1:1
        PushRule {
            user_id: user_id.to_owned(),
            scope: "global".to_owned(),
            kind: "underride".to_owned(),
            rule_id: ".m.rule.encrypted_room_one_to_one".to_owned(),
            priority: 11,
            enabled: true,
            conditions: serde_json::json!([
                { "kind": "room_member_count", "is": "2" },
                { "kind": "event_match", "key": "type", "pattern": "m.room.encrypted" }
            ]),
            actions: serde_json::json!(["notify", { "set_tweak": "sound", "value": "default" }]),
            pattern: None,
            is_default: true,
        },
        // .m.rule.message — notify for any room message
        PushRule {
            user_id: user_id.to_owned(),
            scope: "global".to_owned(),
            kind: "underride".to_owned(),
            rule_id: ".m.rule.message".to_owned(),
            priority: 20,
            enabled: true,
            conditions: serde_json::json!([{
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.message"
            }]),
            actions: serde_json::json!(["notify"]),
            pattern: None,
            is_default: true,
        },
        // .m.rule.encrypted — notify for encrypted messages
        PushRule {
            user_id: user_id.to_owned(),
            scope: "global".to_owned(),
            kind: "underride".to_owned(),
            rule_id: ".m.rule.encrypted".to_owned(),
            priority: 21,
            enabled: true,
            conditions: serde_json::json!([{
                "kind": "event_match",
                "key": "type",
                "pattern": "m.room.encrypted"
            }]),
            actions: serde_json::json!(["notify"]),
            pattern: None,
            is_default: true,
        },
    ]
}

// ---------------------------------------------------------------------------
// Action types
// ---------------------------------------------------------------------------

/// The result of evaluating a rule's actions.
#[derive(Debug, Clone, PartialEq)]
pub struct EvaluatedActions {
    pub should_notify: bool,
    pub highlight: bool,
    pub sound: Option<String>,
}

impl EvaluatedActions {
    pub fn dont_notify() -> Self {
        Self { should_notify: false, highlight: false, sound: None }
    }
}

/// Parse a list of Matrix push actions into evaluated form.
pub fn parse_actions(actions: &Value) -> EvaluatedActions {
    let mut result = EvaluatedActions { should_notify: false, highlight: false, sound: None };

    let arr = match actions.as_array() {
        Some(a) => a,
        None => return result,
    };

    for action in arr {
        match action {
            Value::String(s) if s == "notify" => result.should_notify = true,
            Value::String(s) if s == "dont_notify" => result.should_notify = false,
            Value::String(s) if s == "coalesce" => result.should_notify = true,
            Value::Object(obj) => {
                if let Some(Value::String(tweak)) = obj.get("set_tweak") {
                    match tweak.as_str() {
                        "highlight" => {
                            // value defaults to true when not provided
                            let val = obj.get("value")
                                .and_then(Value::as_bool)
                                .unwrap_or(true);
                            result.highlight = val;
                        }
                        "sound" => {
                            result.sound = obj.get("value")
                                .and_then(Value::as_str)
                                .map(|s| s.to_owned());
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Condition evaluation context
// ---------------------------------------------------------------------------

/// Context needed to evaluate all condition types.
pub struct EvalContext<'a> {
    /// The event being evaluated (as JSON).
    pub event: &'a Value,
    /// The user's display name (for contains_display_name).
    pub displayname: Option<&'a str>,
    /// Number of joined members in the room (for room_member_count).
    pub member_count: usize,
    /// Power levels content of the room (for sender_notification_permission).
    pub power_levels: Option<&'a Value>,
    /// The sender's user_id (for sender_notification_permission).
    pub sender: &'a str,
}

// ---------------------------------------------------------------------------
// Main evaluator
// ---------------------------------------------------------------------------

/// Evaluate whether an event matches a push rule, and return the resulting
/// actions if it does. Returns `None` if the rule does not match.
///
/// Rules are evaluated in priority order (caller's responsibility to sort).
/// Once a rule matches, evaluation stops (the first-match-wins semantics).
pub fn evaluate_rule(rule: &PushRule, ctx: &EvalContext<'_>) -> Option<EvaluatedActions> {
    if !rule.enabled {
        return None;
    }

    let conditions = rule.conditions.as_array();

    // Content rules use `pattern` to match `content.body`.
    if rule.kind == "content" {
        if let Some(pat) = &rule.pattern {
            let body = event_value(ctx.event, "content.body")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !glob_match(pat, body) {
                return None;
            }
        } else {
            return None;
        }
        return Some(parse_actions(&rule.actions));
    }

    // Room rules match only on room_id.
    if rule.kind == "room" {
        let room_id = event_value(ctx.event, "room_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if room_id != rule.rule_id {
            return None;
        }
        return Some(parse_actions(&rule.actions));
    }

    // Sender rules match only on sender.
    if rule.kind == "sender" {
        let sender = event_value(ctx.event, "sender")
            .and_then(Value::as_str)
            .unwrap_or("");
        if sender != rule.rule_id {
            return None;
        }
        return Some(parse_actions(&rule.actions));
    }

    // Override / underride: evaluate all conditions.
    let conditions = match conditions {
        Some(c) => c,
        None => return None,
    };

    for cond in conditions {
        if !evaluate_condition(cond, ctx) {
            return None;
        }
    }

    Some(parse_actions(&rule.actions))
}

fn evaluate_condition(cond: &Value, ctx: &EvalContext<'_>) -> bool {
    let kind = cond.get("kind").and_then(Value::as_str).unwrap_or("");

    match kind {
        "event_match" => {
            let key = cond.get("key").and_then(Value::as_str).unwrap_or("");
            let pattern = cond.get("pattern").and_then(Value::as_str).unwrap_or("");
            let val = event_value(ctx.event, key)
                .and_then(|v| match v {
                    Value::String(s) => Some(s.as_str().to_owned()),
                    Value::Bool(b) => Some(b.to_string()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .unwrap_or_default();
            glob_match(pattern, &val)
        }
        "contains_display_name" => {
            let displayname = match ctx.displayname {
                Some(d) if !d.is_empty() => d,
                _ => return false,
            };
            let body = event_value(ctx.event, "content.body")
                .and_then(Value::as_str)
                .unwrap_or("");
            // Case-insensitive substring search.
            body.to_lowercase().contains(&displayname.to_lowercase())
        }
        "room_member_count" => {
            let is_expr = cond.get("is").and_then(Value::as_str).unwrap_or("0");
            evaluate_member_count(is_expr, ctx.member_count)
        }
        "sender_notification_permission" => {
            let key = cond.get("key").and_then(Value::as_str).unwrap_or("room");
            evaluate_notification_permission(key, ctx)
        }
        // Unknown conditions → false (don't match).
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get a value from an event by dotted path (e.g. `"content.body"`).
pub fn event_value<'a>(event: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = event;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

/// Match a glob pattern against a string. Supports `*` (any sequence) and
/// `?` (single character). Matching is case-insensitive.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    // Convert glob to regex.
    let regex_pattern = glob_to_regex(pattern);
    if let Ok(re) = Regex::new(&regex_pattern) {
        re.is_match(text)
    } else {
        pattern.eq_ignore_ascii_case(text)
    }
}

fn glob_to_regex(glob: &str) -> String {
    let mut re = String::from("(?i)^");
    for ch in glob.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c => {
                // Escape regex metacharacters.
                if "^$.|?+()[]{}\\".contains(c) {
                    re.push('\\');
                }
                re.push(c);
            }
        }
    }
    re.push('$');
    re
}

/// Evaluate a `room_member_count` `is` expression like `"2"`, `"<=5"`, `">1"`.
fn evaluate_member_count(is_expr: &str, count: usize) -> bool {
    let count = count as i64;

    // Parse optional operator prefix.
    let (op, num_str) = if is_expr.starts_with("<=") {
        ("<=", &is_expr[2..])
    } else if is_expr.starts_with(">=") {
        (">=", &is_expr[2..])
    } else if is_expr.starts_with('<') {
        ("<", &is_expr[1..])
    } else if is_expr.starts_with('>') {
        (">", &is_expr[1..])
    } else if is_expr.starts_with("==") {
        ("==", &is_expr[2..])
    } else {
        // Plain number → equality.
        ("==", is_expr)
    };

    let n: i64 = match num_str.trim().parse() {
        Ok(v) => v,
        Err(_) => return false,
    };

    match op {
        "<=" => count <= n,
        ">=" => count >= n,
        "<" => count < n,
        ">" => count > n,
        _ => count == n, // "==" or bare number
    }
}

/// Evaluate `sender_notification_permission` for a given `key`.
fn evaluate_notification_permission(key: &str, ctx: &EvalContext<'_>) -> bool {
    let pl = match ctx.power_levels {
        Some(pl) => pl,
        None => return false,
    };

    // Required PL for this notification key from power_levels.notifications.<key>.
    let required_pl: i64 = pl
        .get("notifications")
        .and_then(|n| n.get(key))
        .and_then(Value::as_i64)
        .unwrap_or(50); // Default: moderator level.

    // Sender's PL.
    let sender_pl: i64 = pl
        .get("users")
        .and_then(|u| u.get(ctx.sender))
        .and_then(Value::as_i64)
        .or_else(|| pl.get("users_default").and_then(Value::as_i64))
        .unwrap_or(0);

    sender_pl >= required_pl
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn glob_match_wildcard() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("hello*", "hello world"));
        assert!(!glob_match("hello*", "world hello"));
        assert!(glob_match("*world*", "say hello world today"));
    }

    #[test]
    fn glob_match_case_insensitive() {
        assert!(glob_match("Alice", "alice"));
        assert!(glob_match("HELLO", "hello"));
    }

    #[test]
    fn member_count_evaluation() {
        assert!(evaluate_member_count("2", 2));
        assert!(!evaluate_member_count("2", 3));
        assert!(evaluate_member_count("<=2", 2));
        assert!(evaluate_member_count("<=2", 1));
        assert!(!evaluate_member_count("<=2", 3));
        assert!(evaluate_member_count(">=5", 5));
        assert!(evaluate_member_count(">3", 4));
        assert!(!evaluate_member_count(">3", 3));
    }

    #[test]
    fn event_match_condition() {
        let event = json!({
            "type": "m.room.message",
            "content": { "msgtype": "m.text", "body": "Hello world" }
        });
        let ctx = EvalContext {
            event: &event,
            displayname: None,
            member_count: 2,
            power_levels: None,
            sender: "@alice:localhost",
        };
        let cond = json!({ "kind": "event_match", "key": "type", "pattern": "m.room.message" });
        assert!(evaluate_condition(&cond, &ctx));

        let cond2 = json!({ "kind": "event_match", "key": "content.msgtype", "pattern": "m.notice" });
        assert!(!evaluate_condition(&cond2, &ctx));
    }

    #[test]
    fn contains_display_name_match() {
        let event = json!({
            "type": "m.room.message",
            "content": { "body": "Hey Alice, what do you think?" }
        });
        let ctx = EvalContext {
            event: &event,
            displayname: Some("Alice"),
            member_count: 3,
            power_levels: None,
            sender: "@bob:localhost",
        };
        let cond = json!({ "kind": "contains_display_name" });
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn parse_actions_highlight() {
        let actions = json!(["notify", { "set_tweak": "highlight" }]);
        let result = parse_actions(&actions);
        assert!(result.should_notify);
        assert!(result.highlight);
    }
}
