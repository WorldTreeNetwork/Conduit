//! Push rule model, server-default rules and evaluator (conduit-y99.30,
//! Matrix v1.19 #push-rules, #predefined-rules, appendices #glob-style-matching
//! and #dot-separated-property-paths).
//!
//! Storage keeps only what users changed: user-defined rules
//! (`is_default = false`, ordered by `priority`, lower is more important)
//! and overlays for server-default rules (`is_default = true`, carrying the
//! user's `enabled` and `actions`). [`ruleset`] merges those rows with the
//! code-defined defaults, so new server defaults reach every user.

use std::collections::HashMap;

use regex::Regex;
use serde_json::{json, Map, Value};

use conduit::storage::PushRule;

/// Rule kinds in evaluation order.
pub const KINDS: [&str; 5] = ["override", "content", "room", "sender", "underride"];

/// One rule as clients see it (`PushRule` in the spec).
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub kind: String,
    pub rule_id: String,
    pub default: bool,
    pub enabled: bool,
    /// Override/underride rules only.
    pub conditions: Option<Vec<Value>>,
    /// Content rules only.
    pub pattern: Option<String>,
    pub actions: Vec<Value>,
}

impl Rule {
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "rule_id": self.rule_id,
            "default": self.default,
            "enabled": self.enabled,
            "actions": self.actions,
        });
        if let Some(conditions) = &self.conditions {
            v["conditions"] = Value::Array(conditions.clone());
        }
        if let Some(pattern) = &self.pattern {
            v["pattern"] = json!(pattern);
        }
        v
    }
}

fn default_rule(kind: &str, rule_id: &str, enabled: bool, conditions: Value, actions: Value) -> Rule {
    Rule {
        kind: kind.to_owned(),
        rule_id: rule_id.to_owned(),
        default: true,
        enabled,
        conditions: conditions.as_array().cloned(),
        pattern: None,
        actions: actions.as_array().cloned().unwrap_or_default(),
    }
}

/// The v1.19 server-default rules for `user_id`, in specification order.
/// (v1.17 removed the legacy body-mention rules `.m.rule.contains_display_name`,
/// `.m.rule.contains_user_name` and `.m.rule.roomnotif`.)
pub fn server_default_rules(user_id: &str) -> Vec<Rule> {
    let sound = json!({"set_tweak": "sound", "value": "default"});
    let highlight = json!({"set_tweak": "highlight"});
    vec![
        default_rule("override", ".m.rule.master", false, json!([]), json!([])),
        default_rule(
            "override",
            ".m.rule.suppress_notices",
            true,
            json!([{"kind": "event_match", "key": "content.msgtype", "pattern": "m.notice"}]),
            json!([]),
        ),
        default_rule(
            "override",
            ".m.rule.invite_for_me",
            true,
            json!([
                {"kind": "event_match", "key": "type", "pattern": "m.room.member"},
                {"kind": "event_match", "key": "content.membership", "pattern": "invite"},
                {"kind": "event_match", "key": "state_key", "pattern": user_id}
            ]),
            json!(["notify", sound]),
        ),
        default_rule(
            "override",
            ".m.rule.member_event",
            true,
            json!([{"kind": "event_match", "key": "type", "pattern": "m.room.member"}]),
            json!([]),
        ),
        default_rule(
            "override",
            ".m.rule.is_user_mention",
            true,
            json!([{"kind": "event_property_contains", "key": "content.m\\.mentions.user_ids", "value": user_id}]),
            json!(["notify", sound, highlight]),
        ),
        default_rule(
            "override",
            ".m.rule.is_room_mention",
            true,
            json!([
                {"kind": "event_property_is", "key": "content.m\\.mentions.room", "value": true},
                {"kind": "sender_notification_permission", "key": "room"}
            ]),
            json!(["notify", highlight]),
        ),
        default_rule(
            "override",
            ".m.rule.tombstone",
            true,
            json!([
                {"kind": "event_match", "key": "type", "pattern": "m.room.tombstone"},
                {"kind": "event_match", "key": "state_key", "pattern": ""}
            ]),
            json!(["notify", highlight]),
        ),
        default_rule(
            "override",
            ".m.rule.reaction",
            true,
            json!([{"kind": "event_match", "key": "type", "pattern": "m.reaction"}]),
            json!([]),
        ),
        default_rule(
            "override",
            ".m.rule.room.server_acl",
            true,
            json!([
                {"kind": "event_match", "key": "type", "pattern": "m.room.server_acl"},
                {"kind": "event_match", "key": "state_key", "pattern": ""}
            ]),
            json!([]),
        ),
        default_rule(
            "override",
            ".m.rule.suppress_edits",
            true,
            json!([{"kind": "event_property_is", "key": "content.m\\.relates_to.rel_type", "value": "m.replace"}]),
            json!([]),
        ),
        default_rule(
            "underride",
            ".m.rule.call",
            true,
            json!([{"kind": "event_match", "key": "type", "pattern": "m.call.invite"}]),
            json!(["notify", {"set_tweak": "sound", "value": "ring"}]),
        ),
        default_rule(
            "underride",
            ".m.rule.encrypted_room_one_to_one",
            true,
            json!([
                {"kind": "room_member_count", "is": "2"},
                {"kind": "event_match", "key": "type", "pattern": "m.room.encrypted"}
            ]),
            json!(["notify", sound]),
        ),
        default_rule(
            "underride",
            ".m.rule.room_one_to_one",
            true,
            json!([
                {"kind": "room_member_count", "is": "2"},
                {"kind": "event_match", "key": "type", "pattern": "m.room.message"}
            ]),
            json!(["notify", sound]),
        ),
        default_rule(
            "underride",
            ".m.rule.message",
            true,
            json!([{"kind": "event_match", "key": "type", "pattern": "m.room.message"}]),
            json!(["notify"]),
        ),
        default_rule(
            "underride",
            ".m.rule.encrypted",
            true,
            json!([{"kind": "event_match", "key": "type", "pattern": "m.room.encrypted"}]),
            json!(["notify"]),
        ),
    ]
}

/// Rule IDs starting with a dot are reserved for server-default rules.
pub fn is_server_default_id(rule_id: &str) -> bool {
    rule_id.starts_with('.')
}

fn user_rule(row: &PushRule) -> Rule {
    let (conditions, pattern) = match row.kind.as_str() {
        "override" | "underride" => (Some(row.conditions.as_array().cloned().unwrap_or_default()), None),
        "content" => (None, row.pattern.clone()),
        _ => (None, None),
    };
    Rule {
        kind: row.kind.clone(),
        rule_id: row.rule_id.clone(),
        default: false,
        enabled: row.enabled,
        conditions,
        pattern,
        actions: strip_historical(row.actions.as_array().cloned().unwrap_or_default()),
    }
}

/// The user's full global ruleset in evaluation order: `.m.rule.master`,
/// then per kind the user-defined rules before the server defaults.
pub fn ruleset(user_id: &str, stored: &[PushRule]) -> Vec<Rule> {
    let overlays: HashMap<(&str, &str), &PushRule> = stored
        .iter()
        .filter(|r| r.is_default && r.scope == "global")
        .map(|r| ((r.kind.as_str(), r.rule_id.as_str()), r))
        .collect();
    let mut defaults = server_default_rules(user_id);
    for rule in &mut defaults {
        if let Some(row) = overlays.get(&(rule.kind.as_str(), rule.rule_id.as_str())) {
            rule.enabled = row.enabled;
            rule.actions = strip_historical(row.actions.as_array().cloned().unwrap_or_default());
        }
    }
    let mut users: Vec<&PushRule> = stored
        .iter()
        .filter(|r| !r.is_default && r.scope == "global" && KINDS.contains(&r.kind.as_str()))
        .collect();
    users.sort_by_key(|r| r.priority);

    let mut out = Vec::new();
    for kind in KINDS {
        if kind == "override" {
            out.extend(defaults.iter().filter(|r| r.rule_id == ".m.rule.master").cloned());
        }
        out.extend(users.iter().filter(|r| r.kind == kind).map(|r| user_rule(r)));
        out.extend(
            defaults
                .iter()
                .filter(|r| r.kind == kind && r.rule_id != ".m.rule.master")
                .cloned(),
        );
    }
    out
}

/// `{"override": [...], "content": [...], ...}` for a ruleset.
pub fn ruleset_json(rules: &[Rule]) -> Value {
    let mut out = Map::new();
    for kind in KINDS {
        out.insert(
            kind.to_owned(),
            Value::Array(rules.iter().filter(|r| r.kind == kind).map(Rule::to_json).collect()),
        );
    }
    Value::Object(out)
}

/// Historical `dont_notify` / `coalesce` actions MUST be ignored.
fn strip_historical(actions: Vec<Value>) -> Vec<Value> {
    actions
        .into_iter()
        .filter(|a| !matches!(a.as_str(), Some("dont_notify" | "coalesce")))
        .collect()
}

/// Validate client-supplied actions and drop historical ones.
pub fn normalize_actions(actions: &Value) -> Result<Vec<Value>, String> {
    let list = actions.as_array().ok_or("actions must be an array")?;
    for action in list {
        match action {
            Value::String(s) if matches!(s.as_str(), "notify" | "dont_notify" | "coalesce") => {}
            Value::String(s) => return Err(format!("unrecognised action: {s}")),
            Value::Object(o) if o.get("set_tweak").is_some_and(Value::is_string) => {}
            _ => return Err("actions must be strings or set_tweak objects".to_owned()),
        }
    }
    Ok(strip_historical(list.clone()))
}

/// Validate conditions: an array of objects each with a string `kind`.
/// Unknown kinds are accepted (they simply never match).
pub fn validate_conditions(conditions: &Value) -> Result<Vec<Value>, String> {
    let list = conditions.as_array().ok_or("conditions must be an array")?;
    for condition in list {
        if !condition.get("kind").is_some_and(Value::is_string) {
            return Err("each condition needs a string kind".to_owned());
        }
    }
    Ok(list.clone())
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// The effect of a matched rule's actions.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Outcome {
    pub notify: bool,
    pub highlight: bool,
    /// Every `set_tweak` (highlight included) as sent to push gateways.
    pub tweaks: Map<String, Value>,
}

pub fn outcome(actions: &[Value]) -> Outcome {
    let mut out = Outcome::default();
    for action in actions {
        match action {
            Value::String(s) if s == "notify" => out.notify = true,
            Value::Object(o) => {
                if let Some(name) = o.get("set_tweak").and_then(Value::as_str) {
                    let value = o.get("value").cloned().unwrap_or_else(|| {
                        if name == "highlight" { Value::Bool(true) } else { Value::Null }
                    });
                    if name == "highlight" {
                        out.highlight = value.as_bool().unwrap_or(false);
                    }
                    out.tweaks.insert(name.to_owned(), value);
                }
            }
            _ => {}
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Everything a condition may consult besides the event.
pub struct EvalContext<'a> {
    /// The event in client format (`type`, `content`, `sender`, ...).
    pub event: &'a Value,
    /// The user whose rules are evaluated.
    pub user_id: &'a str,
    /// The user's display name in the room (`contains_display_name`).
    pub display_name: Option<&'a str>,
    /// Joined members (`room_member_count`).
    pub member_count: u64,
    /// The room's `m.room.power_levels` content, if any.
    pub power_levels: Option<&'a Value>,
    /// The sender's power level in the room.
    pub sender_power_level: i64,
}

/// The first enabled rule that matches, in ruleset order.
pub fn evaluate<'r>(rules: &'r [Rule], ctx: &EvalContext<'_>) -> Option<&'r Rule> {
    rules.iter().find(|rule| rule.enabled && rule_matches(rule, ctx))
}

pub fn rule_matches(rule: &Rule, ctx: &EvalContext<'_>) -> bool {
    match rule.kind.as_str() {
        "override" | "underride" => rule
            .conditions
            .as_deref()
            .unwrap_or_default()
            .iter()
            .all(|c| condition_matches(c, ctx)),
        "content" => match (&rule.pattern, lookup(ctx.event, "content.body").and_then(Value::as_str)) {
            (Some(pattern), Some(body)) => body_glob_match(pattern, body),
            _ => false,
        },
        "room" => ctx.event.get("room_id").and_then(Value::as_str) == Some(rule.rule_id.as_str()),
        "sender" => ctx.event.get("sender").and_then(Value::as_str) == Some(rule.rule_id.as_str()),
        _ => false,
    }
}

pub fn condition_matches(cond: &Value, ctx: &EvalContext<'_>) -> bool {
    let key = cond.get("key").and_then(Value::as_str);
    match cond.get("kind").and_then(Value::as_str).unwrap_or("") {
        "event_match" => {
            let (Some(key), Some(pattern)) = (key, cond.get("pattern").and_then(Value::as_str)) else {
                return false;
            };
            match lookup(ctx.event, key).and_then(Value::as_str) {
                Some(value) if key == "content.body" => body_glob_match(pattern, value),
                Some(value) => glob_match(pattern, value),
                None => false,
            }
        }
        "event_property_is" => {
            let (Some(key), Some(expected)) = (key, cond.get("value")) else { return false };
            lookup(ctx.event, key).is_some_and(|actual| scalar_eq(actual, expected))
        }
        "event_property_contains" => {
            let (Some(key), Some(expected)) = (key, cond.get("value")) else { return false };
            lookup(ctx.event, key)
                .and_then(Value::as_array)
                .is_some_and(|items| items.iter().any(|item| scalar_eq(item, expected)))
        }
        "contains_display_name" => {
            let (Some(name), Some(body)) =
                (ctx.display_name, lookup(ctx.event, "content.body").and_then(Value::as_str))
            else {
                return false;
            };
            !name.is_empty() && word_match(&regex::escape(name), body)
        }
        "room_member_count" => cond
            .get("is")
            .and_then(Value::as_str)
            .is_some_and(|is| member_count_matches(is, ctx.member_count)),
        "sender_notification_permission" => {
            let Some(key) = key else { return false };
            ctx.sender_power_level >= notification_level(ctx.power_levels, key)
        }
        // Unrecognised conditions MUST NOT match.
        _ => false,
    }
}

/// Non-compound canonical JSON equality: strings, integers, booleans, null.
fn scalar_eq(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Null, Value::Null) => true,
        (Value::Number(a), Value::Number(b)) => match (a.as_i64(), b.as_i64()) {
            (Some(a), Some(b)) => a == b && a.abs() < (1 << 53),
            _ => false,
        },
        _ => false,
    }
}

/// Split a dot-separated property path, honouring `\.` and `\\` escapes;
/// any other backslash sequence is literal.
pub fn split_path(path: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.peek() {
                Some('.') | Some('\\') => parts.last_mut().unwrap().push(chars.next().unwrap()),
                _ => parts.last_mut().unwrap().push('\\'),
            },
            '.' => parts.push(String::new()),
            c => parts.last_mut().unwrap().push(c),
        }
    }
    parts
}

/// The event property at a dot-separated path.
pub fn lookup<'a>(event: &'a Value, path: &str) -> Option<&'a Value> {
    split_path(path)
        .iter()
        .try_fold(event, |current, part| current.as_object()?.get(part))
}

fn glob_regex(glob: &str) -> String {
    let mut out = String::new();
    for c in glob.chars() {
        match c {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            c => out.push_str(&regex::escape(&c.to_string())),
        }
    }
    out
}

/// Case-insensitive glob over the entire value.
pub fn glob_match(glob: &str, value: &str) -> bool {
    Regex::new(&format!("(?is)^{}$", glob_regex(glob))).is_ok_and(|re| re.is_match(value))
}

/// `content.body` matching: the glob must match a substring that starts
/// and ends at word boundaries (anything outside `[A-Za-z0-9_]`).
pub fn body_glob_match(glob: &str, body: &str) -> bool {
    word_match(&glob_regex(glob), body)
}

fn word_match(inner: &str, body: &str) -> bool {
    Regex::new(&format!("(?is)(?:^|[^A-Za-z0-9_])(?:{inner})(?:[^A-Za-z0-9_]|$)"))
        .is_ok_and(|re| re.is_match(body))
}

/// `room_member_count` `is`: an integer with an optional `==`, `<`, `>`,
/// `<=` or `>=` prefix. Malformed expressions never match.
pub fn member_count_matches(is: &str, count: u64) -> bool {
    let (op, number) = ["==", "<=", ">=", "<", ">"]
        .iter()
        .find_map(|op| is.strip_prefix(op).map(|rest| (*op, rest)))
        .unwrap_or(("==", is));
    let Ok(n) = number.parse::<u64>() else { return false };
    match op {
        "<" => count < n,
        ">" => count > n,
        "<=" => count <= n,
        ">=" => count >= n,
        _ => count == n,
    }
}

fn as_level(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

/// Power needed to trigger notifications of type `key` (`room` defaults to 50).
fn notification_level(power_levels: Option<&Value>, key: &str) -> i64 {
    power_levels
        .and_then(|pl| pl.get("notifications"))
        .and_then(|n| n.get(key))
        .and_then(as_level)
        .unwrap_or(50)
}

/// A user's power level from `m.room.power_levels` content; with no power
/// levels event the room creator has 100 and everyone else 0.
pub fn power_level(power_levels: Option<&Value>, creator: Option<&str>, user_id: &str) -> i64 {
    match power_levels {
        Some(pl) => pl
            .get("users")
            .and_then(|u| u.get(user_id))
            .and_then(as_level)
            .or_else(|| pl.get("users_default").and_then(as_level))
            .unwrap_or(0),
        None if creator == Some(user_id) => 100,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(event: &'a Value, pl: Option<&'a Value>, sender_pl: i64) -> EvalContext<'a> {
        EvalContext {
            event,
            user_id: "@alice:hs",
            display_name: Some("Alice"),
            member_count: 3,
            power_levels: pl,
            sender_power_level: sender_pl,
        }
    }

    fn first(rules: &[Rule], ctx: &EvalContext<'_>) -> Option<String> {
        evaluate(rules, ctx).map(|r| r.rule_id.clone())
    }

    #[test]
    fn dot_paths_honour_escapes() {
        assert_eq!(split_path("content.m\\.relates_to.rel_type"), ["content", "m.relates_to", "rel_type"]);
        assert_eq!(split_path("content.m\\\\foo"), ["content", "m\\foo"]);
        assert_eq!(split_path("content.a\\xb"), ["content", "a\\xb"]);
        let event = json!({"content": {"m.relates_to": {"rel_type": "m.replace"}, "m\\foo": 1}});
        assert_eq!(lookup(&event, "content.m\\.relates_to.rel_type"), Some(&json!("m.replace")));
        assert_eq!(lookup(&event, "content.m\\\\foo"), Some(&json!(1)));
        assert_eq!(lookup(&event, "content.m.relates_to"), None);
    }

    #[test]
    fn globs_match_whole_values_case_insensitively() {
        assert!(glob_match("lunc?*", "Lunch plans"));
        assert!(glob_match("lunc?*", "LUNCH"));
        assert!(!glob_match("lunc?*", " lunch"));
        assert!(!glob_match("lunc?*", "lunc"));
        assert!(glob_match("a.b", "A.B"));
        assert!(!glob_match("a.b", "axb"), "regex metacharacters are literal");
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }

    #[test]
    fn body_globs_match_at_word_boundaries() {
        assert!(body_glob_match("ex*ple", "An example event."));
        assert!(body_glob_match("ex*ple", "exple"));
        assert!(body_glob_match("ex*ple", "An exciting triple-whammy"));
        assert!(!body_glob_match("cake", "pancakes"));
        assert!(body_glob_match("cake", "I like cake!"));
    }

    #[test]
    fn event_match_requires_string_values() {
        let event = json!({"content": {"topic": null, "n": 1}});
        let c = ctx(&event, None, 0);
        assert!(!condition_matches(&json!({"kind": "event_match", "key": "content.topic", "pattern": "*"}), &c));
        assert!(!condition_matches(&json!({"kind": "event_match", "key": "content.n", "pattern": "*"}), &c));
        assert!(!condition_matches(&json!({"kind": "event_match", "key": "content.absent", "pattern": "*"}), &c));
    }

    #[test]
    fn property_is_and_contains_are_exact() {
        let event = json!({"content": {
            "m.federate": true, "s": "true", "n": 1,
            "alt_aliases": ["#somewhere:example.org", "#myroom:example.com", 7, null]
        }});
        let c = ctx(&event, None, 0);
        let is = |key: &str, value: Value| condition_matches(&json!({"kind": "event_property_is", "key": key, "value": value}), &c);
        assert!(is("content.m\\.federate", json!(true)));
        assert!(!is("content.m\\.federate", json!("true")));
        assert!(!is("content.m\\.federate", json!(1)));
        assert!(is("content.n", json!(1)));
        assert!(!is("content.s", json!(true)));
        let contains = |value: Value| condition_matches(&json!({"kind": "event_property_contains", "key": "content.alt_aliases", "value": value}), &c);
        assert!(contains(json!("#myroom:example.com")));
        assert!(contains(json!(7)));
        assert!(contains(Value::Null));
        assert!(!contains(json!(":example.com")));
        assert!(!condition_matches(&json!({"kind": "event_property_contains", "key": "content.s", "value": "true"}), &c));
    }

    #[test]
    fn member_count_expressions() {
        assert!(member_count_matches("2", 2));
        assert!(member_count_matches("==2", 2));
        assert!(!member_count_matches("2", 3));
        assert!(member_count_matches("<=2", 1));
        assert!(member_count_matches(">=5", 5));
        assert!(member_count_matches(">3", 4));
        assert!(!member_count_matches("<3", 3));
        assert!(!member_count_matches("abc", 3));
        assert!(!member_count_matches("<>3", 3));
    }

    #[test]
    fn unknown_conditions_never_match() {
        let event = json!({"type": "m.room.message"});
        assert!(!condition_matches(&json!({"kind": "org.example.future"}), &ctx(&event, None, 0)));
    }

    #[test]
    fn sender_notification_permission_uses_power_levels() {
        let event = json!({});
        let pl = json!({"users": {"@mod:hs": 50}, "users_default": 0, "notifications": {"room": 40}});
        let cond = json!({"kind": "sender_notification_permission", "key": "room"});
        assert!(condition_matches(&cond, &ctx(&event, Some(&pl), 50)));
        assert!(!condition_matches(&cond, &ctx(&event, Some(&pl), 0)));
        assert_eq!(power_level(Some(&pl), None, "@mod:hs"), 50);
        assert_eq!(power_level(Some(&pl), None, "@x:hs"), 0);
        assert_eq!(power_level(None, Some("@c:hs"), "@c:hs"), 100);
        let default_pl = json!({});
        assert!(!condition_matches(&cond, &ctx(&event, Some(&default_pl), 49)));
        assert!(condition_matches(&cond, &ctx(&event, Some(&default_pl), 50)));
    }

    #[test]
    fn default_ruleset_matches_spec_order_and_outcomes() {
        let rules = ruleset("@alice:hs", &[]);
        let ids: Vec<_> = rules.iter().map(|r| r.rule_id.as_str()).collect();
        assert_eq!(
            ids,
            [
                ".m.rule.master", ".m.rule.suppress_notices", ".m.rule.invite_for_me",
                ".m.rule.member_event", ".m.rule.is_user_mention", ".m.rule.is_room_mention",
                ".m.rule.tombstone", ".m.rule.reaction", ".m.rule.room.server_acl",
                ".m.rule.suppress_edits", ".m.rule.call", ".m.rule.encrypted_room_one_to_one",
                ".m.rule.room_one_to_one", ".m.rule.message", ".m.rule.encrypted",
            ]
        );
        let pl = json!({"users": {"@mod:hs": 100}});
        let cases = [
            (json!({"type": "m.room.message", "content": {"msgtype": "m.text", "body": "hi"}}), 0, Some(".m.rule.message"), false),
            (json!({"type": "m.room.message", "content": {"msgtype": "m.notice", "body": "hi"}}), 0, Some(".m.rule.suppress_notices"), false),
            (json!({"type": "m.room.message", "content": {"body": "x", "m.mentions": {"user_ids": ["@alice:hs"]}}}), 0, Some(".m.rule.is_user_mention"), true),
            (json!({"type": "m.room.message", "content": {"body": "x", "m.mentions": {"room": true}}}), 100, Some(".m.rule.is_room_mention"), true),
            (json!({"type": "m.room.message", "content": {"body": "x", "m.mentions": {"room": true}}}), 0, Some(".m.rule.message"), false),
            (json!({"type": "m.room.message", "content": {"body": "* x", "m.relates_to": {"rel_type": "m.replace", "event_id": "$e"}}}), 0, Some(".m.rule.suppress_edits"), false),
            (json!({"type": "m.room.member", "state_key": "@alice:hs", "content": {"membership": "invite"}}), 0, Some(".m.rule.invite_for_me"), false),
            (json!({"type": "m.room.member", "state_key": "@bob:hs", "content": {"membership": "join"}}), 0, Some(".m.rule.member_event"), false),
            (json!({"type": "m.room.tombstone", "state_key": "", "content": {}}), 0, Some(".m.rule.tombstone"), true),
            (json!({"type": "m.reaction", "content": {}}), 0, Some(".m.rule.reaction"), false),
            (json!({"type": "m.room.server_acl", "state_key": "", "content": {}}), 0, Some(".m.rule.room.server_acl"), false),
            (json!({"type": "m.call.invite", "content": {}}), 0, Some(".m.rule.call"), false),
            (json!({"type": "m.room.encrypted", "content": {}}), 0, Some(".m.rule.encrypted"), false),
            (json!({"type": "m.room.topic", "state_key": "", "content": {}}), 0, None, false),
        ];
        for (event, sender_pl, expected, highlight) in cases {
            let c = ctx(&event, Some(&pl), sender_pl);
            assert_eq!(first(&rules, &c).as_deref(), expected, "{event}");
            if let Some(rule) = evaluate(&rules, &c) {
                assert_eq!(outcome(&rule.actions).highlight, highlight, "{event}");
            }
        }
        // 1:1 rooms.
        let event = json!({"type": "m.room.message", "content": {"body": "hi"}});
        let mut c = ctx(&event, None, 0);
        c.member_count = 2;
        assert_eq!(first(&rules, &c).as_deref(), Some(".m.rule.room_one_to_one"));
    }

    #[test]
    fn user_rules_precede_defaults_and_master_precedes_all() {
        let row = |kind: &str, id: &str, priority: i32, actions: Value, conditions: Value, pattern: Option<&str>, default: bool, enabled: bool| PushRule {
            user_id: "@alice:hs".into(), scope: "global".into(), kind: kind.into(), rule_id: id.into(),
            priority, enabled, conditions, actions, pattern: pattern.map(str::to_owned), is_default: default,
        };
        let stored = vec![
            row("content", "cake", 1, json!(["notify", {"set_tweak": "highlight"}]), json!([]), Some("cake"), false, true),
            row("room", "!quiet:hs", 0, json!(["dont_notify"]), json!([]), None, false, true),
            row("override", "second", 1, json!([]), json!([]), None, false, true),
            row("override", "first", 0, json!(["notify"]), json!([{"kind": "event_match", "key": "type", "pattern": "x.never"}]), None, false, true),
        ];
        let rules = ruleset("@alice:hs", &stored);
        let ids: Vec<_> = rules.iter().map(|r| r.rule_id.as_str()).collect();
        assert_eq!(&ids[..4], [".m.rule.master", "first", "second", ".m.rule.suppress_notices"]);
        // "dont_notify" is stripped.
        assert!(rules.iter().find(|r| r.rule_id == "!quiet:hs").unwrap().actions.is_empty());

        let quiet = json!({"type": "m.room.message", "room_id": "!quiet:hs", "content": {"body": "cake"}});
        // "second" (no conditions, empty actions) wins over everything after it.
        assert_eq!(first(&rules, &ctx(&quiet, None, 0)).as_deref(), Some("second"));

        let without_second: Vec<PushRule> = stored.into_iter().filter(|r| r.rule_id != "second").collect();
        let mut rules = ruleset("@alice:hs", &without_second);
        assert_eq!(first(&rules, &ctx(&quiet, None, 0)).as_deref(), Some("cake"));
        let loud = json!({"type": "m.room.message", "room_id": "!quiet:hs", "content": {"body": "pie"}});
        assert_eq!(first(&rules, &ctx(&loud, None, 0)).as_deref(), Some("!quiet:hs"));

        // Enabling master silences everything.
        rules.iter_mut().find(|r| r.rule_id == ".m.rule.master").unwrap().enabled = true;
        assert_eq!(first(&rules, &ctx(&loud, None, 0)).as_deref(), Some(".m.rule.master"));
        assert!(!outcome(&evaluate(&rules, &ctx(&loud, None, 0)).unwrap().actions).notify);
    }

    #[test]
    fn default_overlays_change_enabled_and_actions() {
        let overlay = PushRule {
            user_id: "@alice:hs".into(), scope: "global".into(), kind: "underride".into(),
            rule_id: ".m.rule.message".into(), priority: 0, enabled: false,
            conditions: json!([]), actions: json!(["notify", {"set_tweak": "sound", "value": "bing"}]),
            pattern: None, is_default: true,
        };
        let rules = ruleset("@alice:hs", &[overlay]);
        let message = rules.iter().find(|r| r.rule_id == ".m.rule.message").unwrap();
        assert!(!message.enabled);
        assert!(message.default);
        assert_eq!(message.actions[1]["value"], "bing");
        // Conditions still come from the server default.
        assert_eq!(message.conditions.as_ref().unwrap()[0]["pattern"], "m.room.message");
    }

    #[test]
    fn actions_validation_and_outcome() {
        assert_eq!(normalize_actions(&json!(["dont_notify"])).unwrap(), Vec::<Value>::new());
        assert!(normalize_actions(&json!(["explode"])).is_err());
        assert!(normalize_actions(&json!("notify")).is_err());
        assert!(normalize_actions(&json!([{"value": 1}])).is_err());
        let o = outcome(&[json!("notify"), json!({"set_tweak": "highlight"}), json!({"set_tweak": "sound", "value": "default"})]);
        assert!(o.notify && o.highlight);
        assert_eq!(o.tweaks["sound"], "default");
        assert_eq!(o.tweaks["highlight"], true);
        let o = outcome(&[json!("notify"), json!({"set_tweak": "highlight", "value": false})]);
        assert!(o.notify && !o.highlight);
    }

    #[test]
    fn contains_display_name_is_word_bounded() {
        let event = json!({"content": {"body": "hey alice, look"}});
        assert!(condition_matches(&json!({"kind": "contains_display_name"}), &ctx(&event, None, 0)));
        let event = json!({"content": {"body": "malice"}});
        assert!(!condition_matches(&json!({"kind": "contains_display_name"}), &ctx(&event, None, 0)));
    }
}
