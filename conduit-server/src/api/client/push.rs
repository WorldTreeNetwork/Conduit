//! Push notification endpoints (conduit-y99.30, conduit-y99.31; Matrix
//! v1.19 #push-notifications).
//!
//!   GET    /_matrix/client/v3/pushers
//!   POST   /_matrix/client/v3/pushers/set
//!   GET    /_matrix/client/v3/pushrules/
//!   GET    /_matrix/client/v3/pushrules/global/
//!   GET    /_matrix/client/v3/pushrules/global/:kind/:ruleId
//!   PUT    /_matrix/client/v3/pushrules/global/:kind/:ruleId
//!   DELETE /_matrix/client/v3/pushrules/global/:kind/:ruleId
//!   GET    /_matrix/client/v3/pushrules/global/:kind/:ruleId/enabled
//!   PUT    /_matrix/client/v3/pushrules/global/:kind/:ruleId/enabled
//!   GET    /_matrix/client/v3/pushrules/global/:kind/:ruleId/actions
//!   PUT    /_matrix/client/v3/pushrules/global/:kind/:ruleId/actions
//!   GET    /_matrix/client/v3/notifications
//!
//! Rule changes are mirrored into the server-managed `m.push_rules`
//! account data so clients see them in `/sync`.

pub mod notifications;
pub mod rules;

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use conduit::storage::{PushRule, Pusher};

use self::rules::{is_server_default_id, Rule, KINDS};
use super::{AuthState, AuthedUser, MatrixError};

pub fn router<S: AuthState>() -> Router<S> {
    let v3 = "/_matrix/client/v3";
    Router::new()
        .route(&format!("{v3}/pushers"), get(get_pushers::<S>))
        .route(&format!("{v3}/pushers/set"), post(set_pusher::<S>))
        .route(&format!("{v3}/pushrules/"), get(get_all_push_rules::<S>))
        .route(&format!("{v3}/pushrules/global/"), get(get_global_push_rules::<S>))
        .route(
            &format!("{v3}/pushrules/global/:kind/:ruleId"),
            get(get_push_rule::<S>).put(put_push_rule::<S>).delete(delete_push_rule::<S>),
        )
        .route(
            &format!("{v3}/pushrules/global/:kind/:ruleId/enabled"),
            get(get_push_rule_enabled::<S>).put(put_push_rule_enabled::<S>),
        )
        .route(
            &format!("{v3}/pushrules/global/:kind/:ruleId/actions"),
            get(get_push_rule_actions::<S>).put(put_push_rule_actions::<S>),
        )
        .route(&format!("{v3}/notifications"), get(get_notifications::<S>))
}

fn error(status: StatusCode, errcode: &str, message: impl Into<String>) -> Response {
    (status, Json(json!({ "errcode": errcode, "error": message.into() }))).into_response()
}

fn invalid(message: impl Into<String>) -> Response {
    error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", message)
}

fn rule_not_found() -> Response {
    MatrixError::new_not_found("The push rule was not found.").into_response()
}

fn internal(e: impl std::fmt::Display) -> Response {
    MatrixError::unknown(e.to_string()).into_response()
}

fn ok() -> Response {
    (StatusCode::OK, Json(json!({}))).into_response()
}

// ---------------------------------------------------------------------------
// Pushers
// ---------------------------------------------------------------------------

pub async fn get_pushers<S: AuthState>(State(state): State<S>, authed: AuthedUser) -> Response {
    match state.storage().list_pushers(&authed.user_id).await {
        Ok(pushers) => {
            let arr: Vec<Value> = pushers.into_iter().map(pusher_to_json).collect();
            Json(json!({ "pushers": arr })).into_response()
        }
        Err(e) => internal(e),
    }
}

fn pusher_to_json(p: Pusher) -> Value {
    let mut v = json!({
        "pushkey": p.pushkey,
        "kind": p.kind,
        "app_id": p.app_id,
        "app_display_name": p.app_display_name,
        "device_display_name": p.device_display_name,
        "lang": p.lang,
        "data": p.data,
    });
    if let Some(tag) = p.profile_tag {
        v["profile_tag"] = json!(tag);
    }
    v
}

/// The URL path every HTTP pusher must target.
pub const NOTIFY_PATH: &str = "/_matrix/push/v1/notify";

/// `POST /pushers/set`: create, update (kind set) or delete (kind null).
pub async fn set_pusher<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<Value>,
) -> Response {
    let storage = state.storage();
    let Some(body) = body.as_object() else {
        return error(StatusCode::BAD_REQUEST, "M_BAD_JSON", "body must be an object");
    };
    let string = |key: &str| body.get(key).and_then(Value::as_str).map(str::to_owned);
    let (Some(pushkey), Some(app_id)) = (string("pushkey"), string("app_id")) else {
        return error(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", "pushkey and app_id are required");
    };
    if !body.contains_key("kind") {
        return error(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", "kind is required (null deletes)");
    }
    if app_id.chars().count() > 64 {
        return invalid("app_id is longer than 64 characters");
    }
    if pushkey.len() > 512 {
        return invalid("pushkey is longer than 512 bytes");
    }
    let kind = match body.get("kind") {
        Some(Value::Null) => {
            return match storage.delete_pusher(&authed.user_id, &pushkey, &app_id).await {
                Ok(()) => ok(),
                Err(e) => internal(e),
            };
        }
        Some(Value::String(kind)) => kind.clone(),
        _ => return invalid("kind must be a string or null"),
    };
    let missing: Vec<&str> = ["app_display_name", "device_display_name", "lang", "data"]
        .into_iter()
        .filter(|k| match *k {
            "data" => !body.get(*k).is_some_and(Value::is_object),
            k => string(k).is_none(),
        })
        .collect();
    if !missing.is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "M_MISSING_PARAM",
            format!("Missing parameters: {}", missing.join(", ")),
        );
    }
    if kind != "http" {
        // Email pushers need an email sender this server does not have.
        return invalid(format!("unsupported pusher kind: {kind}"));
    }
    let data = body["data"].clone();
    let Some(url) = data.get("url").and_then(Value::as_str).map(str::to_owned) else {
        return error(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", "http pushers require data.url");
    };
    match url::Url::parse(&url) {
        Ok(parsed) if matches!(parsed.scheme(), "http" | "https") && parsed.path() == NOTIFY_PATH => {}
        _ => return invalid(format!("data.url must be an absolute URL with path {NOTIFY_PATH}")),
    }
    let format = match data.get("format") {
        None => None,
        Some(Value::String(f)) if f == "event_id_only" => Some(f.clone()),
        Some(_) => return invalid("data.format must be event_id_only when present"),
    };
    let pusher = Pusher {
        user_id: authed.user_id.clone(),
        pushkey: pushkey.clone(),
        app_id: app_id.clone(),
        app_display_name: string("app_display_name"),
        device_display_name: string("device_display_name"),
        kind,
        lang: string("lang").unwrap_or_default(),
        profile_tag: string("profile_tag"),
        url: Some(url),
        format,
        data,
        pushkey_ts: chrono::Utc::now().timestamp(),
    };
    // append=false (the default): the pushkey now belongs to this user only.
    if !body.get("append").and_then(Value::as_bool).unwrap_or(false) {
        if let Err(e) = storage.delete_pushers_for_key(&app_id, &pushkey, Some(&authed.user_id)).await {
            return internal(e);
        }
    }
    match storage.upsert_pusher(&pusher).await {
        Ok(()) => ok(),
        Err(e) => internal(e),
    }
}

// ---------------------------------------------------------------------------
// Push rules
// ---------------------------------------------------------------------------

async fn load_ruleset<S: AuthState>(state: &S, user_id: &str) -> Result<Vec<Rule>, Response> {
    let stored = state.storage().list_push_rules(user_id).await.map_err(internal)?;
    Ok(rules::ruleset(user_id, &stored))
}

/// Keep `m.push_rules` account data equal to the current ruleset.
async fn publish_push_rules<S: AuthState>(state: &S, user_id: &str, ruleset: &[Rule]) -> Result<(), Response> {
    let content = json!({ "global": rules::ruleset_json(ruleset) });
    let storage = state.storage();
    let current = storage.get_account_data(user_id, None, "m.push_rules").await.map_err(internal)?;
    if current.as_ref() != Some(&content) {
        storage
            .set_account_data(user_id, None, "m.push_rules", &content)
            .await
            .map_err(internal)?;
        state.sync_notify().notify_waiters();
    }
    Ok(())
}

async fn republish<S: AuthState>(state: &S, user_id: &str) -> Response {
    match load_ruleset(state, user_id).await {
        Ok(ruleset) => match publish_push_rules(state, user_id, &ruleset).await {
            Ok(()) => ok(),
            Err(r) => r,
        },
        Err(r) => r,
    }
}

/// `GET /pushrules/`
pub async fn get_all_push_rules<S: AuthState>(State(state): State<S>, authed: AuthedUser) -> Response {
    match load_ruleset(&state, &authed.user_id).await {
        Ok(ruleset) => {
            if let Err(r) = publish_push_rules(&state, &authed.user_id, &ruleset).await {
                return r;
            }
            Json(json!({ "global": rules::ruleset_json(&ruleset) })).into_response()
        }
        Err(r) => r,
    }
}

/// `GET /pushrules/global/`
pub async fn get_global_push_rules<S: AuthState>(State(state): State<S>, authed: AuthedUser) -> Response {
    match load_ruleset(&state, &authed.user_id).await {
        Ok(ruleset) => Json(rules::ruleset_json(&ruleset)).into_response(),
        Err(r) => r,
    }
}

#[allow(clippy::result_large_err)]
fn check_kind(kind: &str) -> Result<(), Response> {
    if KINDS.contains(&kind) {
        Ok(())
    } else {
        Err(invalid(format!("unknown push rule kind: {kind}")))
    }
}

async fn find_rule<S: AuthState>(state: &S, user_id: &str, kind: &str, rule_id: &str) -> Result<Rule, Response> {
    check_kind(kind)?;
    load_ruleset(state, user_id)
        .await?
        .into_iter()
        .find(|r| r.kind == kind && r.rule_id == rule_id)
        .ok_or_else(rule_not_found)
}

pub async fn get_push_rule<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((kind, rule_id)): Path<(String, String)>,
) -> Response {
    match find_rule(&state, &authed.user_id, &kind, &rule_id).await {
        Ok(rule) => Json(rule.to_json()).into_response(),
        Err(r) => r,
    }
}

#[derive(Debug, Deserialize)]
pub struct PutPushRuleQuery {
    pub before: Option<String>,
    pub after: Option<String>,
}

/// `PUT /pushrules/global/{kind}/{ruleId}`: create or update a user rule.
pub async fn put_push_rule<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((kind, rule_id)): Path<(String, String)>,
    Query(query): Query<PutPushRuleQuery>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_kind(&kind) {
        return r;
    }
    if is_server_default_id(&rule_id) {
        return invalid("rule IDs starting with '.' are reserved for server-default rules");
    }
    if rule_id.is_empty() || rule_id.contains('/') || rule_id.contains('\\') {
        return invalid("rule IDs may not be empty or contain slashes or backslashes");
    }
    let Some(actions) = body.get("actions") else {
        return error(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", "actions is required");
    };
    let actions = match rules::normalize_actions(actions) {
        Ok(a) => a,
        Err(e) => return invalid(e),
    };
    let mut conditions = json!([]);
    let mut pattern = None;
    match kind.as_str() {
        "override" | "underride" => {
            if let Some(c) = body.get("conditions") {
                match rules::validate_conditions(c) {
                    Ok(c) => conditions = Value::Array(c),
                    Err(e) => return invalid(e),
                }
            }
        }
        "content" => match body.get("pattern").and_then(Value::as_str) {
            Some(p) => pattern = Some(p.to_owned()),
            None => return error(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", "content rules require a pattern"),
        },
        _ => {}
    }

    let storage = state.storage();
    let stored = match storage.list_push_rules(&authed.user_id).await {
        Ok(s) => s,
        Err(e) => return internal(e),
    };
    // User-defined rules of this kind, most important first.
    let mut ordered: Vec<PushRule> = stored
        .into_iter()
        .filter(|r| !r.is_default && r.scope == "global" && r.kind == kind)
        .collect();
    ordered.sort_by_key(|r| r.priority);
    let existing = ordered.iter().position(|r| r.rule_id == rule_id).map(|i| ordered.remove(i));
    let anchor = |id: &str, ordered: &[PushRule]| ordered.iter().position(|r| r.rule_id == id);
    let index = match (query.before.as_deref(), query.after.as_deref()) {
        (Some(before), _) => match anchor(before, &ordered) {
            Some(i) => Some(i),
            None => return error(StatusCode::BAD_REQUEST, "M_UNKNOWN", format!("before/after rule not found: {before}")),
        },
        (None, Some(after)) => match anchor(after, &ordered) {
            Some(i) => Some(i + 1),
            None => return error(StatusCode::BAD_REQUEST, "M_UNKNOWN", format!("before/after rule not found: {after}")),
        },
        (None, None) => None,
    };
    let rule = PushRule {
        user_id: authed.user_id.clone(),
        scope: "global".to_owned(),
        kind: kind.clone(),
        rule_id: rule_id.clone(),
        priority: 0,
        // New rules MUST be enabled; updates keep the current state.
        enabled: existing.as_ref().is_none_or(|r| r.enabled),
        conditions,
        actions: Value::Array(actions),
        pattern,
        is_default: false,
    };
    match (index, &existing) {
        (Some(i), _) => ordered.insert(i, rule),
        // An update without before/after keeps its place.
        (None, Some(old)) => {
            let i = ordered.iter().position(|r| r.priority > old.priority).unwrap_or(ordered.len());
            ordered.insert(i, rule);
        }
        // A new rule is the most important user-defined rule of its kind.
        (None, None) => ordered.insert(0, rule),
    }
    for (priority, mut rule) in ordered.into_iter().enumerate() {
        rule.priority = priority as i32;
        if let Err(e) = storage.upsert_push_rule(&rule).await {
            return internal(e);
        }
    }
    republish(&state, &authed.user_id).await
}

/// `DELETE /pushrules/global/{kind}/{ruleId}`: user rules only.
pub async fn delete_push_rule<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((kind, rule_id)): Path<(String, String)>,
) -> Response {
    let rule = match find_rule(&state, &authed.user_id, &kind, &rule_id).await {
        Ok(rule) => rule,
        Err(r) => return r,
    };
    if rule.default {
        return invalid("server-default rules cannot be deleted; disable them instead");
    }
    if let Err(e) = state.storage().delete_push_rule(&authed.user_id, "global", &kind, &rule_id).await {
        return internal(e);
    }
    republish(&state, &authed.user_id).await
}

pub async fn get_push_rule_enabled<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((kind, rule_id)): Path<(String, String)>,
) -> Response {
    match find_rule(&state, &authed.user_id, &kind, &rule_id).await {
        Ok(rule) => Json(json!({ "enabled": rule.enabled })).into_response(),
        Err(r) => r,
    }
}

pub async fn get_push_rule_actions<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((kind, rule_id)): Path<(String, String)>,
) -> Response {
    match find_rule(&state, &authed.user_id, &kind, &rule_id).await {
        Ok(rule) => Json(json!({ "actions": rule.actions })).into_response(),
        Err(r) => r,
    }
}

/// Store a change to `enabled` or `actions`: user rules are updated in
/// place, server-default rules get (or update) an overlay row.
async fn modify_rule<S: AuthState>(
    state: &S,
    user_id: &str,
    kind: &str,
    rule_id: &str,
    enabled: Option<bool>,
    actions: Option<Vec<Value>>,
) -> Response {
    let rule = match find_rule(state, user_id, kind, rule_id).await {
        Ok(rule) => rule,
        Err(r) => return r,
    };
    let storage = state.storage();
    let stored = match storage.get_push_rule(user_id, "global", kind, rule_id).await {
        Ok(stored) => stored,
        Err(e) => return internal(e),
    };
    let mut row = stored.unwrap_or_else(|| PushRule {
        user_id: user_id.to_owned(),
        scope: "global".to_owned(),
        kind: kind.to_owned(),
        rule_id: rule_id.to_owned(),
        priority: 0,
        enabled: rule.enabled,
        conditions: json!([]),
        actions: Value::Array(rule.actions.clone()),
        pattern: None,
        is_default: rule.default,
    });
    if let Some(enabled) = enabled {
        row.enabled = enabled;
    }
    if let Some(actions) = actions {
        row.actions = Value::Array(actions);
    }
    if let Err(e) = storage.upsert_push_rule(&row).await {
        return internal(e);
    }
    republish(state, user_id).await
}

pub async fn put_push_rule_enabled<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((kind, rule_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Response {
    let Some(enabled) = body.get("enabled").and_then(Value::as_bool) else {
        return error(StatusCode::BAD_REQUEST, "M_BAD_JSON", "enabled must be a boolean");
    };
    modify_rule(&state, &authed.user_id, &kind, &rule_id, Some(enabled), None).await
}

pub async fn put_push_rule_actions<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((kind, rule_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Response {
    let Some(actions) = body.get("actions") else {
        return error(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", "actions is required");
    };
    let actions = match rules::normalize_actions(actions) {
        Ok(a) => a,
        Err(e) => return invalid(e),
    };
    modify_rule(&state, &authed.user_id, &kind, &rule_id, None, Some(actions)).await
}

// ---------------------------------------------------------------------------
// GET /notifications
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct NotificationsQuery {
    pub from: Option<String>,
    pub limit: Option<String>,
    pub only: Option<String>,
}

const DEFAULT_NOTIFICATION_LIMIT: i64 = 50;
const MAX_NOTIFICATION_LIMIT: i64 = 1000;

pub async fn get_notifications<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(query): Query<NotificationsQuery>,
) -> Response {
    let before = match query.from.as_deref() {
        None => None,
        Some(token) => match token.parse::<i64>() {
            Ok(pos) if pos > 0 => Some(pos),
            _ => return invalid("from is not a token returned by /notifications"),
        },
    };
    let limit = match query.limit.as_deref() {
        None => DEFAULT_NOTIFICATION_LIMIT,
        Some(l) => match l.parse::<i64>() {
            Ok(l) if l > 0 => l.min(MAX_NOTIFICATION_LIMIT),
            _ => return invalid("limit must be a positive integer"),
        },
    };
    let only_highlight = query.only.as_deref() == Some("highlight");
    let storage = state.storage();
    if let Err(e) = notifications::process_pending(storage.as_ref(), state.server_name()).await {
        return internal(e);
    }
    let rows = match storage
        .list_push_notifications(&authed.user_id, before, limit + 1, only_highlight)
        .await
    {
        Ok(rows) => rows,
        Err(e) => return internal(e),
    };
    let more = rows.len() as i64 > limit;
    let mut read_cache = HashMap::new();
    let mut out = Vec::new();
    for row in rows.iter().take(limit as usize) {
        let event = match storage.get_event(&row.event_id).await {
            Ok(Some(event)) => event,
            Ok(None) => continue,
            Err(e) => return internal(e),
        };
        let read = match super::notification_counts::is_read(storage.as_ref(), &mut read_cache, &authed.user_id, row).await {
            Ok(read) => read,
            Err(e) => return internal(e),
        };
        out.push(json!({
            "actions": row.actions,
            "event": serde_json::to_value(&event).unwrap_or(Value::Null),
            "read": read,
            "room_id": row.room_id,
            "ts": row.ts,
        }));
    }
    let mut response = json!({ "notifications": out });
    if more {
        if let Some(last) = rows.get(limit as usize - 1) {
            response["next_token"] = json!(last.stream_pos.to_string());
        }
    }
    Json(response).into_response()
}
