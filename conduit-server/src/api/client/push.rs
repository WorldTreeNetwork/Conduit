//! Push notification endpoints (E11 P1–P6).
//!
//! Implements:
//!   GET  /_matrix/client/v3/pushers
//!   POST /_matrix/client/v3/pushers/set
//!   GET  /_matrix/client/v3/pushrules/
//!   GET  /_matrix/client/v3/pushrules/:scope/:kind/:ruleId
//!   PUT  /_matrix/client/v3/pushrules/:scope/:kind/:ruleId
//!   DELETE /_matrix/client/v3/pushrules/:scope/:kind/:ruleId
//!   GET  /_matrix/client/v3/pushrules/:scope/:kind/:ruleId/enabled
//!   PUT  /_matrix/client/v3/pushrules/:scope/:kind/:ruleId/enabled
//!   GET  /_matrix/client/v3/pushrules/:scope/:kind/:ruleId/actions
//!   PUT  /_matrix/client/v3/pushrules/:scope/:kind/:ruleId/actions
//!   POST /_matrix/client/v3/notifications

pub mod rules;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use conduit::storage::{Pusher, PushRule};

use super::{AuthState, AuthedUser, MatrixError};
use self::rules::default_push_rules;

// ---------------------------------------------------------------------------
// GET /_matrix/client/v3/pushers
// ---------------------------------------------------------------------------

pub async fn get_pushers<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
) -> Response {
    match state.storage().list_pushers(&authed.user_id).await {
        Ok(pushers) => {
            let arr: Vec<Value> = pushers.into_iter().map(pusher_to_json).collect();
            Json(json!({ "pushers": arr })).into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

fn pusher_to_json(p: Pusher) -> Value {
    let mut data = p.data.clone();
    if let Value::Object(ref mut map) = data {
        if let Some(url) = &p.url {
            map.insert("url".to_owned(), Value::String(url.clone()));
        }
        if let Some(fmt) = &p.format {
            map.insert("format".to_owned(), Value::String(fmt.clone()));
        }
    }
    json!({
        "pushkey": p.pushkey,
        "kind": p.kind,
        "app_id": p.app_id,
        "app_display_name": p.app_display_name,
        "device_display_name": p.device_display_name,
        "profile_tag": p.profile_tag,
        "lang": p.lang,
        "data": data,
    })
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/pushers/set
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SetPusherRequest {
    pub pushkey: String,
    pub kind: Option<String>,
    pub app_id: String,
    pub app_display_name: Option<String>,
    pub device_display_name: Option<String>,
    pub profile_tag: Option<String>,
    pub lang: Option<String>,
    pub data: Option<Value>,
    pub append: Option<bool>,
}

pub async fn set_pusher<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Json(body): Json<SetPusherRequest>,
) -> Response {
    let storage = state.storage();

    // kind=null means delete
    if body.kind.is_none() {
        match storage.delete_pusher(&authed.user_id, &body.pushkey, &body.app_id).await {
            Ok(_) => return (StatusCode::OK, Json(json!({}))).into_response(),
            Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
        }
    }

    let kind = body.kind.unwrap();
    if kind == "http" && body.data.as_ref().and_then(|d| d.get("url")).is_none() {
        return MatrixError::bad_json("http pusher requires data.url").into_response();
    }

    let data = body.data.clone().unwrap_or_else(|| json!({}));
    let url = data.get("url").and_then(Value::as_str).map(|s| s.to_owned());
    let format = data.get("format").and_then(Value::as_str).map(|s| s.to_owned());

    let pusher = Pusher {
        user_id: authed.user_id.clone(),
        pushkey: body.pushkey.clone(),
        app_id: body.app_id.clone(),
        app_display_name: body.app_display_name.clone(),
        device_display_name: body.device_display_name.clone(),
        kind,
        lang: body.lang.clone().unwrap_or_else(|| "en".to_owned()),
        profile_tag: body.profile_tag.clone(),
        url,
        format,
        data,
    };

    match storage.upsert_pusher(&pusher).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /_matrix/client/v3/pushrules/
// ---------------------------------------------------------------------------

pub async fn get_all_push_rules<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
) -> Response {
    let storage = state.storage();

    let mut rules = match storage.list_push_rules(&authed.user_id).await {
        Ok(r) => r,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };

    // If no rules at all, seed with defaults.
    if rules.is_empty() {
        let defaults = default_push_rules(&authed.user_id);
        for rule in &defaults {
            let _ = storage.upsert_push_rule(rule).await;
        }
        rules = defaults;
    }

    Json(json!({ "global": rules_to_global_json(rules) })).into_response()
}

fn rules_to_global_json(rules: Vec<PushRule>) -> Value {
    let mut override_rules: Vec<Value> = vec![];
    let mut content_rules: Vec<Value> = vec![];
    let mut room_rules: Vec<Value> = vec![];
    let mut sender_rules: Vec<Value> = vec![];
    let mut underride_rules: Vec<Value> = vec![];

    for rule in rules {
        let v = rule_to_json(&rule);
        match rule.kind.as_str() {
            "override" => override_rules.push(v),
            "content" => content_rules.push(v),
            "room" => room_rules.push(v),
            "sender" => sender_rules.push(v),
            "underride" => underride_rules.push(v),
            _ => {}
        }
    }

    json!({
        "override": override_rules,
        "content": content_rules,
        "room": room_rules,
        "sender": sender_rules,
        "underride": underride_rules,
    })
}

fn rule_to_json(rule: &PushRule) -> Value {
    let mut v = json!({
        "rule_id": rule.rule_id,
        "enabled": rule.enabled,
        "actions": rule.actions,
    });
    // Add conditions (for override/underride) or pattern (for content).
    if rule.kind == "content" {
        if let Some(pat) = &rule.pattern {
            v["pattern"] = Value::String(pat.clone());
        }
    } else {
        v["conditions"] = rule.conditions.clone();
    }
    v
}

// ---------------------------------------------------------------------------
// GET /_matrix/client/v3/pushrules/:scope/:kind/:ruleId
// ---------------------------------------------------------------------------

pub async fn get_push_rule<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((scope, kind, rule_id)): Path<(String, String, String)>,
) -> Response {
    match state.storage().get_push_rule(&authed.user_id, &scope, &kind, &rule_id).await {
        Ok(Some(rule)) => Json(rule_to_json(&rule)).into_response(),
        Ok(None) => MatrixError::new_not_found("push rule not found").into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /_matrix/client/v3/pushrules/:scope/:kind/:ruleId
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PutPushRuleRequest {
    pub actions: Value,
    pub conditions: Option<Value>,
    pub pattern: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PutPushRuleQuery {
    pub before: Option<String>,
    pub after: Option<String>,
}

pub async fn put_push_rule<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((scope, kind, rule_id)): Path<(String, String, String)>,
    Query(_query): Query<PutPushRuleQuery>,
    Json(body): Json<PutPushRuleRequest>,
) -> Response {
    let storage = state.storage();

    // Check for existing to determine priority.
    let existing = storage.get_push_rule(&authed.user_id, &scope, &kind, &rule_id).await.ok().flatten();
    let priority = existing.map(|r| r.priority).unwrap_or(100);

    let rule = PushRule {
        user_id: authed.user_id.clone(),
        scope: scope.clone(),
        kind: kind.clone(),
        rule_id: rule_id.clone(),
        priority,
        enabled: true,
        conditions: body.conditions.unwrap_or_else(|| json!([])),
        actions: body.actions,
        pattern: body.pattern,
        is_default: false,
    };

    match storage.upsert_push_rule(&rule).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// DELETE /_matrix/client/v3/pushrules/:scope/:kind/:ruleId
// ---------------------------------------------------------------------------

pub async fn delete_push_rule<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((scope, kind, rule_id)): Path<(String, String, String)>,
) -> Response {
    match state.storage().delete_push_rule(&authed.user_id, &scope, &kind, &rule_id).await {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /_matrix/client/v3/pushrules/:scope/:kind/:ruleId/enabled
// ---------------------------------------------------------------------------

pub async fn get_push_rule_enabled<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((scope, kind, rule_id)): Path<(String, String, String)>,
) -> Response {
    match state.storage().get_push_rule(&authed.user_id, &scope, &kind, &rule_id).await {
        Ok(Some(rule)) => Json(json!({ "enabled": rule.enabled })).into_response(),
        Ok(None) => MatrixError::new_not_found("push rule not found").into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /_matrix/client/v3/pushrules/:scope/:kind/:ruleId/enabled
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

pub async fn put_push_rule_enabled<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((scope, kind, rule_id)): Path<(String, String, String)>,
    Json(body): Json<SetEnabledRequest>,
) -> Response {
    match state.storage()
        .set_push_rule_enabled(&authed.user_id, &scope, &kind, &rule_id, body.enabled)
        .await
    {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /_matrix/client/v3/pushrules/:scope/:kind/:ruleId/actions
// ---------------------------------------------------------------------------

pub async fn get_push_rule_actions<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((scope, kind, rule_id)): Path<(String, String, String)>,
) -> Response {
    match state.storage().get_push_rule(&authed.user_id, &scope, &kind, &rule_id).await {
        Ok(Some(rule)) => Json(json!({ "actions": rule.actions })).into_response(),
        Ok(None) => MatrixError::new_not_found("push rule not found").into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /_matrix/client/v3/pushrules/:scope/:kind/:ruleId/actions
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SetActionsRequest {
    pub actions: Value,
}

pub async fn put_push_rule_actions<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((scope, kind, rule_id)): Path<(String, String, String)>,
    Json(body): Json<SetActionsRequest>,
) -> Response {
    match state.storage()
        .set_push_rule_actions(&authed.user_id, &scope, &kind, &rule_id, body.actions)
        .await
    {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /_matrix/client/v3/notifications  (stub — returns empty list for v0)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct NotificationsQuery {
    pub from: Option<String>,
    pub limit: Option<i64>,
    pub only: Option<String>,
}

pub async fn get_notifications<S: AuthState>(
    State(_state): State<S>,
    _authed: AuthedUser,
    Query(_query): Query<NotificationsQuery>,
) -> Json<Value> {
    Json(json!({
        "next_token": null,
        "notifications": []
    }))
}
