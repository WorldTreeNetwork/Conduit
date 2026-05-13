//! Typed content structs for Matrix room state events.
//!
//! Each struct corresponds to a well-known `m.room.*` event type and can be
//! deserialised from the `content` field of a [`crate::event::Event`].
//!
//! Reference: <https://spec.matrix.org/latest/rooms/v11/>

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// The `membership` field on `m.room.member` content.
///
/// Wire values are lowercase strings (`"invite"`, `"join"`, …).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Membership {
    Invite,
    Join,
    Leave,
    Ban,
    Knock,
}

/// The `join_rule` field on `m.room.join_rules` content.
///
/// Wire values are snake_case strings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinRule {
    Public,
    Invite,
    Knock,
    Restricted,
    KnockRestricted,
    Private,
}

/// The `history_visibility` field on `m.room.history_visibility` content.
///
/// Wire values are snake_case strings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryVisibility {
    Invited,
    Joined,
    Shared,
    WorldReadable,
}

// ---------------------------------------------------------------------------
// Content structs
// ---------------------------------------------------------------------------

/// Content of `m.room.create`.
///
/// In room version 11 the `creator` field was removed from the content; the
/// creator is now the `sender` of the create event.  The field is kept here
/// (as `Option<String>`) for wire-format compatibility with earlier versions.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CreateContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    /// Room version string (e.g. `"11"`).  Defaults to `"1"` if absent on
    /// the wire (spec-defined default), but we store it explicitly.
    #[serde(default = "default_room_version")]
    pub room_version: String,
    /// Optional federation predecessor data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predecessor: Option<Value>,
}

fn default_room_version() -> String {
    "1".to_owned()
}

/// Content of `m.room.member`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MemberContent {
    pub membership: Membership,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub displayname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// Reason supplied by the sender (kick/ban/leave).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether this invite is a direct message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_direct: Option<bool>,
}

/// Content of `m.room.power_levels`.
///
/// All integer fields default to sensible spec values when absent.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PowerLevelsContent {
    #[serde(default = "default_pl_50")]
    pub ban: i64,
    #[serde(default = "default_pl_50")]
    pub kick: i64,
    #[serde(default = "default_pl_50")]
    pub redact: i64,
    #[serde(default = "default_pl_50")]
    pub invite: i64,
    #[serde(default)]
    pub events_default: i64,
    #[serde(default = "default_pl_50")]
    pub state_default: i64,
    #[serde(default)]
    pub users_default: i64,
    #[serde(default)]
    pub events: HashMap<String, i64>,
    #[serde(default)]
    pub users: HashMap<String, i64>,
    /// Notification-target power levels (e.g. `"room": 50`).
    #[serde(default)]
    pub notifications: HashMap<String, i64>,
}

fn default_pl_50() -> i64 {
    50
}

impl Default for PowerLevelsContent {
    fn default() -> Self {
        Self {
            ban: 50,
            kick: 50,
            redact: 50,
            invite: 50,
            events_default: 0,
            state_default: 50,
            users_default: 0,
            events: HashMap::new(),
            users: HashMap::new(),
            notifications: HashMap::new(),
        }
    }
}

/// Content of `m.room.join_rules`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JoinRulesContent {
    pub join_rule: JoinRule,
    /// `allow` conditions — only relevant for `restricted` / `knock_restricted`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Value>,
}

/// Content of `m.room.history_visibility`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistoryVisibilityContent {
    pub history_visibility: HistoryVisibility,
}

// ---------------------------------------------------------------------------
// Parse helpers
// ---------------------------------------------------------------------------

/// Parse `m.room.create` content from a raw JSON value.
pub fn parse_create(content: &Value) -> Result<CreateContent, serde_json::Error> {
    serde_json::from_value(content.clone())
}

/// Parse `m.room.member` content from a raw JSON value.
pub fn parse_member(content: &Value) -> Result<MemberContent, serde_json::Error> {
    serde_json::from_value(content.clone())
}

/// Parse `m.room.power_levels` content from a raw JSON value.
pub fn parse_power_levels(content: &Value) -> Result<PowerLevelsContent, serde_json::Error> {
    serde_json::from_value(content.clone())
}

/// Parse `m.room.join_rules` content from a raw JSON value.
pub fn parse_join_rules(content: &Value) -> Result<JoinRulesContent, serde_json::Error> {
    serde_json::from_value(content.clone())
}

/// Parse `m.room.history_visibility` content from a raw JSON value.
pub fn parse_history_visibility(
    content: &Value,
) -> Result<HistoryVisibilityContent, serde_json::Error> {
    serde_json::from_value(content.clone())
}
