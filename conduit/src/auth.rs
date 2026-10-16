//! Room v11 authorization rules.
//!
//! The single entry point is [`check_auth`], which evaluates a candidate
//! event against the relevant subset of the room's current state and returns
//! `Ok(())` if the event is allowed or an [`AuthError`] describing why it was
//! rejected.
//!
//! Reference: <https://spec.matrix.org/latest/rooms/v11/#authorization-rules>

use std::collections::HashMap;

use thiserror::Error;

use crate::event::Event;
use crate::state_events::{
    parse_create, parse_history_visibility, parse_join_rules, parse_member, parse_power_levels,
    HistoryVisibility, JoinRule, JoinRulesContent, Membership, PowerLevelsContent,
};

// ---------------------------------------------------------------------------
// StateMap type alias
// ---------------------------------------------------------------------------

/// A snapshot of a room's current state, keyed by `(event_type, state_key)`.
///
/// Used as the "auth state" passed to [`check_auth`] and [`apply_state_event`].
pub type StateMap<T> = HashMap<(String, String), T>;

// ---------------------------------------------------------------------------
// AuthError
// ---------------------------------------------------------------------------

/// Detailed rejection reasons from the v11 auth rule set.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("room already has a create event")]
    RoomAlreadyCreated,

    #[error("create event has non-empty prev_events")]
    CreateHasPrevEvents,

    #[error("create event sender domain does not match room_id domain")]
    CreateSenderDomainMismatch,

    #[error("create event content.room_version is not a string")]
    CreateInvalidRoomVersion,

    #[error("create event is missing content.creator")]
    CreateMissingCreator,

    #[error("room version 12 create event must omit room_id")]
    CreateMustOmitRoomId,

    #[error("m.room.aliases state_key must be the sender's server name")]
    AliasStateKey,

    #[error("power levels cannot name a room creator")]
    CreatorInPowerLevels,

    #[error("no m.room.create event in auth state")]
    MissingCreateEvent,

    #[error("sender is not joined to the room")]
    SenderNotJoined,

    #[error("sender is banned from the room")]
    SenderBanned,

    #[error("state_key starts with '@' but does not match sender")]
    StateKeyUserMismatch,

    #[error("invalid membership transition: {from:?} -> {to:?}")]
    InvalidMemberTransition {
        from: Option<Membership>,
        to: Membership,
    },

    #[error("join rejected: join_rule is {join_rule:?} and sender has no invite")]
    JoinRequiresInvite { join_rule: JoinRule },

    #[error("join rejected: target is banned")]
    JoinTargetBanned,

    #[error("invite rejected: target is already joined or banned")]
    InviteTargetAlreadyJoinedOrBanned,

    #[error("insufficient power level: needed {needed}, sender has {sender_has}")]
    InsufficientPowerLevel { needed: i64, sender_has: i64 },

    #[error("sender cannot set a power level above their own ({sender_has})")]
    PowerLevelExceedsSelf { sender_has: i64 },

    #[error("sender cannot demote a user with equal or higher power level")]
    CannotDemoteHigherLevel,

    #[error("m.room.member event missing state_key")]
    MemberEventMissingStateKey,

    #[error("failed to parse event content: {0}")]
    ContentParseError(String),

    #[error("join_authorised_via_users_server is not validly signed by its homeserver")]
    AuthoriserSignatureMissing,

    #[error("third-party invite rejected: {0}")]
    ThirdPartyInvite(&'static str),

    #[error("redaction is not allowed by room versions 1 and 2")]
    RedactionDenied,
}

/// v11 auth rule 4.2: "If `content` has a `join_authorised_via_users_server`
/// key: If the event is not validly signed by the homeserver of the user ID
/// denoted by the key, reject."
///
/// `signed_by` is the set of servers whose signatures verified on receipt
/// ([`crate::signing::verify_signatures`]). Joins never reach this check
/// without the authoriser (they are dropped at the signature stage, as
/// Synapse does); for other memberships this is where a missing or invalid
/// authoriser signature becomes a rejection rather than a drop. Passing it
/// leaves every other auth rule applicable.
pub fn check_authoriser_signature(event: &crate::event::Pdu, signed_by: &crate::event::SignedBy) -> Result<(), AuthError> {
    if event.event_type != "m.room.member" {
        return Ok(());
    }
    let Some(authoriser) = event.content.get("join_authorised_via_users_server") else {
        return Ok(());
    };
    match authoriser.as_str().and_then(crate::signing::server_of_user_id) {
        Some(server) if signed_by.contains(server) => Ok(()),
        _ => Err(AuthError::AuthoriserSignatureMissing),
    }
}

// ---------------------------------------------------------------------------
// dn9.4 — Power level helpers
// ---------------------------------------------------------------------------

/// Return the effective power level of `user_id` given the optional
/// `m.room.power_levels` state event.
///
/// If no power_levels event exists the spec defines the following defaults:
/// - creator of the room → 100
/// - everyone else → 0
///
/// Because we don't have the create event here, callers who need creator
/// handling should pass `creator_id` separately; we take it as `Option<&str>`.
pub fn user_power_level(
    user_id: &str,
    pl_event: Option<&Event>,
    creator_id: Option<&str>,
) -> i64 {
    match pl_event {
        None => {
            // Spec: before any power_levels event the creator has level 100,
            // everyone else has 0.
            if creator_id.map(|c| c == user_id).unwrap_or(false) {
                100
            } else {
                0
            }
        }
        Some(ev) => {
            match parse_power_levels(&ev.content) {
                Ok(pl) => *pl.users.get(user_id).unwrap_or(&pl.users_default),
                // If content is malformed, treat as defaults.
                Err(_) => 0,
            }
        }
    }
}

/// Return the minimum power level required to send an event of `event_type`.
///
/// `is_state` controls whether `state_default` or `events_default` is the
/// fallback when the type has no explicit entry in `pl.events`.
pub fn level_required_for_event(
    event_type: &str,
    is_state: bool,
    pl: &PowerLevelsContent,
) -> i64 {
    if let Some(&lvl) = pl.events.get(event_type) {
        return lvl;
    }
    if is_state {
        pl.state_default
    } else {
        pl.events_default
    }
}

// ---------------------------------------------------------------------------
// dn9.7 — Auth-event lookup helper
// ---------------------------------------------------------------------------

/// Return the `(event_type, state_key)` pairs whose current-state events are
/// required to authorize `event`.
///
/// Callers use this to build the `auth_state` slice passed to [`check_auth`].
pub fn auth_event_keys(event: &Event) -> Vec<(String, String)> {
    let mut keys: Vec<(String, String)> = Vec::new();

    // m.room.create is its own auth — nothing is needed.
    if event.event_type == "m.room.create" {
        return keys;
    }

    // Every non-create event needs the create and power_levels events.
    keys.push(("m.room.create".to_owned(), String::new()));
    keys.push(("m.room.power_levels".to_owned(), String::new()));

    // Sender's own membership.
    keys.push(("m.room.member".to_owned(), event.sender.clone()));

    // For m.room.member we also need the target and join_rules.
    if event.event_type == "m.room.member" {
        if let Some(state_key) = &event.state_key {
            // Target's current membership (may differ from sender).
            if state_key != &event.sender {
                keys.push(("m.room.member".to_owned(), state_key.clone()));
            }
            // join_rules is needed for join, invite and knock (spec
            // "Auth events selection").
            if let Ok(mc) = parse_member(&event.content) {
                if matches!(mc.membership, Membership::Join | Membership::Invite | Membership::Knock) {
                    keys.push(("m.room.join_rules".to_owned(), String::new()));
                }
                // A third-party invite is authorised by the matching
                // m.room.third_party_invite (spec "auth events selection").
                if matches!(mc.membership, Membership::Invite) {
                    if let Some(token) = event.content["third_party_invite"]["signed"]["token"].as_str() {
                        keys.push(("m.room.third_party_invite".to_owned(), token.to_owned()));
                    }
                }
                // Restricted joins (room versions that support them) are
                // authorised by the named user's member event. The field is
                // only written for those versions; selecting it here is what
                // puts that event in auth state.
                if matches!(mc.membership, Membership::Join) {
                    if let Some(authoriser) = event
                        .content
                        .get("join_authorised_via_users_server")
                        .and_then(|value| value.as_str())
                        .filter(|authoriser| !authoriser.is_empty())
                    {
                        if authoriser != event.sender && authoriser != state_key.as_str() {
                            keys.push(("m.room.member".to_owned(), authoriser.to_owned()));
                        }
                    }
                }
            }
        }
    }

    keys
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn get_pl_content(auth_state: &StateMap<Event>) -> PowerLevelsContent {
    let Some(ev) = auth_state.get(&("m.room.power_levels".to_owned(), String::new())) else {
        return PowerLevelsContent::default();
    };
    // Versions 1–5 coerce strings and truncated floats. Versions 6–9 coerce
    // integer strings only. Version 10 keeps JSON integers and nothing else.
    let content = crate::room_version::power_levels_for_auth(
        &ev.content,
        room_version_from_state(auth_state),
    );
    parse_power_levels(&content).unwrap_or_default()
}

fn get_join_rule(auth_state: &StateMap<Event>) -> JoinRule {
    auth_state
        .get(&("m.room.join_rules".to_owned(), String::new()))
        .and_then(|ev| parse_join_rules(&ev.content).ok())
        .map(|c| c.join_rule)
        .unwrap_or(JoinRule::Invite) // default per spec
}

/// Check whether `event` satisfies the `allow` conditions of the room's
/// join_rules (applicable only to `restricted` / `knock_restricted` rules).
///
/// Event auth does not call this. A foreign `allow.room_id` is unevaluable
/// from this room's state and fails closed; the tests keep that pin.
#[cfg_attr(not(test), allow(dead_code))]
///
/// Returns `true` if:
/// - The join rule is NOT restricted/knock_restricted (no extra check needed), OR
/// - Any `allow` condition is satisfied (the user is a member of the referenced room).
///
/// Returns `false` if no `allow` condition matches and the rule IS restricted.
fn check_allow_conditions(event: &Event, state: &StateMap<Event>) -> bool {
    let join_rules: Option<JoinRulesContent> = state
        .get(&("m.room.join_rules".to_owned(), String::new()))
        .and_then(|ev| parse_join_rules(&ev.content).ok());

    let Some(jr) = join_rules else {
        // No join_rules event means default (invite) — no allow check needed.
        return true;
    };

    // Only restricted/knock_restricted have meaningful allow conditions.
    if jr.join_rule != JoinRule::Restricted && jr.join_rule != JoinRule::KnockRestricted {
        return true;
    }

    // Iterate allow conditions.
    for condition in &jr.allow {
        match condition.get("type").and_then(|v| v.as_str()) {
            Some("m.room_membership") => {
                // `room_id` names the room whose membership would satisfy
                // the condition — in practice a space, i.e. some *other*
                // room.  We only hold this room's state here, so any
                // foreign room_id is unevaluable and fails closed.
                //
                // Reading this room's member event and calling that proof
                // of membership in the space is not a weaker check, it is
                // a different check that happens to be green.
                //
                // Where the real thing belongs: for room versions 8+ the
                // join is authorized by `join_authorised_via_users_server`
                // plus that server's signature, which event auth verifies;
                // the other-room membership lookup belongs on the CS
                // `join_room` originator path, where this server decides
                // whether to vouch.  Neither one lives in
                // `check_allow_conditions` (conduit-jt5).
                let Some(room_id) = condition.get("room_id").and_then(|v| v.as_str()) else {
                    continue;
                };
                if room_id != event.room_id {
                    continue;
                }
                let member_key = ("m.room.member".to_owned(), event.sender.clone());
                let membership = state
                    .get(&member_key)
                    .and_then(|ev| parse_member(&ev.content).ok())
                    .map(|mc| mc.membership);
                if membership == Some(Membership::Join) {
                    return true;
                }
            }
            _ => {
                // Unknown condition type — skip per spec (not an error).
                continue;
            }
        }
    }

    false
}

/// Room-version auth for a restricted join: `join_authorised_via_users_server`
/// names a user who is joined to this room and whose power is at least the
/// invite level. The other room's membership is not visible here.
fn authoriser_may_invite(event: &Event, auth_state: &StateMap<Event>, pl: &PowerLevelsContent) -> bool {
    let Some(authoriser) = event
        .content
        .get("join_authorised_via_users_server")
        .and_then(|value| value.as_str())
    else {
        return false;
    };
    if get_membership(auth_state, authoriser) != Some(Membership::Join) {
        return false;
    }
    effective_user_level(authoriser, auth_state) >= pl.invite
}

fn get_membership(auth_state: &StateMap<Event>, user_id: &str) -> Option<Membership> {
    auth_state
        .get(&("m.room.member".to_owned(), user_id.to_owned()))
        .and_then(|ev| parse_member(&ev.content).ok())
        .map(|mc| mc.membership)
}

fn create_event(auth_state: &StateMap<Event>) -> Option<&Event> {
    auth_state.get(&("m.room.create".to_owned(), String::new()))
}

fn room_version_from_state(auth_state: &StateMap<Event>) -> u32 {
    create_event(auth_state)
        .map(crate::room_version::version_of_event)
        .unwrap_or(11)
}

/// Creators with infinite power in room version 12, or the single creator before that.
fn creators_of(auth_state: &StateMap<Event>) -> Vec<String> {
    let Some(create) = create_event(auth_state) else {
        return Vec::new();
    };
    let version = crate::room_version::version_of_event(create);
    if version >= 12 {
        let mut creators = vec![create.sender.clone()];
        creators.extend(crate::room_version::additional_creators(&create.content));
        return creators;
    }
    if version >= 11 {
        return vec![create.sender.clone()];
    }
    match create.content.get("creator").and_then(serde_json::Value::as_str) {
        Some(creator) => vec![creator.to_owned()],
        None => vec![create.sender.clone()],
    }
}

fn creator_id(auth_state: &StateMap<Event>) -> Option<String> {
    creators_of(auth_state).into_iter().next()
}

/// Power level used by the auth rules, including infinite room-version-12 creators.
pub fn effective_user_level(user_id: &str, auth_state: &StateMap<Event>) -> i64 {
    if room_version_from_state(auth_state) >= 12
        && creators_of(auth_state).iter().any(|creator| creator == user_id)
    {
        return i64::MAX;
    }
    let pl_event = auth_state.get(&("m.room.power_levels".to_owned(), String::new()));
    if pl_event.is_none() {
        return user_power_level(user_id, None, creator_id(auth_state).as_deref());
    }
    let pl = get_pl_content(auth_state);
    *pl.users.get(user_id).unwrap_or(&pl.users_default)
}

/// Extract the local-server domain from a Matrix ID or room ID.
/// `@user:example.com` → `"example.com"`
/// `!room:example.com` → `"example.com"`
fn domain_of(id: &str) -> &str {
    id.splitn(2, ':').nth(1).unwrap_or("")
}

// ---------------------------------------------------------------------------
// dn9.8 — check_auth
// ---------------------------------------------------------------------------

/// Evaluate a candidate event against the v11 authorization rules.
///
/// `auth_state` should contain the events returned by
/// [`auth_event_keys`] looked up from the room's current state.
pub fn check_auth(event: &Event, auth_state: &StateMap<Event>) -> Result<(), AuthError> {
    // -----------------------------------------------------------------------
    // Rule 1: m.room.create
    // -----------------------------------------------------------------------
    if event.event_type == "m.room.create" {
        return check_create(event, auth_state);
    }

    // -----------------------------------------------------------------------
    // Rule 2: every non-create event must have a create event in auth state.
    // -----------------------------------------------------------------------
    if !auth_state.contains_key(&("m.room.create".to_owned(), String::new())) {
        return Err(AuthError::MissingCreateEvent);
    }

    let version = room_version_from_state(auth_state);
    // Room versions 1–5: m.room.aliases is allowed exactly when state_key is
    // the sender's server name, before the membership check.
    if version <= 5 && event.event_type == "m.room.aliases" {
        let Some(state_key) = event.state_key.as_deref() else {
            return Err(AuthError::AliasStateKey);
        };
        if domain_of(&event.sender) != state_key {
            return Err(AuthError::AliasStateKey);
        }
        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Rule 3: state_key starting with '@' must equal sender (user-namespaced
    //         state).  Exemption: m.room.member handles its own rules below.
    // -----------------------------------------------------------------------
    if event.event_type != "m.room.member" {
        if let Some(sk) = &event.state_key {
            if sk.starts_with('@') && sk != &event.sender {
                return Err(AuthError::StateKeyUserMismatch);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Rule 4: sender must be joined (unless it's their own leave/ban).
    // -----------------------------------------------------------------------
    let sender_membership = get_membership(auth_state, &event.sender);

    // We defer the sender-joined check for m.room.member because the target
    // might be the sender doing a self-leave or join.
    if event.event_type != "m.room.member" {
        match &sender_membership {
            Some(Membership::Join) => {} // ok
            Some(Membership::Ban) => return Err(AuthError::SenderBanned),
            _ => return Err(AuthError::SenderNotJoined),
        }
    }

    // -----------------------------------------------------------------------
    // Per-type rules
    // -----------------------------------------------------------------------
    match event.event_type.as_str() {
        "m.room.member" => check_member(event, auth_state, &sender_membership, version)?,
        "m.room.power_levels" => check_power_levels(event, auth_state)?,
        // Allowed iff the sender's power level is at least the invite level.
        "m.room.third_party_invite" => {
            let pl = get_pl_content(auth_state);
            let sender_level = effective_user_level(&event.sender, auth_state);
            if sender_level < pl.invite {
                return Err(AuthError::InsufficientPowerLevel {
                    needed: pl.invite,
                    sender_has: sender_level,
                });
            }
            return Ok(());
        }
        _ => {
            // Generic rule: sender must be joined.
            match &sender_membership {
                Some(Membership::Join) => {}
                Some(Membership::Ban) => return Err(AuthError::SenderBanned),
                _ => return Err(AuthError::SenderNotJoined),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Rule 5: power level check — sender has enough level for this event.
    // -----------------------------------------------------------------------
    // (m.room.member and m.room.power_levels have their own internal checks.)
    if event.event_type != "m.room.member" && event.event_type != "m.room.power_levels" {
        let pl = get_pl_content(auth_state);
        let sender_level = effective_user_level(&event.sender, auth_state);
        let is_state = event.state_key.is_some();
        let required = level_required_for_event(&event.event_type, is_state, &pl);
        if sender_level < required {
            return Err(AuthError::InsufficientPowerLevel {
                needed: required,
                sender_has: sender_level,
            });
        }
    }

    // Room versions 1 and 2, rule 11. The redact level gates the event, and
    // a sender below that level may still redact an event whose id shares
    // this redaction's event-id domain. Version 3 drops this auth rule.
    if version <= 2 && event.event_type == "m.room.redaction" {
        let pl = get_pl_content(auth_state);
        let sender_level = effective_user_level(&event.sender, auth_state);
        if sender_level < pl.redact {
            let target = event
                .extensions
                .get("redacts")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let redaction_domain = domain_of(&event.event_id);
            if redaction_domain.is_empty() || domain_of(target) != redaction_domain {
                return Err(AuthError::RedactionDenied);
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// dn9.2 — m.room.create checks
// ---------------------------------------------------------------------------

fn check_create(event: &Event, auth_state: &StateMap<Event>) -> Result<(), AuthError> {
    // No prior create event may exist.
    if auth_state.contains_key(&("m.room.create".to_owned(), String::new())) {
        return Err(AuthError::RoomAlreadyCreated);
    }

    // prev_events must be empty.
    if !event.prev_events.is_empty() {
        return Err(AuthError::CreateHasPrevEvents);
    }

    let version = crate::room_version::version_of_event(event);
    if version >= 12 {
        if !event.room_id.is_empty() {
            return Err(AuthError::CreateMustOmitRoomId);
        }
        if let Some(extra) = event.content.get("additional_creators") {
            let ok = extra.as_array().is_some_and(|items| {
                items.iter().all(|item| item.as_str().is_some_and(crate::room_version::valid_user_id))
            });
            if !ok {
                return Err(AuthError::ContentParseError(
                    "additional_creators must be an array of user ids".into(),
                ));
            }
        }
    } else if domain_of(&event.sender) != domain_of(&event.room_id) {
        return Err(AuthError::CreateSenderDomainMismatch);
    }

    // room_version in content must be a string (if present).
    let content = parse_create(&event.content)
        .map_err(|e| AuthError::ContentParseError(e.to_string()))?;
    if version < 11 && content.creator.as_deref().unwrap_or("").is_empty() {
        return Err(AuthError::CreateMissingCreator);
    }
    let _ = content.room_version;

    Ok(())
}

// ---------------------------------------------------------------------------
// Third-party invites (conduit-y99.36)
// ---------------------------------------------------------------------------

/// Decode an Ed25519 public key in unpadded standard or URL-safe base64.
fn decode_public_key(key: &str) -> Option<ed25519_dalek::VerifyingKey> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    let trimmed = key.trim_end_matches('=');
    let bytes = STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes.try_into().ok()?).ok()
}

/// Whether any signature in `signed.signatures` verifies against `key`.
pub fn third_party_signed_matches(signed: &serde_json::Value, key: &str) -> bool {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    let Some(verifying) = decode_public_key(key) else {
        return false;
    };
    let mut unsigned = signed.clone();
    let Some(object) = unsigned.as_object_mut() else {
        return false;
    };
    object.remove("signatures");
    object.remove("unsigned");
    let Ok(bytes) = crate::canonical_json::to_canonical_bytes(&unsigned) else {
        return false;
    };
    let Some(servers) = signed["signatures"].as_object() else {
        return false;
    };
    servers
        .values()
        .filter_map(serde_json::Value::as_object)
        .flat_map(|keys| keys.iter())
        .filter(|(key_id, _)| key_id.starts_with("ed25519:"))
        .filter_map(|(_, sig)| sig.as_str())
        .filter_map(|sig| {
            let sig = sig.trim_end_matches('=');
            STANDARD_NO_PAD.decode(sig).or_else(|_| URL_SAFE_NO_PAD.decode(sig)).ok()
        })
        .filter_map(|raw| ed25519_dalek::Signature::from_slice(&raw).ok())
        .any(|signature| verifying.verify_strict(&bytes, &signature).is_ok())
}

/// v11 auth rule for `m.room.member` invites carrying
/// `content.third_party_invite` (rules 4.4.1.1-4.4.1.8).
fn check_third_party_invite(
    event: &Event,
    state_key: &str,
    third_party_invite: &serde_json::Value,
    auth_state: &StateMap<Event>,
    target_membership: &Option<Membership>,
) -> Result<(), AuthError> {
    if matches!(target_membership, Some(Membership::Ban)) {
        return Err(AuthError::InviteTargetAlreadyJoinedOrBanned);
    }
    let signed = third_party_invite
        .get("signed")
        .filter(|s| s.is_object())
        .ok_or(AuthError::ThirdPartyInvite("no signed object"))?;
    let (Some(mxid), Some(token)) = (signed["mxid"].as_str(), signed["token"].as_str()) else {
        return Err(AuthError::ThirdPartyInvite("signed lacks mxid or token"));
    };
    if mxid != state_key {
        return Err(AuthError::ThirdPartyInvite("signed.mxid does not match state_key"));
    }
    let invite = auth_state
        .get(&("m.room.third_party_invite".to_owned(), token.to_owned()))
        .ok_or(AuthError::ThirdPartyInvite("no m.room.third_party_invite for the token"))?;
    if invite.sender != event.sender {
        return Err(AuthError::ThirdPartyInvite("sender differs from the third-party invite's sender"));
    }
    let mut keys: Vec<&str> = Vec::new();
    if let Some(key) = invite.content["public_key"].as_str() {
        keys.push(key);
    }
    if let Some(list) = invite.content["public_keys"].as_array() {
        keys.extend(list.iter().filter_map(|k| k["public_key"].as_str()));
    }
    if keys.iter().any(|key| third_party_signed_matches(signed, key)) {
        Ok(())
    } else {
        Err(AuthError::ThirdPartyInvite("no signature matches the invite's public keys"))
    }
}

// ---------------------------------------------------------------------------
// dn9.3 — m.room.member checks
// ---------------------------------------------------------------------------

fn check_member(
    event: &Event,
    auth_state: &StateMap<Event>,
    sender_membership: &Option<Membership>,
    version: u32,
) -> Result<(), AuthError> {
    let state_key = event
        .state_key
        .as_deref()
        .ok_or(AuthError::MemberEventMissingStateKey)?;

    let new_membership = parse_member(&event.content)
        .map_err(|e| AuthError::ContentParseError(e.to_string()))?
        .membership;

    let target_membership = get_membership(auth_state, state_key);
    let join_rule = get_join_rule(auth_state);

    let creator = creator_id(auth_state);
    let pl = get_pl_content(auth_state);

    let sender_level = effective_user_level(&event.sender, auth_state);
    let target_level = effective_user_level(state_key, auth_state);

    match new_membership {
        // -------------------------------------------------------------------
        // Join
        // -------------------------------------------------------------------
        Membership::Join => {
            // Target must be the sender (can't join for someone else).
            if state_key != event.sender {
                return Err(AuthError::InvalidMemberTransition {
                    from: target_membership,
                    to: Membership::Join,
                });
            }

            // Cannot join if banned.
            if target_membership == Some(Membership::Ban) {
                return Err(AuthError::JoinTargetBanned);
            }

            // Special exemption: if there is no m.room.join_rules event yet
            // (absent from auth_state) and the sender is the room creator,
            // allow the join.  This covers the creator's initial self-join
            // during room bootstrapping before join_rules has been authored.
            let join_rules_absent = !auth_state
                .contains_key(&("m.room.join_rules".to_owned(), String::new()));
            let sender_is_creator = creator.as_deref() == Some(event.sender.as_str());
            if join_rules_absent && sender_is_creator && state_key == event.sender {
                // Creator bootstrapping the room — allow unconditionally.
            } else {
                match &join_rule {
                    JoinRule::Public => {} // anyone can join
                    JoinRule::Invite | JoinRule::Knock if version >= 7 || matches!(join_rule, JoinRule::Invite) => {
                        // Must have a prior invite (or already joined).
                        match &target_membership {
                            Some(Membership::Invite) | Some(Membership::Join) => {}
                            _ => {
                                return Err(AuthError::JoinRequiresInvite {
                                    join_rule: join_rule.clone(),
                                })
                            }
                        }
                    }
                    JoinRule::Restricted | JoinRule::KnockRestricted
                        if (matches!(join_rule, JoinRule::Restricted) && version >= 8)
                            || (matches!(join_rule, JoinRule::KnockRestricted) && version >= 10) =>
                    {
                        // An invite (or an existing join) bypasses allow
                        // conditions. Otherwise the event must name a joined
                        // user who can invite. Membership in the allowed room
                        // is decided by the server authoring the join, not
                        // from this room's state.
                        match &target_membership {
                            Some(Membership::Invite) | Some(Membership::Join) => {}
                            _ if authoriser_may_invite(event, auth_state, &pl) => {}
                            _ => {
                                return Err(AuthError::JoinRequiresInvite {
                                    join_rule: join_rule.clone(),
                                })
                            }
                        }
                    }
                    JoinRule::Private => {
                        return Err(AuthError::JoinRequiresInvite {
                            join_rule: join_rule.clone(),
                        });
                    }
                    _ => {
                        return Err(AuthError::JoinRequiresInvite {
                            join_rule: join_rule.clone(),
                        });
                    }
                }
            }
        }

        // -------------------------------------------------------------------
        // Invite
        // -------------------------------------------------------------------
        Membership::Invite => {
            if let Some(tpi) = event.content.get("third_party_invite") {
                return check_third_party_invite(event, state_key, tpi, auth_state, &target_membership);
            }
            // Sender must be joined.
            if sender_membership != &Some(Membership::Join) {
                return Err(AuthError::SenderNotJoined);
            }

            // Target must not already be joined or banned.
            if matches!(
                &target_membership,
                Some(Membership::Join) | Some(Membership::Ban)
            ) {
                return Err(AuthError::InviteTargetAlreadyJoinedOrBanned);
            }

            // Sender needs invite-level power.
            if sender_level < pl.invite {
                return Err(AuthError::InsufficientPowerLevel {
                    needed: pl.invite,
                    sender_has: sender_level,
                });
            }
        }

        // -------------------------------------------------------------------
        // Leave (self-leave or kick-by-other)
        // -------------------------------------------------------------------
        Membership::Leave => {
            if state_key == event.sender {
                // Self-leave: allowed from invite (reject), join (leave)
                // and knock (rescind), per the v11 rules.
                match &sender_membership {
                    Some(Membership::Invite) | Some(Membership::Join) | Some(Membership::Knock) => {}
                    _ => {
                        return Err(AuthError::InvalidMemberTransition {
                            from: sender_membership.clone(),
                            to: Membership::Leave,
                        })
                    }
                }
            } else {
                // Kick: sender must be joined and have kick power.
                if sender_membership != &Some(Membership::Join) {
                    return Err(AuthError::SenderNotJoined);
                }

                // Unbanning (ban -> leave) additionally needs the ban level.
                // Any other current membership — join, invite, knock (deny
                // a knock), leave or none — is governed by the kick level
                // alone, per the v11 rules.
                if target_membership == Some(Membership::Ban) && sender_level < pl.ban {
                    return Err(AuthError::InsufficientPowerLevel {
                        needed: pl.ban,
                        sender_has: sender_level,
                    });
                }

                if sender_level < pl.kick {
                    return Err(AuthError::InsufficientPowerLevel {
                        needed: pl.kick,
                        sender_has: sender_level,
                    });
                }

                // Cannot kick someone with >= your own level.
                if target_level >= sender_level {
                    return Err(AuthError::CannotDemoteHigherLevel);
                }
            }
        }

        // -------------------------------------------------------------------
        // Ban
        // -------------------------------------------------------------------
        Membership::Ban => {
            // Sender must be joined.
            if sender_membership != &Some(Membership::Join) {
                return Err(AuthError::SenderNotJoined);
            }

            if sender_level < pl.ban {
                return Err(AuthError::InsufficientPowerLevel {
                    needed: pl.ban,
                    sender_has: sender_level,
                });
            }

            // Cannot ban someone with >= your own level.
            if target_level >= sender_level {
                return Err(AuthError::CannotDemoteHigherLevel);
            }
        }

        // -------------------------------------------------------------------
        // Knock
        // -------------------------------------------------------------------
        Membership::Knock => {
            if version < 7 || (join_rule == JoinRule::KnockRestricted && version < 10) {
                return Err(AuthError::InvalidMemberTransition {
                    from: target_membership,
                    to: Membership::Knock,
                });
            }
            // Target must be the sender.
            if state_key != event.sender {
                return Err(AuthError::InvalidMemberTransition {
                    from: target_membership,
                    to: Membership::Knock,
                });
            }

            // join_rule must permit knocking.
            if !matches!(join_rule, JoinRule::Knock | JoinRule::KnockRestricted) {
                return Err(AuthError::InvalidMemberTransition {
                    from: target_membership,
                    to: Membership::Knock,
                });
            }

            // Cannot knock if banned, already invited, or already joined.
            if matches!(
                &target_membership,
                Some(Membership::Ban) | Some(Membership::Invite) | Some(Membership::Join)
            ) {
                return Err(AuthError::InvalidMemberTransition {
                    from: target_membership,
                    to: Membership::Knock,
                });
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// m.room.power_levels change checks
// ---------------------------------------------------------------------------

fn check_power_levels(event: &Event, auth_state: &StateMap<Event>) -> Result<(), AuthError> {
    // Sender must be joined.
    let sender_membership = get_membership(auth_state, &event.sender);
    if sender_membership != Some(Membership::Join) {
        return Err(AuthError::SenderNotJoined);
    }

    let current_pl = get_pl_content(auth_state);
    let sender_level = effective_user_level(&event.sender, auth_state);
    let version = room_version_from_state(auth_state);

    // Sender needs enough level to send a power_levels state event.
    let required = level_required_for_event("m.room.power_levels", true, &current_pl);
    if sender_level < required {
        return Err(AuthError::InsufficientPowerLevel {
            needed: required,
            sender_has: sender_level,
        });
    }

    // Versions 1–5 coerce strings and truncated floats. Versions 6–9 still
    // accept an integer encoded as a string. Version 10 requires JSON integers.
    let content = crate::room_version::power_levels_for_auth(&event.content, version);
    let new_pl = parse_power_levels(&content)
        .map_err(|e| AuthError::ContentParseError(e.to_string()))?;
    if version >= 12 {
        let creators = creators_of(auth_state);
        if new_pl.users.keys().any(|user| creators.iter().any(|creator| creator == user)) {
            return Err(AuthError::CreatorInPowerLevels);
        }
    }

    // Spec rule: with no previous power-levels event, the integer content is
    // allowed. The sender's right to send the event was already checked, and
    // room version 12 still rejects creators listed in `users`.
    if !auth_state.contains_key(&("m.room.power_levels".to_owned(), String::new())) {
        return Ok(());
    }

    // Sender cannot grant anyone (including themselves) a level above their own.
    for (user, &level) in &new_pl.users {
        if level > sender_level {
            return Err(AuthError::PowerLevelExceedsSelf {
                sender_has: sender_level,
            });
        }
        // Sender cannot demote a user whose current level >= sender's level
        // (unless that user is themselves).
        if user != &event.sender {
            let current_level = *current_pl.users.get(user).unwrap_or(&current_pl.users_default);
            if current_level >= sender_level && level != current_level {
                return Err(AuthError::CannotDemoteHigherLevel);
            }
        }
    }

    // Sender cannot raise the top-level fields above their own level.
    for &field_level in &[
        new_pl.ban,
        new_pl.kick,
        new_pl.redact,
        new_pl.invite,
        new_pl.events_default,
        new_pl.state_default,
        new_pl.users_default,
    ] {
        if field_level > sender_level {
            return Err(AuthError::PowerLevelExceedsSelf {
                sender_has: sender_level,
            });
        }
    }

    for &event_level in new_pl.events.values() {
        if event_level > sender_level {
            return Err(AuthError::PowerLevelExceedsSelf {
                sender_has: sender_level,
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// dn9.6 — history_visibility helper
// ---------------------------------------------------------------------------

/// Position of a user relative to an event for history visibility checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserEventPosition {
    /// User was a member when the event was sent.
    WasMember,
    /// User was invited (but not yet joined) when the event was sent.
    WasInvited,
    /// User has joined since the event was sent.
    JoinedAfter,
    /// User has never been a member.
    NeverMember,
}

/// Determine whether a user can see an event given the room's history
/// visibility setting and their position relative to that event.
///
/// This is a pure predicate — it does not touch storage.  Wire it into
/// `/messages` and `/sync` handlers in E04.
pub fn can_see(
    history_visibility: &HistoryVisibility,
    user_position: &UserEventPosition,
) -> bool {
    match history_visibility {
        HistoryVisibility::WorldReadable => true,
        HistoryVisibility::Shared => {
            // Members can see all history; non-members cannot.
            !matches!(user_position, UserEventPosition::NeverMember)
        }
        HistoryVisibility::Invited => matches!(
            user_position,
            UserEventPosition::WasMember | UserEventPosition::WasInvited
        ),
        HistoryVisibility::Joined => matches!(user_position, UserEventPosition::WasMember),
    }
}

// ---------------------------------------------------------------------------
// Read access — membership and history visibility
// ---------------------------------------------------------------------------

/// The room's `history_visibility`, defaulting to `shared` per spec.
pub fn history_visibility_of(state: &StateMap<Event>) -> HistoryVisibility {
    state
        .get(&("m.room.history_visibility".to_owned(), String::new()))
        .and_then(|ev| parse_history_visibility(&ev.content).ok())
        .map(|c| c.history_visibility)
        .unwrap_or(HistoryVisibility::Shared)
}

/// May `user_id` read this room's state, member list, and timeline?
///
/// The one membership predicate.  Every CS read path calls this, rather
/// than each handler growing its own lookup.
///
/// - joined: yes.
/// - invited: yes — a client must be able to render invite state.
/// - anyone else: only when the room is `world_readable`.
///
/// The `world_readable` case is peeking, and it is **not** a hole in
/// agency: the caller has already verified a capability grant before it
/// gets here.  An unauthenticated request never reaches this function.
pub fn may_read_room(user_id: &str, state: &StateMap<Event>) -> bool {
    match get_membership(state, user_id) {
        Some(Membership::Join) | Some(Membership::Invite) => true,
        _ => history_visibility_of(state) == HistoryVisibility::WorldReadable,
    }
}

/// Where a user stood relative to an event, derived from their own
/// membership events in that room.
///
/// `member_events` is every `m.room.member` event whose state_key is
/// this user, paired with its stream position, ordered ascending —
/// exactly what [`crate::storage::Storage::member_events_for_user`]
/// returns.  `event_pos` is the stream position of the event whose
/// visibility is in question.
///
/// There are no state-at-event snapshots in this homeserver and this
/// derivation does not need any: the user's latest own member event
/// below `event_pos` *is* their membership at that point.  Do not write
/// a second derivation — backfill uses this one too.
pub fn user_event_position(
    member_events: &[(i64, Event)],
    event_pos: i64,
) -> UserEventPosition {
    let membership_at = |ev: &Event| parse_member(&ev.content).ok().map(|mc| mc.membership);

    let prior = member_events
        .iter()
        .filter(|(pos, _)| *pos < event_pos)
        .next_back()
        .and_then(|(_, ev)| membership_at(ev));

    match prior {
        Some(Membership::Join) => UserEventPosition::WasMember,
        Some(Membership::Invite) => UserEventPosition::WasInvited,
        // Left, banned, or knocking at the time — and a later join, if
        // there is one, is what `shared` history visibility keys on.
        _ => {
            let joined_later = member_events
                .iter()
                .filter(|(pos, _)| *pos >= event_pos)
                .any(|(_, ev)| membership_at(ev) == Some(Membership::Join));
            if joined_later {
                UserEventPosition::JoinedAfter
            } else {
                UserEventPosition::NeverMember
            }
        }
    }
}

/// The same derivation, for a whole origin server rather than one user.
///
/// Federation backfill asks whether the requesting server could see an
/// event.  A server could if *any* of its users could, so this takes
/// the most permissive position across the origin's members.
///
/// `member_events` is every `m.room.member` event in the room whose
/// state_key belongs to the origin, paired with its stream position.
pub fn server_event_position(
    member_events: &[(i64, Event)],
    event_pos: i64,
) -> UserEventPosition {
    let mut by_user: HashMap<&str, Vec<(i64, Event)>> = HashMap::new();
    for (pos, ev) in member_events {
        if let Some(state_key) = &ev.state_key {
            by_user
                .entry(state_key.as_str())
                .or_default()
                .push((*pos, ev.clone()));
        }
    }

    let rank = |p: &UserEventPosition| match p {
        UserEventPosition::WasMember => 3,
        UserEventPosition::WasInvited => 2,
        UserEventPosition::JoinedAfter => 1,
        UserEventPosition::NeverMember => 0,
    };

    by_user
        .into_values()
        .map(|mut evs| {
            evs.sort_by_key(|(pos, _)| *pos);
            user_event_position(&evs, event_pos)
        })
        .max_by_key(|p| rank(p))
        .unwrap_or(UserEventPosition::NeverMember)
}

/// The domain half of a Matrix ID (`@alice:example.com` → `example.com`).
pub fn server_of(user_id: &str) -> &str {
    domain_of(user_id)
}

// ---------------------------------------------------------------------------
// Storage-backed wrappers
// ---------------------------------------------------------------------------
//
// The predicates above are pure.  These wrappers do the I/O once, so a
// host handler is a single call rather than its own membership walk.

/// Load a room's current state as a [`StateMap`].
pub async fn current_state_map(
    storage: &dyn crate::storage::Storage,
    room_id: &str,
) -> crate::Result<StateMap<Event>> {
    let events = storage.get_current_state(room_id).await?;
    let mut state: StateMap<Event> = HashMap::new();
    for ev in events {
        apply_state_event(&mut state, &ev);
    }
    Ok(state)
}

/// [`may_read_room`], against stored state.
pub async fn may_read_stored_room(
    storage: &dyn crate::storage::Storage,
    room_id: &str,
    user_id: &str,
) -> crate::Result<bool> {
    let state = current_state_map(storage, room_id).await?;
    Ok(may_read_room(user_id, &state))
}

/// [`may_read_room`], returning `Forbidden` instead of `false`, so a
/// handler can `?` it straight into a Matrix error.
pub async fn require_read_access(
    storage: &dyn crate::storage::Storage,
    room_id: &str,
    user_id: &str,
) -> crate::Result<()> {
    if may_read_stored_room(storage, room_id, user_id).await? {
        Ok(())
    } else {
        Err(crate::Error::Forbidden(format!(
            "{user_id} is not a member of {room_id}"
        )))
    }
}

/// Is `user_id` joined to the room with enough power to send a state
/// event of `event_type`?
///
/// The permission the published-room directory and alias deletion use:
/// a user who could change `m.room.canonical_alias` may also change how
/// the room is advertised.
pub fn may_send_state_event(state: &StateMap<Event>, user_id: &str, event_type: &str) -> bool {
    if get_membership(state, user_id) != Some(Membership::Join) {
        return false;
    }
    // Room version 12 creators have infinite power even when the power-levels
    // event does not list them. `effective_user_level` is what auth uses.
    let level = effective_user_level(user_id, state);
    level >= level_required_for_event(event_type, true, &get_pl_content(state))
}

/// Drop the events in `events` that `user_id` may not see, per the
/// room's history visibility.
pub async fn filter_visible_for_user(
    storage: &dyn crate::storage::Storage,
    room_id: &str,
    user_id: &str,
    events: Vec<Event>,
) -> crate::Result<Vec<Event>> {
    let members = storage.member_events_for_user(room_id, user_id).await?;
    filter_with(storage, room_id, &members, events, user_event_position, Some(user_id)).await
}

/// The same filter, for a requesting origin server (federation
/// backfill and get_missing_events).
pub async fn filter_visible_for_server(
    storage: &dyn crate::storage::Storage,
    room_id: &str,
    origin: &str,
    events: Vec<Event>,
) -> crate::Result<Vec<Event>> {
    let members = storage.member_events_for_server(room_id, origin).await?;
    filter_with(storage, room_id, &members, events, server_event_position, None).await
}

/// `m.room.history_visibility` values in stream order, as `(position, value)`.
async fn visibility_history(
    storage: &dyn crate::storage::Storage,
    room_id: &str,
) -> crate::Result<Vec<(i64, HistoryVisibility)>> {
    let changes: Vec<Event> = storage
        .room_events(room_id)
        .await?
        .into_iter()
        .filter(|event| event.event_type == "m.room.history_visibility" && event.state_key.as_deref() == Some(""))
        .collect();
    let ids: Vec<String> = changes.iter().map(|event| event.event_id.clone()).collect();
    let positions = storage.event_stream_positions(&ids).await?;
    let mut history: Vec<_> = changes
        .iter()
        .filter_map(|event| {
            let position = *positions.get(&event.event_id)?;
            // An unparseable value is treated as `shared`, per spec.
            let value = parse_history_visibility(&event.content)
                .map(|content| content.history_visibility)
                .unwrap_or(HistoryVisibility::Shared);
            Some((position, value))
        })
        .collect();
    history.sort_by_key(|(position, _)| *position);
    Ok(history)
}

/// Visibility in force at an event: the latest change strictly before it,
/// defaulting to `shared`.
fn visibility_before(history: &[(i64, HistoryVisibility)], position: i64) -> HistoryVisibility {
    history
        .iter()
        .take_while(|(changed, _)| *changed < position)
        .last()
        .map(|(_, value)| value.clone())
        .unwrap_or(HistoryVisibility::Shared)
}

/// Spec "History visibility": the rules use the state of the room at each
/// event. A history-visibility event is visible if the value before or after
/// it allows; a user's own membership event is visible if their membership
/// before or after it allows (so a user always sees their own join).
async fn filter_with(
    storage: &dyn crate::storage::Storage,
    room_id: &str,
    members: &[(i64, Event)],
    events: Vec<Event>,
    position: fn(&[(i64, Event)], i64) -> UserEventPosition,
    own_user: Option<&str>,
) -> crate::Result<Vec<Event>> {
    let history = visibility_history(storage, room_id).await?;
    // One lookup for the whole page, not one per event.
    let ids: Vec<String> = events.iter().map(|e| e.event_id.clone()).collect();
    let positions = storage.event_stream_positions(&ids).await?;

    Ok(events
        .into_iter()
        .filter(|ev| {
            // An event we cannot place is an event we cannot clear.
            let Some(pos) = positions.get(&ev.event_id).copied() else {
                return false;
            };
            let before = visibility_before(&history, pos);
            let standing = position(members, pos);
            if can_see(&before, &standing) {
                return true;
            }
            if ev.event_type == "m.room.history_visibility" && ev.state_key.as_deref() == Some("") {
                if let Ok(after) = parse_history_visibility(&ev.content) {
                    if can_see(&after.history_visibility, &standing) {
                        return true;
                    }
                }
            }
            if ev.event_type == "m.room.member" && own_user.is_some() && ev.state_key.as_deref() == own_user {
                let after = match parse_member(&ev.content).map(|content| content.membership) {
                    Ok(Membership::Join) => UserEventPosition::WasMember,
                    Ok(Membership::Invite) => UserEventPosition::WasInvited,
                    _ => standing,
                };
                return can_see(&before, &after);
            }
            false
        })
        .collect())
}

// ---------------------------------------------------------------------------
// dn9.9 — apply_state_event
// ---------------------------------------------------------------------------

/// Apply a state event to an in-memory state map.
///
/// If the event has a `state_key`, the entry at
/// `(event_type, state_key)` is replaced with this event.
/// Non-state events (no `state_key`) are a no-op.
pub fn apply_state_event(state: &mut StateMap<Event>, event: &Event) {
    if let Some(state_key) = &event.state_key {
        state.insert(
            (event.event_type.clone(), state_key.clone()),
            event.clone(),
        );
    }
}

// ---------------------------------------------------------------------------
// dn9.10 — Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------------

    fn make_event(
        event_id: &str,
        event_type: &str,
        sender: &str,
        room_id: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
        prev_events: Vec<String>,
    ) -> Event {
        Event {
            event_id: event_id.to_owned(),
            pdu: crate::event::Pdu {
                room_id: room_id.to_owned(),
                sender: sender.to_owned(),
                event_type: event_type.to_owned(),
                content,
                state_key: state_key.map(|s| s.to_owned()),
                origin_server_ts: 1_000_000,
                auth_events: vec![],
                prev_events,
                hashes: json!({}),
                signatures: json!({}),
                depth: 1,
                extensions: Default::default(),
            },
            unsigned: None,
        }
    }

    fn make_create_event(sender: &str, room_id: &str) -> Event {
        make_event(
            "$create",
            "m.room.create",
            sender,
            room_id,
            Some(""),
            json!({ "room_version": "11" }),
            vec![],
        )
    }

    fn make_member_event(
        event_id: &str,
        sender: &str,
        target: &str,
        room_id: &str,
        membership: &str,
    ) -> Event {
        make_event(
            event_id,
            "m.room.member",
            sender,
            room_id,
            Some(target),
            json!({ "membership": membership }),
            vec![],
        )
    }

    fn make_power_levels_event(
        event_id: &str,
        sender: &str,
        room_id: &str,
        content: serde_json::Value,
    ) -> Event {
        make_event(
            event_id,
            "m.room.power_levels",
            sender,
            room_id,
            Some(""),
            content,
            vec![],
        )
    }

    fn make_join_rules_event(sender: &str, room_id: &str, rule: &str) -> Event {
        make_event(
            "$join_rules",
            "m.room.join_rules",
            sender,
            room_id,
            Some(""),
            json!({ "join_rule": rule }),
            vec![],
        )
    }

    /// Build a base auth state for a public room with `creator` joined.
    fn base_state(creator: &str, room_id: &str, join_rule: &str) -> StateMap<Event> {
        let mut state: StateMap<Event> = HashMap::new();

        apply_state_event(&mut state, &make_create_event(creator, room_id));
        apply_state_event(
            &mut state,
            &make_member_event("$creator_join", creator, creator, room_id, "join"),
        );
        apply_state_event(&mut state, &make_join_rules_event(creator, room_id, join_rule));

        state
    }

    // -----------------------------------------------------------------------
    // Test 1: create event passes auth against empty state
    // -----------------------------------------------------------------------
    #[test]
    fn create_event_passes_auth() {
        let create = make_create_event("@alice:example.com", "!room:example.com");
        let state: StateMap<Event> = HashMap::new();
        assert!(check_auth(&create, &state).is_ok());
    }

    fn create_with(version: &str, sender: &str, room_id: &str, extra: serde_json::Value) -> Event {
        let mut content = json!({ "room_version": version });
        if let Some(map) = extra.as_object() {
            for (key, value) in map {
                content[key] = value.clone();
            }
        }
        make_event("$create", "m.room.create", sender, room_id, Some(""), content, vec![])
    }

    /// Room-version auth differences from v1.19: aliases, power-level
    /// integers, knock gates, creator field, and v12 creators.
    #[test]
    fn room_version_auth_rules_follow_the_spec() {
        let alice = "@alice:example.com";
        let room = "!room:example.com";

        let v1 = create_with("1", alice, room, json!({ "creator": alice }));
        assert!(check_auth(&v1, &HashMap::new()).is_ok(), "v1 create with creator");
        let v1_missing = create_with("1", alice, room, json!({}));
        assert!(
            matches!(check_auth(&v1_missing, &HashMap::new()), Err(AuthError::CreateMissingCreator)),
            "v1 create requires content.creator"
        );
        let v11 = create_with("11", alice, room, json!({}));
        assert!(check_auth(&v11, &HashMap::new()).is_ok(), "v11 create omits content.creator");

        let mut v12 = create_with("12", alice, "", json!({ "additional_creators": ["@bob:example.com"] }));
        v12.room_id.clear();
        assert!(check_auth(&v12, &HashMap::new()).is_ok(), "v12 create omits room_id");
        let mut v12_with_room = v12.clone();
        v12_with_room.room_id = room.to_owned();
        assert!(
            matches!(check_auth(&v12_with_room, &HashMap::new()), Err(AuthError::CreateMustOmitRoomId)),
            "v12 create must omit room_id"
        );

        let mut v5_state = HashMap::new();
        apply_state_event(&mut v5_state, &create_with("5", alice, room, json!({ "creator": alice })));
        let alias = make_event(
            "$aliases",
            "m.room.aliases",
            alice,
            room,
            Some("example.com"),
            json!({ "aliases": ["#a:example.com"] }),
            vec![],
        );
        assert!(check_auth(&alias, &v5_state).is_ok(), "v5 alias state_key is the sender domain");
        let mut v6_state = HashMap::new();
        apply_state_event(&mut v6_state, &create_with("6", alice, room, json!({ "creator": alice })));
        assert!(
            matches!(check_auth(&alias, &v6_state), Err(AuthError::SenderNotJoined)),
            "v6 drops the aliases special case"
        );

        let mut joined = v6_state.clone();
        apply_state_event(&mut joined, &make_member_event("$join", alice, alice, room, "join"));
        let string_levels = make_power_levels_event(
            "$pl",
            alice,
            room,
            json!({ "users": { alice: 100 }, "events_default": "0", "state_default": 50 }),
        );
        assert!(
            check_auth(&string_levels, &v5_state_with_join(alice, room)).is_ok(),
            "v5 coerces string power levels"
        );
        assert!(
            check_auth(&string_levels, &joined).is_ok(),
            "v6 accepts an integer power level encoded as a string"
        );

        let knock = make_member_event("$knock", "@kate:example.com", "@kate:example.com", room, "knock");
        let mut knockable = HashMap::new();
        apply_state_event(&mut knockable, &create_with("7", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut knockable, &make_member_event("$join", alice, alice, room, "join"));
        apply_state_event(&mut knockable, &make_join_rules_event(alice, room, "knock"));
        assert!(check_auth(&knock, &knockable).is_ok(), "v7 room accepts a knock");
        let mut too_old = HashMap::new();
        apply_state_event(&mut too_old, &create_with("6", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut too_old, &make_member_event("$join", alice, alice, room, "join"));
        apply_state_event(&mut too_old, &make_join_rules_event(alice, room, "knock"));
        assert!(check_auth(&knock, &too_old).is_err(), "v6 rejects knock membership");

        let mut creators = HashMap::new();
        let mut create = create_with(
            "12",
            alice,
            "",
            json!({ "additional_creators": ["@bob:example.com"] }),
        );
        create.room_id.clear();
        apply_state_event(&mut creators, &create);
        apply_state_event(&mut creators, &make_member_event("$join", alice, alice, "", "join"));
        let listed = make_power_levels_event("$pl12", alice, "", json!({ "users": { alice: 100 } }));
        assert!(
            matches!(check_auth(&listed, &creators), Err(AuthError::CreatorInPowerLevels)),
            "v12 creators must not appear in power level users"
        );
        let clear = make_power_levels_event("$pl12b", alice, "", json!({ "users": {} }));
        assert!(check_auth(&clear, &creators).is_ok(), "v12 creator power is infinite without a users entry");
    }

    /// Room version 1 must not strictly enforce canonical JSON: a float power
    /// level is truncated and accepted. Version 6 rejects the same event.
    #[test]
    fn room_version_1_accepts_a_float_power_level() {
        let alice = "@alice:example.com";
        let room = "!room:example.com";
        let mut v1 = HashMap::new();
        apply_state_event(&mut v1, &create_with("1", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v1, &make_member_event("$join", alice, alice, room, "join"));
        let levels = make_power_levels_event(
            "$pl",
            alice,
            room,
            json!({ "users": { alice: 100 }, "events_default": 50.9 }),
        );
        assert!(check_auth(&levels, &v1).is_ok(), "v1 does not reject a float power level");
        let mut v6 = HashMap::new();
        apply_state_event(&mut v6, &create_with("6", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v6, &make_member_event("$join", alice, alice, room, "join"));
        assert!(check_auth(&levels, &v6).is_err(), "v6 rejects a float power level");
    }

    /// Room version 2 does not strictly enforce canonical JSON. String power
    /// levels and a truncated float take effect. A decimal string is rejected.
    /// Version 6 rejects the same event.
    #[test]
    fn room_version_2_accepts_float_and_string_power_levels() {
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let room = "!room:example.com";
        let mut v2 = HashMap::new();
        apply_state_event(&mut v2, &create_with("2", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v2, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v2, &make_member_event("$bj", alice, bob, room, "join"));
        let levels = make_power_levels_event(
            "$pl",
            alice,
            room,
            json!({
                "ban": "050",
                "events": {
                    "m.room.name": "50",
                    "m.room.topic": "51",
                    "m.room.power_levels": "100"
                },
                "events_default": "+0",
                "state_default": " 50 ",
                "users": { alice: "+100", bob: 50.9 },
                "users_default": "0",
                "notifications": { "room": " 0 " }
            }),
        );
        assert!(
            check_auth(&levels, &v2).is_ok(),
            "v2 accepts string and float power levels"
        );
        let decimal = make_power_levels_event(
            "$bad",
            alice,
            room,
            json!({ "users": { alice: "100" }, "events_default": "50.9" }),
        );
        assert!(
            check_auth(&decimal, &v2).is_err(),
            "v2 rejects a power-level string that contains a decimal point"
        );

        apply_state_event(&mut v2, &levels);
        let name = make_event(
            "$name",
            "m.room.name",
            bob,
            room,
            Some(""),
            json!({ "name": "n" }),
            vec![],
        );
        assert!(
            check_auth(&name, &v2).is_ok(),
            "v2 truncates 50.9 to 50, which meets the string level 50"
        );
        let topic = make_event(
            "$topic",
            "m.room.topic",
            bob,
            room,
            Some(""),
            json!({ "topic": "t" }),
            vec![],
        );
        assert!(
            matches!(check_auth(&topic, &v2), Err(AuthError::InsufficientPowerLevel { .. })),
            "v2 truncation does not round 50.9 up to 51"
        );

        let mut v6 = HashMap::new();
        apply_state_event(&mut v6, &create_with("6", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v6, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v6, &make_member_event("$bj", alice, bob, room, "join"));
        assert!(
            check_auth(&levels, &v6).is_err(),
            "v6 rejects the same float power level"
        );
    }

    /// Room version 3 still accepts a truncated float and a string power
    /// level. Later checks use the integers. Version 6 rejects the float.
    #[test]
    fn room_version_3_accepts_float_and_string_power_levels() {
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let room = "!room:example.com";
        let mut v3 = HashMap::new();
        apply_state_event(&mut v3, &create_with("3", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v3, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v3, &make_member_event("$bj", alice, bob, room, "join"));
        let levels = make_power_levels_event(
            "$pl",
            alice,
            room,
            json!({
                "events": { "m.room.name": "50", "m.room.topic": "51" },
                "users": { alice: "100", bob: 50.9 },
                "events_default": "0"
            }),
        );
        assert!(check_auth(&levels, &v3).is_ok(), "v3 accepts string and float power levels");
        apply_state_event(&mut v3, &levels);
        let name = make_event(
            "$name",
            "m.room.name",
            bob,
            room,
            Some(""),
            json!({ "name": "n" }),
            vec![],
        );
        assert!(check_auth(&name, &v3).is_ok(), "v3 truncates 50.9 to 50");
        let topic = make_event(
            "$topic",
            "m.room.topic",
            bob,
            room,
            Some(""),
            json!({ "topic": "t" }),
            vec![],
        );
        assert!(
            matches!(check_auth(&topic, &v3), Err(AuthError::InsufficientPowerLevel { .. })),
            "v3 does not round 50.9 up to 51"
        );
        let mut v6 = HashMap::new();
        apply_state_event(&mut v6, &create_with("6", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v6, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v6, &make_member_event("$bj", alice, bob, room, "join"));
        assert!(check_auth(&levels, &v6).is_err(), "v6 rejects the same float power level");
    }

    /// Room version 4 still accepts a truncated float and a string power
    /// level. Later checks use the integers. Version 6 rejects the float.
    #[test]
    fn room_version_4_accepts_float_and_string_power_levels() {
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let room = "!room:example.com";
        let mut v4 = HashMap::new();
        apply_state_event(&mut v4, &create_with("4", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v4, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v4, &make_member_event("$bj", alice, bob, room, "join"));
        let levels = make_power_levels_event(
            "$pl",
            alice,
            room,
            json!({
                "events": { "m.room.name": "50", "m.room.topic": "51" },
                "users": { alice: "100", bob: 50.9 },
                "events_default": "0"
            }),
        );
        assert!(check_auth(&levels, &v4).is_ok(), "v4 accepts string and float power levels");
        apply_state_event(&mut v4, &levels);
        let name = make_event(
            "$name",
            "m.room.name",
            bob,
            room,
            Some(""),
            json!({ "name": "n" }),
            vec![],
        );
        assert!(check_auth(&name, &v4).is_ok(), "v4 truncates 50.9 to 50");
        let topic = make_event(
            "$topic",
            "m.room.topic",
            bob,
            room,
            Some(""),
            json!({ "topic": "t" }),
            vec![],
        );
        assert!(
            matches!(check_auth(&topic, &v4), Err(AuthError::InsufficientPowerLevel { .. })),
            "v4 does not round 50.9 up to 51"
        );
        let mut v6 = HashMap::new();
        apply_state_event(&mut v6, &create_with("6", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v6, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v6, &make_member_event("$bj", alice, bob, room, "join"));
        assert!(check_auth(&levels, &v6).is_err(), "v6 rejects the same float power level");
    }

    /// Room version 2 rule 11: below the redact level, the redaction is
    /// allowed only when its event id and the target event id share a domain.
    /// The sender's server is not the thing compared. Version 3 accepts the
    /// same event without consulting the redact level.
    #[test]
    fn room_version_2_redaction_auth_matches_event_id_domains() {
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let room = "!room:example.com";
        let mut state = HashMap::new();
        apply_state_event(&mut state, &create_with("2", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut state, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut state, &make_member_event("$bj", alice, bob, room, "join"));
        apply_state_event(
            &mut state,
            &make_power_levels_event(
                "$pl",
                alice,
                room,
                json!({ "users": { alice: 100, bob: 0 }, "redact": 50, "events_default": 0 }),
            ),
        );

        let same_domain = redaction("$redact:elsewhere.test", bob, room, "$target:elsewhere.test");
        assert!(
            check_auth(&same_domain, &state).is_ok(),
            "v2 allows a redaction whose event id shares the target's domain"
        );
        let other_domain = redaction("$redact:elsewhere.test", bob, room, "$target:example.com");
        assert!(
            matches!(check_auth(&other_domain, &state), Err(AuthError::RedactionDenied)),
            "v2 rejects a below-level redaction of a different event-id domain"
        );

        let mut powerful = state.clone();
        apply_state_event(
            &mut powerful,
            &make_power_levels_event(
                "$pl2",
                alice,
                room,
                json!({ "users": { alice: 100, bob: 50 }, "redact": 50, "events_default": 0 }),
            ),
        );
        assert!(
            check_auth(&other_domain, &powerful).is_ok(),
            "v2 allows any redaction at the redact level"
        );

        let mut v3 = HashMap::new();
        apply_state_event(&mut v3, &create_with("3", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v3, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v3, &make_member_event("$bj", alice, bob, room, "join"));
        apply_state_event(
            &mut v3,
            &make_power_levels_event(
                "$pl",
                alice,
                room,
                json!({ "users": { alice: 100, bob: 0 }, "redact": 50, "events_default": 0 }),
            ),
        );
        assert!(
            check_auth(&other_domain, &v3).is_ok(),
            "v3 auth does not apply the redact level"
        );
    }

    /// Room version 3 authorises a redaction like any other event. The redact
    /// level is not an auth check. An `events` requirement still is. Version 2
    /// still rejects the same cross-domain redaction.
    #[test]
    fn room_version_3_redaction_auth_ignores_the_redact_level() {
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let room = "!room:example.com";
        let cross = redaction("$redact:elsewhere.test", bob, room, "$target:example.com");

        let mut v3 = HashMap::new();
        apply_state_event(&mut v3, &create_with("3", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v3, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v3, &make_member_event("$bj", alice, bob, room, "join"));
        apply_state_event(
            &mut v3,
            &make_power_levels_event(
                "$pl",
                alice,
                room,
                json!({ "users": { alice: 100, bob: 0 }, "redact": 100, "events_default": 0 }),
            ),
        );
        assert!(
            check_auth(&cross, &v3).is_ok(),
            "v3 allows a redaction below the redact level"
        );

        let mut gated = v3.clone();
        apply_state_event(
            &mut gated,
            &make_power_levels_event(
                "$pl2",
                alice,
                room,
                json!({
                    "users": { alice: 100, bob: 0 },
                    "redact": 0,
                    "events": { "m.room.redaction": 50 },
                    "events_default": 0
                }),
            ),
        );
        assert!(
            matches!(
                check_auth(&cross, &gated),
                Err(AuthError::InsufficientPowerLevel { .. })
            ),
            "v3 still enforces the events power level for a redaction"
        );

        let mut v2 = HashMap::new();
        apply_state_event(&mut v2, &create_with("2", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v2, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v2, &make_member_event("$bj", alice, bob, room, "join"));
        apply_state_event(
            &mut v2,
            &make_power_levels_event(
                "$pl",
                alice,
                room,
                json!({ "users": { alice: 100, bob: 0 }, "redact": 100, "events_default": 0 }),
            ),
        );
        assert!(
            matches!(check_auth(&cross, &v2), Err(AuthError::RedactionDenied)),
            "v2 still rejects that redaction below the redact level"
        );
    }

    /// Room version 4 keeps the version 3 authorisation rules: the redact
    /// level is not an auth check, and an events power level still is.
    #[test]
    fn room_version_4_redaction_auth_ignores_the_redact_level() {
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let room = "!room:example.com";
        let cross = redaction("$redact:elsewhere.test", bob, room, "$target:example.com");

        let mut v4 = HashMap::new();
        apply_state_event(&mut v4, &create_with("4", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v4, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v4, &make_member_event("$bj", alice, bob, room, "join"));
        apply_state_event(
            &mut v4,
            &make_power_levels_event(
                "$pl",
                alice,
                room,
                json!({ "users": { alice: 100, bob: 0 }, "redact": 100, "events_default": 0 }),
            ),
        );
        assert!(
            check_auth(&cross, &v4).is_ok(),
            "v4 allows a redaction below the redact level"
        );

        let mut gated = v4.clone();
        apply_state_event(
            &mut gated,
            &make_power_levels_event(
                "$pl2",
                alice,
                room,
                json!({
                    "users": { alice: 100, bob: 0 },
                    "redact": 0,
                    "events": { "m.room.redaction": 50 },
                    "events_default": 0
                }),
            ),
        );
        assert!(
            matches!(
                check_auth(&cross, &gated),
                Err(AuthError::InsufficientPowerLevel { .. })
            ),
            "v4 still enforces the events power level for a redaction"
        );

        let mut v2 = HashMap::new();
        apply_state_event(&mut v2, &create_with("2", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v2, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v2, &make_member_event("$bj", alice, bob, room, "join"));
        apply_state_event(
            &mut v2,
            &make_power_levels_event(
                "$pl",
                alice,
                room,
                json!({ "users": { alice: 100, bob: 0 }, "redact": 100, "events_default": 0 }),
            ),
        );
        assert!(
            matches!(check_auth(&cross, &v2), Err(AuthError::RedactionDenied)),
            "v2 still rejects that redaction below the redact level"
        );
    }

    fn redaction(event_id: &str, sender: &str, room: &str, target: &str) -> Event {
        let mut event = make_event(event_id, "m.room.redaction", sender, room, None, json!({}), vec![]);
        event.pdu.extensions.insert("redacts".into(), json!(target));
        event
    }

    fn v5_state_with_join(alice: &str, room: &str) -> StateMap<Event> {
        let mut state = HashMap::new();
        apply_state_event(&mut state, &create_with("5", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut state, &make_member_event("$join", alice, alice, room, "join"));
        state
    }

    // -----------------------------------------------------------------------
    // Test 2: second create rejected
    // -----------------------------------------------------------------------
    #[test]
    fn second_create_rejected() {
        let create = make_create_event("@alice:example.com", "!room:example.com");
        let mut state: StateMap<Event> = HashMap::new();
        apply_state_event(&mut state, &create);

        let second = make_create_event("@alice:example.com", "!room:example.com");
        let err = check_auth(&second, &state).unwrap_err();
        assert_eq!(err, AuthError::RoomAlreadyCreated);
    }

    // -----------------------------------------------------------------------
    // Test 3: join public room succeeds
    // -----------------------------------------------------------------------
    #[test]
    fn join_public_room_succeeds() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let state = base_state(creator, room_id, "public");

        let join = make_member_event("$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join");
        assert!(check_auth(&join, &state).is_ok());
    }

    // -----------------------------------------------------------------------
    // Test 4: join invite-only without invite rejected
    // -----------------------------------------------------------------------
    #[test]
    fn join_invite_only_without_invite_rejected() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let state = base_state(creator, room_id, "invite");

        let join = make_member_event("$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join");
        let err = check_auth(&join, &state).unwrap_err();
        assert!(matches!(err, AuthError::JoinRequiresInvite { .. }));
    }

    // -----------------------------------------------------------------------
    // Test 5: join invite-only with prior invite succeeds
    // -----------------------------------------------------------------------
    #[test]
    fn join_invite_only_with_invite_succeeds() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let mut state = base_state(creator, room_id, "invite");

        // Alice invites Bob.
        apply_state_event(
            &mut state,
            &make_member_event("$bob_invite", creator, "@bob:example.com", room_id, "invite"),
        );

        let join = make_member_event("$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join");
        assert!(check_auth(&join, &state).is_ok());
    }

    // -----------------------------------------------------------------------
    // Test 6: invite below invite level rejected
    // -----------------------------------------------------------------------
    #[test]
    fn invite_below_invite_level_rejected() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let mut state = base_state(creator, room_id, "public");

        // Bob joins.
        apply_state_event(
            &mut state,
            &make_member_event("$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join"),
        );

        // Set invite level to 50 (default); Bob has level 0.
        apply_state_event(
            &mut state,
            &make_power_levels_event(
                "$pl",
                creator,
                room_id,
                json!({
                    "invite": 50,
                    "kick": 50,
                    "ban": 50,
                    "redact": 50,
                    "events_default": 0,
                    "state_default": 50,
                    "users_default": 0,
                    "users": {
                        "@alice:example.com": 100
                    }
                }),
            ),
        );

        // Bob (level 0) tries to invite Charlie.
        let invite = make_member_event(
            "$charlie_invite",
            "@bob:example.com",
            "@charlie:example.com",
            room_id,
            "invite",
        );
        let err = check_auth(&invite, &state).unwrap_err();
        assert!(matches!(err, AuthError::InsufficientPowerLevel { .. }));
    }

    // -----------------------------------------------------------------------
    // Test 7: kick target with higher level rejected
    // -----------------------------------------------------------------------
    #[test]
    fn kick_target_with_higher_level_rejected() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let mut state = base_state(creator, room_id, "public");

        // Bob joins with level 50; Charlie joins with level 100.
        apply_state_event(
            &mut state,
            &make_member_event("$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join"),
        );
        apply_state_event(
            &mut state,
            &make_member_event("$charlie_join", "@charlie:example.com", "@charlie:example.com", room_id, "join"),
        );
        apply_state_event(
            &mut state,
            &make_power_levels_event(
                "$pl",
                creator,
                room_id,
                json!({
                    "kick": 50,
                    "ban": 50,
                    "invite": 50,
                    "redact": 50,
                    "events_default": 0,
                    "state_default": 50,
                    "users_default": 0,
                    "users": {
                        "@alice:example.com": 100,
                        "@bob:example.com": 50,
                        "@charlie:example.com": 100
                    }
                }),
            ),
        );

        // Bob (50) tries to kick Charlie (100).
        let kick = make_member_event(
            "$charlie_kick",
            "@bob:example.com",
            "@charlie:example.com",
            room_id,
            "leave",
        );
        let err = check_auth(&kick, &state).unwrap_err();
        assert_eq!(err, AuthError::CannotDemoteHigherLevel);
    }

    // -----------------------------------------------------------------------
    // Test 8: power level change exceeding self rejected
    // -----------------------------------------------------------------------
    #[test]
    fn power_level_change_exceeding_self_rejected() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let mut state = base_state(creator, room_id, "public");

        // Set Alice at 100, Bob at 50.
        apply_state_event(
            &mut state,
            &make_member_event("$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join"),
        );
        apply_state_event(
            &mut state,
            &make_power_levels_event(
                "$pl",
                creator,
                room_id,
                json!({
                    "kick": 50, "ban": 50, "invite": 50, "redact": 50,
                    "events_default": 0, "state_default": 50, "users_default": 0,
                    "users": { "@alice:example.com": 100, "@bob:example.com": 50 }
                }),
            ),
        );

        // Bob (50) tries to set Charlie to 100.
        let bad_pl = make_power_levels_event(
            "$pl2",
            "@bob:example.com",
            room_id,
            json!({
                "kick": 50, "ban": 50, "invite": 50, "redact": 50,
                "events_default": 0, "state_default": 50, "users_default": 0,
                "users": {
                    "@alice:example.com": 100,
                    "@bob:example.com": 50,
                    "@charlie:example.com": 100
                }
            }),
        );
        let err = check_auth(&bad_pl, &state).unwrap_err();
        assert!(matches!(err, AuthError::PowerLevelExceedsSelf { .. }));
    }

    // -----------------------------------------------------------------------
    // Test 9: power level change within own level succeeds
    // -----------------------------------------------------------------------
    #[test]
    fn power_level_change_within_own_level_succeeds() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let mut state = base_state(creator, room_id, "public");

        apply_state_event(
            &mut state,
            &make_member_event("$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join"),
        );
        apply_state_event(
            &mut state,
            &make_power_levels_event(
                "$pl",
                creator,
                room_id,
                json!({
                    "kick": 50, "ban": 50, "invite": 50, "redact": 50,
                    "events_default": 0, "state_default": 50, "users_default": 0,
                    "users": { "@alice:example.com": 100, "@bob:example.com": 50 }
                }),
            ),
        );

        // Alice (100) raises Bob to 75 — within Alice's own level.
        let good_pl = make_power_levels_event(
            "$pl2",
            creator,
            room_id,
            json!({
                "kick": 50, "ban": 50, "invite": 50, "redact": 50,
                "events_default": 0, "state_default": 50, "users_default": 0,
                "users": { "@alice:example.com": 100, "@bob:example.com": 75 }
            }),
        );
        assert!(check_auth(&good_pl, &state).is_ok());
    }

    // -----------------------------------------------------------------------
    // Test 10: unrelated event passes when sender can send at default level
    // -----------------------------------------------------------------------
    #[test]
    fn unrelated_event_passes_when_sender_can_send_default() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let mut state = base_state(creator, room_id, "public");

        // Bob joins.
        apply_state_event(
            &mut state,
            &make_member_event("$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join"),
        );

        // events_default = 0; Bob (level 0) sends a message — should pass.
        let msg = make_event(
            "$msg1",
            "m.room.message",
            "@bob:example.com",
            room_id,
            None, // not a state event
            json!({ "msgtype": "m.text", "body": "hello" }),
            vec![],
        );
        assert!(check_auth(&msg, &state).is_ok());
    }

    fn make_join_rules_event_with_allow(
        sender: &str,
        room_id: &str,
        rule: &str,
        allow: serde_json::Value,
    ) -> Event {
        make_event(
            "$join_rules",
            "m.room.join_rules",
            sender,
            room_id,
            Some(""),
            json!({ "join_rule": rule, "allow": allow }),
            vec![],
        )
    }

    // -----------------------------------------------------------------------
    // Test 11: a foreign room_id in `allow` fails closed
    //
    // This replaces a test that planted Bob's member event for
    // `!other:example.com` into *this* room's state map and called the
    // resulting pass a satisfied allow condition.  It was green for the
    // wrong reason: this room's state can never prove membership of
    // another room.  Until that lookup exists (conduit-jt5), the join
    // is rejected.
    // -----------------------------------------------------------------------
    #[test]
    fn join_restricted_with_foreign_allow_room_fails_closed() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let mut state: StateMap<Event> = HashMap::new();

        apply_state_event(&mut state, &make_create_event(creator, room_id));
        apply_state_event(
            &mut state,
            &make_member_event("$creator_join", creator, creator, room_id, "join"),
        );
        apply_state_event(
            &mut state,
            &make_join_rules_event_with_allow(
                creator,
                room_id,
                "restricted",
                json!([
                    { "type": "m.room_membership", "room_id": "!space:example.com" }
                ]),
            ),
        );
        // The shape the old test used to plant: a member event whose
        // `room_id` field names the space, sitting in this room's state
        // map under Bob's member key.  It says nothing about the space.
        apply_state_event(
            &mut state,
            &make_member_event(
                "$bob_member_other",
                "@bob:example.com",
                "@bob:example.com",
                "!space:example.com",
                "join",
            ),
        );

        let join = make_member_event(
            "$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join",
        );
        assert!(
            !check_allow_conditions(&join, &state),
            "a foreign allow.room_id is unevaluable here and must fail closed"
        );
    }

    // -----------------------------------------------------------------------
    // Test 11a: an allow condition naming *this* room is still evaluable
    // -----------------------------------------------------------------------
    #[test]
    fn allow_condition_naming_this_room_is_evaluated() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let mut state: StateMap<Event> = HashMap::new();

        apply_state_event(&mut state, &make_create_event(creator, room_id));
        apply_state_event(
            &mut state,
            &make_join_rules_event_with_allow(
                creator,
                room_id,
                "restricted",
                json!([{ "type": "m.room_membership", "room_id": room_id }]),
            ),
        );
        let join = make_member_event(
            "$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join",
        );
        assert!(!check_allow_conditions(&join, &state));

        apply_state_event(
            &mut state,
            &make_member_event(
                "$bob_join_prior", "@bob:example.com", "@bob:example.com", room_id, "join",
            ),
        );
        assert!(check_allow_conditions(&join, &state));
    }

    // -----------------------------------------------------------------------
    // Test 11b: the invite path still joins a restricted room
    // -----------------------------------------------------------------------
    #[test]
    fn join_restricted_with_invite_still_passes() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let mut state: StateMap<Event> = HashMap::new();

        apply_state_event(&mut state, &make_create_event(creator, room_id));
        apply_state_event(
            &mut state,
            &make_member_event("$creator_join", creator, creator, room_id, "join"),
        );
        apply_state_event(
            &mut state,
            &make_join_rules_event_with_allow(
                creator,
                room_id,
                "restricted",
                json!([
                    { "type": "m.room_membership", "room_id": "!space:example.com" }
                ]),
            ),
        );
        // Alice invited Bob.
        apply_state_event(
            &mut state,
            &make_member_event("$bob_invite", creator, "@bob:example.com", room_id, "invite"),
        );

        let join = make_member_event(
            "$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join",
        );
        assert!(
            check_auth(&join, &state).is_ok(),
            "an invite authorizes the join, without the stub allow check"
        );
    }

    /// A restricted join is allowed only when the named authoriser is joined
    /// and can invite. Membership of some other room is not in this state.
    #[test]
    fn restricted_join_requires_a_joined_authoriser_with_invite_power() {
        let alice = "@alice:example.com";
        let dave = "@dave:example.com";
        let carol = "@carol:example.com";
        let bob = "@bob:example.com";
        let room_id = "!room:example.com";

        let mut state = base_state(alice, room_id, "invite");
        apply_state_event(
            &mut state,
            &make_join_rules_event_with_allow(
                alice,
                room_id,
                "restricted",
                json!([{ "type": "m.room_membership", "room_id": "!space:example.com" }]),
            ),
        );
        apply_state_event(
            &mut state,
            &make_power_levels_event(
                "$pl",
                alice,
                room_id,
                json!({ "invite": 50, "users": { alice: 100, carol: 49, dave: 50 } }),
            ),
        );
        apply_state_event(&mut state, &make_member_event("$dave", alice, dave, room_id, "join"));
        apply_state_event(&mut state, &make_member_event("$carol", alice, carol, room_id, "join"));

        let join_via = |authoriser: &str| {
            let mut join = make_member_event("$bob_join", bob, bob, room_id, "join");
            join.content["join_authorised_via_users_server"] = json!(authoriser);
            join
        };
        let bare = make_member_event("$bob_join", bob, bob, room_id, "join");
        assert!(
            matches!(check_auth(&bare, &state), Err(AuthError::JoinRequiresInvite { .. })),
            "no invite and no authoriser"
        );
        assert!(check_auth(&join_via(dave), &state).is_ok(), "dave has invite power and is joined");
        assert!(check_auth(&join_via(alice), &state).is_ok(), "the creator can invite");
        assert!(
            matches!(check_auth(&join_via(carol), &state), Err(AuthError::JoinRequiresInvite { .. })),
            "carol is below the invite level"
        );
        assert!(
            matches!(check_auth(&join_via("@ghost:example.com"), &state), Err(AuthError::JoinRequiresInvite { .. })),
            "an authoriser who is not joined is rejected"
        );
        let mut without_dave = state.clone();
        without_dave.remove(&("m.room.member".to_owned(), dave.to_owned()));
        assert!(
            check_auth(&join_via(dave), &without_dave).is_err(),
            "the authoriser's member event has to be in auth state"
        );

        let via_dave = join_via(dave);
        let keys = auth_event_keys(&via_dave);
        assert!(
            keys.contains(&("m.room.member".to_owned(), dave.to_owned())),
            "auth events include the authoriser: {keys:?}"
        );
        assert!(
            !auth_event_keys(&bare).iter().any(|(_, key)| key == dave),
            "a join without the field does not select the authoriser"
        );

        // Room version 7 does not support restricted joins.
        let mut old = state.clone();
        apply_state_event(&mut old, &create_with("7", alice, room_id, json!({ "creator": alice })));
        assert!(check_auth(&join_via(dave), &old).is_err(), "v7 ignores the authoriser");

        // knock_restricted starts at room version 10.
        apply_state_event(
            &mut state,
            &make_join_rules_event_with_allow(
                alice,
                room_id,
                "knock_restricted",
                json!([{ "type": "m.room_membership", "room_id": "!space:example.com" }]),
            ),
        );
        let mut v8 = state.clone();
        apply_state_event(&mut v8, &create_with("8", alice, room_id, json!({ "creator": alice })));
        assert!(check_auth(&join_via(dave), &v8).is_err(), "v8 has no knock_restricted");
        let mut v9 = state.clone();
        apply_state_event(&mut v9, &create_with("9", alice, room_id, json!({ "creator": alice })));
        assert!(check_auth(&join_via(dave), &v9).is_err(), "v9 has no knock_restricted");
        let mut v10 = state.clone();
        apply_state_event(&mut v10, &create_with("10", alice, room_id, json!({ "creator": alice })));
        assert!(check_auth(&join_via(dave), &v10).is_ok(), "v10 knock_restricted accepts the authoriser");
    }

    /// Room version 9 still accepts a restricted join. It does not accept
    /// `knock_restricted`, which starts at room version 10.
    #[test]
    fn room_version_9_keeps_restricted_joins_and_rejects_knock_restricted() {
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let dave = "@dave:example.com";
        let room = "!room:example.com";
        let room_at = |rule: &str| {
            let mut state = HashMap::new();
            apply_state_event(&mut state, &create_with("9", alice, room, json!({ "creator": alice })));
            apply_state_event(&mut state, &make_member_event("$aj", alice, alice, room, "join"));
            apply_state_event(&mut state, &make_member_event("$dj", alice, dave, room, "join"));
            apply_state_event(
                &mut state,
                &make_join_rules_event_with_allow(
                    alice,
                    room,
                    rule,
                    json!([{ "type": "m.room_membership", "room_id": "!space:example.com" }]),
                ),
            );
            apply_state_event(
                &mut state,
                &make_power_levels_event(
                    "$pl",
                    alice,
                    room,
                    json!({ "invite": 50, "users": { alice: 100, dave: 50 } }),
                ),
            );
            state
        };
        let mut join = make_member_event("$bj", bob, bob, room, "join");
        join.content["join_authorised_via_users_server"] = json!(dave);
        assert!(check_auth(&join, &room_at("restricted")).is_ok(), "v9 keeps restricted joins");
        assert!(
            check_auth(&join, &room_at("knock_restricted")).is_err(),
            "v9 does not recognise knock_restricted"
        );
        let knock = make_member_event("$bk", bob, bob, room, "knock");
        assert!(check_auth(&knock, &room_at("knock")).is_ok(), "v9 still allows knock");
        assert!(
            check_auth(&knock, &room_at("knock_restricted")).is_err(),
            "v9 does not allow knocking on knock_restricted"
        );
    }

    /// Room version 10 accepts `knock_restricted` and rejects a power level
    /// that is an integer encoded as a string. Version 9 still accepts that
    /// string, and still rejects a float.
    #[test]
    fn room_version_10_accepts_knock_restricted_and_rejects_string_power_levels() {
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let dave = "@dave:example.com";
        let room = "!room:example.com";
        let room_at = |version: &str, rule: &str| {
            let mut state = HashMap::new();
            apply_state_event(&mut state, &create_with(version, alice, room, json!({ "creator": alice })));
            apply_state_event(&mut state, &make_member_event("$aj", alice, alice, room, "join"));
            apply_state_event(&mut state, &make_member_event("$dj", alice, dave, room, "join"));
            apply_state_event(
                &mut state,
                &make_join_rules_event_with_allow(
                    alice,
                    room,
                    rule,
                    json!([{ "type": "m.room_membership", "room_id": "!space:example.com" }]),
                ),
            );
            apply_state_event(
                &mut state,
                &make_power_levels_event(
                    "$pl",
                    alice,
                    room,
                    json!({ "invite": 50, "users": { alice: 100, dave: 50 } }),
                ),
            );
            state
        };
        let mut join = make_member_event("$bj", bob, bob, room, "join");
        join.content["join_authorised_via_users_server"] = json!(dave);
        assert!(
            check_auth(&join, &room_at("10", "knock_restricted")).is_ok(),
            "v10 accepts a knock_restricted join from an authoriser"
        );
        assert!(
            check_auth(&join, &room_at("9", "knock_restricted")).is_err(),
            "v9 still rejects knock_restricted"
        );
        let knock = make_member_event("$bk", bob, bob, room, "knock");
        assert!(
            check_auth(&knock, &room_at("10", "knock_restricted")).is_ok(),
            "v10 allows a knock when the join rule is knock_restricted"
        );

        let mut v9 = HashMap::new();
        apply_state_event(&mut v9, &create_with("9", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v9, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v9, &make_member_event("$bj", alice, bob, room, "join"));
        let strings = make_power_levels_event(
            "$strings",
            alice,
            room,
            json!({
                "events": { "m.room.name": "50" },
                "events_default": "0",
                "users": { alice: "100", bob: "0" }
            }),
        );
        assert!(check_auth(&strings, &v9).is_ok(), "v9 accepts integer strings");
        let mut v10 = HashMap::new();
        apply_state_event(&mut v10, &create_with("10", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut v10, &make_member_event("$aj", alice, alice, room, "join"));
        apply_state_event(&mut v10, &make_member_event("$bj", alice, bob, room, "join"));
        assert!(check_auth(&strings, &v10).is_err(), "v10 rejects integer strings");
        let integers = make_power_levels_event(
            "$ints",
            alice,
            room,
            json!({
                "events": { "m.room.name": 50 },
                "events_default": 0,
                "users": { alice: 100, bob: 0 }
            }),
        );
        assert!(check_auth(&integers, &v10).is_ok(), "v10 accepts JSON integers");
        let float_level = make_power_levels_event(
            "$float",
            alice,
            room,
            json!({ "users": { alice: 100 }, "events_default": 0.9 }),
        );
        assert!(check_auth(&float_level, &v9).is_err(), "v9 still rejects a float power level");

        apply_state_event(&mut v9, &strings);
        let name = make_event(
            "$name",
            "m.room.name",
            bob,
            room,
            Some(""),
            json!({ "name": "n" }),
            vec![],
        );
        assert!(
            matches!(check_auth(&name, &v9), Err(AuthError::InsufficientPowerLevel { .. })),
            "v9 uses the string level 50, so bob at 0 cannot rename the room"
        );
    }

    /// Room version 8 accepts a restricted join that names a joined user who
    /// can invite. Version 7 rejects that event. A bare join still needs an invite.
    #[test]
    fn room_version_8_accepts_a_restricted_join_from_an_authoriser() {
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let dave = "@dave:example.com";
        let room = "!room:example.com";
        let room_at = |version: &str| {
            let mut state = HashMap::new();
            apply_state_event(&mut state, &create_with(version, alice, room, json!({ "creator": alice })));
            apply_state_event(&mut state, &make_member_event("$aj", alice, alice, room, "join"));
            apply_state_event(&mut state, &make_member_event("$dj", alice, dave, room, "join"));
            apply_state_event(
                &mut state,
                &make_join_rules_event_with_allow(
                    alice,
                    room,
                    "restricted",
                    json!([{ "type": "m.room_membership", "room_id": "!space:example.com" }]),
                ),
            );
            apply_state_event(
                &mut state,
                &make_power_levels_event(
                    "$pl",
                    alice,
                    room,
                    json!({ "invite": 50, "users": { alice: 100, dave: 50 } }),
                ),
            );
            state
        };
        let mut join = make_member_event("$bj", bob, bob, room, "join");
        join.content["join_authorised_via_users_server"] = json!(dave);
        assert!(check_auth(&join, &room_at("8")).is_ok(), "v8 accepts the authoriser");
        assert!(check_auth(&join, &room_at("7")).is_err(), "v7 rejects a restricted join");
        let bare = make_member_event("$bj", bob, bob, room, "join");
        assert!(
            matches!(check_auth(&bare, &room_at("8")), Err(AuthError::JoinRequiresInvite { .. })),
            "v8 still requires an invite or an authoriser"
        );
    }

    // -----------------------------------------------------------------------
    // Test 12: join restricted room with no satisfied allow condition fails
    // -----------------------------------------------------------------------
    #[test]
    fn join_restricted_without_satisfied_allow_fails() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let mut state = base_state(creator, room_id, "restricted");
        // Replace the default join_rules with one that has allow conditions.
        apply_state_event(
            &mut state,
            &make_join_rules_event_with_allow(
                creator,
                room_id,
                "restricted",
                json!([
                    { "type": "m.room_membership", "room_id": "!other:example.com" }
                ]),
            ),
        );
        // Bob is NOT a member of !other:example.com — no member event in state.

        let join = make_member_event(
            "$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join",
        );
        let err = check_auth(&join, &state).unwrap_err();
        assert!(matches!(err, AuthError::JoinRequiresInvite { .. }));
    }

    // -----------------------------------------------------------------------
    // Test 13: join restricted room with empty allow fails
    // -----------------------------------------------------------------------
    #[test]
    fn join_restricted_with_empty_allow_fails() {
        let creator = "@alice:example.com";
        let room_id = "!room:example.com";
        let mut state = base_state(creator, room_id, "restricted");
        // Replace with join_rules that has an empty allow list.
        apply_state_event(
            &mut state,
            &make_join_rules_event_with_allow(
                creator,
                room_id,
                "restricted",
                json!([]),
            ),
        );

        let join = make_member_event(
            "$bob_join", "@bob:example.com", "@bob:example.com", room_id, "join",
        );
        let err = check_auth(&join, &state).unwrap_err();
        assert!(matches!(err, AuthError::JoinRequiresInvite { .. }));
    }

    // -----------------------------------------------------------------------
    // Read access: may_read_room
    // -----------------------------------------------------------------------

    fn room_with_visibility(room_id: &str, visibility: &str) -> StateMap<Event> {
        let creator = "@alice:example.com";
        let mut state = base_state(creator, room_id, "invite");
        apply_state_event(
            &mut state,
            &make_event(
                "$hist_vis",
                "m.room.history_visibility",
                creator,
                room_id,
                Some(""),
                json!({ "history_visibility": visibility }),
                vec![],
            ),
        );
        state
    }

    #[test]
    fn joined_user_may_read_and_a_stranger_may_not() {
        let room_id = "!room:example.com";
        let state = room_with_visibility(room_id, "shared");

        assert!(may_read_room("@alice:example.com", &state));
        assert!(!may_read_room("@bob:example.com", &state));
    }

    #[test]
    fn invited_user_may_read_invite_state() {
        let room_id = "!room:example.com";
        let mut state = room_with_visibility(room_id, "shared");
        apply_state_event(
            &mut state,
            &make_member_event(
                "$bob_invite",
                "@alice:example.com",
                "@bob:example.com",
                room_id,
                "invite",
            ),
        );
        assert!(may_read_room("@bob:example.com", &state));
    }

    #[test]
    fn left_user_may_not_read() {
        let room_id = "!room:example.com";
        let mut state = room_with_visibility(room_id, "shared");
        apply_state_event(
            &mut state,
            &make_member_event(
                "$bob_leave",
                "@bob:example.com",
                "@bob:example.com",
                room_id,
                "leave",
            ),
        );
        assert!(!may_read_room("@bob:example.com", &state));
    }

    #[test]
    fn world_readable_room_may_be_peeked() {
        let room_id = "!room:example.com";
        let state = room_with_visibility(room_id, "world_readable");
        // The caller has already presented a valid grant to get here;
        // world_readable relaxes membership, never agency.
        assert!(may_read_room("@bob:example.com", &state));
    }

    #[test]
    fn missing_history_visibility_defaults_to_shared() {
        let room_id = "!room:example.com";
        let state = base_state("@alice:example.com", room_id, "invite");
        assert_eq!(history_visibility_of(&state), HistoryVisibility::Shared);
        assert!(!may_read_room("@bob:example.com", &state));
    }

    // -----------------------------------------------------------------------
    // UserEventPosition derivation
    // -----------------------------------------------------------------------

    fn member_at(pos: i64, user: &str, membership: &str) -> (i64, Event) {
        let mut ev = make_member_event(
            &format!("$m{pos}"),
            user,
            user,
            "!room:example.com",
            membership,
        );
        ev.depth = pos;
        (pos, ev)
    }

    #[test]
    fn position_is_membership_at_the_event() {
        let members = vec![member_at(10, "@bob:example.com", "join")];

        // Event before Bob's join.
        assert_eq!(
            user_event_position(&members, 5),
            UserEventPosition::JoinedAfter
        );
        // Event after Bob's join.
        assert_eq!(
            user_event_position(&members, 15),
            UserEventPosition::WasMember
        );
    }

    #[test]
    fn a_never_member_has_no_position() {
        assert_eq!(user_event_position(&[], 5), UserEventPosition::NeverMember);
    }

    #[test]
    fn an_invite_is_its_own_position() {
        let members = vec![member_at(10, "@bob:example.com", "invite")];
        assert_eq!(
            user_event_position(&members, 15),
            UserEventPosition::WasInvited
        );
    }

    #[test]
    fn leaving_and_rejoining_reads_the_latest_prior_event() {
        let members = vec![
            member_at(10, "@bob:example.com", "join"),
            member_at(20, "@bob:example.com", "leave"),
            member_at(30, "@bob:example.com", "join"),
        ];

        assert_eq!(
            user_event_position(&members, 15),
            UserEventPosition::WasMember
        );
        // Between the leave and the rejoin Bob was out of the room, but
        // he did join later — which is what `shared` keys on.
        assert_eq!(
            user_event_position(&members, 25),
            UserEventPosition::JoinedAfter
        );
        assert_eq!(
            user_event_position(&members, 35),
            UserEventPosition::WasMember
        );
    }

    #[test]
    fn joined_visibility_hides_events_before_the_join() {
        let members = vec![member_at(10, "@bob:example.com", "join")];

        let before = user_event_position(&members, 5);
        let after = user_event_position(&members, 15);

        assert!(!can_see(&HistoryVisibility::Joined, &before));
        assert!(can_see(&HistoryVisibility::Joined, &after));
        // `shared` shows both to a member.
        assert!(can_see(&HistoryVisibility::Shared, &before));
    }

    #[test]
    fn a_server_sees_what_its_most_present_user_sees() {
        let members = vec![
            member_at(10, "@carol:other.example", "invite"),
            member_at(20, "@dave:other.example", "join"),
        ];

        assert_eq!(
            server_event_position(&members, 15),
            UserEventPosition::WasInvited
        );
        assert_eq!(
            server_event_position(&members, 25),
            UserEventPosition::WasMember
        );
        assert_eq!(
            server_event_position(&[], 25),
            UserEventPosition::NeverMember
        );
    }

    // -----------------------------------------------------------------------
    // Storage-backed wrappers
    // -----------------------------------------------------------------------

    use crate::storage::{MemoryStorage, Storage as _};

    /// A room where Alice creates, sends `$early`, then Bob joins, then
    /// Alice sends `$late`.  `history_visibility` is `visibility`.
    async fn room_fixture(visibility: &str) -> (MemoryStorage, &'static str) {
        let storage = MemoryStorage::default();
        let room_id = "!room:example.com";
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";

        let mut events = vec![
            make_create_event(alice, room_id),
            make_member_event("$alice_join", alice, alice, room_id, "join"),
            make_event(
                "$hist_vis",
                "m.room.history_visibility",
                alice,
                room_id,
                Some(""),
                json!({ "history_visibility": visibility }),
                vec![],
            ),
            make_event(
                "$early",
                "m.room.message",
                alice,
                room_id,
                None,
                json!({ "body": "before bob" }),
                vec![],
            ),
            make_member_event("$bob_join", bob, bob, room_id, "join"),
            make_event(
                "$late",
                "m.room.message",
                alice,
                room_id,
                None,
                json!({ "body": "after bob" }),
                vec![],
            ),
        ];

        for (i, ev) in events.iter_mut().enumerate() {
            // MemoryStorage uses depth as its stream position.
            ev.depth = i as i64 + 1;
            storage.put_event(ev).await.unwrap();
            if let Some(state_key) = ev.state_key.clone() {
                storage
                    .set_state_entry(room_id, &ev.event_type, &state_key, &ev.event_id)
                    .await
                    .unwrap();
            }
        }

        (storage, room_id)
    }

    async fn timeline(storage: &MemoryStorage, room_id: &str) -> Vec<Event> {
        let mut evs = storage.room_events(room_id).await.unwrap();
        evs.retain(|e| e.event_type == "m.room.message");
        evs.sort_by_key(|e| e.depth);
        evs
    }

    #[tokio::test]
    async fn stored_membership_gates_room_reads() {
        let (storage, room_id) = room_fixture("shared").await;

        assert!(may_read_stored_room(&storage, room_id, "@alice:example.com")
            .await
            .unwrap());
        assert!(may_read_stored_room(&storage, room_id, "@bob:example.com")
            .await
            .unwrap());
        assert!(
            !may_read_stored_room(&storage, room_id, "@mallory:example.com")
                .await
                .unwrap()
        );

        let err = require_read_access(&storage, room_id, "@mallory:example.com")
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::Forbidden(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn joined_visibility_hides_pre_join_events_from_storage() {
        let (storage, room_id) = room_fixture("joined").await;
        let events = timeline(&storage, room_id).await;
        assert_eq!(events.len(), 2);

        let bobs = filter_visible_for_user(&storage, room_id, "@bob:example.com", events.clone())
            .await
            .unwrap();
        let ids: Vec<&str> = bobs.iter().map(|e| e.event_id.as_str()).collect();
        assert_eq!(ids, vec!["$late"], "Bob must not see events before his join");

        let alices = filter_visible_for_user(&storage, room_id, "@alice:example.com", events)
            .await
            .unwrap();
        assert_eq!(alices.len(), 2, "Alice was there for both");
    }

    #[tokio::test]
    async fn shared_visibility_shows_history_to_a_late_joiner() {
        let (storage, room_id) = room_fixture("shared").await;
        let events = timeline(&storage, room_id).await;

        let bobs = filter_visible_for_user(&storage, room_id, "@bob:example.com", events.clone())
            .await
            .unwrap();
        assert_eq!(bobs.len(), 2);

        let strangers =
            filter_visible_for_user(&storage, room_id, "@mallory:example.com", events)
                .await
                .unwrap();
        assert!(strangers.is_empty(), "a non-member sees nothing");
    }

    #[tokio::test]
    async fn world_readable_visibility_shows_everything() {
        let (storage, room_id) = room_fixture("world_readable").await;
        let events = timeline(&storage, room_id).await;

        let strangers =
            filter_visible_for_user(&storage, room_id, "@mallory:example.com", events)
                .await
                .unwrap();
        assert_eq!(strangers.len(), 2);
    }

    #[tokio::test]
    async fn backfill_filters_against_the_origin_server() {
        let (storage, room_id) = room_fixture("joined").await;
        let events = timeline(&storage, room_id).await;

        // No member from other.example has ever been in the room.
        let none = filter_visible_for_server(&storage, room_id, "other.example", events.clone())
            .await
            .unwrap();
        assert!(
            none.is_empty(),
            "backfill must not hand events to a server with no membership"
        );

        // example.com hosts both Alice and Bob, so it sees both.
        let ours = filter_visible_for_server(&storage, room_id, "example.com", events)
            .await
            .unwrap();
        assert_eq!(ours.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Knock membership rules (v7+ / v11), directory lane conduit-y99.20
    // -----------------------------------------------------------------------

    const KNOCKER: &str = "@kate:example.com";

    fn knock_room(rule: &str) -> StateMap<Event> {
        let mut state = base_state("@alice:example.com", "!k:example.com", rule);
        apply_state_event(
            &mut state,
            &make_power_levels_event(
                "$pl",
                "@alice:example.com",
                "!k:example.com",
                json!({"kick": 50, "ban": 50, "invite": 0, "users": {"@alice:example.com": 100}}),
            ),
        );
        state
    }

    fn member(sender: &str, target: &str, membership: &str) -> Event {
        make_member_event("$m", sender, target, "!k:example.com", membership)
    }

    #[test]
    fn knock_allowed_only_under_knock_join_rules() {
        for rule in ["knock", "knock_restricted"] {
            assert!(check_auth(&member(KNOCKER, KNOCKER, "knock"), &knock_room(rule)).is_ok(), "{rule}");
        }
        for rule in ["public", "invite", "restricted", "private"] {
            assert!(check_auth(&member(KNOCKER, KNOCKER, "knock"), &knock_room(rule)).is_err(), "{rule}");
        }
    }

    #[test]
    fn knock_selects_join_rules_as_an_auth_event() {
        let keys = auth_event_keys(&member(KNOCKER, KNOCKER, "knock"));
        assert!(keys.contains(&("m.room.join_rules".to_owned(), String::new())));
    }

    #[test]
    fn knock_on_behalf_of_another_user_rejected() {
        let state = knock_room("knock");
        assert!(check_auth(&member("@alice:example.com", KNOCKER, "knock"), &state).is_err());
    }

    #[test]
    fn knock_rejected_when_banned_invited_or_joined() {
        for current in ["ban", "invite", "join"] {
            let mut state = knock_room("knock");
            apply_state_event(&mut state, &member("@alice:example.com", KNOCKER, current));
            assert!(check_auth(&member(KNOCKER, KNOCKER, "knock"), &state).is_err(), "{current}");
        }
        let mut state = knock_room("knock");
        apply_state_event(&mut state, &member(KNOCKER, KNOCKER, "leave"));
        assert!(check_auth(&member(KNOCKER, KNOCKER, "knock"), &state).is_ok());
    }

    #[test]
    fn knocker_may_rescind_with_self_leave() {
        let mut state = knock_room("knock");
        apply_state_event(&mut state, &member(KNOCKER, KNOCKER, "knock"));
        assert!(check_auth(&member(KNOCKER, KNOCKER, "leave"), &state).is_ok());
    }

    #[test]
    fn knock_is_accepted_by_invite_and_denied_by_kick() {
        let mut state = knock_room("knock");
        apply_state_event(&mut state, &member(KNOCKER, KNOCKER, "knock"));
        assert!(check_auth(&member("@alice:example.com", KNOCKER, "invite"), &state).is_ok());
        assert!(check_auth(&member("@alice:example.com", KNOCKER, "leave"), &state).is_ok());
        // A knocker may not join directly under `knock`; they need the invite.
        assert!(check_auth(&member(KNOCKER, KNOCKER, "join"), &state).is_err());
    }

    #[test]
    fn unban_requires_ban_level_as_well_as_kick_level() {
        let mut state = knock_room("knock");
        apply_state_event(
            &mut state,
            &make_member_event("$bob", "@bob:example.com", "@bob:example.com", "!k:example.com", "join"),
        );
        apply_state_event(
            &mut state,
            &make_power_levels_event(
                "$pl2",
                "@alice:example.com",
                "!k:example.com",
                json!({"kick": 50, "ban": 75, "users": {"@alice:example.com": 100, "@bob:example.com": 60}}),
            ),
        );
        apply_state_event(&mut state, &member("@alice:example.com", KNOCKER, "ban"));
        assert!(check_auth(&member("@bob:example.com", KNOCKER, "leave"), &state).is_err());
        assert!(check_auth(&member("@alice:example.com", KNOCKER, "leave"), &state).is_ok());
    }

    /// Room v11 auth rule 9.4: the first power-levels event may set values
    /// above the sender. A later event is still bounded by the sender.
    #[test]
    fn first_power_levels_event_may_exceed_the_sender() {
        let alice = "@alice:example.com";
        let room = "!room:example.com";
        let mut state = HashMap::new();
        apply_state_event(&mut state, &create_with("11", alice, room, json!({ "creator": alice })));
        apply_state_event(&mut state, &make_member_event("$join", alice, alice, room, "join"));
        let first = make_power_levels_event(
            "$pl",
            alice,
            room,
            json!({ "users": { alice: 100 }, "events": { "m.room.tombstone": 150 } }),
        );
        assert!(check_auth(&first, &state).is_ok(), "{:?}", check_auth(&first, &state));

        apply_state_event(&mut state, &first);
        let raised = make_power_levels_event(
            "$pl2",
            alice,
            room,
            json!({ "users": { alice: 100 }, "events": { "m.room.tombstone": 200 } }),
        );
        assert!(matches!(
            check_auth(&raised, &state),
            Err(AuthError::PowerLevelExceedsSelf { sender_has: 100 })
        ));

        let mut v12 = HashMap::new();
        let mut create = create_with("12", alice, "", json!({}));
        create.room_id.clear();
        apply_state_event(&mut v12, &create);
        apply_state_event(&mut v12, &make_member_event("$join", alice, alice, room, "join"));
        let lists_creator = make_power_levels_event(
            "$pl",
            alice,
            room,
            json!({ "users": { alice: 100 }, "events": { "m.room.tombstone": 150 } }),
        );
        assert!(matches!(
            check_auth(&lists_creator, &v12),
            Err(AuthError::CreatorInPowerLevels)
        ));
    }
}
