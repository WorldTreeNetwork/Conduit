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

    #[error("kick/leave rejected: target is not in the room")]
    TargetNotInRoom,

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
            // join_rules is needed when the membership target is joining.
            if let Ok(mc) = parse_member(&event.content) {
                if mc.membership == Membership::Join || mc.membership == Membership::Invite {
                    keys.push(("m.room.join_rules".to_owned(), String::new()));
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
    auth_state
        .get(&("m.room.power_levels".to_owned(), String::new()))
        .and_then(|ev| parse_power_levels(&ev.content).ok())
        .unwrap_or_default()
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

fn get_membership(auth_state: &StateMap<Event>, user_id: &str) -> Option<Membership> {
    auth_state
        .get(&("m.room.member".to_owned(), user_id.to_owned()))
        .and_then(|ev| parse_member(&ev.content).ok())
        .map(|mc| mc.membership)
}

fn creator_id(auth_state: &StateMap<Event>) -> Option<String> {
    auth_state
        .get(&("m.room.create".to_owned(), String::new()))
        .map(|ev| ev.sender.clone())
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
        "m.room.member" => check_member(event, auth_state, &sender_membership)?,
        "m.room.power_levels" => check_power_levels(event, auth_state)?,
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
        let creator = creator_id(auth_state);
        let pl_event = auth_state.get(&("m.room.power_levels".to_owned(), String::new()));
        let sender_level = user_power_level(&event.sender, pl_event, creator.as_deref());
        let is_state = event.state_key.is_some();
        let required = level_required_for_event(&event.event_type, is_state, &pl);
        if sender_level < required {
            return Err(AuthError::InsufficientPowerLevel {
                needed: required,
                sender_has: sender_level,
            });
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

    // Sender's server domain must match the room's server domain.
    if domain_of(&event.sender) != domain_of(&event.room_id) {
        return Err(AuthError::CreateSenderDomainMismatch);
    }

    // room_version in content must be a string (if present).
    let content = parse_create(&event.content)
        .map_err(|e| AuthError::ContentParseError(e.to_string()))?;
    // room_version has a serde default so it's always a String after parse.
    let _ = content.room_version; // already validated by serde

    Ok(())
}

// ---------------------------------------------------------------------------
// dn9.3 — m.room.member checks
// ---------------------------------------------------------------------------

fn check_member(
    event: &Event,
    auth_state: &StateMap<Event>,
    sender_membership: &Option<Membership>,
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

    let pl_event = auth_state.get(&("m.room.power_levels".to_owned(), String::new()));
    let creator = creator_id(auth_state);
    let pl = get_pl_content(auth_state);

    let sender_level = user_power_level(&event.sender, pl_event, creator.as_deref());
    let target_level = user_power_level(state_key, pl_event, creator.as_deref());

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
                    JoinRule::Invite | JoinRule::Knock => {
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
                    JoinRule::Restricted | JoinRule::KnockRestricted => {
                        // First check allow conditions (e.g. membership in a space).
                        // If they pass, the join is allowed regardless of invite status.
                        if check_allow_conditions(event, auth_state) {
                            // Allow conditions satisfied — join permitted.
                        } else {
                            // Allow conditions not satisfied; fall through to invite check.
                            match &target_membership {
                                Some(Membership::Invite) | Some(Membership::Join) => {}
                                _ => {
                                    return Err(AuthError::JoinRequiresInvite {
                                        join_rule: join_rule.clone(),
                                    })
                                }
                            }
                        }
                    }
                    JoinRule::Private => {
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
                // Self-leave: sender must be invited or joined.
                match &sender_membership {
                    Some(Membership::Invite) | Some(Membership::Join) => {}
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

                // Target must currently be in the room.
                if !matches!(
                    &target_membership,
                    Some(Membership::Join) | Some(Membership::Invite)
                ) {
                    return Err(AuthError::TargetNotInRoom);
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

            // Cannot knock if banned or already joined.
            if matches!(
                &target_membership,
                Some(Membership::Ban) | Some(Membership::Join)
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

    let pl_event = auth_state.get(&("m.room.power_levels".to_owned(), String::new()));
    let creator = creator_id(auth_state);
    let current_pl = get_pl_content(auth_state);
    let sender_level = user_power_level(&event.sender, pl_event, creator.as_deref());

    // Sender needs enough level to send a power_levels state event.
    let required = level_required_for_event("m.room.power_levels", true, &current_pl);
    if sender_level < required {
        return Err(AuthError::InsufficientPowerLevel {
            needed: required,
            sender_has: sender_level,
        });
    }

    // Parse the proposed new power_levels content.
    let new_pl = parse_power_levels(&event.content)
        .map_err(|e| AuthError::ContentParseError(e.to_string()))?;

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

/// Drop the events in `events` that `user_id` may not see, per the
/// room's history visibility.
pub async fn filter_visible_for_user(
    storage: &dyn crate::storage::Storage,
    room_id: &str,
    user_id: &str,
    events: Vec<Event>,
) -> crate::Result<Vec<Event>> {
    let state = current_state_map(storage, room_id).await?;
    let hist_vis = history_visibility_of(&state);
    let members = storage.member_events_for_user(room_id, user_id).await?;
    filter_with(storage, hist_vis, &members, events, user_event_position).await
}

/// The same filter, for a requesting origin server (federation
/// backfill and get_missing_events).
pub async fn filter_visible_for_server(
    storage: &dyn crate::storage::Storage,
    room_id: &str,
    origin: &str,
    events: Vec<Event>,
) -> crate::Result<Vec<Event>> {
    let state = current_state_map(storage, room_id).await?;
    let hist_vis = history_visibility_of(&state);
    let members = storage.member_events_for_server(room_id, origin).await?;
    filter_with(storage, hist_vis, &members, events, server_event_position).await
}

async fn filter_with(
    storage: &dyn crate::storage::Storage,
    hist_vis: HistoryVisibility,
    members: &[(i64, Event)],
    events: Vec<Event>,
    position: fn(&[(i64, Event)], i64) -> UserEventPosition,
) -> crate::Result<Vec<Event>> {
    if hist_vis == HistoryVisibility::WorldReadable {
        return Ok(events);
    }

    // One lookup for the whole page, not one per event.
    let ids: Vec<String> = events.iter().map(|e| e.event_id.clone()).collect();
    let positions = storage.event_stream_positions(&ids).await?;

    Ok(events
        .into_iter()
        .filter(|ev| match positions.get(&ev.event_id) {
            Some(pos) => can_see(&hist_vis, &position(members, *pos)),
            // An event we cannot place is an event we cannot clear.
            None => false,
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
}
