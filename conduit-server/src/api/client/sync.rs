//! `GET /_matrix/client/v3/sync` handler.
//!
//! Implements:
//!   - il0.14: full sync (no `since`)
//!   - il0.15: incremental sync + long-poll (`since` + `timeout`)
//!   - il0.16: best-effort filter support (`room.timeline.limit`, `.types`, `.rooms`)
//!   - il0.17: stream-position token format `"s<position>"`

use sha2::{Digest, Sha256};
use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::time::Duration;

use conduit::state_events::{parse_member, Membership};

use super::{AuthState, AuthedUser, MatrixError};

// ---------------------------------------------------------------------------
// Token helpers (il0.17)
// ---------------------------------------------------------------------------

/// Combined sync token: `"s{events}_d{devices}_a{account}_r{receipts}_t{to_device}_y{typing}_p{presence}_e{epoch}_k{keys}"`.
///
/// Streams and their cursor positions:
///   - `s` — event stream_position
///   - `d` — device list change stream position
///   - `a` — account_data stream_pos (default 0)
///   - `r` — receipts stream_pos (default 0)
///   - `t` — last delivered to-device queue ID (default 0)
///   - `y`, `p` — typing and presence revisions for the process generation `e`
///   - `k` — fingerprint of the owning device's key inventory
///
/// Old formats (`s{e}` and `s{e}_d{d}`) are accepted on parse and
/// extended with default zero cursors.
#[derive(Clone)]
pub(crate) struct SyncToken {
    pub(crate) events_pos: i64,
    pub(crate) device_pos: i64,
    account_data_pos: i64,
    receipts_pos: i64,
    to_device_pos: i64,
    typing_pos: i64,
    presence_pos: i64,
    ephemeral_epoch: Option<u64>,
    key_summary: Option<String>,
}

impl SyncToken {
    fn encode(&self) -> String {
        format!(
            "s{}_d{}_a{}_r{}_t{}_y{}_p{}_e{}_k{}",
            self.events_pos,
            self.device_pos,
            self.account_data_pos,
            self.receipts_pos,
            self.to_device_pos,
            self.typing_pos,
            self.presence_pos,
            self.ephemeral_epoch.unwrap_or_else(ephemeral_epoch),
            self.key_summary.as_deref().unwrap_or("")
        )
    }
}

/// Parse a sync `since` token.
/// Accepts:
///   - `"s{events}"` (legacy)
///   - `"s{events}_d{device}"` (previous format)
///   - `"s{events}_d{device}_a{acct}_r{rcpts}"` (previous format)
///   - `"s{events}_d{device}_a{acct}_r{rcpts}_t{to_device}"` (previous format)
///   - optional `y`, `p`, `e`, `k` fields for ephemeral streams and key inventory
pub(crate) fn parse_since(raw: &str) -> Result<SyncToken, Response> {
    let bad = || {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errcode": "M_INVALID_PARAM",
                "error": "invalid since token"
            })),
        )
            .into_response()
    };

    let s_part = raw.strip_prefix('s').ok_or_else(bad)?;

    // Stream cursors are independent; absent cursors default to zero.
    let events_pos: i64;
    let mut device_pos = 0i64;
    let mut account_data_pos = 0i64;
    let mut receipts_pos = 0i64;
    let mut to_device_pos = 0i64;
    let mut typing_pos = 0i64;
    let mut presence_pos = 0i64;
    let mut epoch = None;
    let mut key_summary = None;

    // Parse the events part (everything before the first '_').
    let rest = if let Some(idx) = s_part.find('_') {
        events_pos = s_part[..idx].parse::<i64>().map_err(|_| bad())?;
        &s_part[idx + 1..]
    } else {
        events_pos = s_part.parse::<i64>().map_err(|_| bad())?;
        ""
    };

    for segment in rest.split('_') {
        if segment.is_empty() {
            continue;
        }
        if let Some(v) = segment.strip_prefix('d') {
            device_pos = v.parse::<i64>().map_err(|_| bad())?;
        } else if let Some(v) = segment.strip_prefix('a') {
            account_data_pos = v.parse::<i64>().map_err(|_| bad())?;
        } else if let Some(v) = segment.strip_prefix('r') {
            receipts_pos = v.parse::<i64>().map_err(|_| bad())?;
        } else if let Some(v) = segment.strip_prefix('t') {
            to_device_pos = v.parse::<i64>().map_err(|_| bad())?;
        } else if let Some(v) = segment.strip_prefix('y') {
            typing_pos = v.parse::<i64>().map_err(|_| bad())?;
        } else if let Some(v) = segment.strip_prefix('p') {
            presence_pos = v.parse::<i64>().map_err(|_| bad())?;
        } else if let Some(v) = segment.strip_prefix('e') {
            epoch = Some(v.parse::<u64>().map_err(|_| bad())?);
        } else if let Some(v) = segment.strip_prefix('k') {
            if !v.is_empty() && (v.len() != 64 || !v.bytes().all(|byte| byte.is_ascii_hexdigit())) {
                return Err(bad());
            }
            if !v.is_empty() {
                key_summary = Some(v.to_owned());
            }
        }
        // Unknown segments are ignored for forward-compat.
    }

    if [
        events_pos,
        device_pos,
        account_data_pos,
        receipts_pos,
        to_device_pos,
        typing_pos,
        presence_pos,
    ]
    .iter()
    .any(|position| *position < 0)
    {
        return Err(bad());
    }
    Ok(SyncToken {
        events_pos,
        device_pos,
        account_data_pos,
        receipts_pos,
        to_device_pos,
        typing_pos,
        presence_pos,
        ephemeral_epoch: epoch,
        key_summary,
    })
}

fn ephemeral_epoch() -> u64 {
    static EPOCH: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(rand::random)
}

struct SyncResponse {
    has_key_changes: bool,
    body: Value,
    next_expiry: Option<std::time::Instant>,
    /// Member events sent under lazy loading, `(room, member, event_id)`,
    /// recorded only once this response is actually returned.
    lazy_sent: Vec<(String, String, String)>,
    events_pos: i64,
}

fn has_updates(body: &Value) -> bool {
    for field in ["to_device", "presence", "account_data"] {
        if body[field]["events"]
            .as_array()
            .is_some_and(|events| !events.is_empty())
        {
            return true;
        }
    }
    for field in ["changed", "left"] {
        if body["device_lists"][field]
            .as_array()
            .is_some_and(|users| !users.is_empty())
        {
            return true;
        }
    }
    for field in ["invite", "leave", "knock"] {
        if body["rooms"][field]
            .as_object()
            .is_some_and(|rooms| !rooms.is_empty())
        {
            return true;
        }
    }
    if let Some(rooms) = body["rooms"]["join"].as_object() {
        for room in rooms.values() {
            for field in ["timeline", "state", "ephemeral", "account_data"] {
                if room[field]["events"]
                    .as_array()
                    .is_some_and(|events| !events.is_empty())
                {
                    return true;
                }
            }
        }
    }
    false
}

fn encode_token(pos: i64) -> String {
    format!("s{pos}")
}

// ---------------------------------------------------------------------------
// Filter parsing (il0.16 — best-effort)
// ---------------------------------------------------------------------------

struct SyncFilter {
    definition: conduit::filter::Filter,
    timeline_limit: i64,
    /// `m.ignored_user_list` of the syncing user (conduit-y99.19).
    ignored: std::collections::HashSet<String>,
    /// Forgotten rooms: room → the departure event that was forgotten.
    forgotten: HashMap<String, String>,
}

impl SyncFilter {
    fn parse(value: Value) -> Result<Self, Response> {
        let definition: conduit::filter::Filter = serde_json::from_value(value)
            .map_err(|error| MatrixError::bad_json(error.to_string()).into_response())?;
        let timeline_limit = definition.room.timeline.events.limit.unwrap_or(10).min(500) as i64;
        Ok(Self {
            definition,
            timeline_limit,
            ignored: Default::default(),
            forgotten: Default::default(),
        })
    }
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SyncQuery {
    pub since: Option<String>,
    /// Long-poll timeout in milliseconds. 0 = no wait (default).
    pub timeout: Option<u64>,
    pub filter: Option<String>,
    #[serde(default)]
    pub full_state: bool,
    #[serde(default)]
    pub include_leave: bool,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TimelineBlock {
    events: Vec<Value>,
    limited: bool,
    prev_batch: String,
}

#[derive(Serialize)]
struct StateBlock {
    events: Vec<Value>,
}

#[derive(Serialize)]
struct EphemeralBlock {
    events: Vec<Value>,
}

#[derive(Serialize)]
struct AccountDataBlock {
    events: Vec<Value>,
}

#[derive(Serialize)]
struct UnreadNotifications {
    highlight_count: u64,
    notification_count: u64,
}

#[derive(Serialize)]
struct JoinedRoomBlock {
    timeline: TimelineBlock,
    state: StateBlock,
    account_data: AccountDataBlock,
    ephemeral: EphemeralBlock,
    unread_notifications: UnreadNotifications,
    #[serde(skip_serializing_if = "Option::is_none")]
    unread_thread_notifications: Option<serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<Value>,
    /// Hero members whose membership lazy loading must include.
    #[serde(skip)]
    heroes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub async fn sync<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(query): Query<SyncQuery>,
) -> Response {
    let user_id = &authed.user_id;
    let value = match query.filter.as_deref() {
        None => json!({}),
        Some(raw) if raw.starts_with('{') => match serde_json::from_str::<Value>(raw) {
            Ok(value) => value,
            Err(error) => return MatrixError::bad_json(error.to_string()).into_response(),
        },
        Some(id) => match state.storage().get_filter(user_id, id).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"errcode": "M_INVALID_PARAM", "error": "unknown filter ID"})),
                )
                    .into_response()
            }
            Err(error) => return MatrixError::unknown(error.to_string()).into_response(),
        },
    };
    let mut filter = match SyncFilter::parse(value) {
        Ok(filter) => filter,
        Err(error) => return error,
    };
    match super::room_content::serve::ignored_users(state.storage().as_ref(), user_id).await {
        Ok(ignored) => filter.ignored = ignored,
        Err(error) => return MatrixError::unknown(error.to_string()).into_response(),
    }
    match state.storage().forgotten_rooms(user_id).await {
        Ok(forgotten) => filter.forgotten = forgotten,
        Err(error) => return MatrixError::unknown(error.to_string()).into_response(),
    }

    // Parse `since` token.
    let since_token: Option<SyncToken> = match &query.since {
        None => None,
        Some(raw) => match parse_since(raw) {
            Ok(tok) => Some(tok),
            Err(resp) => return resp,
        },
    };

    // Clamp timeout: 0–30000 ms.
    let timeout_ms = query.timeout.unwrap_or(0).min(30_000);
    // A client without a since token (or asking for full state) has no
    // remembered membership: nothing it was sent before is redundant.
    if since_token.is_none() || query.full_state {
        super::room_summary::forget_device(user_id, &authed.device_id);
    }

    // Subscribe and enable the notification before observing any streams.
    // A wakeup is a hint to rebuild the response, never a fake room position.
    let notify = state.sync_notify();
    let mut events = state.events_tx().subscribe();
    let mut typing = state.typing_store().subscribe();
    let mut presence = state.presence_store().subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let response = match build_sync_response(
            &state,
            user_id,
            &authed.device_id,
            since_token.as_ref(),
            &filter,
            query.full_state,
            query.include_leave || filter.definition.room.include_leave,
        )
        .await
        {
            Ok(response) => response,
            Err(error) => return error,
        };
        if since_token.is_none()
            || query.full_state
            || timeout_ms == 0
            || has_updates(&response.body)
            || response.has_key_changes
            || tokio::time::Instant::now() >= deadline
        {
            super::room_summary::record_sent(user_id, &authed.device_id, response.lazy_sent, response.events_pos);
            return (StatusCode::OK, Json(response.body)).into_response();
        }
        let expiry = response
            .next_expiry
            .map(tokio::time::Instant::from_std)
            .unwrap_or(deadline)
            .min(deadline);
        tokio::select! {
            _ = &mut notified => {},
            result = events.recv() => {
                if matches!(result, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                    super::room_summary::record_sent(user_id, &authed.device_id, response.lazy_sent, response.events_pos);
                    return (StatusCode::OK, Json(response.body)).into_response();
                }
            },
            _ = typing.changed() => {},
            _ = presence.changed() => {},
            _ = tokio::time::sleep_until(expiry) => {},
            // Other processes may commit durable streams without an in-process
            // wakeup. Poll until PostgreSQL notification wiring replaces this.
            _ = tokio::time::sleep(Duration::from_millis(250)) => {},
        }
    }
}

async fn build_sync_response<S: AuthState>(
    state: &S,
    user_id: &str,
    authed_device_id: &str,
    since_token: Option<&SyncToken>,
    filter: &SyncFilter,
    full_state: bool,
    include_leave: bool,
) -> Result<SyncResponse, Response> {
    let storage = state.storage();

    let since = since_token.as_ref().map(|t| t.events_pos).unwrap_or(0);
    let device_since = since_token.as_ref().map(|t| t.device_pos).unwrap_or(0);
    let account_data_since = since_token
        .as_ref()
        .map(|t| t.account_data_pos)
        .unwrap_or(0);
    let receipts_since = since_token.as_ref().map(|t| t.receipts_pos).unwrap_or(0);
    let to_device_since = since_token.as_ref().map(|t| t.to_device_pos).unwrap_or(0);

    // --- Global account data (1mo.8) ---
    // Must be computed before the room loop so per-room data is available.
    let acct_data_changes = match storage
        .account_data_since(user_id, account_data_since)
        .await
    {
        Ok(v) => v,
        Err(error) => return Err(MatrixError::unknown(error.to_string()).into_response()),
    };
    let mut next_account_data_pos = account_data_since;
    let mut quotas: HashMap<Option<String>, usize> = HashMap::new();
    let mut included = Vec::new();
    for change in acct_data_changes {
        let (room, kind, content, position) = &change;
        let event = json!({"type": kind, "content": content});
        let (matches, limit) = match room {
            None => (
                filter.definition.account_data.matches(&event),
                filter.definition.account_data.limit,
            ),
            Some(room) => (
                filter.definition.room.allows(room)
                    && filter.definition.room.account_data.matches(room, &event),
                filter.definition.room.account_data.events.limit,
            ),
        };
        let used = quotas.entry(room.clone()).or_default();
        if matches && limit.is_some_and(|limit| *used >= limit.min(5000)) {
            break;
        }
        next_account_data_pos = *position;
        if matches {
            *used += 1;
            included.push(change);
        }
    }
    let acct_data_changes = included;

    let mut global_account_data_events: Vec<Value> = acct_data_changes
        .iter()
        .filter(|(room_id, _, _, _)| room_id.is_none())
        .map(|(_, event_type, content, _)| json!({ "type": event_type, "content": content }))
        .collect();

    // Per-room account data: group by room_id.
    let mut per_room_account_data: HashMap<String, Vec<Value>> = HashMap::new();
    for (room_id_opt, event_type, content, _) in &acct_data_changes {
        if let Some(rid) = room_id_opt {
            per_room_account_data
                .entry(rid.clone())
                .or_default()
                .push(json!({ "type": event_type, "content": content }));
        }
    }

    // --- Receipts EDU (1mo.8) ---
    let receipt_changes = match storage.threaded_receipts_since(receipts_since).await {
        Ok(v) => v,
        Err(error) => return Err(MatrixError::unknown(error.to_string()).into_response()),
    };

    // Collect all new events since `since` (large limit for correctness; v0).
    let new_events = match storage.events_since(since, i64::MAX).await {
        Ok(evs) => evs,
        Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
    };

    let epoch_matches =
        since_token.is_some_and(|token| token.ephemeral_epoch == Some(ephemeral_epoch()));
    let typing_since = since_token
        .filter(|_| epoch_matches)
        .map(|token| token.typing_pos);
    let presence_since = since_token
        .filter(|_| epoch_matches)
        .map(|token| token.presence_pos);
    let (mut next_typing_pos, typing_changes, typing_expiry) =
        state.typing_store().snapshot(typing_since).await;
    let (mut next_presence_pos, presence_changes, presence_expiry) =
        state.presence_store().snapshot(presence_since).await;
    let next_expiry = typing_expiry.into_iter().chain(presence_expiry).min();
    let room_index = super::device_lists::JoinedRoomIndex::load(storage.as_ref(), user_id)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;

    // Group receipts by room as a stream-ordered prefix: each room's
    // ephemeral limit counts its typing event and one m.receipt event per
    // thread scope. A receipt that would exceed a room's limit stops the
    // batch there, and the cursor stays before it so it arrives next time.
    let ephemeral_rule = &filter.definition.room.ephemeral;
    let ephemeral_limit = ephemeral_rule.events.limit.map(|limit| limit.min(5000));
    let mut next_receipts_pos = receipts_since;
    let mut receipts_by_room: HashMap<String, Vec<conduit::storage::ReceiptRecord>> = HashMap::new();
    let mut receipt_scopes: HashMap<String, std::collections::HashSet<Option<String>>> = HashMap::new();
    for receipt in receipt_changes {
        let room = receipt.room_id.clone();
        // Private read receipts must never be shown to another user.
        let visible = !(receipt.receipt_type == "m.read.private" && receipt.user_id != user_id)
            && room_index.rooms.contains_key(&room)
            && filter.definition.room.allows(&room)
            && ephemeral_rule.matches(&room, &json!({"type": "m.receipt", "room_id": room}));
        if visible {
            let scopes = receipt_scopes.entry(room.clone()).or_default();
            if !scopes.contains(&receipt.thread_id) {
                let typing_slot = usize::from(
                    (typing_changes.contains_key(&room) || !epoch_matches)
                        && ephemeral_rule.matches(&room, &json!({"type": "m.typing"})),
                );
                if ephemeral_limit.is_some_and(|limit| scopes.len() + typing_slot >= limit) {
                    break;
                }
                scopes.insert(receipt.thread_id.clone());
            }
            next_receipts_pos = receipt.stream_pos;
            receipts_by_room.entry(room).or_default().push(receipt);
        } else {
            next_receipts_pos = receipt.stream_pos;
        }
    }
    let memberships = storage
        .current_memberships(user_id)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    let joined: Vec<_> = memberships
        .iter()
        .filter(|event| event.content["membership"] == "join")
        .map(|event| event.room_id.clone())
        .collect();
    let member_ids: Vec<_> = memberships
        .iter()
        .map(|event| event.event_id.clone())
        .collect();
    let member_positions = storage
        .event_stream_positions(&member_ids)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    // Invite blocking (v1.18): pending invites MUST NOT be served.
    let invites_blocked =
        super::room_membership::blocks_invites(storage.as_ref(), user_id).await;
    let mut invited_rooms = HashMap::new();
    let mut knocked_rooms = HashMap::new();
    let mut left_rooms = HashMap::new();
    for membership in &memberships {
        if !filter.definition.room.allows(&membership.room_id) {
            continue;
        }
        let position = *member_positions.get(&membership.event_id).unwrap_or(&0);
        let changed = since_token.is_none() || position > since;
        // Forgotten departures and invites from ignored users stay hidden.
        if filter.forgotten.get(&membership.room_id) == Some(&membership.event_id)
            || (membership.content["membership"] == "invite"
                && (invites_blocked || filter.ignored.contains(&membership.sender)))
        {
            continue;
        }
        match membership.content["membership"].as_str() {
            Some("invite" | "knock") if changed => {
                let preview =
                    stripped_membership_preview(storage.as_ref(), membership, user_id).await?;
                let key = if membership.content["membership"] == "invite" {
                    "invite_state"
                } else {
                    "knock_state"
                };
                let mut block = serde_json::Map::new();
                block.insert(key.into(), json!({"events": preview}));
                if key == "invite_state" {
                    invited_rooms.insert(membership.room_id.clone(), Value::Object(block));
                } else {
                    knocked_rooms.insert(membership.room_id.clone(), Value::Object(block));
                }
            }
            Some("leave" | "ban")
                if (since_token.is_some() && position > since)
                    || (since_token.is_none() && include_leave) =>
            {
                let mut block = departed_room_block(
                    storage.as_ref(),
                    user_id,
                    membership,
                    position,
                    since,
                    filter,
                )
                .await?;
                decorate_block(storage.as_ref(), user_id, filter, &mut block).await?;
                filter_room_block(&mut block, filter, &membership.room_id, user_id);
                project_room_block(&mut block, filter);
                left_rooms.insert(membership.room_id.clone(), block);
            }
            _ => {}
        }
    }
    let mut changed_rooms: std::collections::HashSet<_> = new_events
        .iter()
        .map(|event| event.room_id.clone())
        .collect();
    changed_rooms.extend(receipts_by_room.keys().cloned());
    changed_rooms.extend(per_room_account_data.keys().cloned());
    changed_rooms.extend(typing_changes.keys().cloned());
    let all_rooms_to_check: Vec<_> = joined
        .iter()
        .filter(|room| {
            since_token.is_none() || full_state || !epoch_matches || changed_rooms.contains(*room)
        })
        .cloned()
        .collect();

    let rooms_to_check: Vec<_> = all_rooms_to_check
        .into_iter()
        .filter(|room| filter.definition.room.allows(room))
        .collect();

    // For each room, check if user is currently joined.
    let mut joined_rooms: HashMap<String, JoinedRoomBlock> = HashMap::new();

    // Advance to observed event rows, never a later MAX read that could skip
    // an event committed after we collected this batch.
    let ids: Vec<_> = new_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect();
    let positions = storage
        .event_stream_positions(&ids)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    let next_events_pos = positions.values().copied().max().unwrap_or(since);

    // Push rules and display name for unread counts (once per response).
    let push_rules = super::notification_counts::effective_push_rules(storage.as_ref(), user_id)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    let displayname = storage
        .get_account(user_id)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?
        .and_then(|account| account.displayname);
    let thread_counts = filter.definition.room.timeline.unread_thread_notifications;
    let lazy = filter.definition.room.state.lazy_load_members;
    let drop_redundant = lazy
        && !filter.definition.room.state.include_redundant_members
        && since_token.is_some()
        && !full_state;
    let mut lazy_sent = Vec::new();

    for room_id in &rooms_to_check {
        // Check current membership.
        let member_ev = match storage
            .get_state_entry(room_id, "m.room.member", user_id)
            .await
        {
            Ok(ev) => ev,
            Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
        };

        let is_joined = member_ev
            .as_ref()
            .and_then(|ev| parse_member(&ev.content).ok())
            .map(|mc| mc.membership == Membership::Join)
            .unwrap_or(false);

        if !is_joined {
            continue;
        }

        let prior_members = storage
            .member_events_for_user(room_id, user_id)
            .await
            .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
        let was_joined = prior_members
            .iter()
            .filter(|(position, _)| *position <= since)
            .max_by_key(|(position, _)| *position)
            .is_some_and(|(_, event)| event.content["membership"] == "join");
        let block = if since_token.is_none() || !was_joined {
            // Initial sync: state = current state, timeline = recent events.
            match build_initial_room_block(state, user_id, room_id, filter).await {
                Ok(b) => b,
                Err(resp) => return Err(resp),
            }
        } else {
            // Incremental: state = empty, timeline = new events since `since`.
            match build_incremental_room_block(
                state,
                user_id,
                room_id,
                &new_events,
                since,
                filter,
                full_state,
            )
            .await
            {
                Ok(b) => b,
                Err(resp) => return Err(resp),
            }
        };

        // Inject per-room account data.
        let mut block = block;
        if let Some(ad_events) = per_room_account_data.get(room_id) {
            block.account_data.events.extend(ad_events.iter().cloned());
        }

        // Inject ephemeral EDUs: typing + receipts.
        // Typing (m.typing):
        if let Some(typers) = typing_changes.get(room_id) {
            // A typer who has since left is no longer typing here.
            let members = room_index.rooms.get(room_id).map(|room| &room.members);
            let typers: Vec<_> = typers
                .iter()
                .filter(|typer| members.is_some_and(|members| members.contains(*typer)))
                .collect();
            block.ephemeral.events.push(json!({
                "type": "m.typing", "content": { "user_ids": typers }
            }));
        } else if !epoch_matches {
            block
                .ephemeral
                .events
                .push(json!({"type": "m.typing", "content": {"user_ids": []}}));
        }

        // Receipts (m.receipt), batched into one event per thread scope so
        // a user's unthreaded and threaded receipts never collide.
        if let Some(room_receipts) = receipts_by_room.get(room_id) {
            block.ephemeral.events.extend(receipt_events(room_id, room_receipts));
        }

        // Room summary (heroes feed lazy loading) and unread counts.
        let (summary, heroes) = super::room_summary::summary(storage.as_ref(), room_id, user_id)
            .await
            .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
        block.summary = Some(summary);
        block.heroes = heroes;
        let counts = super::notification_counts::room_counts(
            storage.as_ref(),
            user_id,
            room_id,
            &push_rules,
            displayname.as_deref(),
        )
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
        let unread = if thread_counts {
            block.unread_thread_notifications = Some(
                counts
                    .threads
                    .iter()
                    .map(|(root, counts)| (root.clone(), counts.to_json()))
                    .collect(),
            );
            counts.main
        } else {
            counts.total()
        };
        block.unread_notifications = UnreadNotifications {
            highlight_count: unread.highlight_count,
            notification_count: unread.notification_count,
        };

        decorate_block(state.storage().as_ref(), user_id, filter, &mut block).await?;
        add_lazy_members(
            state.storage().as_ref(),
            &mut block,
            filter,
            room_id,
            user_id,
        )
        .await?;
        let (held_receipts, held_typing) = filter_room_block(&mut block, filter, room_id, user_id);
        if held_receipts {
            next_receipts_pos = receipts_since;
        }
        if held_typing {
            next_typing_pos = typing_since.unwrap_or(0);
        }
        if lazy {
            // Skip member events this device already holds, unless the
            // filter asks for redundant members; remember what is sent.
            if drop_redundant {
                block.state.events.retain(|event| {
                    !(event["type"] == "m.room.member"
                        && super::room_summary::already_sent(
                            user_id,
                            authed_device_id,
                            room_id,
                            event["state_key"].as_str().unwrap_or_default(),
                            event["event_id"].as_str().unwrap_or_default(),
                            since,
                        ))
                });
            }
            for event in block.state.events.iter().chain(block.timeline.events.iter()) {
                if event["type"] == "m.room.member" {
                    if let (Some(member), Some(id)) = (event["state_key"].as_str(), event["event_id"].as_str()) {
                        lazy_sent.push((room_id.clone(), member.to_owned(), id.to_owned()));
                    }
                }
            }
        }
        project_room_block(&mut block, filter);
        joined_rooms.insert(room_id.clone(), block);
    }

    // Capture the device-list boundary before fetching its changes.
    let next_device_pos = storage
        .device_list_max_position()
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;

    // --- Presence EDU (1mo.8) ---
    // Presence is visible to the user and users sharing a joined room.
    let mut visible_users = room_index.peers();
    visible_users.insert(user_id.to_owned());
    let mut selected_presence = Vec::new();
    for (uid, entry) in presence_changes {
        let event = json!({"type": "m.presence", "sender": uid});
        if !visible_users.contains(&uid) || !filter.definition.presence.matches(&event) {
            continue;
        }
        if filter
            .definition
            .presence
            .limit
            .is_some_and(|limit| selected_presence.len() >= limit.min(5000))
        {
            next_presence_pos = entry.stream_position.saturating_sub(1);
            break;
        }
        selected_presence.push((uid, entry));
    }
    let all_presence = selected_presence.into_iter();
    let mut presence_events: Vec<Value> = all_presence
        .into_iter()
        .map(|(uid, entry)| {
            let last_active_ago = entry.last_changed_at.elapsed().as_millis() as u64;
            let effective = entry.effective_presence().to_owned();
            let mut ev = json!({
                "type": "m.presence",
                "sender": uid,
                "content": {
                    "presence": effective,
                    "last_active_ago": last_active_ago,
                    "currently_active": effective == "online",
                }
            });
            if let Some(msg) = &entry.status_msg {
                ev["content"]["status_msg"] = json!(msg);
            }
            if let Some(name) = &entry.displayname {
                ev["content"]["displayname"] = json!(name);
            }
            if let Some(url) = &entry.avatar_url {
                ev["content"]["avatar_url"] = json!(url);
            }
            ev
        })
        .collect();

    // --- To-device messages (mrm.7) ---
    // Only the since token acknowledges a previously delivered batch. Keep
    // newly returned messages so an interrupted response can be retried.
    if to_device_since > 0 {
        if let Err(error) = storage
            .delete_to_device_before(user_id, authed_device_id, to_device_since)
            .await
        {
            return Err(MatrixError::unknown(error.to_string()).into_response());
        }
    }
    let to_device_events = match storage
        .drain_to_device(user_id, authed_device_id, to_device_since, 100)
        .await
    {
        Ok(msgs) => msgs,
        Err(error) => return Err(MatrixError::unknown(error.to_string()).into_response()),
    };

    let next_to_device_pos = to_device_events
        .iter()
        .map(|m| m.id)
        .max()
        .unwrap_or(to_device_since);

    let to_device_json: Vec<Value> = to_device_events
        .iter()
        .map(|m| {
            json!({
                "type": m.event_type,
                "sender": m.sender,
                "content": m.content,
            })
        })
        .collect();

    // --- Device list changes (mrm.12, conduit-y99.14) ---
    // Only users sharing a room (or the user themself) are
    // reported, and only on incremental sync.
    let device_lists = if since_token.is_some() {
        let key_updates = storage
            .device_list_changes_between(device_since, next_device_pos)
            .await
            .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
        let window: Vec<_> = new_events
            .iter()
            .filter(|event| matches!(event.event_type.as_str(), "m.room.member" | "m.room.encryption"))
            .cloned()
            .collect();
        let (changed, left) = super::device_lists::device_list_delta(
            storage.as_ref(),
            user_id,
            &room_index,
            &key_updates,
            &window,
        )
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
        Some(json!({"changed": changed, "left": left}))
    } else {
        None
    };

    // --- OTK counts and fallback usage, observed in one snapshot ---
    let (otk_counts, unused_fallback_key_types) = storage
        .device_key_inventory(user_id, authed_device_id)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    let otk_counts_json: serde_json::Map<String, Value> =
        otk_counts.into_iter().map(|(k, v)| (k, json!(v))).collect();
    let key_summary = hex::encode(Sha256::digest(
        conduit::canonical_json::to_canonical_bytes(&json!({
            "counts": otk_counts_json, "fallback": unused_fallback_key_types
        }))
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?,
    ));
    let has_key_changes =
        since_token.is_some_and(|token| token.key_summary.as_deref() != Some(&key_summary));
    let next_batch = SyncToken {
        events_pos: next_events_pos,
        device_pos: next_device_pos,
        account_data_pos: next_account_data_pos,
        receipts_pos: next_receipts_pos,
        to_device_pos: next_to_device_pos,
        typing_pos: next_typing_pos,
        presence_pos: next_presence_pos,
        ephemeral_epoch: Some(ephemeral_epoch()),
        key_summary: Some(key_summary),
    }
    .encode();

    apply_value_filter(
        &mut global_account_data_events,
        &filter.definition.account_data,
    );
    apply_value_filter(&mut presence_events, &filter.definition.presence);
    for events in [&mut global_account_data_events, &mut presence_events] {
        for event in events {
            *event = filter.definition.project(std::mem::take(event));
        }
    }
    let rooms_obj = json!({
        "join": joined_rooms,
        "invite": invited_rooms,
        "leave": left_rooms,
        "knock": knocked_rooms
    });

    let mut body = json!({
        "next_batch": next_batch,
        "rooms": rooms_obj,
        "presence":     { "events": presence_events },
        "account_data": { "events": global_account_data_events },
        "to_device":    { "events": to_device_json },
        "device_one_time_keys_count": otk_counts_json,
        "device_unused_fallback_key_types": unused_fallback_key_types,
    });
    if let Some(device_lists) = device_lists {
        body["device_lists"] = device_lists;
    }
    Ok(SyncResponse {
        has_key_changes,
        next_expiry,
        body,
        lazy_sent,
        events_pos: next_events_pos,
    })
}

/// `m.receipt` events for one room: one per thread scope (unthreaded first),
/// each receipt carrying its `thread_id` when threaded.
fn receipt_events(room_id: &str, receipts: &[conduit::storage::ReceiptRecord]) -> Vec<Value> {
    let mut scopes: std::collections::BTreeMap<Option<&str>, serde_json::Map<String, Value>> =
        std::collections::BTreeMap::new();
    for receipt in receipts {
        let content = scopes.entry(receipt.thread_id.as_deref()).or_default();
        let entry = content.entry(receipt.event_id.clone()).or_insert_with(|| json!({}));
        if entry.get(&receipt.receipt_type).is_none() {
            entry[&receipt.receipt_type] = json!({});
        }
        let mut body = json!({"ts": receipt.ts});
        if let Some(thread) = &receipt.thread_id {
            body["thread_id"] = json!(thread);
        }
        entry[&receipt.receipt_type][&receipt.user_id] = body;
    }
    scopes
        .into_values()
        .map(|content| json!({"type": "m.receipt", "room_id": room_id, "content": content}))
        .collect()
}

async fn stripped_membership_preview(
    storage: &dyn conduit::storage::Storage,
    membership: &conduit::event::Event,
    user: &str,
) -> Result<Vec<Value>, Response> {
    let events = storage
        .get_current_state(&membership.room_id)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    let mut preview = Vec::new();
    for event in events {
        let safe = matches!(
            event.event_type.as_str(),
            "m.room.create"
                | "m.room.name"
                | "m.room.topic"
                | "m.room.avatar"
                | "m.room.canonical_alias"
                | "m.room.join_rules"
                | "m.room.encryption"
        ) || (event.event_type == "m.room.member"
            && event
                .state_key
                .as_deref()
                .is_some_and(|target| target == user || target == membership.sender));
        if safe {
            preview.push(json!({"type": event.event_type, "state_key": event.state_key, "sender": event.sender, "content": event.content}));
        }
    }
    Ok(preview)
}

async fn departed_room_block(
    storage: &dyn conduit::storage::Storage,
    user: &str,
    membership: &conduit::event::Event,
    departure: i64,
    since: i64,
    filter: &SyncFilter,
) -> Result<JoinedRoomBlock, Response> {
    let raw = storage
        .room_events(&membership.room_id)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    let ids: Vec<_> = raw.iter().map(|event| event.event_id.clone()).collect();
    let positions = storage
        .event_stream_positions(&ids)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    let raw = raw
        .into_iter()
        .filter(|event| {
            positions
                .get(&event.event_id)
                .is_some_and(|position| *position > since && *position <= departure)
        })
        .collect();
    let mut visible =
        conduit::auth::filter_visible_for_user(storage, &membership.room_id, user, raw)
            .await
            .map_err(|error| MatrixError::from_conduit(error).into_response())?;
    // A user always needs their own departure, even where joined-history
    // visibility stops at the instant that membership changes to leave/ban.
    if !visible
        .iter()
        .any(|event| event.event_id == membership.event_id)
    {
        visible.push(membership.clone());
    }
    visible.sort_by_key(|event| positions.get(&event.event_id).copied().unwrap_or(0));
    let mut events = apply_type_filter(visible, filter);
    let limited = events.len() > filter.timeline_limit as usize;
    if limited {
        events = events.split_off(events.len() - filter.timeline_limit as usize);
    }
    let first = events
        .first()
        .and_then(|event| positions.get(&event.event_id))
        .copied()
        .unwrap_or(departure);
    let before = state_before(storage, &membership.room_id, first).await?;
    let previous = state_before(storage, &membership.room_id, since.saturating_add(1)).await?;
    let state = before
        .into_iter()
        .filter(|(key, event)| {
            previous
                .get(key)
                .is_none_or(|old| old.event_id != event.event_id)
        })
        .map(|(_, event)| serde_json::to_value(event).expect("state JSON"))
        .collect();
    Ok(JoinedRoomBlock {
        timeline: TimelineBlock {
            events: events
                .iter()
                .map(|event| serde_json::to_value(event).expect("event JSON"))
                .collect(),
            limited,
            prev_batch: encode_token(first.saturating_sub(1)),
        },
        state: StateBlock { events: state },
        account_data: AccountDataBlock { events: vec![] },
        ephemeral: EphemeralBlock { events: vec![] },
        unread_notifications: UnreadNotifications {
            notification_count: 0,
            highlight_count: 0,
        },
        unread_thread_notifications: None,
        summary: None,
        heroes: Vec::new(),
    })
}

/// Build a room block for initial sync.
async fn build_initial_room_block<S: AuthState>(
    state: &S,
    user_id: &str,
    room_id: &str,
    filter: &SyncFilter,
) -> Result<JoinedRoomBlock, Response> {
    let storage = state.storage();

    let latest_pos = storage
        .room_latest_stream_position(room_id)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?
        .unwrap_or(0);
    let (mut events, _) = storage
        .room_events_paginated(room_id, 'b', latest_pos, i64::MAX)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    events.reverse();
    let mut events = apply_type_filter(events, filter);
    events = conduit::auth::filter_visible_for_user(storage.as_ref(), room_id, user_id, events)
        .await
        .map_err(|error| MatrixError::from_conduit(error).into_response())?;
    let limited = events.len() > filter.timeline_limit as usize;
    if limited {
        events = events.split_off(events.len() - filter.timeline_limit as usize);
    }
    let ids: Vec<_> = events.iter().map(|event| event.event_id.clone()).collect();
    let positions = storage
        .event_stream_positions(&ids)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    let first = events
        .first()
        .and_then(|event| positions.get(&event.event_id))
        .copied()
        .unwrap_or(latest_pos.saturating_add(1));
    let state_events = state_before(storage.as_ref(), room_id, first).await?;
    Ok(JoinedRoomBlock {
        timeline: TimelineBlock {
            events: events
                .iter()
                .map(|event| serde_json::to_value(event).expect("event JSON"))
                .collect(),
            limited,
            prev_batch: encode_token(first.saturating_sub(1)),
        },
        state: StateBlock {
            events: state_events
                .into_values()
                .map(|event| serde_json::to_value(event).expect("state JSON"))
                .collect(),
        },
        account_data: AccountDataBlock { events: vec![] },
        ephemeral: EphemeralBlock { events: vec![] },
        unread_notifications: UnreadNotifications {
            highlight_count: 0,
            notification_count: 0,
        },
        unread_thread_notifications: None,
        summary: None,
        heroes: Vec::new(),
    })
}

async fn state_before(
    storage: &dyn conduit::storage::Storage,
    room_id: &str,
    before: i64,
) -> Result<HashMap<(String, String), conduit::event::Event>, Response> {
    let events = storage
        .room_events(room_id)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    let ids: Vec<_> = events.iter().map(|event| event.event_id.clone()).collect();
    let positions = storage
        .event_stream_positions(&ids)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    let mut events: Vec<_> = events
        .into_iter()
        .filter_map(|event| {
            positions
                .get(&event.event_id)
                .copied()
                .map(|position| (position, event))
        })
        .filter(|(position, _)| *position < before)
        .collect();
    events.sort_by_key(|(position, _)| *position);
    let mut state = HashMap::new();
    for (_, event) in events {
        if let Some(key) = &event.state_key {
            state.insert((event.event_type.clone(), key.clone()), event);
        }
    }
    Ok(state)
}

/// Build a room block for incremental sync from pre-fetched new events.
async fn build_incremental_room_block<S: AuthState>(
    state: &S,
    user_id: &str,
    room_id: &str,
    new_events: &[conduit::event::Event],
    since: i64,
    filter: &SyncFilter,
    full_state: bool,
) -> Result<JoinedRoomBlock, Response> {
    let mut room_events: Vec<conduit::event::Event> = new_events
        .iter()
        .filter(|e| e.room_id == room_id)
        .cloned()
        .collect();

    // Apply type filter.
    room_events = apply_type_filter(room_events, filter);

    // …then history visibility, the same predicate the initial block
    // and /messages use.
    room_events = conduit::auth::filter_visible_for_user(
        state.storage().as_ref(),
        room_id,
        user_id,
        room_events,
    )
    .await
    .map_err(|e| MatrixError::from_conduit(e).into_response())?;

    // Cap to timeline_limit (take most-recent).
    let limited = room_events.len() > filter.timeline_limit as usize;
    if limited {
        let start = room_events.len() - filter.timeline_limit as usize;
        room_events = room_events[start..].to_vec();
    }

    let ids: Vec<_> = room_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect();
    let positions = state
        .storage()
        .event_stream_positions(&ids)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    let fallback = state
        .storage()
        .room_latest_stream_position(room_id)
        .await
        .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?
        .unwrap_or(since)
        .saturating_add(1);
    let first = room_events
        .first()
        .and_then(|event| positions.get(&event.event_id))
        .copied()
        .unwrap_or(fallback);
    let previous_state =
        state_before(state.storage().as_ref(), room_id, since.saturating_add(1)).await?;
    let before_timeline = state_before(state.storage().as_ref(), room_id, first).await?;
    let state_values = before_timeline
        .into_iter()
        .filter(|(key, event)| {
            full_state
                || previous_state
                    .get(key)
                    .is_none_or(|old| old.event_id != event.event_id)
        })
        .map(|(_, event)| serde_json::to_value(event).expect("state JSON"))
        .collect();
    let prev_batch = encode_token(first.saturating_sub(1));

    let timeline_values: Vec<Value> = room_events
        .iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();

    Ok(JoinedRoomBlock {
        timeline: TimelineBlock {
            events: timeline_values,
            limited,
            prev_batch,
        },
        state: StateBlock {
            events: state_values,
        },
        account_data: AccountDataBlock { events: vec![] },
        ephemeral: EphemeralBlock { events: vec![] },
        unread_notifications: UnreadNotifications {
            highlight_count: 0,
            notification_count: 0,
        },
        unread_thread_notifications: None,
        summary: None,
        heroes: Vec::new(),
    })
}

async fn add_lazy_members(
    storage: &dyn conduit::storage::Storage,
    block: &mut JoinedRoomBlock,
    filter: &SyncFilter,
    room: &str,
    user: &str,
) -> Result<(), Response> {
    if !filter.definition.room.state.lazy_load_members {
        return Ok(());
    }
    let mut senders: std::collections::HashSet<_> = block
        .timeline
        .events
        .iter()
        .filter_map(|event| event["sender"].as_str().map(str::to_owned))
        .collect();
    senders.insert(user.to_owned());
    senders.extend(block.heroes.iter().cloned());
    let member_snapshot = if let Some(first) = block
        .timeline
        .events
        .first()
        .and_then(|event| event["event_id"].as_str())
    {
        let positions = storage
            .event_stream_positions(&[first.to_owned()])
            .await
            .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
        state_before(storage, room, *positions.get(first).unwrap_or(&i64::MAX)).await?
    } else {
        state_before(storage, room, i64::MAX).await?
    };
    for member in senders {
        if block
            .state
            .events
            .iter()
            .any(|event| event["type"] == "m.room.member" && event["state_key"] == member)
            || block
                .timeline
                .events
                .iter()
                .any(|event| event["type"] == "m.room.member" && event["state_key"] == member)
        {
            continue;
        }
        if let Some(event) = member_snapshot.get(&("m.room.member".to_owned(), member)) {
            block
                .state
                .events
                .push(serde_json::to_value(event).expect("member JSON"));
        }
    }
    Ok(())
}

/// Serve redactions (`unsigned.redacted_because`) and, for limited
/// timelines, bundled aggregations (conduit-y99.19).
async fn decorate_block(
    storage: &dyn conduit::storage::Storage,
    user_id: &str,
    filter: &SyncFilter,
    block: &mut JoinedRoomBlock,
) -> Result<(), Response> {
    let viewer = super::room_content::serve::Viewer {
        storage,
        user_id,
        ignored: filter.ignored.clone(),
    };
    let limited = block.timeline.limited;
    for (events, bundle) in [(&mut block.timeline.events, limited), (&mut block.state.events, false)] {
        viewer
            .decorate_values(events, bundle)
            .await
            .map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    }
    Ok(())
}

fn apply_type_filter(
    events: Vec<conduit::event::Event>,
    filter: &SyncFilter,
) -> Vec<conduit::event::Event> {
    events
        .into_iter()
        .filter(|event| !super::room_content::serve::hidden_by_ignore(&filter.ignored, event))
        .filter(|event| {
            filter.definition.room.timeline.matches(
                &event.room_id,
                &serde_json::to_value(event).expect("event JSON"),
            )
        })
        .collect()
}

fn apply_value_filter(events: &mut Vec<Value>, rule: &conduit::filter::EventFilter) {
    events.retain(|event| rule.matches(event));
    if let Some(limit) = rule.limit {
        events.truncate(limit.min(5000));
    }
}

fn filter_room_block(
    block: &mut JoinedRoomBlock,
    filter: &SyncFilter,
    room: &str,
    user: &str,
) -> (bool, bool) {
    let timeline_members: std::collections::HashSet<_> = block
        .timeline
        .events
        .iter()
        .filter(|event| event["type"] == "m.room.member")
        .filter_map(|event| event["event_id"].as_str().map(str::to_owned))
        .collect();
    let mut senders: std::collections::HashSet<_> = block
        .timeline
        .events
        .iter()
        .filter_map(|event| event["sender"].as_str().map(str::to_owned))
        .collect();
    senders.insert(user.to_owned());
    senders.extend(block.heroes.iter().cloned());
    let state_rule = &filter.definition.room.state;
    block.state.events.retain(|event| {
        state_rule.matches(room, event)
            && (!state_rule.lazy_load_members
                || event["type"] != "m.room.member"
                || event["state_key"]
                    .as_str()
                    .is_some_and(|member| senders.contains(member)))
            && (state_rule.include_redundant_members
                || event["type"] != "m.room.member"
                || event["event_id"]
                    .as_str()
                    .is_none_or(|id| !timeline_members.contains(id)))
    });
    // Deterministic order: members the client needs (own, timeline senders,
    // heroes) first, then by type and state key, so a state limit trims the
    // least necessary events.
    block.state.events.sort_by_key(|event| {
        let required = event["type"] == "m.room.member"
            && event["state_key"].as_str().is_some_and(|member| senders.contains(member));
        (
            !required,
            event["type"].as_str().unwrap_or_default().to_owned(),
            event["state_key"].as_str().unwrap_or_default().to_owned(),
        )
    });
    if let Some(limit) = state_rule.events.limit {
        block.state.events.truncate(limit.min(5000));
    }
    let mut held = (false, false);
    for (events, rule) in [
        (
            &mut block.ephemeral.events,
            &filter.definition.room.ephemeral,
        ),
        (
            &mut block.account_data.events,
            &filter.definition.room.account_data,
        ),
    ] {
        events.retain(|event| rule.matches(room, event));
        if let Some(limit) = rule.events.limit {
            for event in events.iter().skip(limit.min(5000)) {
                if event["type"] == "m.receipt" {
                    held.0 = true;
                }
                if event["type"] == "m.typing" {
                    held.1 = true;
                }
            }
            events.truncate(limit.min(5000));
        }
    }
    held
}

/// Apply `event_fields` projection, after every filter that reads fields.
fn project_room_block(block: &mut JoinedRoomBlock, filter: &SyncFilter) {
    for events in [
        &mut block.timeline.events,
        &mut block.state.events,
        &mut block.ephemeral.events,
        &mut block.account_data.events,
    ] {
        for event in events {
            *event = filter.definition.project(std::mem::take(event));
        }
    }
}

#[cfg(test)]
mod token_tests {
    use super::parse_since;

    #[test]
    fn legacy_tokens_do_not_acknowledge_the_to_device_queue() {
        for raw in ["s7", "s7_d99", "s7_d99_a3_r4"] {
            let token = parse_since(raw).unwrap_or_else(|_| panic!("legacy token {raw}"));
            assert_eq!(token.events_pos, 7);
            assert_eq!(token.to_device_pos, 0);
        }
    }

    #[test]
    fn to_device_cursor_is_independent_of_device_list_cursor() {
        let token = parse_since("s7_d99_a3_r4_t2").unwrap_or_else(|_| panic!("valid token"));
        assert_eq!(token.device_pos, 99);
        assert_eq!(token.to_device_pos, 2);
        assert!(token.encode().starts_with("s7_d99_a3_r4_t2_y0_p0_e"));
    }

    #[test]
    fn extended_tokens_keep_ephemeral_and_key_cursors_independent() {
        let raw = format!("s7_d99_a3_r4_t2_y5_p6_e8_k{}", "a".repeat(64));
        let token = parse_since(&raw).unwrap_or_else(|_| panic!("extended token"));
        assert_eq!(token.typing_pos, 5);
        assert_eq!(token.presence_pos, 6);
        assert_eq!(token.ephemeral_epoch, Some(8));
        assert_eq!(token.key_summary.as_deref(), Some("a".repeat(64).as_str()));
        assert_eq!(token.encode(), raw);
    }

    #[test]
    fn negative_and_malformed_cursors_are_rejected() {
        for raw in [
            "s-1",
            "s0_d-1",
            "s0_a-1",
            "s0_r-1",
            "s0_t-1",
            "s0_tbad",
            "s0_y-1",
            "s0_p-1",
            "s0_ebad",
            "s0_kbad",
            "s0_t9223372036854775808",
        ] {
            assert!(parse_since(raw).is_err(), "{raw}");
        }
    }
}
