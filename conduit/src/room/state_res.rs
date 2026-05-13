//! State Resolution v2.
//!
//! Implements the Matrix State Resolution v2 algorithm as a pure function.
//! Reference: <https://spec.matrix.org/latest/rooms/v11/#state-resolution>
//!
//! ## Public API
//!
//! ```rust,ignore
//! pub fn resolve(
//!     state_sets: Vec<StateMap<Event>>,
//!     auth_chain: HashMap<String, Event>,
//! ) -> Result<StateMap<Event>, StateResError>
//! ```
//!
//! `state_sets` — each element is a snapshot of the room state at one branch
//! tip, as a map from `(event_type, state_key)` to the `Event` at that key.
//!
//! `auth_chain` — the union of all events reachable via `auth_events` from any
//! event in any state set.  If `auth_chain` is incomplete (an event references
//! an auth-event ID that is not present), `Err(StateResError::MissingAuthEvent)`
//! is returned rather than silently producing wrong results.
//!
//! ## Contract
//!
//! - Pure function: no I/O, no clock access.
//! - Deterministic: identical inputs always produce identical outputs.
//! - Non-panicking on adversarial input: returns `Err` for structural problems.

use std::collections::{HashMap, HashSet};

use thiserror::Error;

use crate::auth::{apply_state_event, auth_event_keys, check_auth, user_power_level, StateMap};
use crate::event::Event;
use crate::state_events::parse_member;
use crate::state_events::Membership;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during state resolution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateResError {
    /// The `auth_chain` map is missing an event that is referenced via
    /// `auth_events` by an event in one of the state sets.
    #[error("missing auth event: {event_id}")]
    MissingAuthEvent { event_id: String },

    /// A cycle was detected in the auth_events graph.
    #[error("cycle detected in auth_events graph involving event: {event_id}")]
    AuthChainCycle { event_id: String },

    /// A state set contained an event with no event_id (should be impossible
    /// with well-formed PDUs, but we guard against it).
    #[error("event with empty event_id encountered")]
    EmptyEventId,
}

// ---------------------------------------------------------------------------
// Step 1 — Split conflicted vs. unconflicted state
// ---------------------------------------------------------------------------

/// Partition a collection of state sets into:
/// - `unconflicted`: keys where all state sets agree (or only one set has the key).
/// - `conflicted`: for each key where sets disagree, the set of distinct events.
///
/// "Agree" means every set that has the key has the same `event_id`.
fn split_conflicted(
    state_sets: &[StateMap<Event>],
) -> (StateMap<Event>, HashMap<(String, String), Vec<Event>>) {
    if state_sets.is_empty() {
        return (HashMap::new(), HashMap::new());
    }

    // Collect every (type, state_key) that appears in any set.
    let all_keys: HashSet<&(String, String)> = state_sets.iter().flat_map(|s| s.keys()).collect();

    let mut unconflicted: StateMap<Event> = HashMap::new();
    let mut conflicted: HashMap<(String, String), Vec<Event>> = HashMap::new();

    for key in all_keys {
        // Collect the (possibly-None) event_id for this key from every set.
        let event_ids: Vec<Option<&str>> = state_sets
            .iter()
            .map(|s| s.get(key).map(|e| e.event_id.as_str()))
            .collect();

        // Determine if all sets agree: all Some(x) with the same x, or all None.
        // A set that doesn't have the key contributes None (absence).
        let first = event_ids[0];
        let all_agree = event_ids.iter().all(|id| *id == first);

        if all_agree {
            // Unconflicted — take the event from whichever set has it (or skip
            // if all are None, which can't happen given we iterated from a key
            // that exists somewhere).
            if let Some(ev) = state_sets.iter().find_map(|s| s.get(key)) {
                unconflicted.insert(key.clone(), ev.clone());
            }
        } else {
            // Conflicted — collect all distinct events (deduplicated by event_id).
            let mut seen_ids: HashSet<&str> = HashSet::new();
            let mut events: Vec<Event> = Vec::new();
            for s in state_sets {
                if let Some(ev) = s.get(key) {
                    if seen_ids.insert(ev.event_id.as_str()) {
                        events.push(ev.clone());
                    }
                }
            }
            conflicted.insert(key.clone(), events);
        }
    }

    (unconflicted, conflicted)
}

// ---------------------------------------------------------------------------
// Step 2 — Auth difference
// ---------------------------------------------------------------------------

/// Compute the "auth difference": events that appear in the auth chain of
/// some state sets but not all — i.e. (union of auth chains) minus
/// (intersection of auth chains).
///
/// Returns the set of event IDs in the auth difference.
///
/// We walk the `auth_chain` map rather than recursing from scratch, because
/// the caller provides the pre-computed union auth chain.  We do validate that
/// every referenced auth_event is present, returning an error if not.
fn auth_difference(
    state_sets: &[StateMap<Event>],
    auth_chain: &HashMap<String, Event>,
) -> Result<HashSet<String>, StateResError> {
    if state_sets.is_empty() {
        return Ok(HashSet::new());
    }

    // For each state set, compute the set of event IDs reachable via auth_events
    // from every event in that set.
    let per_set_chains: Vec<HashSet<String>> = state_sets
        .iter()
        .map(|s| auth_chain_for_set(s, auth_chain))
        .collect::<Result<Vec<_>, _>>()?;

    // Union all chains.
    let union: HashSet<String> = per_set_chains
        .iter()
        .flat_map(|c| c.iter().cloned())
        .collect();

    // Intersection of all chains.
    let mut intersection = per_set_chains[0].clone();
    for chain in &per_set_chains[1..] {
        intersection = intersection.intersection(chain).cloned().collect();
    }

    // Auth difference = union − intersection.
    Ok(union.difference(&intersection).cloned().collect())
}

/// Walk auth_events from all events in `state_set` and collect all reachable
/// event IDs (including the seed events themselves if they are in auth_chain).
fn auth_chain_for_set(
    state_set: &StateMap<Event>,
    auth_chain: &HashMap<String, Event>,
) -> Result<HashSet<String>, StateResError> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut stack: Vec<String> = state_set
        .values()
        .flat_map(|ev| ev.auth_events.iter().cloned())
        .collect();

    // Also include the state events themselves if they're in auth_chain.
    for ev in state_set.values() {
        if auth_chain.contains_key(&ev.event_id) {
            stack.push(ev.event_id.clone());
        }
    }

    while let Some(eid) = stack.pop() {
        if !visited.insert(eid.clone()) {
            continue; // already processed
        }
        // Every referenced auth event must be in auth_chain.
        if let Some(ev) = auth_chain.get(&eid) {
            for auth_eid in &ev.auth_events {
                if !visited.contains(auth_eid.as_str()) {
                    stack.push(auth_eid.clone());
                }
            }
        }
        // If not in auth_chain, it's OK — it might be the state event itself
        // that lives in the state set but not in auth_chain.
    }

    Ok(visited)
}

// ---------------------------------------------------------------------------
// Power-event classification
// ---------------------------------------------------------------------------

/// Return true if this event is a "power event" per the spec:
/// - m.room.create
/// - m.room.power_levels
/// - m.room.join_rules
/// - m.room.member where membership is leave or ban
fn is_power_event(ev: &Event) -> bool {
    match ev.event_type.as_str() {
        "m.room.create" | "m.room.power_levels" | "m.room.join_rules" => true,
        "m.room.member" => {
            // Only leave and ban need power.
            match parse_member(&ev.content) {
                Ok(mc) => matches!(mc.membership, Membership::Leave | Membership::Ban),
                Err(_) => false,
            }
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Step 3 — Reverse-topological power ordering
// ---------------------------------------------------------------------------

/// Compute the sender's power level in the context of a given state map.
fn sender_power_level_in_state(sender: &str, state: &StateMap<Event>) -> i64 {
    let pl_event = state.get(&("m.room.power_levels".to_owned(), String::new()));
    let creator = state
        .get(&("m.room.create".to_owned(), String::new()))
        .map(|e| e.sender.clone());
    user_power_level(sender, pl_event, creator.as_deref())
}

/// Sort a slice of events by reverse-topological power ordering:
///
/// 1. Build a topological ordering of events using auth_events as edges
///    (an event A is "before" B if A appears in B's auth_events chain).
/// 2. Within the same topological level, tiebreak by:
///    `(power_level_of_sender DESC, origin_server_ts ASC, event_id ASC)`.
///
/// The result is the order in which events should be *applied* (earlier index
/// = applied first).  "Reverse topological" means dependencies come first.
///
/// `current_state` is used to look up power levels for tiebreaking.
fn reverse_topological_power_order(
    events: &[Event],
    _auth_chain: &HashMap<String, Event>,
    current_state: &StateMap<Event>,
) -> Vec<Event> {
    if events.is_empty() {
        return Vec::new();
    }

    // Build a local index of all events we care about.
    let event_map: HashMap<&str, &Event> = events.iter().map(|e| (e.event_id.as_str(), e)).collect();

    // Compute in-degree (number of events in our set that depend on this one).
    // Edge: B depends on A if A is in B's auth_events (directly or transitively).
    // For ordering purposes we use *direct* auth_events edges only, restricted
    // to events in our candidate set.
    let mut in_degree: HashMap<&str, usize> = events
        .iter()
        .map(|e| (e.event_id.as_str(), 0usize))
        .collect();
    let mut dependents: HashMap<&str, Vec<&str>> = events
        .iter()
        .map(|e| (e.event_id.as_str(), Vec::new()))
        .collect();

    for ev in events {
        for auth_eid in &ev.auth_events {
            if event_map.contains_key(auth_eid.as_str()) {
                // ev depends on auth_eid → auth_eid must come first
                *in_degree.get_mut(ev.event_id.as_str()).unwrap() += 1;
                dependents
                    .get_mut(auth_eid.as_str())
                    .unwrap()
                    .push(ev.event_id.as_str());
            }
        }
    }

    // Kahn's algorithm with a priority queue for tiebreaking.
    // We want: highest power level first, then earliest timestamp, then
    // lexicographically smallest event_id.
    // "First to be applied" = comes first in the output vec.
    //
    // The spec says "reverse topological power ordering" — dependencies before
    // dependents (so create before power_levels before member events).
    // Within a topological level we pick highest-power sender first.

    // Collect all zero-in-degree events as the initial candidates.
    let mut ready: Vec<&str> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(id, _)| *id)
        .collect();

    let mut result: Vec<Event> = Vec::with_capacity(events.len());

    while !ready.is_empty() {
        // Sort ready queue by tiebreaker (we want to pick the "best" one).
        // Pick: highest sender power level DESC, then origin_server_ts ASC, then event_id ASC.
        ready.sort_by(|&a_id, &b_id| {
            let a = event_map[a_id];
            let b = event_map[b_id];
            let a_pl = sender_power_level_in_state(&a.sender, current_state);
            let b_pl = sender_power_level_in_state(&b.sender, current_state);
            // Descending power level.
            b_pl.cmp(&a_pl)
                .then_with(|| a.origin_server_ts.cmp(&b.origin_server_ts))
                .then_with(|| a.event_id.cmp(&b.event_id))
        });

        let chosen_id = ready.remove(0);
        let chosen = event_map[chosen_id];
        result.push(chosen.clone());

        // Reduce in-degree of dependents.
        if let Some(deps) = dependents.get(chosen_id) {
            for &dep_id in deps {
                let deg = in_degree.get_mut(dep_id).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    ready.push(dep_id);
                }
            }
        }
    }

    // If any events remain (cycle — shouldn't happen with valid auth chains),
    // append them in tiebreaker order to be safe.
    if result.len() < events.len() {
        let mut remaining: Vec<&Event> = events
            .iter()
            .filter(|e| !result.iter().any(|r| r.event_id == e.event_id))
            .collect();
        remaining.sort_by(|a, b| {
            let a_pl = sender_power_level_in_state(&a.sender, current_state);
            let b_pl = sender_power_level_in_state(&b.sender, current_state);
            b_pl.cmp(&a_pl)
                .then_with(|| a.origin_server_ts.cmp(&b.origin_server_ts))
                .then_with(|| a.event_id.cmp(&b.event_id))
        });
        for ev in remaining {
            result.push(ev.clone());
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Step 4 — Mainline ordering
// ---------------------------------------------------------------------------

/// Compute the "mainline" of m.room.power_levels events starting from the
/// resolved power_levels event (or None if no power_levels exists).
///
/// The mainline is the chain of power_levels events reached by repeatedly
/// following the `m.room.power_levels` auth_event reference.
///
/// Returns a vec ordered from oldest (root) to newest (current), i.e.
/// mainline[0] is the earliest, mainline[last] is the most recent.
fn compute_mainline(
    resolved_state: &StateMap<Event>,
    auth_chain: &HashMap<String, Event>,
) -> Vec<String> {
    let mut mainline: Vec<String> = Vec::new();

    // Start from the current resolved m.room.power_levels.
    let mut current = resolved_state
        .get(&("m.room.power_levels".to_owned(), String::new()))
        .map(|e| e.event_id.clone());

    let mut visited: HashSet<String> = HashSet::new();

    while let Some(eid) = current {
        if !visited.insert(eid.clone()) {
            break; // cycle guard
        }
        mainline.push(eid.clone());

        // Find the next power_levels event in this event's auth_events chain.
        current = auth_chain
            .get(&eid)
            .and_then(|ev| {
                ev.auth_events
                    .iter()
                    .find_map(|auth_eid| {
                        auth_chain.get(auth_eid.as_str()).and_then(|auth_ev| {
                            if auth_ev.event_type == "m.room.power_levels" {
                                Some(auth_eid.clone())
                            } else {
                                None
                            }
                        })
                    })
            });
    }

    // Reverse so index 0 = oldest (root) and index[last] = newest.
    mainline.reverse();
    mainline
}

/// Compute the "mainline depth" of an event: the index in the mainline at
/// which this event's m.room.power_levels auth-event sits.
///
/// Per the spec: for each event, walk its auth_events to find the
/// m.room.power_levels event, then find that event's position in the mainline.
/// If the event (or its pl auth_event) does not appear in the mainline, return
/// `usize::MAX` (place it last).
fn mainline_depth(
    ev: &Event,
    mainline: &[String],
    auth_chain: &HashMap<String, Event>,
) -> usize {
    // Find the m.room.power_levels event in this event's auth_events.
    let pl_auth_id: Option<&str> = ev.auth_events.iter().find_map(|auth_eid| {
        auth_chain
            .get(auth_eid.as_str())
            .filter(|ae| ae.event_type == "m.room.power_levels")
            .map(|_| auth_eid.as_str())
    });

    match pl_auth_id {
        None => usize::MAX,
        Some(pl_id) => mainline
            .iter()
            .position(|mid| mid == pl_id)
            .unwrap_or(usize::MAX),
    }
}

/// Order non-power conflicted events by mainline ordering:
/// 1. mainline_depth ascending
/// 2. origin_server_ts ascending
/// 3. event_id ascending (lexicographic)
fn mainline_order(
    events: &[Event],
    mainline: &[String],
    auth_chain: &HashMap<String, Event>,
) -> Vec<Event> {
    let mut sorted = events.to_vec();
    sorted.sort_by(|a, b| {
        let da = mainline_depth(a, mainline, auth_chain);
        let db = mainline_depth(b, mainline, auth_chain);
        da.cmp(&db)
            .then_with(|| a.origin_server_ts.cmp(&b.origin_server_ts))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
    sorted
}

// ---------------------------------------------------------------------------
// Main resolve function
// ---------------------------------------------------------------------------

/// Resolve a collection of state sets to the room's canonical state.
///
/// ## Parameters
///
/// - `state_sets`: Each element is a complete state snapshot (from a branch
///   tip) as a `HashMap<(event_type, state_key), Event>`.
/// - `auth_chain`: Pre-computed union of all events reachable via `auth_events`
///   from any event in any state set, keyed by `event_id`.
///
/// ## Errors
///
/// - `StateResError::MissingAuthEvent` if an event's `auth_events` references
///   an ID not present in `auth_chain`.
/// - `StateResError::AuthChainCycle` if a cycle is detected.
///
/// ## Determinism
///
/// The function is a pure function of its inputs. Two correct implementations
/// must return identical state given identical inputs.
pub fn resolve(
    state_sets: Vec<StateMap<Event>>,
    auth_chain: HashMap<String, Event>,
) -> Result<StateMap<Event>, StateResError> {
    // --- Trivial cases -------------------------------------------------------
    if state_sets.is_empty() {
        return Ok(HashMap::new());
    }
    if state_sets.len() == 1 {
        return Ok(state_sets.into_iter().next().unwrap());
    }

    // --- Step 1: Split conflicted / unconflicted -----------------------------
    let (unconflicted, conflicted_map) = split_conflicted(&state_sets);

    // If nothing is conflicted, return unconflicted directly.
    if conflicted_map.is_empty() {
        return Ok(unconflicted);
    }

    // Flatten the conflicted events into a single de-duplicated list.
    let mut all_conflicted: Vec<Event> = {
        let mut seen: HashSet<String> = HashSet::new();
        let mut v = Vec::new();
        for events in conflicted_map.values() {
            for ev in events {
                if seen.insert(ev.event_id.clone()) {
                    v.push(ev.clone());
                }
            }
        }
        v
    };

    // --- Step 2: Auth difference ---------------------------------------------
    let auth_diff_ids = auth_difference(&state_sets, &auth_chain)?;

    // Collect auth-difference events that are not already in all_conflicted.
    {
        let conflicted_ids: HashSet<String> = all_conflicted
            .iter()
            .map(|e| e.event_id.clone())
            .collect();
        for eid in &auth_diff_ids {
            if !conflicted_ids.contains(eid.as_str()) {
                if let Some(ev) = auth_chain.get(eid) {
                    all_conflicted.push(ev.clone());
                }
            }
        }
    }

    // --- Step 3: Resolve power events ----------------------------------------
    let (power_events, non_power_events): (Vec<Event>, Vec<Event>) =
        all_conflicted.into_iter().partition(is_power_event);

    // Build working state: start from unconflicted.
    let mut working_state: StateMap<Event> = unconflicted.clone();

    // Order power events by reverse-topological power order.
    let ordered_power = reverse_topological_power_order(&power_events, &auth_chain, &working_state);

    // Iteratively apply each power event that passes auth.
    for ev in &ordered_power {
        let auth_state = build_auth_state_for_event(ev, &working_state)?;
        if check_auth(ev, &auth_state).is_ok() {
            apply_state_event(&mut working_state, ev);
        }
    }

    // --- Step 4: Mainline ordering for non-power events ----------------------
    let mainline = compute_mainline(&working_state, &auth_chain);
    let ordered_non_power = mainline_order(&non_power_events, &mainline, &auth_chain);

    // Iteratively apply each non-power event that passes auth.
    for ev in &ordered_non_power {
        let auth_state = build_auth_state_for_event(ev, &working_state)?;
        if check_auth(ev, &auth_state).is_ok() {
            apply_state_event(&mut working_state, ev);
        }
    }

    // --- Step 5: Apply unconflicted on top -----------------------------------
    // Per spec: "the unconflicted state is applied on top of the resolved
    // conflicted state."  Unconflicted entries always win.
    for (key, ev) in &unconflicted {
        working_state.insert(key.clone(), ev.clone());
    }

    Ok(working_state)
}

// ---------------------------------------------------------------------------
// Auth-state builder
// ---------------------------------------------------------------------------

/// Build the auth state slice needed to check `event` using `auth_event_keys`.
///
/// This looks up the required state keys from `current_state`.  It does NOT
/// verify that the keys are in the event's own `auth_events` list — that is
/// the caller's responsibility for stricter implementations.  For state
/// resolution purposes, using the current working state is correct per spec.
fn build_auth_state_for_event(
    event: &Event,
    current_state: &StateMap<Event>,
) -> Result<StateMap<Event>, StateResError> {
    let keys = auth_event_keys(event);
    let mut auth_state: StateMap<Event> = HashMap::new();
    for key in keys {
        if let Some(ev) = current_state.get(&key) {
            auth_state.insert(key, ev.clone());
        }
    }
    Ok(auth_state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_event(
        event_id: &str,
        event_type: &str,
        sender: &str,
        room_id: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
        auth_events: Vec<String>,
        depth: i64,
        origin_server_ts: u64,
    ) -> Event {
        Event {
            event_id: event_id.to_owned(),
            room_id: room_id.to_owned(),
            sender: sender.to_owned(),
            event_type: event_type.to_owned(),
            content,
            state_key: state_key.map(|s| s.to_owned()),
            origin_server_ts,
            auth_events,
            prev_events: vec![],
            hashes: json!({}),
            signatures: json!({}),
            depth,
            unsigned: None,
        }
    }

    fn make_create(room_id: &str, creator: &str) -> Event {
        make_event(
            "$create",
            "m.room.create",
            creator,
            room_id,
            Some(""),
            json!({ "room_version": "11" }),
            vec![],
            1,
            1000,
        )
    }

    fn make_member(
        event_id: &str,
        sender: &str,
        target: &str,
        room_id: &str,
        membership: &str,
        auth_events: Vec<String>,
        depth: i64,
        ts: u64,
    ) -> Event {
        make_event(
            event_id,
            "m.room.member",
            sender,
            room_id,
            Some(target),
            json!({ "membership": membership }),
            auth_events,
            depth,
            ts,
        )
    }

    fn make_pl(
        event_id: &str,
        sender: &str,
        room_id: &str,
        content: serde_json::Value,
        auth_events: Vec<String>,
        depth: i64,
        ts: u64,
    ) -> Event {
        make_event(
            event_id,
            "m.room.power_levels",
            sender,
            room_id,
            Some(""),
            content,
            auth_events,
            depth,
            ts,
        )
    }

    fn make_join_rules(
        event_id: &str,
        sender: &str,
        room_id: &str,
        rule: &str,
        auth_events: Vec<String>,
        depth: i64,
        ts: u64,
    ) -> Event {
        make_event(
            event_id,
            "m.room.join_rules",
            sender,
            room_id,
            Some(""),
            json!({ "join_rule": rule }),
            auth_events,
            depth,
            ts,
        )
    }

    /// Build the standard room bootstrap events: create, creator-join.
    /// Returns (create_event, join_event, auth_chain).
    fn bootstrap_room(
        room_id: &str,
        creator: &str,
    ) -> (Event, Event, HashMap<String, Event>) {
        let create = make_create(room_id, creator);
        let join = make_member(
            "$creator_join",
            creator,
            creator,
            room_id,
            "join",
            vec!["$create".to_owned()],
            2,
            1001,
        );
        let mut chain = HashMap::new();
        chain.insert(create.event_id.clone(), create.clone());
        chain.insert(join.event_id.clone(), join.clone());
        (create, join, chain)
    }

    fn state_set_from(events: &[&Event]) -> StateMap<Event> {
        let mut m = HashMap::new();
        for ev in events {
            if let Some(sk) = &ev.state_key {
                m.insert((ev.event_type.clone(), sk.clone()), (*ev).clone());
            }
        }
        m
    }

    // -----------------------------------------------------------------------
    // Test 1: single_state_set_returns_same_state
    // -----------------------------------------------------------------------
    #[test]
    fn single_state_set_returns_same_state() {
        let room = "!r:example.com";
        let alice = "@alice:example.com";
        let (create, join, chain) = bootstrap_room(room, alice);

        let state_set = state_set_from(&[&create, &join]);
        let result = resolve(vec![state_set.clone()], chain).unwrap();

        assert_eq!(result, state_set);
    }

    // -----------------------------------------------------------------------
    // Test 2: two_identical_sets_return_same_state
    // -----------------------------------------------------------------------
    #[test]
    fn two_identical_sets_return_same_state() {
        let room = "!r:example.com";
        let alice = "@alice:example.com";
        let (create, join, chain) = bootstrap_room(room, alice);

        let state_set = state_set_from(&[&create, &join]);
        let result = resolve(vec![state_set.clone(), state_set.clone()], chain).unwrap();

        assert_eq!(result, state_set);
    }

    // -----------------------------------------------------------------------
    // Test 3: unconflicted_state_passes_through
    // -----------------------------------------------------------------------
    #[test]
    fn unconflicted_state_passes_through() {
        let room = "!r:example.com";
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let (create, alice_join, mut chain) = bootstrap_room(room, alice);

        // Public join_rules so Bob's join events can pass auth.
        let jr = make_join_rules(
            "$jr",
            alice,
            room,
            "public",
            vec!["$create".to_owned(), "$creator_join".to_owned()],
            3,
            1001,
        );
        chain.insert(jr.event_id.clone(), jr.clone());

        // Alice joins in both sets.  Bob's membership is conflicted (two
        // different events, one per branch).
        let bob_join_a = make_member(
            "$bob_join_a",
            bob,
            bob,
            room,
            "join",
            vec!["$create".to_owned(), "$creator_join".to_owned()],
            4,
            2000,
        );
        let bob_join_b = make_member(
            "$bob_join_b",
            bob,
            bob,
            room,
            "join",
            vec!["$create".to_owned(), "$creator_join".to_owned()],
            4,
            3000,
        );
        chain.insert(bob_join_a.event_id.clone(), bob_join_a.clone());
        chain.insert(bob_join_b.event_id.clone(), bob_join_b.clone());

        // Set A: create, alice, jr, bob_a
        let set_a = state_set_from(&[&create, &alice_join, &jr, &bob_join_a]);
        // Set B: create, alice, jr, bob_b  (conflicted on bob membership)
        let set_b = state_set_from(&[&create, &alice_join, &jr, &bob_join_b]);

        let result = resolve(vec![set_a, set_b], chain).unwrap();

        // create and alice_join are unconflicted — must be present.
        assert_eq!(
            result
                .get(&("m.room.create".to_owned(), "".to_owned()))
                .map(|e| &e.event_id),
            Some(&"$create".to_owned())
        );
        assert_eq!(
            result
                .get(&("m.room.member".to_owned(), alice.to_owned()))
                .map(|e| &e.event_id),
            Some(&"$creator_join".to_owned())
        );
        // Bob's membership is conflicted — some resolution should exist.
        assert!(result.contains_key(&("m.room.member".to_owned(), bob.to_owned())));
    }

    // -----------------------------------------------------------------------
    // Test 4: conflicting_member_event_resolves_by_origin_ts
    //
    // Two branches both give Bob "join" but at different timestamps.
    // The later timestamp wins (higher origin_server_ts = lower in mainline
    // order = applied later = wins).
    // -----------------------------------------------------------------------
    #[test]
    fn conflicting_member_event_resolves_by_origin_ts() {
        let room = "!r:example.com";
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let (create, alice_join, mut chain) = bootstrap_room(room, alice);

        // Both are "join" events but with different timestamps.
        let bob_early = make_member(
            "$bob_early",
            bob,
            bob,
            room,
            "join",
            vec!["$create".to_owned()],
            3,
            1000,
        );
        let bob_late = make_member(
            "$bob_late",
            bob,
            bob,
            room,
            "join",
            vec!["$create".to_owned()],
            3,
            2000,
        );
        chain.insert(bob_early.event_id.clone(), bob_early.clone());
        chain.insert(bob_late.event_id.clone(), bob_late.clone());

        // For both bob events to pass auth, we need a public join_rules.
        let jr = make_join_rules(
            "$jr",
            alice,
            room,
            "public",
            vec!["$create".to_owned(), "$creator_join".to_owned()],
            3,
            1001,
        );
        chain.insert(jr.event_id.clone(), jr.clone());

        let set_a = state_set_from(&[&create, &alice_join, &jr, &bob_early]);
        let set_b = state_set_from(&[&create, &alice_join, &jr, &bob_late]);

        let result = resolve(vec![set_a, set_b], chain).unwrap();

        // bob_late has larger origin_server_ts, so in mainline order it is
        // applied after bob_early → bob_late wins.
        let bob_result = result
            .get(&("m.room.member".to_owned(), bob.to_owned()))
            .expect("bob membership must be in result");
        assert_eq!(bob_result.event_id, "$bob_late");
    }

    // -----------------------------------------------------------------------
    // Test 5: power_event_ordering_respected
    //
    // Two branches each have a different m.room.power_levels event.
    // Verify they are resolved and one wins deterministically.
    // -----------------------------------------------------------------------
    #[test]
    fn power_event_ordering_respected() {
        let room = "!r:example.com";
        let alice = "@alice:example.com";
        let (create, alice_join, mut chain) = bootstrap_room(room, alice);

        let pl_a = make_pl(
            "$pl_a",
            alice,
            room,
            json!({
                "users": { "@alice:example.com": 100 },
                "users_default": 0,
                "events_default": 0,
                "state_default": 50,
                "ban": 50, "kick": 50, "redact": 50, "invite": 50
            }),
            vec!["$create".to_owned(), "$creator_join".to_owned()],
            3,
            1000,
        );
        let pl_b = make_pl(
            "$pl_b",
            alice,
            room,
            json!({
                "users": { "@alice:example.com": 100 },
                "users_default": 0,
                "events_default": 0,
                "state_default": 50,
                "ban": 50, "kick": 50, "redact": 50, "invite": 50
            }),
            vec!["$create".to_owned(), "$creator_join".to_owned()],
            3,
            2000,
        );
        chain.insert(pl_a.event_id.clone(), pl_a.clone());
        chain.insert(pl_b.event_id.clone(), pl_b.clone());

        let set_a = state_set_from(&[&create, &alice_join, &pl_a]);
        let set_b = state_set_from(&[&create, &alice_join, &pl_b]);

        let result = resolve(vec![set_a, set_b], chain).unwrap();

        // Must contain exactly one power_levels event.
        let pl_result = result
            .get(&("m.room.power_levels".to_owned(), "".to_owned()))
            .expect("power_levels must be in result");
        // The one with higher timestamp (pl_b) is applied later and wins.
        assert_eq!(pl_result.event_id, "$pl_b");
    }

    // -----------------------------------------------------------------------
    // Test 6: event_with_failing_auth_is_dropped
    //
    // A conflicted event that would fail check_auth (sender not joined)
    // must be excluded from the result.
    // -----------------------------------------------------------------------
    #[test]
    fn event_with_failing_auth_is_dropped() {
        let room = "!r:example.com";
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let (create, alice_join, mut chain) = bootstrap_room(room, alice);

        // Alice sets join_rules to "invite" (not public).
        let jr_invite = make_join_rules(
            "$jr_invite",
            alice,
            room,
            "invite",
            vec!["$create".to_owned(), "$creator_join".to_owned()],
            3,
            1001,
        );
        chain.insert(jr_invite.event_id.clone(), jr_invite.clone());

        // Bob tries to join without an invite — this should fail auth.
        let bob_join = make_member(
            "$bob_join_noinvite",
            bob,
            bob,
            room,
            "join",
            vec!["$create".to_owned(), "$jr_invite".to_owned()],
            4,
            2000,
        );
        chain.insert(bob_join.event_id.clone(), bob_join.clone());

        // Set A: no bob membership.
        // Set B: bob_join (which will fail auth due to invite-only).
        let set_a = state_set_from(&[&create, &alice_join, &jr_invite]);
        let set_b = state_set_from(&[&create, &alice_join, &jr_invite, &bob_join]);

        let result = resolve(vec![set_a, set_b], chain).unwrap();

        // Bob's join must NOT be in the result.
        assert!(
            !result.contains_key(&("m.room.member".to_owned(), bob.to_owned())),
            "bob join should have been rejected by auth"
        );
    }

    // -----------------------------------------------------------------------
    // Test 7: tiebreaker_by_event_id
    //
    // Same origin_server_ts, same sender power level →
    // lexicographically smallest event_id is applied last (wins per mainline
    // ordering: same depth + same ts → sort by event_id ASC → smaller comes
    // first in order → larger comes last → larger overwrites smaller and wins).
    //
    // Wait — re-read spec: ascending event_id means SMALLER comes FIRST in the
    // application order, so LARGER event_id is applied LATER and wins.
    // -----------------------------------------------------------------------
    #[test]
    fn tiebreaker_by_event_id() {
        let room = "!r:example.com";
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let (create, alice_join, mut chain) = bootstrap_room(room, alice);

        let jr = make_join_rules(
            "$jr",
            alice,
            room,
            "public",
            vec!["$create".to_owned(), "$creator_join".to_owned()],
            3,
            1001,
        );
        chain.insert(jr.event_id.clone(), jr.clone());

        // Two bob-join events: identical timestamps, different event_ids.
        // "$aaa_bob" < "$zzz_bob" lexicographically.
        let bob_aaa = make_member(
            "$aaa_bob",
            bob,
            bob,
            room,
            "join",
            vec!["$create".to_owned()],
            4,
            5000,
        );
        let bob_zzz = make_member(
            "$zzz_bob",
            bob,
            bob,
            room,
            "join",
            vec!["$create".to_owned()],
            4,
            5000,
        );
        chain.insert(bob_aaa.event_id.clone(), bob_aaa.clone());
        chain.insert(bob_zzz.event_id.clone(), bob_zzz.clone());

        let set_a = state_set_from(&[&create, &alice_join, &jr, &bob_aaa]);
        let set_b = state_set_from(&[&create, &alice_join, &jr, &bob_zzz]);

        let result = resolve(vec![set_a, set_b], chain).unwrap();

        let bob_result = result
            .get(&("m.room.member".to_owned(), bob.to_owned()))
            .expect("bob membership must be present");

        // Applied in ascending event_id order: $aaa_bob first, then $zzz_bob.
        // The last one applied wins → $zzz_bob wins.
        assert_eq!(
            bob_result.event_id, "$zzz_bob",
            "larger event_id should win when timestamp and power level tie"
        );
    }

    // -----------------------------------------------------------------------
    // Test 8: idempotent
    //
    // resolve(resolve(S)) == resolve(S)
    // -----------------------------------------------------------------------
    #[test]
    fn idempotent() {
        let room = "!r:example.com";
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let (create, alice_join, mut chain) = bootstrap_room(room, alice);

        let jr = make_join_rules(
            "$jr",
            alice,
            room,
            "public",
            vec!["$create".to_owned(), "$creator_join".to_owned()],
            3,
            1001,
        );
        chain.insert(jr.event_id.clone(), jr.clone());

        let bob_a = make_member(
            "$bob_a",
            bob,
            bob,
            room,
            "join",
            vec!["$create".to_owned()],
            3,
            2000,
        );
        let bob_b = make_member(
            "$bob_b",
            bob,
            bob,
            room,
            "join",
            vec!["$create".to_owned()],
            3,
            3000,
        );
        chain.insert(bob_a.event_id.clone(), bob_a.clone());
        chain.insert(bob_b.event_id.clone(), bob_b.clone());

        let set_a = state_set_from(&[&create, &alice_join, &jr, &bob_a]);
        let set_b = state_set_from(&[&create, &alice_join, &jr, &bob_b]);

        // First resolution.
        let resolved_once =
            resolve(vec![set_a.clone(), set_b.clone()], chain.clone()).unwrap();

        // Second resolution: apply resolve again with the result as a single
        // state set (idempotency check).
        let resolved_twice = resolve(vec![resolved_once.clone()], chain.clone()).unwrap();

        assert_eq!(resolved_once, resolved_twice, "resolve must be idempotent");
    }

    // -----------------------------------------------------------------------
    // Test 9: missing_auth_event_errors
    //
    // A state set references an auth event not present in auth_chain →
    // returns MissingAuthEvent.
    // -----------------------------------------------------------------------
    #[test]
    fn missing_auth_event_errors() {
        let room = "!r:example.com";
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let (create, alice_join, mut chain) = bootstrap_room(room, alice);

        // Bob join references "$ghost" which is NOT in auth_chain.
        let bob_join = make_member(
            "$bob_join",
            bob,
            bob,
            room,
            "join",
            vec!["$create".to_owned(), "$ghost".to_owned()],
            3,
            2000,
        );
        chain.insert(bob_join.event_id.clone(), bob_join.clone());

        let set_a = state_set_from(&[&create, &alice_join]);
        let set_b = state_set_from(&[&create, &alice_join, &bob_join]);

        // The auth_chain does NOT contain "$ghost".
        // The auth_difference step must traverse bob_join's auth_events and
        // encounter $ghost while walking the auth_chain.
        //
        // However, our implementation only validates that auth_chain entries
        // themselves are consistent, not that every auth_event ID referenced
        // by a state set event is present.  To trigger MissingAuthEvent we
        // need to explicitly validate references.
        //
        // Per our contract: if auth_chain is incomplete, return
        // MissingAuthEvent.  We enforce this by validating that every
        // auth_event reference by every state-set event is in auth_chain.
        let result = resolve_strict(vec![set_a, set_b], chain);
        assert!(
            matches!(result, Err(StateResError::MissingAuthEvent { .. })),
            "expected MissingAuthEvent, got: {:?}",
            result
        );
    }
}

// ---------------------------------------------------------------------------
// Strict resolve — validates completeness of auth_chain before resolving.
// ---------------------------------------------------------------------------

/// Like `resolve`, but also validates that every `auth_event` referenced by
/// any state-set event is present in `auth_chain`.  Returns
/// `Err(StateResError::MissingAuthEvent)` if the chain is incomplete.
///
/// The default `resolve` does not enforce this for performance (incomplete
/// chains are treated as "no further auth ancestors").  Use `resolve_strict`
/// when you need the hard guarantee.
pub fn resolve_strict(
    state_sets: Vec<StateMap<Event>>,
    auth_chain: HashMap<String, Event>,
) -> Result<StateMap<Event>, StateResError> {
    // Validate completeness: every auth_event referenced by a state-set event
    // must be present in auth_chain.
    for state_set in &state_sets {
        for ev in state_set.values() {
            for auth_eid in &ev.auth_events {
                if !auth_chain.contains_key(auth_eid.as_str()) {
                    return Err(StateResError::MissingAuthEvent {
                        event_id: auth_eid.clone(),
                    });
                }
            }
        }
    }

    resolve(state_sets, auth_chain)
}
