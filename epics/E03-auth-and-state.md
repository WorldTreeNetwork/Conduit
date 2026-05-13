# E03 — Auth Rules & State Machine

**Status:** 🔵 Not started
**Implementation guide:** [docs/features/auth-and-state.md](../docs/features/auth-and-state.md)
**Depends on:** E02
**Blocks:** E04, E05

## Scope

Implement the room v11 authorization rules and the state machine that
applies state events. Single-server-only for now — state-res v2
([E05](E05-state-resolution.md)) is stubbed.

## "Done" looks like

- A single function `check_auth(event, state) -> Result<(), AuthError>`
  evaluates correctly for spec scenarios.
- Applying state events updates the room's current state map.
- Auth-event lookup returns the right minimal set for any event type.
- Spec auth test scenarios pass.

## Stories

- [ ] **E03-1**: Define `Event` enough to express auth state types
      (member, power_levels, join_rules, history_visibility, create).
- [ ] **E03-2**: `m.room.create` semantics — first event, names
      creator + room version.
- [ ] **E03-3**: `m.room.member` membership transitions
      (invite/join/leave/kick/ban/knock).
- [ ] **E03-4**: `m.room.power_levels` math (defaults, per-type,
      events_default, users_default, state_default).
- [ ] **E03-5**: `m.room.join_rules` (public, invite, knock,
      restricted).
- [ ] **E03-6**: `m.room.history_visibility` enforcement on read.
- [ ] **E03-7**: Auth-event lookup helper.
- [ ] **E03-8**: `check_auth(event, state)` per the v11 spec.
- [ ] **E03-9**: Apply state events to in-memory state map.
- [ ] **E03-10**: Test scenarios covering the spec's auth examples.

## Open questions

- Room version 10 vs 11 — both are reasonable starts. v11 is newest
  but v10 has wider deployment. Pick one to begin.

## Risks

- Power-level edge cases (event-type overrides) cause subtle bugs.
- Restricted-room join rule is more complex than the others; can defer.
