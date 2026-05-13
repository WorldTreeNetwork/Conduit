# E05 — State Resolution v2

**Status:** 🔵 Not started
**Implementation guide:** [docs/features/state-resolution.md](../docs/features/state-resolution.md)
**Depends on:** E03
**Blocks:** E09

## Scope

Implement the State Resolution v2 algorithm as a pure function of
`(state_sets, auth_chain) → resolved_state`. Required before
federation accepts events that could conflict.

## "Done" looks like

- Pure-function `resolve(state_sets, auth_chain) -> Vec<Event>`.
- Passes the matrix-spec state-res test vectors (or equivalent
  scenarios from the spec).

## Stories

- [ ] **E05-1**: Split conflicted vs. unconflicted state.
- [ ] **E05-2**: Reverse-topological power ordering of conflicted
      power events.
- [ ] **E05-3**: Iterative auth check while applying ordered power
      events.
- [ ] **E05-4**: Mainline ordering for remaining conflicted events.
- [ ] **E05-5**: Final apply of unconflicted state on top.
- [ ] **E05-6**: Deterministic tiebreakers (`origin_server_ts`, then
      `event_id`).
- [ ] **E05-7**: Test vectors / spec scenarios.

## Open questions

- Pull in an existing Rust state-res crate as an oracle for testing,
  or implement from spec only? (Recommend: spec only, use any
  reference impl as a *test oracle*, not a copy source.)

## Risks

- Most subtle bug surface in the whole server. A wrong tiebreaker or
  wrong auth-chain handling causes silent disagreement with peers.
- Performance matters: state-res runs on every conflicting federated
  send. Cache resolved states by `(room_id, prev_state_set_ids)`.
