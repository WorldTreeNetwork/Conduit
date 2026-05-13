# E09 — 🚦 Federation: Inbound

**Status:** 🔵 Not started
**Implementation guide:** [docs/features/federation.md](../docs/features/federation.md)
**Depends on:** E05, E08
**Blocks:** E10, E12

## Scope

What our server *accepts* from other Matrix servers. The second major
user-visible milestone — once this works, remote users can join our
rooms and exchange messages.

## "Done" looks like

- A `@user:matrix.org` joins a Conduit-hosted room.
- Messages flow in both directions, state stays consistent under
  basic conflicts.
- Backfill works: history older than the join is fetchable.

## Stories

- [ ] **E09-1**: X-Matrix inbound signature verification middleware.
- [ ] **E09-2**: `PUT /_matrix/federation/v1/send/{txnId}` handler.
- [ ] **E09-3**: PDU event-signature verification (separate from
      request sig).
- [ ] **E09-4**: Incoming PDU pipeline: auth check → state-res →
      persist → reindex → fanout to local `/sync`.
- [ ] **E09-5**: `/make_join` + `/send_join/v2` inbound.
- [ ] **E09-6**: `/invite/v2` inbound.
- [ ] **E09-7**: `/state`, `/state_ids` serving.
- [ ] **E09-8**: `/backfill` serving (history-visibility filtered).
- [ ] **E09-9**: `/event/{eventId}`, `/get_missing_events`.
- [ ] **E09-10**: `/query/profile`, `/query/directory` serving.
- [ ] **E09-11**: Federation rate limiting + per-origin backpressure.
- [ ] **E09-12**: Federation tester suite (sytest or equivalent).

## Open questions

- Run sytest / complement against this implementation? Both are
  standard correctness suites; complement is newer.

## Risks

- Misbehaving remotes are real. Defensive parsing, hard size limits,
  and timeouts on every inbound path. Don't trust anything.
- State-res bugs surface here first — keep [E05](E05-state-resolution.md)
  test vectors green before merging anything that touches state.
