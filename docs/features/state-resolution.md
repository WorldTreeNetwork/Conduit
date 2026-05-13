# State Resolution

**Spec reference:** [State resolution v2]
**Default:** on (required once federation is active)
**Depends on:** [`auth-and-state`](auth-and-state.md)
**Depended on by:** federation (inbound)

[State resolution v2]: https://spec.matrix.org/latest/rooms/v11/#state-resolution

## What this is

When two homeservers each accept conflicting state events (e.g. both
promote a different user to admin in the same logical "moment"),
they need a deterministic algorithm to agree on the resulting state.
That algorithm is State Resolution v2.

If you only run a single homeserver and never federate, conflicting
state is impossible and this module can stay stubbed.

## The algorithm in one breath

1. **Split** the conflicting state events from the unconflicted ones.
2. **Resolve power events first**, ordered by reverse-topological
   power ordering. Apply each in order, keeping it only if it passes
   the auth check against the partial state built so far.
3. **Resolve the remaining conflicted events** via mainline ordering
   (each event's distance from the `m.room.power_levels` mainline).
4. **Apply the unconflicted state** on top.

## Implementation approach

1. Read the spec — there is no shortcut for state-res. Implement it
   exactly. Use the reference Python or an existing Rust crate as a
   correctness oracle, not a copy source.
2. Test against the [matrix-spec test vectors] if available;
   otherwise build scenarios from the spec examples.
3. Keep state-res a pure function of `(state_sets, auth_chain) →
   resolved_state` — no I/O, no clock.

[matrix-spec test vectors]: https://github.com/matrix-org/matrix-spec

## Gotchas

- Topological ordering with ties: spec specifies a deterministic
  tiebreaker (`origin_server_ts`, then `event_id`). Do not skip the
  tiebreaker; otherwise you'll silently disagree with other servers.
- Auth-chain fetching during federation is part of the protocol —
  state-res needs the chain to be complete.
- Performance matters: state-res runs on every federated send with
  conflicts. Cache resolved states.
