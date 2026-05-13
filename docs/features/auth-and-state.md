# Auth & State Machine

**Spec reference:** [Authorization rules], [Room state]
**Default:** on
**Depends on:** [`events-and-signing`](events-and-signing.md)
**Depended on by:** client-server-api, federation, state-resolution

[Authorization rules]: https://spec.matrix.org/latest/rooms/v11/#authorization-rules
[Room state]: https://spec.matrix.org/latest/client-server-api/#room-state

## What this is

Every event in a room must pass authorization rules before it's
accepted, and many events carry **state**: who is in the room, what
power level each person has, what the room is named, etc. The state
machine applies state events to a snapshot.

## What the homeserver needs to do

- Maintain the current `(type, state_key) → event` map per room.
- For each new event, look up its **auth events** — the small set of
  state events that authorize it: room create, sender's membership,
  power levels, join rules.
- Run the **auth check** for the room version: does the sender have
  permission to send this event, at this state?
- If the event passes auth and is a state event, update the room
  state.

## Key state event types

| Type                              | What it carries                                 |
|-----------------------------------|-------------------------------------------------|
| `m.room.create`                   | First event in any room; names the creator.     |
| `m.room.member`                   | One per (room, user); `state_key` is user ID.   |
| `m.room.power_levels`             | Role → level + per-event-type levels.           |
| `m.room.join_rules`               | public / invite / knock / restricted.           |
| `m.room.history_visibility`       | What new members can see.                       |
| `m.room.name`, `m.room.topic`     | Cosmetic.                                       |

## Implementation approach

1. Translate the spec's auth rules into a single function:
   `fn check_auth(event, state) -> Result<(), AuthError>`.
2. Build the auth-event lookup helper: given an event, what state
   events authorize it? Spec gives an explicit list per event type.
3. For state events, apply post-auth: replace `state[(type, key)]`
   with the new event.
4. Resist the urge to inline auth into HTTP handlers. Keep auth pure
   so it's testable against spec scenarios.

## Gotchas

- Power level math has subtle edge cases — events can set their own
  required power level via `events_default` or `events[type]`.
- A user's join can be authorized by an invite from *another user* —
  the sender of the join is the joiner, but the auth chain references
  the inviter's membership.
- For single-server-only operation you can stub state resolution.
  The moment federation lands, [`state-resolution`](state-resolution.md)
  becomes mandatory.
