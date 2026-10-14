# Presence Layer

**Spec reference:** [Presence], [Profiles], [Typing], [Receipts], [Account data]
**Default:** on
**Depends on:** [`client-server-api`](client-server-api.md)

[Presence]: https://spec.matrix.org/latest/client-server-api/#presence
[Profiles]: https://spec.matrix.org/latest/client-server-api/#profiles
[Typing]: https://spec.matrix.org/latest/client-server-api/#typing-notifications
[Receipts]: https://spec.matrix.org/latest/client-server-api/#receipts
[Account data]: https://spec.matrix.org/latest/client-server-api/#client-config

## What this is

The set of "lightweight" signals that make a Matrix client feel alive:
who's online, who's typing, what someone read last, custom per-room
settings. None of these are load-bearing for messaging — but missing
them feels broken.

## Components

| Feature       | Storage shape                                        | EDU         | CS-API endpoint                                              |
|---------------|------------------------------------------------------|-------------|--------------------------------------------------------------|
| Profile       | per-user displayname + avatar URL                    | —           | `/profile/{}/{displayname,avatar_url}`                       |
| Account data  | per-user (and per-user-per-room) JSON blob           | —           | `/user/{}/account_data/{type}`, `/user/{}/rooms/{}/account_data/{type}` |
| Typing        | ephemeral (in-memory TTL)                            | `m.typing`  | `/rooms/{}/typing/{userId}`                                  |
| Receipts      | per-user per-room `last_read` event ID               | `m.receipt` | `/rooms/{}/receipt/m.read/{eventId}`                         |
| Presence      | per-user `online`/`unavailable`/`offline` + status   | `m.presence`| `/presence/{userId}/status`                                  |

## Implementation approach

1. None of these need persistence the way events do. Typing and
   presence can live in memory with a short TTL.
2. Surface them in `/sync` — clients learn about typing/presence
   through sync, not by polling endpoints.
3. Account data is just opaque JSON the client owns. Don't validate
   contents; round-trip it.

## Sync delivery

The production long-poll subscribes before reading any streams. Room events use
the existing broadcast channel; account-data writes, receipts, key changes, and
to-device messages use a separate sync notification so they do not trigger push
or application-service room-event workers. Typing and presence stores carry
revision counters and watch notifications. A wakeup rebuilds the response and
returns only when there is visible data or the original deadline expires.
Durable streams are also checked every 250 ms for changes committed by another
process; PostgreSQL notification integration remains future work.

Account-data and receipt deltas include their actual row positions. PostgreSQL
upserts assign a fresh position on every overwrite and choose the correct
partial unique index for global versus room account data. Sync tokens advance
to observed positions, avoiding replay from row counts or skipped updates from
a later maximum query. Both streams have BRIN indexes.

Typing start, stop, and expiry produce complete user lists, including empty
lists that clear client state. Typing and presence cursors have a process
generation so a restart clears stale ephemeral state. Unchanged presence is
omitted from incremental responses; presence reads require authentication and
self/shared joined-room visibility. Sync uses the same visibility rule.
Private receipts are delivered only to their owner; receipts from multiple
users for one event coexist in the response.

The production journeys in `conduit-server/tests/production_e2e.rs` exercise
these behaviors against an isolated database and the shipped binary. Threaded
receipts, fully-read markers, federated presence/typing, and complete access-rule
and timeout auditing remain tracked work; these tests cover the named delivery
and privacy assertions.

### Threaded receipts and typing rules (conduit-y99.15)

Receipts are keyed by `(room, user, type, thread)`, where the thread is absent
(unthreaded), `main`, or a thread root; scopes coexist and a new receipt only
replaces its own scope. `thread_id` must be a non-empty string naming the
event's actual thread (relations followed up to three hops; a thread root is
in `main` and may also anchor its own thread). Sync emits one `m.receipt` per
room and thread scope with `thread_id` on threaded receipts. Senders must be
joined (403) and the event must be in the room (404). `m.fully_read` belongs
to the read-markers handler.

Typing requires the path user to be the authenticated user and joined to the
room. The 20-30 s figure in the spec is a client refresh recommendation, not
a maximum: requested timeouts are honoured up to a 120 s server cap, oversized
values saturate, and the expiry uses checked arithmetic. Users who have left
are filtered out of `m.typing`. Journeys: `tests/production_sync.rs`.

## Gotchas

- Presence is notoriously expensive at scale because every status
  change must be fanned out to every room the user shares. Many
  large homeservers disable presence federation entirely.
- Read receipts have two flavors: `m.read` (public) and
  `m.read.private` (private). The private one is newer and not all
  servers handle it.
- Typing TTLs short enough to feel responsive but long enough to
  survive a slow keypress. ~10s is canonical.
