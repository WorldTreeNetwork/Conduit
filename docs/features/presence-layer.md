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

## Gotchas

- Presence is notoriously expensive at scale because every status
  change must be fanned out to every room the user shares. Many
  large homeservers disable presence federation entirely.
- Read receipts have two flavors: `m.read` (public) and
  `m.read.private` (private). The private one is newer and not all
  servers handle it.
- Typing TTLs short enough to feel responsive but long enough to
  survive a slow keypress. ~10s is canonical.
