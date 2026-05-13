# Client-Server API

**Spec reference:** [Client-Server API]
**Default:** on (required for any usable server)
**Depends on:** [`auth-and-state`](auth-and-state.md), [`storage`](storage.md)
**Depended on by:** everything user-facing

[Client-Server API]: https://spec.matrix.org/latest/client-server-api/

## What this is

The HTTP API that Matrix clients (Element, FluffyChat, etc.) use to
talk to a homeserver. Mounted at `/_matrix/client/v3/...`. It's the
biggest single surface in the spec.

## Minimal "first usable server" subset

A homeserver is **usable** once these work:

### Auth

| Endpoint                                          | Purpose                                        |
|---------------------------------------------------|------------------------------------------------|
| `GET /_matrix/client/versions`                    | Capability advertisement.                      |
| `POST /_matrix/client/v3/register`                | Create an account.                             |
| `POST /_matrix/client/v3/login`                   | Exchange credentials for an access token.      |
| `POST /_matrix/client/v3/logout`                  | Invalidate the token.                          |
| `GET  /_matrix/client/v3/account/whoami`          | `(access_token) → (user_id, device_id)`.       |

### Rooms

| Endpoint                                                              | Purpose                       |
|-----------------------------------------------------------------------|-------------------------------|
| `POST /_matrix/client/v3/createRoom`                                  | Create a room.                |
| `POST /_matrix/client/v3/join/{roomIdOrAlias}`                        | Join a room.                  |
| `POST /_matrix/client/v3/rooms/{roomId}/leave`/`kick`/`ban`/`invite`  | Membership ops.               |
| `PUT  /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}`     | Send a message event.         |
| `PUT  /_matrix/client/v3/rooms/{roomId}/state/{type}/{stateKey}`      | Send a state event.           |
| `GET  /_matrix/client/v3/rooms/{roomId}/state`                        | Current state.                |
| `GET  /_matrix/client/v3/rooms/{roomId}/messages`                     | Paginate timeline.            |
| `GET  /_matrix/client/v3/rooms/{roomId}/joined_members`               | Member list.                  |

### Sync — the hard one

`GET /_matrix/client/v3/sync` — long-polled delta of everything the
client should know about. Takes `since` (the stream position from the
last sync) and optionally `timeout`. Returns: joined rooms with new
events, invites, leaves, presence updates, account data, to-device
messages, device list changes, ...

## Implementation approach

1. Mount routes in the host (`conduit-server`). The library provides
   handler functions; the host wires HTTP types to library types.
2. Build `/sync` as a streaming aggregator: hold a long-poll until any
   subscribed stream advances. Maintain per-user "next batch" tokens
   that encode positions across all streams (events, account data,
   device lists, to-device, presence).
3. Use **UI Authentication** (UIA) for password changes and other
   sensitive flows — it's a state machine the spec defines.
4. Idempotency via `txnId` — keep a small per-device cache of recent
   transaction IDs.

## Gotchas

- `/sync` is the make-or-break endpoint for client experience. Get
  the long-poll right; get the `since` token right; ship deltas, not
  full state.
- `/createRoom` quietly issues a flurry of state events (create,
  member, power_levels, join_rules, history_visibility, name, topic,
  initial_state). Bundle them so state-res sees a coherent snapshot.
- Many endpoints have "v3" and "r0" variants. v3 is current; some
  clients still call `r0` paths — serve both for now.
- Filters (in `/sync` and `/messages`) are tricky and easy to skimp on
  — but a missing filter implementation surfaces as Element being slow.
