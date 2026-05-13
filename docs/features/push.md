# Push Notifications

**Spec reference:** [Push Notifications], [Push Gateway API]
**Default:** on (recommended off if you don't run a gateway)
**Depends on:** [`client-server-api`](client-server-api.md)

[Push Notifications]: https://spec.matrix.org/latest/client-server-api/#push-notifications
[Push Gateway API]: https://spec.matrix.org/latest/push-gateway-api/

## What this is

How a Matrix server pokes a phone to wake up when a message arrives.
Two protocols are involved:

1. **Push Gateway API** — the server → push gateway protocol. Apple
   APNs and Google FCM aren't reachable directly; a *push gateway*
   sits between them and the homeserver.
2. **Push Rules** — the per-user rule set the server evaluates to
   decide whether to push (and how).

## What the homeserver needs to do

- Let clients register a pusher
  (`POST /_matrix/client/v3/pushers/set`).
- Maintain default push rules per user; let clients edit them
  (`/pushrules/...`).
- On every event in a room, evaluate push rules for every member to
  decide push targets.
- POST to the registered push gateway with the matched events.

## Endpoints (Client-Server)

| Endpoint                                                           | Purpose                          |
|--------------------------------------------------------------------|----------------------------------|
| `POST /_matrix/client/v3/pushers/set`                              | Register / replace / remove.     |
| `GET  /_matrix/client/v3/pushers`                                  | List.                            |
| `GET/PUT/DELETE /_matrix/client/v3/pushrules/{scope}/{kind}/{id}`  | Edit rules.                      |
| `… /pushrules/{scope}/{kind}/{ruleId}/enabled`, `actions`          | Toggle / change action.          |
| `POST /_matrix/client/v3/notifications`                            | List past notifications.         |

## Implementation approach

1. The push-rules evaluator is a small interpreter — conditions are
   `event_match`, `room_member_count`,
   `sender_notification_permission`, etc. Implement the spec's
   default rule set exactly.
2. Maintain an async queue of `(event, target)` pairs and a worker
   that POSTs to the configured gateways with reasonable batching
   and retry.
3. Notification counts on `/sync` come from this evaluator too —
   "unread" is whatever fires a `notify` or `highlight` rule.

## Gotchas

- A poorly-tuned rule evaluator burns CPU on every event in every
  large room. Cache compiled rules per user.
- Push gateways are external — credentials and quotas live in config,
  not in the spec.
- For "encrypted push" the event content is opaque; clients still
  expect counts, so evaluate against the type/sender/room only.
- The default rule set has subtle precedence ordering. Match the
  spec; many clients depend on it.
