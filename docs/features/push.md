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

## Implementation (conduit-y99.30, conduit-y99.31)

Module map: `conduit-server/src/api/client/push.rs` (router + handlers),
`push/rules.rs` (v1.19 server-default rules, ruleset assembly, evaluator),
`push/notifications.rs` (evaluation engine), `notification_counts.rs` (unread
counts, shared by `/sync`, `/notifications` and the gateway badge),
`conduit-server/src/push_worker.rs` (gateway delivery). Migrations `0060`, `0061`.

**Rules.** Server-default rules live in code (v1.19 set: v1.17 removed the body
mention rules `contains_display_name`/`contains_user_name`/`roomnotif`).
`push_rules` stores user-defined rules (`is_default = false`, `priority`
ascending = more important) and overlays of default rules (`is_default = true`,
only `enabled`/`actions` are used). Order: `.m.rule.master`, then per kind user
rules before defaults. Conditions: `event_match` (string values only, whole-value
glob; `content.body` matches at word boundaries), `event_property_is`,
`event_property_contains`, `contains_display_name`, `room_member_count`,
`sender_notification_permission`; unknown kinds never match. Keys are
dot-separated paths with `\.`/`\\` escapes. `dont_notify`/`coalesce` are
stripped. PUT validates kind, reserved `.` IDs, slashes, actions and conditions,
honours `before`/`after` (400 `M_UNKNOWN` if the anchor is not a user rule) and
puts new rules first; server-default rules cannot be deleted (400). Every change
rewrites the server-managed `m.push_rules` account data, so it reaches `/sync`.

**Evaluation.** `process_pending` reads events after a durable cursor
(`push_cursor`, initialised to the head at migration) and, for each local user
joined to the room (plus the target of an invite) except the sender and users
who ignore the sender, records a `push_notifications` row when the matched rule
notifies, and a `push_outbox` row per HTTP pusher, then advances the cursor, all
in one transaction. A local sender's own event is a read mark for its thread
scope (`push_read_marks`). `/sync` calls it after collecting new events, so a
count arrives in the same response as its event; the worker calls it on every
event broadcast and once a second.

**Counts.** Unread = notifications after the read point of their scope: the
later of the unthreaded receipt and the scope's threaded receipt or own-event
mark (`m.read` or `m.read.private`). `unread_thread_notifications` splits
threads out when the filter asks; otherwise they fold into the room counts.
`GET /notifications` pages newest first (`next_token` = stream position,
`only=highlight`), with `read` from the same read points.

**Delivery.** One `POST` per pusher and event to `data.url` (must have path
`/_matrix/push/v1/notify`; http or https). Full format: `event_id`, `room_id`,
`type`, `sender`, `sender_display_name`, `room_name`, `room_alias`, `content`,
`user_is_target`/`membership` for member events; `event_id_only`: `event_id`,
`room_id`, `counts`, `devices`, `prio`. `counts.unread` is the user's total
unread notifications (omitted when 0). `devices[]` carries `app_id`, `pushkey`,
`pushkey_ts` (seconds), `data` minus `url`, and the rule's tweaks. `prio` is
high for sound/highlight/encrypted. 5xx/429/network errors retry with backoff
`base * 2^attempts` (base `CONDUIT_PUSH_RETRY_BASE_MS`, default 1000 ms, cap 10
min) for 24 h; other 4xx drop the notification; pushkeys listed in `rejected`
lose their pusher. `pushers/set` validates required fields (`M_MISSING_PARAM`),
`app_id` <= 64 chars, `pushkey` <= 512 bytes, URL path and `format`
(`M_INVALID_PARAM`); `kind: null` deletes; `append: false` removes other users'
pushers with the same app ID and pushkey. Email pushers are refused.
