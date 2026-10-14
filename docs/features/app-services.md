# Application Services

**Spec reference:** [Application Service API]
**Default:** on
**Depends on:** [`client-server-api`](client-server-api.md)

[Application Service API]: https://spec.matrix.org/latest/application-service-api/

## What this is

Application services ("AS", colloquially "bridges") are external
programs that act as Matrix users (and rooms) on this server. They're
how Matrix talks to Discord, Telegram, IRC, Slack, etc. — but also
how you'd build a bot framework or a custom integration.

An AS registers via static config (a `registration.yaml`) and is
trusted by the server.

## What the homeserver needs to do

- Load AS registrations at startup. Each registration declares a
  shared secret, a base URL, namespaces (regex patterns for users,
  aliases, rooms it claims).
- Forward events to each AS for events matching its namespaces.
  Format: `PUT /_matrix/app/v1/transactions/{txnId}` to the AS.
- Accept AS-authenticated CS-API calls: an AS uses its `as_token`
  instead of a user access token, and can `?user_id=` to act-as any
  user in its namespace.
- Mask the AS-owned user IDs and aliases so regular CS-API can't
  collide.

## Endpoints (Server → AS)

| Endpoint                            | Purpose                              |
|-------------------------------------|--------------------------------------|
| `PUT /transactions/{txnId}`         | Push events.                         |
| `GET /users/{userId}`               | Existence query.                     |
| `GET /rooms/{alias}`                | Existence query.                     |
| `GET /thirdparty/...`               | Protocol metadata for 3PID bridges.  |

## Endpoints (AS → Server)

The AS uses any CS-API endpoint with `Authorization: Bearer {as_token}`
and optionally `?user_id={target_user}`.

## Implementation approach

1. Registration loading is dumb config parsing. Validate that
   namespaces are disjoint between registered services.
2. Transaction pushing should be its own queue per AS, with retries
   and a stable `txnId` — the AS may dedupe on it.
3. "Ghost user" registration: when an AS first sends as a user in
   its namespace, auto-create that user account.

## Gotchas

- An AS effectively has admin powers over its namespace. Compromise
  of an AS token is full compromise of that bridge's users.
- The AS protocol is **older** than most of Matrix and has weird
  edges (token in URL on some legacy paths, polling endpoints, ...).
  Read the spec, don't assume.
- 3PID protocols (Telegram phone numbers, etc.) are negotiated via
  `/thirdparty` endpoints, which most servers stub.
- An AS may legitimately need to backfill events as a user joining
  late; allow `ts=` on send.

## Ping, third-party lookups and network directories (conduit-y99.20)

- Registration `url: null` is accepted: nothing is pushed to that AS and
  `POST /_matrix/client/v1/appservice/{id}/ping` answers `M_URL_NOT_SET`.
  Ping calls `POST /_matrix/app/v1/ping` with `Authorization: Bearer
  <hs_token>`, a 10s timeout (`504 M_CONNECTION_TIMEOUT`), and maps non-2xx
  to `502 M_BAD_STATUS` (with `status`/`body`) and transport failures to
  `502 M_CONNECTION_FAILED`.
- Registration `protocols: [...]` feeds `/thirdparty/protocols`; instances
  get `instance_id = "{as_id}|{network_id}"`. Location/user lookups
  aggregate the AS answers; an empty aggregate is `404 M_NOT_FOUND`.
- `PUT /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}`
  (as_token) maintains per-network lists read by `/publicRooms` with
  `include_all_networks` or `third_party_instance_id`.

## Transaction push (conduit-y99.34)

Code: `conduit-server/src/appservice_push.rs`, `app_service::as_request`.
Tests: `conduit-server/tests/production_appservice.rs` (mock AS in-test).

- One worker per AS with a URL. It folds the event stream (and, with
  `receive_ephemeral: true` — or the pre-stable
  `de.sorunome.msc2409.push_ephemeral` — receipts, typing and presence)
  into transactions of at most 100 events.
- **Durable queue.** The next transaction is frozen in Postgres
  (`appservice_txns`, migration 0080) in the same SQL transaction that
  advances the AS cursor (`appservice_stream`: event and receipt
  positions, next txnId). Only one transaction is in flight; it is
  retried with the same txnId and byte-identical body until 2xx
  (exponential backoff from `CONDUIT_AS_BACKOFF_BASE_MS`, default 1s,
  capped at 10 min), including across restarts. A new AS starts at the
  stream heads (no history backfill).
- **Auth.** `Authorization: Bearer <hs_token>` on every HS→AS request.
  On 404/405 from `/_matrix/app/v1/...` the legacy unprefixed route is
  tried with `?access_token=` (spec "legacy routes"); the current route is
  tried first every time. User/alias queries retry 3x on network error/5xx.
- **Interest.** An event is pushed if its room ID matches a `rooms`
  regex; any room alias (directory aliases and `m.room.canonical_alias`
  `alias`/`alt_aliases`) matches an `aliases` regex; or a *local* user
  that is the AS sender or matches a `users` regex is the sender, the
  `m.room.member` target, or a joined member. Interest is evaluated on
  current room state when the transaction is built.
- **Ephemeral.** `m.typing`/`m.receipt` carry `room_id` and follow room
  interest; `m.read.private` only for namespace users; `m.presence` when
  the user is interesting or shares an interesting room. Typing/presence
  cursors are process-local (their stores are in-memory); receipts are
  durable with the event cursor.
- Not in v1.19 (MSC-only, not implemented): to-device and device-list
  data for application services (MSC2409 to_device, MSC3202).

## Client-server API extensions (conduit-y99.35, conduit-y99.18.1)

Code: `conduit-server/src/api/client/appservice_auth.rs` (+ small hooks in
`mod.rs`, `devices.rs`, `keys.rs`, `directory.rs`, `rooms.rs`,
`registration.rs`, `rate_limit.rs`, `event_pipeline.rs`).

- **Identity assertion.** `AuthedUser` accepts an `as_token`. The request
  acts as `?user_id=` (default: the AS sender user, auto-created), which
  must be a *registered* local user in a `users` namespace — otherwise
  `403 M_FORBIDDEN` (spec: "the server should verify that the given
  user_id is registered by the appservice"). `?device_id=` (v1.17; the
  `org.matrix.msc3202.device_id` name is accepted) must belong to that
  user (`400 M_UNKNOWN_DEVICE`); without it the request is device-less
  (`whoami` omits `device_id`, `/keys/upload` is `400 M_MISSING_PARAM`).
  `AuthedUser.appservice` names the asserting AS; `grant` is `None`.
- **Timestamp massaging.** Route-layer middleware: `?ts=` on
  `PUT /rooms/{id}/send/...` and `PUT /rooms/{id}/state/...` from an
  `as_token` runs the handler inside a `tokio::task_local!` that the event
  pipeline reads for `origin_server_ts`. Bad values: `400 M_INVALID_PARAM`.
- **Registration / login.** `/register` with `type:
  m.login.application_service` requires the `as_token` (401
  `M_MISSING_TOKEN`/`M_UNKNOWN_TOKEN`). `POST /login` type
  `m.login.application_service` is advertised when any AS is registered:
  `403 M_FORBIDDEN` for a bad token or unregistered user, `403
  M_EXCLUSIVE` outside the namespace.
- **Exclusivity.** Aliases inside another AS's exclusive namespace (and
  an AS creating aliases outside its own) are `400 M_EXCLUSIVE` on
  `PUT /directory/room/{alias}` and `createRoom` `room_alias_name`.
- **Rate limits.** `CsRateLimiter::with_appservices`: the AS sender is
  never limited; masqueraded users only when `rate_limited: true`.
  The authenticated bucket defaults to 100 requests/second with a burst
  of 200. `CONDUIT_CS_AUTH_RATE_PER_SECOND` (finite, at least 0) and
  `CONDUIT_CS_AUTH_BURST` (finite, at least 1) override it; malformed
  values fail startup. A rate of 0 never refills, so the isolated
  production rate-limit journey uses rate 0 / burst 2 to assert real
  `M_LIMIT_EXCEEDED` responses independently of runner speed. Anonymous
  limits remain 10 requests/second with a burst of 20.
- **Devices / cross-signing (v1.17).** `PUT /devices/{id}` creates a device
  for the asserted user (201, 200 on update); `DELETE /devices/{id}`,
  `POST /delete_devices` and replacement `keys/device_signing/upload` skip
  UIA for application services.

## Third-party invites and identity servers (conduit-y99.36)

Code: `conduit-server/src/api/client/third_party.rs` (handlers),
`conduit-server/src/identity_service.rs` (IS client),
`conduit/src/auth.rs` (`check_third_party_invite`).
Tests: `conduit-server/tests/production_appservice.rs` (mock identity
server in-test), `conduit/tests/third_party_invite_auth.rs`.

- **`POST /rooms/{id}/invite` 3PID form** (and `createRoom.invite_3pid`):
  the address is canonicalised (email case-folded, msisdn E.164 digits),
  then `GET /hash_details` + `POST /lookup` (sha256 of
  `"{address} {medium} {pepper}"`, URL-safe unpadded base64) with
  `Bearer id_access_token`. A bound 3PID gets a normal invite; otherwise
  `POST /store-invite` and an `m.room.third_party_invite` (state key = token,
  `display_name`, `public_key`, `key_validity_url`, `public_keys`).
- **`PUT /_matrix/federation/v1/3pid/onbind`** (unauthenticated, called by
  identity servers; mounted outside the federation router): for rooms on
  this server the `signed` proof becomes an `m.room.member` invite from the
  original inviter with `content.third_party_invite`; the v11 auth rules
  verify mxid/token/sender and the Ed25519 signature against the
  `m.room.third_party_invite` keys. Remote rooms need
  `exchange_third_party_invite` (conduit-y99.22.6).
- **Account bindings:** `/account/3pid/bind` proxies to the IS and
  remembers `(user, medium, address, id_server)`
  (`threepid_id_server_bindings`, migration 0080); `/unbind`, `/delete`
  and `/account/deactivate` send a homeserver-signed (X-Matrix)
  `/3pid/unbind` and report `id_server_unbind_result`.
- **Safety:** `id_server` must be `hostname[:port]`; requests use HTTPS and
  the outbound SSRF policy (`safe_fetch`), so private/loopback identity
  servers are refused unless allow-listed (`CONDUIT_IS_ALLOW_CIDRS`).
  `CONDUIT_IS_INSECURE_HTTP=1` switches to HTTP for local testing.
- Still refused (conduit-y99.36.1): homeserver-validated 3PIDs —
  `requestToken`, `/account/3pid/add`, deprecated `POST /account/3pid`.
