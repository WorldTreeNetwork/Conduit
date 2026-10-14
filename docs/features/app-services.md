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
