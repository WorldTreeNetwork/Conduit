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
4. Successful room-send and to-device `txnId` results persist atomically with
   their effects, scoped to the device and complete endpoint path. An in-memory
   cache cannot establish restart durability or concurrent idempotency.
   Definitive client errors are retained as well. The authenticated device and
   endpoint identify the original request; completed results replay before a
   later body is parsed. Revoked credentials still fail authentication, and a
   new token for the same device retains its transaction scope.

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

## Sync room transitions and pagination

Sync now enumerates current user memberships. Invitations produce a stripped
preview (safe room metadata and the invitee/inviter membership); acceptance
introduces joined-room state; leave/ban transitions produce a bounded departure
block. Post-departure messages do not appear in that block, and unchanged
invitations/departures are omitted from incremental responses. `include_leave`
controls initial departed-room inclusion. Knock preview serialization exists,
but the full knock API/journey remains required work.

State snapshots precede the returned timeline. Clients fold timeline state
events into them; a short initial timeline may contain the create/join events
rather than duplicating them in the state array. Limited gaps include state
changes omitted from the timeline. `full_state=true` returns room state
immediately, and filter limits are validated as strictly positive, as required by the specification.

`prev_batch` uses the actual insertion position before the first timeline event.
The messages endpoint accepts these opaque sync prefixes and validates malformed
cursors. Backward pagination fetches omitted events without repeating the boundary.
MemoryStorage now uses immutable insertion positions independently of DAG depth,
as PostgreSQL does. Purges retain a durable high-water mark instead of moving the
global stream backwards. Full DAG-resolved historical state snapshots, remaining
filter/format edges, and knock endpoints remain under `conduit-y99.13` and the
persist/state-resolution audit; these local-history checks are not whole-protocol
conformance proof.

## Stored and inline filters

POST/GET `/user/{userId}/filter` persist a user's filter definition in PostgreSQL
and require the authenticated owner. Sync resolves an opaque ID for that user;
unknown IDs and malformed inline definitions produce Matrix errors. Type wildcard
patterns, inclusion/exclusion lists, URL predicates, event field paths (including
escaped dots), room selection and positive limits share the same model for both
forms. Exclusions win; an empty allowed list selects no events.

Presence/account data, room state, timeline, ephemeral and room account-data
criteria are applied on their own streams. Limited account-data and presence
responses retain cursors before omitted updates so the next request delivers the
remainder. Lazy state selects the syncing user and timeline senders, preserving
historical membership events with different event IDs. Redundant sender memberships
may still be resent, as permitted by the specification. Further federation-format
and state/ephemeral limit edge auditing remains under `conduit-y99.13.4`.

### Summaries, unread counts and lazy-loading redundancy (conduit-y99.13.4)

Every joined room block carries `summary` (`m.joined_member_count`,
`m.invited_member_count`, and `m.heroes` when the room has no name or
canonical alias: up to five other joined/invited members in membership order,
else departed ones). Heroes join the requester and timeline senders as the
members lazy loading must include.

`unread_notifications` evaluates the user's effective push rules (stored rules
plus unstored defaults, by kind then priority) over events after the read-up-to
point: the later of the unthreaded receipt and the scope's threaded receipt
(`m.read` or `m.read.private`, whichever is ahead), with the user's own latest
event in a scope also marking it read. Thread membership follows relations up
to three hops. With `unread_thread_notifications` on the timeline filter the
main count excludes threads and `unread_thread_notifications` holds per-root
counts (`room_summary.rs`, `notification_counts.rs`).

Lazy loading omits member events already delivered to the device unless
`include_redundant_members` is set. A delivery counts only once the client's
`since` reaches the response that carried it, so a retried token re-sends;
initial and full-state syncs forget the device's deliveries. Ephemeral limits
take receipts as a stream-ordered prefix (typing plus one `m.receipt` per
thread scope per room) and leave the cursor before the first receipt that does
not fit; state limits trim after sorting required members first.

### Local echo, history visibility and state paths (conduit-y99.27/.26/.47)

Sync adds `unsigned.transaction_id` to timeline events created by the
requesting device (looked up from its stored client transactions; other
devices never see it). History visibility is judged per event from the
`m.room.history_visibility` in force before it (default `shared`), with the
spec's before-or-after exceptions for visibility events and the user's own
membership, so members can page back to `m.room.create`. `/messages` omits
`end` when no further events exist. `PUT`/`GET /state/{eventType}/` (trailing
slash) equal the empty-state-key form (`state_paths.rs`).

## Directories and knocking

Implemented in `room_directory.rs`, `directory.rs`, `user_directory.rs` and
`knock.rs` (conduit-y99.20); journeys in `tests/production_directory.rs`.

- **Published room directory.** `room_directory` (local) and
  `appservice_room_directory` (per AS network) tables, migration 0030.
  `createRoom` with `visibility: public` publishes. `/publicRooms` builds
  each chunk from current state (`room_chunk`), filters
  (`generic_search_term` over name/topic/aliases/room ID, `room_types` with
  `null` = untyped), sorts largest-first then by room ID, and pages with
  opaque offset tokens `n{offset}` / `p{offset}`. `include_all_networks`
  adds AS network rooms; `third_party_instance_id` (`{as_id}|{network_id}`)
  selects one network. `server=<remote>` proxies federation
  `GET /publicRooms` and filters that page locally.
- **Who may publish.** `PUT /directory/list/room/{roomId}` and alias
  `DELETE` need a server admin or a joined member who could send
  `m.room.canonical_alias` (`conduit::auth::may_send_state_event`). Alias
  creators may always delete their own alias.
- **Aliases.** Malformed or foreign aliases are `400 M_INVALID_PARAM`;
  `createRoom` `room_alias_name` checks availability first
  (`400 M_ROOM_IN_USE`) and then sets `m.room.canonical_alias`.
- **User directory.** One SQL query: users joined to rooms the requester
  shares, or rooms with `public` join rule or `world_readable` history;
  account profile preferred over member-event profile; shared-room users
  first; one extra row fetched to compute `limited`.
- **Knocking.** `POST /knock/{roomIdOrAlias}` writes `membership: knock`
  through the normal pipeline; v11 auth decides. Accept = invite (then
  join), deny = kick, rescind = leave. `/sync` reports `rooms.knock` with
  stripped `knock_state`. Federated knocks (`make_knock`/`send_knock`) are
  not implemented.

## Room content

Implemented in `conduit-server/src/api/client/room_content/` with pure rules in
`conduit/src/room_content.rs` (conduit-y99.19); journeys in
`tests/production_rooms.rs`. Migration 0020 adds partial indexes over the event
log plus `room_forgotten` and `content_reports`.

- **Serving (`serve.rs`).** One `Viewer` decides how a stored event looks to a
  user. Redactions are applied at serve time from the log: a redaction applies
  when its sender shares the target sender's server or held `redact` in the
  power levels named by the redaction's own `auth_events` (demoting a moderator
  later does not un-redact). Redacted events are pruned with
  `conduit::redaction::redact_event` and carry `unsigned.redacted_because`.
  Bundles (`unsigned.m.relations`) cover `m.replace` (latest valid edit by
  `origin_server_ts` then event ID; original content is never replaced),
  `m.thread` (`count`, `latest_event` with its own edit bundle,
  `current_user_participated`) and `m.reference` (`chunk` of IDs); children must
  be visible, unredacted and not from ignored users. This module's endpoints
  emit the client format; `/sync` (bundles only when `limited`) and
  `/messages` decorate their PDU-shaped values in place.
- **Access (`RoomAccess`).** Joined users see current state and visible history;
  departed users keep what they could see up to their leave/ban (members as of
  the departure) until they `/forget`; `world_readable` rooms are readable by
  anyone authenticated. Unknown and invisible events are both `404 M_NOT_FOUND`.
- **Tokens.** Every position token is an inclusive stream cursor (`s{pos}`), so
  `/context` `start`/`end`, `/relations` `next_batch` and `/sync`/`/messages`
  tokens interchange. `/members?at=` is clamped to the caller's horizon.
- **Redact.** `PUT /redact` replays through the persisted transactions table.
  Own events need the `m.room.redaction` level (pipeline auth); others' events
  need `redact`, except server admins redacting local users. `/send` of
  `m.room.redaction` applies the same check; `/send` also rejects duplicate
  annotations (`M_DUPLICATE_ANNOTATION`) and threads rooted at relations
  (`400 M_UNKNOWN`, answered without freezing the transaction because replay
  maps `M_UNKNOWN` to 500).
- **Forget.** The marker records the departure event it forgot, so a later
  membership change un-forgets without a write hook. Forgotten departures leave
  `/sync` and all history endpoints.
- **Read markers / tags.** `m.fully_read` is room account data; `m.read` and
  `m.read.private` are receipts. Tags live in `m.tag` room account data and
  appear in `/sync`.
- **Relations / threads.** `recurse=true` follows three levels and reports
  `recursion_depth`; `rel_type` filters every level, `eventType` the results.
  `/threads` orders roots by latest child position; `include=participated`
  counts the root sender and repliers; roots from ignored users are served
  redacted.
- **Search.** `websearch_to_tsquery('english')` over one partial GIN index per
  key (`body` of `m.room.message`, `name` of `m.room.name`, `topic` of
  `m.room.topic`). Candidates (at most 1000 per request) come from rooms the
  user is in or left, then pass visibility, forget, ignore, redaction and the
  request filter before `count` and offset pagination (`o{offset}`).
- **Reports.** Event reports need current membership; room and user reports do
  not. Admins list them at `GET /_matrix/conduit/admin/v1/reports`.
- **Upgrade.** Checks tombstone permission, creates the replacement with
  `predecessor` and the old `type`, copies the recommended state, moves local
  and canonical aliases, tombstones the old room and raises its
  `events_default`/`invite` to max(50, users_default + 1).
- **Hierarchy.** Depth-first over valid `m.space.child` (non-empty `via`),
  ordered by `order`, `origin_server_ts`, room ID; tokens pin `suggested_only`
  and `max_depth`. Rooms unknown locally are skipped (federation fill-in is
  conduit-y99.19.2).
- **Ignored users.** Non-state events from `m.ignored_user_list` users are
  dropped before timeline limits in `/sync`, and from `/messages`, `/context`,
  relations, aggregations and search; their invites are not delivered.
## Account, devices and sessions (conduit-y99.18)

Module map (`conduit-server/src/api/client/`): `account.rs` (router for the
whole lane, password, deactivation, 3PIDs, whois), `devices.rs`,
`registration.rs`, `session.rs` (token issuance, `/refresh`,
`/login/get_token`, device removal, last-seen, guest gate), `uia.rs`,
`auth_fallback.rs`, `well_known.rs`, `account_config.rs` (environment knobs).

**Tokens.** Access tokens are Biscuits bound to the device epoch. Every login
on-ramp goes through `session::issue_session`: a known `device_id` keeps the
device (and its E2EE keys) but advances the epoch, invalidating the device's
previous access and refresh tokens (spec: relationship between tokens and
devices). Deleting a device retires its epoch in `retired_device_epochs`, so a
device recreated with the same ID can never resurrect old tokens. Logout and
`/logout/all` delete devices, as the spec requires.

**Refresh and soft logout.** `refresh_token: true` on login/register issues a
hashed refresh token bound to the device epoch and an access token living
`CONDUIT_REFRESH_TOKEN_ACCESS_LIFETIME_MS` (default 5 min); without it tokens
live 30 days and `expires_in_ms` says so. `/refresh` rotates: the old token
stays usable until the new one is used (siblings issued from a reused token are
revoked). An expired token answers `401 M_UNKNOWN_TOKEN` with
`soft_logout: true`; a deleted device or moved epoch answers `soft_logout:
false`. Tokens are also accepted from the deprecated `access_token` query
parameter.

**UIA.** In-memory sessions bound to the operation and the user; stages must
follow an offered flow in order; completed stages are not re-run; sessions are
deleted on success (so `/login/get_token` always re-prompts). Accounts with a
password get `m.login.password`; passwordless (identikey/SSO) accounts get
`m.login.dummy` for now. The fallback page (`/auth/{type}/fallback/web`) serves
password, dummy and registration-token stages and ends with the
`onAuthDone`/`postMessage("authDone")` script.

**Registration.** Username problems (`M_INVALID_USERNAME`, `M_EXCLUSIVE`,
`M_USER_IN_USE`) are returned before UIA. Usernames map to lowercase
localparts; purely numeric localparts are reserved for guests. Missing
usernames are generated. `inhibit_login`, application-service registration
(`as_token` bearer, namespace enforced) and `CONDUIT_REGISTRATION_TOKENS`
(`m.login.registration_token` flow + `/validity`) are supported;
`CONDUIT_ALLOW_REGISTRATION=false` disables `kind=user`.

**Guests.** `CONDUIT_ALLOW_GUEST_ACCESS=true` enables `kind=guest`
(numeric user ID, all parameters but `initial_device_display_name` ignored).
The `AuthedUser` extractor confines guests to the spec's guest endpoint list
plus sync housekeeping (`session::GUEST_ALLOWED`), answering
`403 M_GUEST_ACCESS_FORBIDDEN` otherwise, and only lets them join rooms whose
`m.room.guest_access` is `can_join`. Guests upgrade by registering with
`guest_access_token` and their own localpart.

**Deactivation.** Leaves joined/invited/knocked rooms, deletes pushers and all
devices (tokens, keys), marks the account; `erase: true` also clears profile and
account data and records `accounts.erased_at`. The admin API deactivates the
same way. Login then answers `M_USER_DEACTIVATED`.

**3PIDs.** None are stored; there is no identity-server client and no outbound
email/SMS. `GET /account/3pid` is empty, add/bind/legacy-add are `403
M_FORBIDDEN` (`m.3pid_changes` disabled), delete/unbind return
`id_server_unbind_result: no-support`, every `requestToken` is `403
M_THREEPID_DENIED`, and deactivation reports `success` (nothing to unbind).

**Discovery.** `/.well-known/matrix/client` uses
`CONDUIT_WELL_KNOWN_CLIENT_BASE_URL` or the origin the request reached
(`X-Forwarded-Host/Proto` aware), plus `CONDUIT_WELL_KNOWN_IDENTITY_SERVER`.
`/.well-known/matrix/server` is 404 unless `CONDUIT_WELL_KNOWN_SERVER` is set.
`/.well-known/matrix/support` uses `CONDUIT_SUPPORT_CONTACTS` (JSON array) and
`CONDUIT_SUPPORT_PAGE`, defaulting to local admins; 404 when nothing is known.
CORS is the global `*` layer. `GET /admin/whois/{userId}` is limited to the user
and server admins and reports last-seen IP, timestamp and user agent per device.

## API standards and discovery (conduit-y99.28)

`conduit-server/src/api/client/standards.rs` owns the cross-cutting rules.
`normalize_errors` is a `map_response` layer on the whole app: axum's empty
404/405 become `404|405 M_UNRECOGNIZED` (the `Allow` header survives), JSON
error bodies from handlers pass through untouched, and every `429` gains a
`Retry-After` header (seconds, rounded up) derived from `retry_after_ms` when a
source did not set one. `/versions` lists v1.1-v1.19 from
`conduit::api::client::SUPPORTED_VERSIONS` with an empty `unstable_features`.
`GET /_matrix/client/v1/auth_metadata` answers `404 M_UNRECOGNIZED` (OAuth 2.0
unsupported; legacy `/login` is the advertised API). Capabilities advertise
only `conduit::ROOM_VERSION`. `PUT` account data of the server-managed types
`m.fully_read`/`m.push_rules` (global or per room) is `405 M_BAD_JSON`.

## Membership, summaries, mutual rooms, invite permission (conduit-y99.29)

`conduit-server/src/api/client/room_membership.rs`:

- `POST /rooms/{roomId}/join` shares `rooms::join_room`; aliases are
  `400 M_INVALID_PARAM`. `reason` is written to the member event on join,
  invite, leave, kick, ban and unban (`Room::*_with_reason`).
- `GET /v1/room_summary/{roomIdOrAlias}` builds the summary from local
  current state. Authentication is optional; anonymous callers see only
  public/knock/knock_restricted or world-readable rooms, members see rooms they
  are joined/invited/knocked in or (restricted) can join through an allowed
  room. Anything else is `404 M_NOT_FOUND` so existence is not leaked. Remote
  rooms (`via`) are conduit-y99.29.2.
- `GET /v1/mutual_rooms` pages sorted room IDs; `next_batch` is a base64 token
  bound to the queried user and valid for an hour. Batch size defaults to 100
  (`CONDUIT_MUTUAL_ROOMS_BATCH` overrides it, used by tests).
- Invite permission: `m.invite_permission_config` with `default_action: block`
  makes `/invite`, PUT `m.room.member` invite state and `createRoom` (checked
  before the room is created) answer `403 M_INVITE_BLOCKED`; `/sync` hides the
  user's pending invites while blocked. The federation `/invite` hook is
  conduit-y99.29.1.
## Profiles, key backup, moderation and server notices (modules lane)

Journeys: `conduit-server/tests/production_modules.rs`.

**Profiles** (`api/client/profile.rs`, conduit-y99.38/.25). `displayname` and
`avatar_url` stay on `accounts`; `m.tz` and namespaced custom keys live in
`profile_fields` (migration 0070). `PUT|DELETE /profile/{userId}/{keyName}`
validates the key grammar (`M_INVALID_PARAM`), key length (`M_KEY_TOO_LARGE`),
the body property (`M_MISSING_PARAM`), value types (`M_BAD_JSON`) and the 64 KiB
whole-profile limit (`M_PROFILE_TOO_LARGE`). `null` custom values are stored;
`null` displayname/avatar clears. A displayname/avatar change sends an updated
`m.room.member` join into every joined room and an `m.presence` update carrying
the new values; the event pipeline also fills a local user's own join with
their profile. Lookups are open by default; `CONDUIT_PROFILE_LOOKUP=restricted`
answers only self, shared rooms, and users joined to public or world-readable
rooms, `403 M_FORBIDDEN` otherwise (unknown users too). `m.profile_fields` is
advertised (guests: `allowed: ["displayname"]`).

**Key backup** (`api/client/keys.rs`, conduit-y99.39). Writes go only to the
current version (`403 M_WRONG_ROOM_KEYS_VERSION` + `current_version`; no backup
is 404). Uploads follow the spec replacement order (is_verified, then lower
first_message_index, then lower forwarded_count) and require all four
`KeyBackupData` fields. The etag is a counter that moves only when stored keys
change; auth_data updates keep it. Deleting a version deletes its keys and is
idempotent; never-existing versions are 404.

**Account moderation** (`api/client/moderation.rs`, conduit-y99.43).
`GET|PUT /_matrix/client/v1/admin/lock|suspend/{userId}`; state in
`account_moderation` (migration 0071). Enforcement is one point lookup in the
`AuthedUser` extractor: locked accounts get `401 M_USER_LOCKED` +
`soft_logout: true` everywhere except logout; `issue_session` and `/refresh`
refuse them too. Suspended accounts get `403 M_USER_SUSPENDED` on join, knock,
invite, send, state, createRoom, upgrade, profile writes and redacting other
users' events.

**Server notices** (`api/client/server_notices.rs`, conduit-y99.41). Operators
call `POST /_matrix/conduit/admin/v1/server_notices`
`{"user_id", "content"}`. The system account
`@${CONDUIT_SERVER_NOTICES_LOCALPART:-server-notices}:server` creates one room per
user (`server_notice_rooms`, migration 0072), invites the user, tags it
`m.server_notice`, and sends `msgtype: m.server_notice`. Rejecting the invite is
`403 M_CANNOT_LEAVE_SERVER_NOTICE_ROOM`; leaving after joining is allowed and
the next notice re-invites.
