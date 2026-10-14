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
