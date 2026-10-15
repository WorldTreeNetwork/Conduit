# Client: the Conduit web client

**Default:** the static SvelteKit app in `web/` (not part of the Rust
workspace). **Depends on:** a homeserver speaking the Matrix
Client-Server API v1.x — Conduit or any other. **Tracking:**
`conduit-y99.9`.

The client is Conduit's own Matrix client. It is TypeScript + SvelteKit,
run with Bun (`packageManager`: `bun@1.3.14`). There is no application
server: `adapter-static` builds a SPA and the homeserver is the backend.

## Layout

```
web/
  src/core/          framework-free Matrix CS-API core (no UI-framework imports)
  src/lib/           Svelte screens, shadcn-svelte primitives, tokens
  src/routes/        the static SPA
  tests/             Playwright journeys and bun:test unit tests
```

## Protocol core (`web/src/core`)

| Module | Responsibility | Spec |
|---|---|---|
| `http.ts` | One request with JSON, bearer auth, Matrix error parsing (`MatrixError` with `errcode`, `httpStatus`, `retryAfterMs`), 429 handling honouring `Retry-After` (seconds) over `retry_after_ms`, exponential backoff for 5xx and connection failures, per-attempt timeouts. Injectable `Transport`. | [API standards](https://spec.matrix.org/v1.19/client-server-api/#api-standards), [rate limiting](https://spec.matrix.org/v1.19/client-server-api/#rate-limiting) |
| `clock.ts` | Injectable `Clock`; `ManualClock` steps time deterministically in tests. | — |
| `discovery.ts` | Full URL → validate `/versions`; server name or `@user:server` → `.well-known/matrix/client` with IGNORE (404/unreachable falls back to `https://server`), FAIL_PROMPT (bad well-known) and FAIL_ERROR (not a homeserver). | [Server discovery](https://spec.matrix.org/v1.19/client-server-api/#server-discovery) |
| `auth.ts` | `m.login.password` with `m.id.user`; registration through UIA, completing `m.login.dummy` (and `m.login.password` where credentials are supplied); unsupported flows fail with the stage names; `well_known` in the login response overrides the base URL. | [Login](https://spec.matrix.org/v1.19/client-server-api/#login), [UIA](https://spec.matrix.org/v1.19/client-server-api/#user-interactive-authentication-api) |
| `sync.ts` | `/sync` loop: initial sync with `timeout=0`, long-poll (`timeout=30000`) once live, `timeout=0` again after any failure so "live" returns as soon as the server answers. Health states `connecting → live ⇄ reconnecting`, fatal `error` on `M_UNKNOWN_TOKEN`; backoff 1s doubling to 15s or the server's `Retry-After`; `retryNow()` skips the wait; a 400 on a stale `since` falls back to an initial sync. | [Syncing](https://spec.matrix.org/v1.19/client-server-api/#syncing) |
| `room.ts` | Room model: authoritative `state_after` when provided, otherwise `state` then timeline state; historical events (`/messages`) never change current state; de-duplication by event ID; a `limited` timeline resets the window and restarts history at `prev_batch`; room name per spec (name → canonical alias → heroes, "Empty room (was …)"); member display-name disambiguation; power levels; snapshots for persistence. | [Room display name](https://spec.matrix.org/v1.19/client-server-api/#calculating-the-display-name-for-a-room), [user display name](https://spec.matrix.org/v1.19/client-server-api/#calculating-the-display-name-for-a-user) |
| `sendQueue.ts` | Local echo. Each send gets a transaction ID once and keeps it across retries, failures and restarts (server idempotency makes retries safe). Sends are serialized per room. Echoes are reconciled by event ID (or `unsigned.transaction_id`), including when the remote echo arrives before the PUT response. Failed sends stay with their error until retried or discarded; the queue is persisted. | [Transaction identifiers](https://spec.matrix.org/v1.19/client-server-api/#transaction-identifiers) |
| `client.ts` | `MatrixClient` facade: owns HTTP, sync, rooms and queue; `subscribe`/`getVersion` for `useSyncExternalStore`; actions (create/join/leave/invite/accept/decline, paginate, receipts, profile); persistence of the session, the since token plus a room snapshot (last 50 events per room) and pending sends; `awaitIdle()`. | — |
| `relations.ts` | Aggregates edits (`m.replace`, valid only from the original sender; bundled `unsigned.m.relations` fill gaps), reactions (`m.annotation`, grouped per key, de-duplicated per sender, own event kept for un-reacting), threads (`m.thread` replies hidden from the main timeline, summaries merged with bundled counts) and redactions (client-side redaction algorithm applied to timeline, thread history and state); strips legacy reply fallbacks. | [Relationships](https://spec.matrix.org/v1.19/client-server-api/#forming-relationships-between-events), [redactions](https://spec.matrix.org/v1.19/client-server-api/#redactions) |
| `media.ts` | `POST /_matrix/media/v3/upload`, authenticated `GET /_matrix/client/v1/media/download|thumbnail` as blobs (object URLs cached per URI/size, revoked on logout), mxc parsing, msgtype from MIME type. Attachments go through the send queue: upload, then send with `content.url`, same txn ID. | [Content repository](https://spec.matrix.org/v1.19/client-server-api/#content-repository) |
| `crypto.ts` | `CryptoBackend` seam for `@matrix-org/matrix-sdk-crypto-wasm`'s `OlmMachine` (phase 3): receives every sync's to-device/device-list/OTK data, decrypts `m.room.encrypted`, encrypts sends in encrypted rooms. The default `noCrypto` refuses sends in encrypted rooms with a clear error rather than sending plaintext. | [E2EE](https://spec.matrix.org/v1.19/client-server-api/#end-to-end-encryption) |

### Tokens, refresh and soft logout

Login and registration request `refresh_token: true`. Any request that
fails with `M_UNKNOWN_TOKEN` and `soft_logout: true` triggers one shared
`POST /refresh` (concurrent 401s wait for the same refresh) and is
retried once with the new token; rotated tokens are persisted at once.
If refreshing is impossible the client enters **soft logout**: sync and
sends stop, everything local is kept, and a re-authentication screen
signs in again with the same `device_id` (keeping the device and, later,
its keys); unsent messages can then be retried. `soft_logout: false`
(device deleted, password reset with logout) is a hard logout that wipes
local state.

The protocol core can still complete UIA with the account password
(`m.login.password`): signing out other devices (`/delete_devices`),
changing the password (`/account/password`), and deactivation
(`/account/deactivate`). The pages show those controls only when the
build sets `VITE_CONDUIT_PASSWORD` to `1`, `true`, `on`, or `yes`.
The default build leaves them out. Device list and rename stay.

### Persistence and reload

Sync requests set `use_state_after=true`. When a room supplies `state_after`,
including an empty section, the client applies only that section to current
room state. Timeline state events remain available as history; redactions still
update timeline content. When the server omits `state_after`, the client falls
back to folding `state` and timeline state events. The persisted snapshot keeps
the authoritative current state independently of the timeline window.

`localStorage` keys (prefix `conduit:`): `session` (homeserver, user,
token, device), `sync` (`since` + room snapshots), `pending` (unsent
messages). On start the client renders cached rooms immediately, then
syncs from the stored `since`. When a snapshot was trimmed, the stored
`prev_batch` would skip events, so it is dropped and back-pagination
restarts from the live end (`/messages` without `from`), skipping known
events. Logout (`POST /logout`) and `M_UNKNOWN_TOKEN` wipe all three keys.

### Server integration and compatibility

Conduit now propagates profile changes into joined-room membership events,
includes the sending device's `unsigned.transaction_id`, supports empty state
keys with a trailing slash, and paginates back through the creator's initial
join and room creation. Production journeys assert these behaviours.

The client retains compatibility with other homeservers: it updates its own
membership when the cached profile has not yet changed, and reconciles local
echoes by the event ID from the PUT response as well as the transaction ID.
Unread badges show `max(notification_count, local unread)`; local unread counts
messages after the user's read receipt or local read marker.

Settings ignores superseded profile fetches, so a late response cannot erase
an edited display-name draft. The browser profile journey deliberately releases
an old response after typing, then checks the saved name on the board and in
the room.

## UI (`web/`)

The screens live in `web/src/lib`. Station enamel (ground, ink, brass) is
`web/src/lib/styles/tokens.css`, with light and dark themes (system, or
forced in Settings). shadcn-svelte supplies button, input, dialog, scroll
area, dropdown menu, and avatar. The timeline, room list, and messages
are custom. Playwright runs axe on the signed-in shell and rejects serious
and critical violations.

Screens: sign in with Identikey when the homeserver offers `m.login.sso`.
The default build has no username or password fields. Set
`VITE_CONDUIT_PASSWORD=1` at build time to offer password registration,
login, password change, other-device sign-out, and deactivation. A key
the person holds uses the Identikey wallet. Room list (invites with accept/decline, unread lamps,
previews, skeleton loading, empty state), room view (topic, invite,
people panel, leave), timeline (day plates, sender grouping, folded
room setup, compact state lines, back-pagination with error/retry,
"beginning of room", jump to latest), composer (Enter sends,
Shift+Enter newline, `/me` emotes, inline retry/delete on failure),
create room / join by address / invite / leave dialogs (native
`<dialog>`), settings (display name, theme, session facts, sign out),
and a reconnecting banner driven by sync health.

Phase 2 surfaces: a per-message action toolbar (react, reply, reply in
thread, edit own, delete own or as moderator; visible on hover or keyboard
focus, always visible on touch), reaction chips (`aria-pressed` for your
own), reply quotes that jump to the original, "(edited)" markers, thread
summaries and a thread panel with its own composer, composer reply/edit
context (Escape cancels, ArrowUp edits your last message), attachments
with image previews and file cards, typing line, "seen by" receipt
plates, presence lamps, room settings (name, topic, picture, who can
join, history visibility, roles), the public room directory inside the
join dialog, user-directory suggestions when inviting, and account
settings (devices; password and deactivation only when
`VITE_CONDUIT_PASSWORD` is on) plus the soft-logout screen.

Accessibility: semantic landmarks and headings; skip link; roving
tabindex with arrow/Home/End through the room list and the timeline;
focus moves to the heading on route changes and to the composer when a
room opens; dialogs restore focus to their opener; `aria-live` for new
messages from others and for the connection banner; errors use
`role="alert"` and `aria-describedby`; `prefers-reduced-motion` stops
the carrier and lamp animations.

## Automation hooks

- **Homeserver:** `?hs=<url>` pins the server (and hides the field),
  else `VITE_CONDUIT_HOMESERVER`, else `http://localhost:8008`.
- **Injectable clock and transport** in the core for unit tests
  (`ManualClock`, `FakeServer` in `web/src/core/testing.ts`).
- Browser journeys talk to a real `conduit-server` and assert on the
  rendered page. They do not read an access token out of the page.

## Running

```bash
cd web
bun install
bun run dev              # http://localhost:5173 (point it at a homeserver with ?hs=)
bun run check            # svelte-check
bun run test             # protocol core and UI helper unit tests
bun run build            # static files in build/
bun run e2e              # Playwright against a real conduit-server
```

`bun run e2e` (`tests/support/server.ts`) runs `cargo build -p conduit-server`
(or uses `CONDUIT_SERVER_BIN`), creates a fresh database through `psql` on
`DATABASE_URL` (default `postgresql://postgres@localhost/postgres`), and
launches the binary with registration open, `CONDUIT_OIDC_ISSUER=off`, and
federation off. The static preview is served with `bun run preview`. CI
runs the same job from `.github/workflows/svelte-client.yml` on Chromium,
Firefox, and WebKit.

## Journeys covered (e2e)

| Spec file | Journey |
|---|---|
| `web/tests/session.spec.ts` | A session stored by the suite, profile, reload, sign-out, and a bound `loginToken` return. The signed-out page has no password fields. A visit with no pending-SSO record sends no login request. |
| `web/tests/chat.spec.ts` | Two people create a room, invite, accept, exchange messages, retry a failed send, page history, and open the app on a phone. |
| `web/tests/rest.spec.ts` | Settings, theme, device rename, image preview, members, presence, directory join, threads, room settings, and reconnect. The signed-in shell has no serious or critical axe violations. |

## Roadmap

Children of `conduit-y99.9`: E2EE through
`@matrix-org/matrix-sdk-crypto-wasm` behind `CryptoBackend` (`.1`),
device verification with SAS emoji and cross-signing (`.2`), key backup
(`.3`), notification settings and mentions (`.4`), rich text, DMs,
search, knocking, spaces, URL previews, inline audio/video (`.5`), and
Firefox/WebKit plus a manual screen-reader audit (`.6`).
