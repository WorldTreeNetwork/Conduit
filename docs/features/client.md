# Client: the Conduit web client

**Default:** separate deliverable in `client/` (not part of the Rust
workspace). **Depends on:** a homeserver speaking the Matrix
Client-Server API v1.x — Conduit or any other. **Tracking:**
`conduit-y99.9`.

The client is Conduit's own Matrix client and its unattended
client-side verification harness. It is TypeScript + React 18 + Vite,
managed with pnpm (pinned `pnpm@9.15.4` through `packageManager`).

## Layout

```
client/
  src/core/        framework-free Matrix CS-API core (no React imports)
  src/ui/          React components and pure view logic
  src/styles/      tokens.css (design tokens, light + dark) and app.css
  src/testHook.ts  window.__conduitClient automation hook
  e2e/             Playwright journeys against the real conduit-server
```

## Protocol core (`client/src/core`)

| Module | Responsibility | Spec |
|---|---|---|
| `http.ts` | One request with JSON, bearer auth, Matrix error parsing (`MatrixError` with `errcode`, `httpStatus`, `retryAfterMs`), 429 handling honouring `Retry-After` (seconds) over `retry_after_ms`, exponential backoff for 5xx and connection failures, per-attempt timeouts. Injectable `Transport`. | [API standards](https://spec.matrix.org/v1.19/client-server-api/#api-standards), [rate limiting](https://spec.matrix.org/v1.19/client-server-api/#rate-limiting) |
| `clock.ts` | Injectable `Clock`; `ManualClock` steps time deterministically in tests. | — |
| `discovery.ts` | Full URL → validate `/versions`; server name or `@user:server` → `.well-known/matrix/client` with IGNORE (404/unreachable falls back to `https://server`), FAIL_PROMPT (bad well-known) and FAIL_ERROR (not a homeserver). | [Server discovery](https://spec.matrix.org/v1.19/client-server-api/#server-discovery) |
| `auth.ts` | `m.login.password` with `m.id.user`; registration through UIA, completing `m.login.dummy` (and `m.login.password` where credentials are supplied); unsupported flows fail with the stage names; `well_known` in the login response overrides the base URL. | [Login](https://spec.matrix.org/v1.19/client-server-api/#login), [UIA](https://spec.matrix.org/v1.19/client-server-api/#user-interactive-authentication-api) |
| `sync.ts` | `/sync` loop: initial sync with `timeout=0`, long-poll (`timeout=30000`) once live, `timeout=0` again after any failure so "live" returns as soon as the server answers. Health states `connecting → live ⇄ reconnecting`, fatal `error` on `M_UNKNOWN_TOKEN`; backoff 1s doubling to 15s or the server's `Retry-After`; `retryNow()` skips the wait; a 400 on a stale `since` falls back to an initial sync. | [Syncing](https://spec.matrix.org/v1.19/client-server-api/#syncing) |
| `room.ts` | Room model: state map folded from `state` then timeline state events; historical events (`/messages`) never change current state; de-duplication by event ID; a `limited` timeline resets the window and restarts history at `prev_batch`; room name per spec (name → canonical alias → heroes, "Empty room (was …)"); member display-name disambiguation; power levels; snapshots for persistence. | [Room display name](https://spec.matrix.org/v1.19/client-server-api/#calculating-the-display-name-for-a-room), [user display name](https://spec.matrix.org/v1.19/client-server-api/#calculating-the-display-name-for-a-user) |
| `sendQueue.ts` | Local echo. Each send gets a transaction ID once and keeps it across retries, failures and restarts (server idempotency makes retries safe). Sends are serialized per room. Echoes are reconciled by event ID (or `unsigned.transaction_id`), including when the remote echo arrives before the PUT response. Failed sends stay with their error until retried or discarded; the queue is persisted. | [Transaction identifiers](https://spec.matrix.org/v1.19/client-server-api/#transaction-identifiers) |
| `client.ts` | `MatrixClient` facade: owns HTTP, sync, rooms and queue; `subscribe`/`getVersion` for `useSyncExternalStore`; actions (create/join/leave/invite/accept/decline, paginate, receipts, profile); persistence of the session, the since token plus a room snapshot (last 50 events per room) and pending sends; `awaitIdle()`. | — |
| `crypto.ts` | `CryptoBackend` seam for `@matrix-org/matrix-sdk-crypto-wasm`'s `OlmMachine` (phase 3): receives every sync's to-device/device-list/OTK data, decrypts `m.room.encrypted`, encrypts sends in encrypted rooms. The default `noCrypto` refuses sends in encrypted rooms with a clear error rather than sending plaintext. | [E2EE](https://spec.matrix.org/v1.19/client-server-api/#end-to-end-encryption) |

### Persistence and reload

`localStorage` keys (prefix `conduit:`): `session` (homeserver, user,
token, device), `sync` (`since` + room snapshots), `pending` (unsent
messages). On start the client renders cached rooms immediately, then
syncs from the stored `since`. When a snapshot was trimmed, the stored
`prev_batch` would skip events, so it is dropped and back-pagination
restarts from the live end (`/messages` without `from`), skipping known
events. Logout (`POST /logout`) and `M_UNKNOWN_TOKEN` wipe all three keys.

### Workarounds for server gaps (keep until the beads close)

- **Unread counts:** Conduit currently sends `unread_notifications` as
  zeros. The room list shows `max(notification_count, local unread)`
  where local unread counts messages from others after the user's own
  `m.read` receipt or local read marker. (`conduit-y99.24`)
- **Display-name propagation:** the server does not rewrite room member
  events after `PUT /profile/{userId}/displayname`; the client updates
  its own `m.room.member` in each joined room whose member event still
  has the old name. (`conduit-y99.25`)
- **`/messages` visibility:** the creator's back-pagination omits the
  room's create/initial join; the timeline still terminates correctly.
  (`conduit-y99.26`)
- **`unsigned.transaction_id`:** absent on the sender's own events; echo
  reconciliation uses the event ID from the PUT response instead.
  (`conduit-y99.27`)

## UI (`client/src/ui`)

Design direction ("station enamel", recorded in
`client/.impeccable/surfaces/src-app-tsx.md`): a deep tube-green
destination board for navigation, pale enamel for the conversation,
brass reserved for unread lamps and the single primary action, signal
red for failures. Each own message carries a carrier mark showing where
it is: hollow queued, filling while sending, solid sent, red notched
when it failed. All colours, type and spacing come from
`src/styles/tokens.css`, with light and dark themes (system,
or forced in Settings) and a Vitest guard (`contrast.test.ts`) that
every text pair meets WCAG AA.

Screens: sign in / create account (field validation, server errors on
the right field), room list (invites with accept/decline, unread lamps,
previews, skeleton loading, empty state), room view (topic, invite,
people panel, leave), timeline (day plates, sender grouping, folded
room setup, compact state lines, back-pagination with error/retry,
"beginning of room", jump to latest), composer (Enter sends,
Shift+Enter newline, `/me` emotes, inline retry/delete on failure),
create room / join by address / invite / leave dialogs (native
`<dialog>`), settings (display name, theme, session facts, sign out),
and a reconnecting banner driven by sync health.

Accessibility: semantic landmarks and headings; skip link; roving
tabindex with arrow/Home/End through the room list and the timeline;
focus moves to the heading on route changes and to the composer when a
room opens; dialogs restore focus to their opener; `aria-live` for new
messages from others and for the connection banner; errors use
`role="alert"` and `aria-describedby`; `prefers-reduced-motion` stops
the carrier and lamp animations.

## Automation hooks

- **`data-testid`** on every interactive and status element (e.g.
  `room-row` with `data-room-id`/`data-room-name`, `unread-badge` with
  `data-count`, `pending-item` with `data-status`, `sync-status` with
  `data-state`, `carrier-mark` with `data-state`).
- **`window.__conduitClient`** — installed only when `import.meta.env.DEV`
  or the build sets `VITE_CONDUIT_TEST_HOOKS=1`:
  `signedIn`, `syncState`, `userId`, `deviceId`, `rooms()`,
  `pendingSends()`, `timeline(roomId)`, `awaitIdle(ms)` (resolves when
  sync is live and no send or user operation is in flight),
  `retrySyncNow()`. It never exposes the access token.
- **Homeserver:** `?hs=<url>` pins the server (and hides the field),
  else `VITE_CONDUIT_HOMESERVER`, else `http://localhost:8008`.
- **Injectable clock and transport** in the core for unit tests
  (`ManualClock`, `FakeServer` in `src/core/testing.ts`).

## Running

```bash
cd client
pnpm install
pnpm dev                 # http://localhost:5173 (point it at a homeserver with ?hs=)
pnpm lint                # tsc -b (typecheck) + eslint
pnpm test                # Vitest unit tests
pnpm build               # typecheck + production bundle in dist/
pnpm e2e:install         # once: Playwright's Chromium
pnpm e2e                 # Playwright against a real conduit-server
```

`pnpm e2e` global setup (`e2e/global-setup.ts`) runs
`cargo build -p conduit-server` (or uses `CONDUIT_SERVER_BIN`), creates
a fresh database through `psql` on `DATABASE_URL` (default
`postgresql://postgres@localhost/postgres`), launches the binary with
the same environment as `conduit-server/tests/common/production.rs`
(`CONDUIT_LISTEN_ADDR=127.0.0.1:0`, `CONDUIT_READY_FILE`,
`CONDUIT_OIDC_ISSUER=off`, `CONDUIT_FEDERATION=0`, `CONDUIT_MEDIA_ROOT`,
`CONDUIT_AS_REGISTRATIONS_DIR`, server name `conduit.test`), waits on
the ready file, and on teardown kills the server and drops the
database (`CONDUIT_E2E_KEEP_LOGS=1` keeps the server log). Set
`CONDUIT_E2E_HS=<url>` to run against an already-running homeserver
instead. `CONDUIT_CAPTURE=1` additionally writes review screenshots to
`client/.impeccable/review/`.

Tests wait only on observable state (DOM, `__conduitClient.awaitIdle()`,
server responses); there are no fixed sleeps. Failures are simulated
with Playwright route interception (aborted `/send` and `/sync`).

## Journeys covered (e2e)

| Spec file | Journey |
|---|---|
| `chat.spec.ts` | Two browser contexts register, create a room, invite (with validation), accept, chat both ways (multi-line), unread lamp and preview while away, member panel with roles, sender grouping, day plates; session survives reload and sign-out revokes the token (`M_UNKNOWN_TOKEN`); display-name change; decline invite; join by room ID with address validation and not-found error, then leave. |
| `resilience.spec.ts` | 75-message history paged back to the beginning, every message once and in order, jump to latest; failed send with inline retry and delete, retry delivers exactly once; failed sends survive reload; sync loss shows the reconnecting banner and recovers; sign-in validation and server errors (wrong password, taken username, weak input); unreachable homeserver. |
| `a11y.spec.ts` | axe (WCAG 2.0/2.1/2.2 A+AA) with zero serious/critical violations on sign-in, sign-in errors, empty home, room view with invite and member panel, failed send, create dialog and settings, in light and dark; keyboard navigation through rooms, composer and timeline; live announcement of incoming messages; reduced motion. |

## Roadmap

Phase 2 and 3 work is tracked as children of `conduit-y99.9`: media,
typing/receipts/presence, relations (reactions, edits, replies,
threads, redactions), device and session management, room settings,
room directory and user search, and E2EE through
`@matrix-org/matrix-sdk-crypto-wasm` (device verification with SAS
emoji, key backup).
