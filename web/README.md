# web/

Conduit's static SvelteKit client (`adapter-static`, SPA fallback, `ssr = false`).
No application server: the homeserver is the only backend.

```bash
bun install --frozen-lockfile
bun run dev        # signed-out screen on http://localhost:5173
bun run check      # svelte-check
bun run test       # core + UI helper unit tests (bun:test)
bun run build      # static files in build/
```

Homeserver: `?hs=<url>` wins and hides the field, then `VITE_CONDUIT_HOMESERVER`,
then `http://localhost:8008`.

Password fields are off. Set `VITE_CONDUIT_PASSWORD=1` in the environment
that runs `bun run dev` or `bun run build` to offer password registration,
login, re-authentication, password change, other-device sign-out, and
deactivation. `true`, `on`, and `yes` also enable it. Anything else leaves
it off. The protocol core still speaks `m.login.password` either way.

Colours come only from `src/lib/styles/tokens.css` (station enamel);
`src/routes/layout.css` maps the shadcn-svelte theme onto them.
Fonts are self-hosted via Fontsource: Bricolage Grotesque (titles, wdth 100,
600) and Atkinson Hyperlegible Next (body, tabular figures). Tactic Sans is not shipped.

Session sign-in uses the framework-free core in `src/core`. The stored
session uses the `conduit:web:` localStorage prefix. The tab-scoped SSO intent is
`sessionStorage['conduit:pending-sso'] = JSON.stringify({ homeserver })`; it is
consumed before token exchange, and the callback must contain that exact `hs`.
Token exchange never retries automatically. Rejected callbacks make no homeserver
request until the person chooses to sign in again.

The browser proof belongs to `web/` and runs with Bun on Chromium, Firefox,
and WebKit. It builds and serves the static production files, builds the real
`conduit-server` from locked sources, creates a fresh PostgreSQL database, and
removes that database and stops the server after the run. PostgreSQL with CREATE
DATABASE permission, `psql`, Rust, and access to the private Cargo git dependencies
are required. Missing prerequisites fail the run.

```bash
bun --bun x playwright install --with-deps chromium firefox webkit
DATABASE_URL=postgresql://postgres:postgres@localhost/postgres bun run e2e
```

For a local binary already built from the current sources, set
`CONDUIT_SERVER_BIN=/absolute/path/to/conduit-server`. The default static preview
port is 4173; set `WEB_PORT` to choose another. Cargo output lives in `.cache/cargo`.
The server always uses its own database, ephemeral port, media directory, and
readiness file. macOS runs keep the machine awake only while Playwright runs.

The twelve browser cases cover:

- A stored session, display name, reload and sign-out persistence. The default build shows no password fields.
- Real login-token issuance through password UIA, pending SSO intent seeded before
  navigation, one token exchange, token removal, replay rejection, and callback guards.
- A fresh tab opening the same token URL without an intent record, sending no
  homeserver request. Revisiting it with intent succeeds, proving the first visit
  did not spend the token. No hosted Identikey provider is used.
- Room creation, invite/accept, two-way messages, local echo, retry with the same
  transaction, room previews and unread counts, pagination, join, and left-room routing.
- Profile/theme persistence, device rename, authenticated image preview, members,
  real sync presence, directory join, threads and retry, room settings, reconnect,
  sync recovery, and mobile navigation.

axe scans the signed-in home shell and a populated room, rejects serious and
critical violations, and attaches its complete results to the Playwright report.
The report lives in `playwright-report/`; failure artifacts and server logs live
in `test-results/`. CI runs the same proof in `.github/workflows/svelte-client.yml`.

`bun run test` loads the core's existing assertions through a Bun-only
Vitest export adapter, plus the Svelte session and homeserver tests. A test-only
File shim preserves the explicit browser MIME type that Bun 1.3.14 otherwise
extends with a charset.

Settings is `#/settings`. People, room settings, and threads open keyboard-accessible
dialogs; Directory is in the room rail. All Matrix operations go through the same
session's protocol core. Theme choice is local (`conduit:theme`); system is the default.
