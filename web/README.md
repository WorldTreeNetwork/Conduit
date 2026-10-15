# web/

Conduit's static SvelteKit client (`adapter-static`, SPA fallback, `ssr = false`).
No application server: the homeserver is the only backend.

```bash
bun install
bun run dev        # signed-out screen on http://localhost:5173
bun run check      # svelte-check
bun test           # unit tests (bun:test)
bun run build      # static files in build/
```

Homeserver: `?hs=<url>` wins and hides the field, then `VITE_CONDUIT_HOMESERVER`,
then `http://localhost:8008`.

Colours come only from `src/lib/styles/tokens.css` (station enamel, copied from
`client/`); `src/routes/layout.css` maps the shadcn-svelte theme onto them.
Fonts are self-hosted via Fontsource: Bricolage Grotesque (titles, wdth 100,
600) and Atkinson Hyperlegible Next (body, tabular figures). Tactic Sans is not shipped.

Session sign-in uses the framework-free core in `../client/src/core`. The stored
session uses the `conduit:web:` localStorage prefix. The tab-scoped SSO intent is
`sessionStorage['conduit:pending-sso'] = JSON.stringify({ homeserver })`; it is
consumed before token exchange, and the callback must contain that exact `hs`.
Token exchange never retries automatically. Rejected callbacks make no homeserver
request until the person chooses to sign in again.

The focused browser journey reuses the existing `client/` Playwright dependency
and installed Chromium. With the local homeserver and web dev server running:

```bash
CONDUIT_TEST_HS=http://localhost:8008 WEB_BASE_URL=http://localhost:5173 bun tests/session-journey.ts
```

It registers a unique account, signs in with a password, checks profile and sign-out
persistence, mints a real Matrix login token, and checks matching, unsolicited,
replayed, mismatched, and missing-homeserver SSO returns without the hosted provider.
