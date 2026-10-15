# Tasks

- [x] Bun is pinned and CI installs with `bun install --frozen-lockfile`. Unit tests run as `bun run test`
- [x] Playwright covers the session, chat, and remaining surfaces on Chromium, Firefox, and WebKit. The `loginToken` return leg is proved without the hosted Identikey provider, with the pending-SSO record seeded first. A second case opens the same URL with no record and asserts that no login request is sent
- [x] axe reports zero serious violations on the signed-in shell
- [x] GitHub Actions installs `web/` with Bun and runs those journeys
- [x] The React pnpm job is still present

## Verification (packet conduit-nl4.6)

- Bun 1.3.14: `bun install --frozen-lockfile` passes using a writable copy of the local package cache; `bun run test` passes all 84 core/UI helper tests.
- `bun run check` passes with zero errors/warnings. TypeScript checking of the Playwright config, specs, support code, and preload passes.
- The static production build succeeds during `bun run e2e`. `bun --bun x playwright test --list` discovers 12 cases across Chromium, Firefox, and WebKit.
- Browser execution is green. `cd web && CONDUIT_SERVER_BIN=target/debug/conduit-server bun run e2e` passed 12 tests: session, chat, and the remaining surfaces on Chromium, Firefox, and WebKit, including the pending-record `loginToken` return, the no-record case, and axe with zero serious or critical violations on the signed-in shell. WebKit 2359 ran via the local cache alias to 2370.
- `.github/workflows/svelte-client.yml` is wired to install from the frozen Bun lockfile and run checking, unit tests, browser installation, and the real-server journeys. The existing React pnpm job remains present; neither `client/` nor `.github/workflows/ci.yml` was edited by this worker.
