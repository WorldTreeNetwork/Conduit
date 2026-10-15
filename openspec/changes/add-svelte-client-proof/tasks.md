# Tasks

- [ ] Bun is pinned and CI installs with `bun install --frozen-lockfile`. Unit tests run as `bun run test`
- [ ] Playwright covers the session, chat, and remaining surfaces on Chromium, Firefox, and WebKit. The `loginToken` return leg is proved without the hosted Identikey provider, with the pending-SSO record seeded first. A second case opens the same URL with no record and asserts that no login request is sent
- [ ] axe reports zero serious violations on the signed-in shell
- [ ] GitHub Actions installs `web/` with Bun and runs those journeys
- [ ] The React pnpm job is still present
