# Tasks

- [x] Call the existing protocol core from `web/` without adding a UI-framework import to that core
- [x] Identikey is offered only when `GET /login` lists `m.login.sso`. The password form is always available, and it is the primary action when SSO is absent
- [x] Before redirect, a pending-SSO record names the homeserver and that same `hs` is placed on `redirectUrl`. On return, `loginToken` is stripped before render and spent only when the record matches that `hs`. No record, a mismatch, or no `hs` strips the token and sends no login request. A bad token shows the signed-out screen with a retry
- [x] Password registration and login still complete for tests
- [x] Sign out clears the stored session
- [x] The shell shows the profile display name

- [ ] Live journey: password register and sign-in against a local conduit-server, and a `loginToken` with no pending record is not spent (`web/tests/session-journey.ts`)

## Verification

- `bun test --cwd web`: 17 passing tests, including registration dummy UIA,
  password login, profile lookup, stored-session removal, SSO flow discovery,
  callback binding, synchronous credential stripping, and non-retrying token exchange.
- `bun run --cwd web check`: zero errors and warnings.
- `bun run --cwd web build`: static production build succeeds.
- Impeccable detector: no findings on the changed page.
- Live acceptance journey remains unverified in this worker sandbox. PostgreSQL
  initialization fails at `shmget` with Operation not permitted, Vite cannot
  listen on loopback (`EPERM`), and Chromium cannot register its Mach rendezvous
  port (Permission denied). The runnable journey is `web/tests/session-journey.ts`;
  see `web/README.md` for the command. Implementation boxes above reflect the
  code and unit checks, not a claim that the live browser acceptance ran green.
