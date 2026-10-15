# Tasks

No implementation in this change. The delta is the contract. Fold lands it after advise accepts.

## Owed from advise 2026-10-14 (opus-arch-review)

- [x] Spec: Identikey sign-in scenarios pin the return leg: `loginToken` is removed from the URL before render, spent once through `m.login.token`, and an expired or reused token returns to the signed-out screen with a retry
- [x] Spec: a pinned `?hs=` homeserver survives the SSO round trip (encoded in `redirectUrl` or held in `sessionStorage`), and the token is never spent against another homeserver
- [x] Spec: Identikey is offered only when `GET /login` lists `m.login.sso`; state whether a person sees the password form (always / only without SSO / never), and what a homeserver without SSO shows
- [x] Spec: an automated scenario proves the SSO completion leg without the hosted OP (`POST /login/get_token` → `?loginToken=` → signed-in shell, token gone from `location`, replay refused)
- [x] Spec/design: correct "Tactic Sans stays" (it is not in `client/`), name its source and confirm its web licence, require self-hosted fonts with no third-party CDN, and replace "wonk axis off" with the actual testable Bricolage setting (e.g. `wdth 100`)
- [x] Spec: carry `client/PRODUCT.md`'s accessibility bar (WCAG 2.2 AA, axe zero serious) and "test hook never in production builds" into `matrix-client`, or name the proof scenario that does
- [x] Design: a static deploy origin must be added to `CONDUIT_SSO_REDIRECT_ALLOWLIST` (loopback dev already passes)

## Owed from advise-2 2026-10-14 (opus-arch-review)

- [x] Spec: `loginToken` is spent only when this tab holds a pending-SSO record in `sessionStorage` (written before redirect) whose homeserver equals the return's `hs`. With no record, a mismatch, or no `hs`, the token is stripped, nothing is spent, no homeserver is called, and the signed-out screen shows
- [x] Spec: the return-leg proof scenario seeds the pending record before opening `?hs=…&loginToken=…`, and a new scenario opens the same URL without the record and asserts that no `/login` call is made

- [x] Fresh advise after preparation (accept: `reviews/2026-10-14-advise-3.md`, contract ref spec.md Requirement "Identikey sign-in")
