# Tasks

- [ ] Call the existing protocol core from `web/` without adding a UI-framework import to that core
- [ ] Identikey is offered only when `GET /login` lists `m.login.sso`. The password form is always available, and it is the primary action when SSO is absent
- [ ] Before redirect, a pending-SSO record names the homeserver and that same `hs` is placed on `redirectUrl`. On return, `loginToken` is stripped before render and spent only when the record matches that `hs`. No record, a mismatch, or no `hs` strips the token and sends no login request. A bad token shows the signed-out screen with a retry
- [ ] Password registration and login still complete for tests
- [ ] Sign out clears the stored session
- [ ] The shell shows the profile display name
