# add-svelte-session

> **PENDING**

## Why

The signed-out screen has to become a Matrix session. The person proves who they are with Identikey. Tests still need a password.

## What

- Use the existing framework-free core for login, registration, session storage, and profile. Do not rewrite it. Import it from `client/src/core` until the React tree is removed.
- Add an Identikey button that follows the homeserver `m.login.sso` redirect and stores the Matrix access token that comes back.
- Keep password registration and login for the automated suite.
- Sign out clears the stored session. The display name comes from the profile.

## Impact

- Capabilities: ADDED requirements on `matrix-client`
- ADRs: none

## User journey & surfaces

From the signed-out screen, a person chooses Identikey and returns signed in, with their display name in the shell. A test run registers with a password instead. Empty: no session, the signed-out screen stays. Failed: SSO that does not return a token stays signed out and says the sign-in did not finish. Off: sign out returns to the signed-out screen and a reload does not restore the session.

## Out of scope

- Room list and composer. Tracked on `add-svelte-chat`.
- Changing the homeserver SSO implementation.
- Holding the OIDC client secret in `web/`.

## Preparation

Blocked on `add-sveltekit-shell`.
