# add-sveltekit-client

> **ACTIVE BUILD**

## Why

The first-party client is React, Vite, and pnpm. The owner wants a SvelteKit app run by Bun, a friendlier title face, and Identikey as the way a person proves who they are. The Matrix homeserver already issues the session and already speaks Identikey. This change records that contract before any UI is built.

## What

- Add the `matrix-client` capability.
- The new app lives in `web/`, beside the React app in `client/`.
- It is a static SvelteKit single-page app, installed and run with Bun. It has no application server.
- Titles are Bricolage Grotesque at width 100, body is Atkinson Hyperlegible Next, and numerals are that body's tabular figures. Tactic Sans is not shipped: the files on hand are personal-use only. Faces are self-hosted.
- Controls that shadcn-svelte already solves come from that registry. The timeline, room list, and messages stay custom. Color starts from the current ground, ink, and brass palette.
- A person signs in with Identikey through the homeserver `m.login.sso` flow. Password login stays for automated tests.
- The React client remains what CI proves until `add-svelte-client-proof` is green. `remove-react-client` deletes it.

## Impact

- Capabilities: ADDED `matrix-client`
- ADRs: none. The client stack is this capability, not a homeserver architecture change.

## User journey & surfaces

No new UI because the signed-out screen lands in `add-sveltekit-shell` and Identikey sign-in lands in `add-svelte-session`. This change only records the contract those nodes build.

## Out of scope

- Homeserver, federation, and protocol changes. Tracked on the server beads, not here.
- matrix-js-sdk and end-to-end encryption.
- The uncommitted React browser fixes and `add-atomic-room-state`. They land or drop on their own before `remove-react-client`.
- Implementing the screens. Tracked on `add-sveltekit-shell`, `add-svelte-session`, `add-svelte-chat`, and `add-svelte-client-rest`.

## Preparation

2026-10-14. Upstream: no prior `matrix-client` spec. `client/src/core` imports no UI framework. The homeserver already advertises `m.login.sso` backed by Identikey and keeps the OIDC secret in `CONDUIT_OIDC_CLIENT_SECRET` (`README.md`, `docs/element-bringup.md`). CORS allows any browser origin (`conduit-server/src/main.rs`). Outcome: revised from the original React/pnpm lock in `client/PRODUCT.md` by the owner's grant on `conduit-nl4`. Authority: that grant. Still the right goal.
