# add-sveltekit-shell

> **ACTIVE BUILD**

## Why

The contract in `add-sveltekit-client` names a static SvelteKit app in `web/`. A person cannot see it until the signed-out screen exists and Bun can serve it.

## What

- Scaffold `web/` with SvelteKit, Bun, and `adapter-static`.
- Install the shadcn-svelte primitives named in the contract.
- Self-host Bricolage Grotesque (wdth 100, semibold) and Atkinson Hyperlegible Next. Do not ship Tactic Sans.
- Show a signed-out screen that resolves the homeserver the way `client/src/config.ts` does: `?hs=` wins, then `VITE_CONDUIT_HOMESERVER`, then `http://localhost:8008`.

## Impact

- Capabilities: ADDED requirements on `matrix-client`
- ADRs: none

## User journey & surfaces

A person opens the dev server. The signed-out screen shows the homeserver field, unless `?hs=` pinned it. Empty: no homeserver typed yet, the field explains that. Failed: an unreachable homeserver is reported on the field. Off: no session yet, so no room list.

## Out of scope

- Identikey and password completion. Tracked on `add-svelte-session`.
- Rooms, timeline, and settings.
- Deleting the React client.

## Preparation

Blocked on `add-sveltekit-client` until that contract is folded. Do not activate before then.
