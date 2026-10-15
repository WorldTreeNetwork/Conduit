# remove-react-client

> **ACTIVE BUILD**

## Why

Two clients will drift. Once the SvelteKit proof is green, the React app, Vite, and pnpm stop being the UI.

## What

- Move the protocol core out of `client/` into a place `web/` owns, still with no UI-framework imports.
- Delete the React app and the pnpm CI job.
- Point the client docs at `web/` and `bun run dev`.

## Impact

- Capabilities: ADDED requirements on `matrix-client`
- ADRs: none

## User journey & surfaces

No new UI because the person already uses the SvelteKit screens. The outcome is one tree and docs that name it.

## Out of scope

- New features.
- Rewriting protocol behavior while the core moves.

## Preparation

`add-svelte-client-proof` is folded. The React browser fixes landed at `a5c6321`. The unrelated `add-atomic-room-state` work stays unstaged.
