# add-svelte-client-proof

> **ACTIVE BUILD**

## Why

The React client is what CI installs with pnpm and proves with Playwright. The SvelteKit app is not the client until Bun can run the same kind of proof.

## What

- Run the protocol-core and UI unit tests with `bun:test` where that API fits.
- Run Playwright on Chromium, Firefox, and WebKit through Bun, against a real `conduit-server`.
- Add a CI job that installs `web/` with Bun. Leave the React pnpm job in place until `remove-react-client`.

## Impact

- Capabilities: ADDED requirements on `matrix-client`
- ADRs: none

## User journey & surfaces

No new UI because the proof exercises the screens `add-svelte-chat` and `add-svelte-client-rest` already built. The outcome is a green CI job.

## Out of scope

- Deleting `client/`. Tracked on `remove-react-client`.
- A new browser runner. Playwright stays.

## Preparation

Chat landed at `b4a4d26` and folded at `26b6a09`. Remaining surfaces landed at `22ae5d4` and folded at `c86581f`. Journeys already exist at `web/tests/session-journey.ts`, `web/tests/chat-journey.ts`, and `web/tests/rest-journey.ts`. Outcome: still valid. Authority: `conduit-nl4` grant, "fold these in, activate all and run." Bounds: prove `web/` with Bun. Leave the React pnpm job. Do not edit `.github/workflows/ci.yml` or `client/`. No new Matrix features.
