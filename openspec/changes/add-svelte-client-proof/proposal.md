# add-svelte-client-proof

> **PENDING**

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

Blocked on `add-svelte-client-rest`.
