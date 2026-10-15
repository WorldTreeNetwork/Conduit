# add-sveltekit-client

## Decisions

The React client is a Vite single-page app. The session lives in `localStorage`, and every Client-Server call uses the Matrix access token. Conduit allows any browser origin. Nothing in that shape needs a client server, so the SvelteKit app is `adapter-static` with an SPA fallback. `bun run dev` is only the local Vite server. Production is static files.

Identikey is the proof of who the person is. Matrix still mints the access token. The primary button follows `/_matrix/client/v3/login/sso/redirect`, the homeserver talks to `https://auth.identikey.me`, and the client finishes on `m.login.token`. The confidential client secret stays on `conduit-server`. The custom `io.identikey.oidc` JWT login remains a homeserver feature for a caller that already holds a token. This UI does not become that caller. Password registration stays so Playwright can run without the hosted OP.

`web/` sits beside `client/` because the React tree has uncommitted work and is still the CI client. `web/` may import `client/src/core` until `remove-react-client` moves that core. The core is not rewritten and does not gain a Svelte import.

Bricolage Grotesque is the title face because room names are read all day and need to be friendly without a costume. Titles use width 100 and a semibold weight. The font's axes are `opsz`, `wdth`, and `wght`. It has no wonk axis. Atkinson Hyperlegible Next stays the body face. Numerals use its tabular figures. Tactic Sans is not shipped: the copies on hand are marked personal use only, which is not a license to embed them in a web app. Space Age and Barlow Condensed were tried and rejected. All faces are self-hosted.

The password form is always on the signed-out screen. Identikey is the primary button only when `GET /login` lists `m.login.sso`. When it does not, the password form is the only action, which is also how local dev and Playwright work if the OIDC secret is unset.

Before the SSO redirect, the client writes a pending-SSO record in `sessionStorage` naming the homeserver, and puts that same `hs` on `redirectUrl`. On return the record wins. The client strips `loginToken` with `history.replaceState` before render, then spends it with `m.login.token` only when the record exists and matches the return `hs`. A link that arrives with a token and no record, or a mismatched `hs`, is stripped and not sent anywhere. A 120-second expiry or a replay (`M_FORBIDDEN`) shows the signed-out screen and a retry. The query parameter alone is never enough, because an attacker can put their own homeserver on an allowlisted `redirectUrl`.

A static origin other than loopback must be added to `CONDUIT_SSO_REDIRECT_ALLOWLIST` or the homeserver answers 403. Loopback dev already matches the default allowlist. The allowlist itself is a string prefix and is a server bug, tracked separately. It is not fixed in this change.

Bun is pinned with `packageManager` in `web/package.json`. CI installs with `bun install --frozen-lockfile`. Unit tests run as `bun run test`. The runner may stay Vitest, invoked by Bun, until a test is cheaper under `bun:test`.

shadcn-svelte may pull in Tailwind. Its theme is generated from the same CSS variables as the custom timeline, so there is one color source.

shadcn-svelte supplies button, input, dialog, scroll area, dropdown menu, and avatar. The timeline, the room list, and the message layout are the product, so they are custom. Tokens start from `--color-ground`, `--color-ink`, and `--color-brass` in `client/src/styles/tokens.css`.

## Cutover

`add-sveltekit-shell` then `add-svelte-session` then `add-svelte-chat` then `add-svelte-client-rest` then `add-svelte-client-proof` then `remove-react-client`. CI keeps the pnpm React job until the proof is green and the remove node lands.
