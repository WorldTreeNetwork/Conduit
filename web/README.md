# web/

Conduit's static SvelteKit client (`adapter-static`, SPA fallback, `ssr = false`).
No application server: the homeserver is the only backend.

```bash
bun install
bun run dev        # signed-out screen on http://localhost:5173
bun run check      # svelte-check
bun test           # unit tests (bun:test)
bun run build      # static files in build/
```

Homeserver: `?hs=<url>` wins and hides the field, then `VITE_CONDUIT_HOMESERVER`,
then `http://localhost:8008`.

Colours come only from `src/lib/styles/tokens.css` (station enamel, copied from
`client/`); `src/routes/layout.css` maps the shadcn-svelte theme onto them.
Fonts are self-hosted via Fontsource: Bricolage Grotesque (titles, wdth 100,
600) and Atkinson Hyperlegible Next (body, tabular figures). Tactic Sans is not shipped.
