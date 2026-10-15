# Tasks

Implementation is present in `web/`. The worker could not run the browser
journey inside its sandbox. The conductor ran it outside the sandbox against
conduit-server on `127.0.0.1:8020` and Vite on `127.0.0.1:5173`:

```sh
cd web
CONDUIT_TEST_HS=http://127.0.0.1:8020 WEB_BASE_URL=http://127.0.0.1:5173 bun tests/rest-journey.ts
```

That command printed `PASS: profile and persistence, theme, device rename, image preview, members, presence, directory join, threads and retry, room settings, reconnect and sync recovery, mobile`.

Two fixes were required first. A 1×1 image preview was 1px tall, so it was not a visible open target; the preview now has the current client's 44px floor. Opening a thread re-ran its loader on every sync version until Svelte stopped the page; the loader now depends on the room id string. A failed thread send also needed a fresh pending object so the row can leave "Sending…".

- [x] Settings and display name match the current client
- [x] Image messages preview
- [x] Member list, directory, and threads work against a real homeserver
- [x] Presence shows when the homeserver sends it
- [x] A dropped homeserver shows the reconnect banner and sync resumes when it returns
