# Tasks

- [x] Room list shows joined rooms with unread counts and a preview
- [x] Timeline pages history and renders messages from the existing core
- [x] Composer sends with local echo and retry
- [x] Create, join, and invite work against a real homeserver
- [x] A hash for a room the person has left returns home

## Implementation verification (conduit-nl4.4)

The web implementation and `web/tests/chat-journey.ts` are present. The
journey covers two accounts, create/invite/accept, two-way messages, held-request
local echo, a failed send retried with the same transaction ID, unread counts,
previews, back pagination, join, a left-room hash, and mobile navigation.

`bun run check` and `bun test` pass (17 tests). The worker could not run the
browser journey inside its sandbox. The conductor ran it outside the sandbox
against conduit-server on `127.0.0.1:8019` and Vite on `127.0.0.1:5173`:

```sh
cd web
CONDUIT_TEST_HS=http://127.0.0.1:8019 WEB_BASE_URL=http://127.0.0.1:5173 bun tests/chat-journey.ts
```

That command printed `PASS: create, invite, accept, two-way send, local echo, retry, previews, unread, history, join, left-room hash, mobile navigation`.

A failed send stayed on "Sending…" until the pending row copied status into a new object. Svelte skips an `{#each}` row whose item reference does not change, and the send queue mutates status on the same object.
