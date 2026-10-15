# add-svelte-client-rest

> **PENDING**

## Why

Chat is the core path. The current client also does settings, media, members, directory, threads, presence, and a reconnect banner. The SvelteKit app is not the same client until those surfaces behave as they do now.

## What

- Port the remaining current surfaces, using the existing core and the current React behavior as the reference.
- Include the uncommitted React browser fixes only after they have landed on their own. Do not copy a dirty tree.

## Impact

- Capabilities: ADDED requirements on `matrix-client`
- ADRs: none

## User journey & surfaces

A signed-in person opens settings and sets a display name, previews an image, sees members, searches the directory, opens a thread, and sees presence. Empty: no media yet, the composer still sends text. Failed: the homeserver drops, the banner says so, and sync resumes when it returns. Off: a surface the current client does not have is not added.

## Out of scope

- New Matrix features, including end-to-end encryption.
- The CI swap. Tracked on `add-svelte-client-proof`.

## Preparation

Blocked on `add-svelte-chat`.
