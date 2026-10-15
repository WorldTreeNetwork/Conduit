# add-svelte-chat

> **ACTIVE BUILD**

## Why

A session without rooms is not the client. Two people need to create a room, invite, and exchange messages, including a failed send they can retry.

## What

- Room list with unread counts and previews.
- Timeline with pagination.
- Composer with local echo and retry.
- Create room, join room, and invite, using the shadcn-svelte dialog primitive.
- Hash routing and sync folding stay the behavior of the current client.

## Impact

- Capabilities: ADDED requirements on `matrix-client`
- ADRs: none

## User journey & surfaces

Two signed-in people. One creates a room and invites the other. Both see the message. A send that fails stays in the timeline with a retry. Empty: no rooms yet, the shell offers create and join. Failed: a failed send shows a retry on that message. Off: a room the person has left is not in the list, and a hash that points at it returns home.

## Out of scope

- Media, settings, directory, threads, presence, and the reconnect banner. Tracked on `add-svelte-client-rest`.
- End-to-end encryption.

## Preparation

Blocked on `add-svelte-session`.
