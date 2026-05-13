# Conduit Documentation

Open documentation for building a Matrix homeserver, organized by
feature. Written against the Conduit codebase but the guidance applies
to any Rust (or other) Matrix homeserver — every homeserver implements
the same spec.

## Who this is for

- Engineers implementing a Matrix homeserver from scratch or extending
  an existing one.
- Operators who want to understand which parts of their server do
  what.
- (Later: client implementers — client docs will live in
  `docs/client/`.)

If you're new to Matrix, start with the [spec introduction] and then
read [`architecture.md`](architecture.md).

[spec introduction]: https://spec.matrix.org/latest/

## Feature model

Each feature below is a self-contained module. **Most are on by
default**; you can omit any of them and still have a functioning
homeserver, though some omissions remove core capabilities (e.g.
dropping federation makes the server local-only).

Off by default: `iroh-transport`.

Each feature doc states its default and what other features depend on
it.

## Features in build order

Each chunk is a testable milestone. Three big user-visible
checkpoints are marked 🚦.

### Foundation

- [`storage`](features/storage.md) — persist events, accounts, keys
- [`events-and-signing`](features/events-and-signing.md) — PDUs, hashing, Ed25519 signatures
- [`auth-and-state`](features/auth-and-state.md) — auth rules and the room state machine

### Local server (no federation)

- 🚦 [`client-server-api`](features/client-server-api.md) — the API clients call (first usable server)
- [`presence-layer`](features/presence-layer.md) — profiles, typing, receipts, presence
- [`media`](features/media.md) — uploads, downloads, thumbnails

### Federation

- [`state-resolution`](features/state-resolution.md) — State Resolution v2 (required before federation)
- 🚦 [`federation`](features/federation.md) — outbound + inbound S2S API

### Crypto

- 🚦 [`e2ee`](features/e2ee.md) — server-side support for end-to-end encryption

### Integrations

- [`push`](features/push.md) — push notifications
- [`app-services`](features/app-services.md) — bridges and bots
- [`admin`](features/admin.md) — server administration

### Experimental

- [`iroh-transport`](features/iroh-transport.md) — federation over iroh P2P

## Authority

The [Matrix specification] is the source of truth. When this
documentation disagrees with the spec, the spec wins; please open an
issue so we can fix the doc.

[Matrix specification]: https://spec.matrix.org/
