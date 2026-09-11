# Design — embeddable kernel crate shape

**Change:** `add-embeddable-kernel`
**Bead:** `conduit-embed-shape`

Send-back 2026-09-10 (`fable-5.1-arch-review`) folded in here.

## Decision 1 — two crates, not three, not features

Keep `conduit` + `conduit-server`. Postgres stays in the host until
`conduit-6jr`. Feature-gating axum on `conduit` is refused. Escape
hatch for durable storage without axum is `conduit-6jr`, not a
feature on `conduit`.

## Decision 2 — Client is in-process on `conduit`

Not an HTTP SDK this pass. Implementation is `add-in-process-client`.

## Decision 3 — v11 only, in the kernel

Create and inbound federation. Typed error. Host maps it. In-process
cannot bypass.

## Decision 4 — dependency direction

Kernel owns build-sign-auth-persist. Host supplies `Storage`, keys,
server name. Today's host-side `RoomEventSender` wrapping HTTP-typed
`build_sign_and_persist` is named debt for `add-library-ops`.

## Decision 5 — errcode on `conduit::Error`

Matrix errcode is kernel semantics. Host maps to HTTP status.

## Decision 6 — Homeserver split

| Moves into kernel `Homeserver` | Stays host-only |
|---|---|
| `Storage` | OIDC issuer / JWKS |
| server signing key + biscuit minter | media blob disk |
| server name | CS/federation rate limit |
| stream broadcast (`events_tx`) | push worker process |
| txn cache | axum / TLS / bind |
| typing + presence stores | |
| Config (and it is read) | |

## Decision 7 — tokio-hosted

Kernel depends on tokio. `Storage` is async-trait. Embeddable ≠
runtime-agnostic.

## Decision 8 — HTTP types

Public API of `conduit` has no `axum`/`http`/`reqwest` types. `axum`
never in `cargo tree -p conduit`. `http`/`reqwest` only transitive
behind `iroh`. No `(u16, Value)` stand-ins.

## What this landing writes

ADR in `docs/architecture.md` plus living capability. Does not move
`build_sign_and_persist`. Names HEAD inversion as debt.
