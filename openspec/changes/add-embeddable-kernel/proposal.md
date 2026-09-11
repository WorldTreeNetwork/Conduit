# add-embeddable-kernel

> **ACTIVE BUILD**

Bead: `conduit-embed-shape`. Epic: `conduit-embed`. Human: activate all
(2026-09-10). Steer forks taken as recommended: two crates; in-process
Client on `conduit`; v11 freeze.

## Why

`docs/architecture.md` describes a pure library with typed handlers and
a thin axum host. `conduit::api` is a stub. Event persist, `/sync`, and
federation live in `conduit-server` and return HTTP types. Embedding
without a webserver is fiction. This change is the ownership ADR so
later nodes (`add-pdu-wire`, `add-library-ops`, `add-in-process-client`)
have a crate to land in.

## What

- ADD capability `embeddable-kernel`.
- Two crates: `conduit` (kernel: PDU, auth, state-res, storage trait,
  typed CS/SS ops, in-process Client) and `conduit-server` (axum,
  Postgres, workers, optional OIDC host).
- No `axum`/`http`/`reqwest` in `conduit`'s public API. `axum` never in
  `cargo tree -p conduit`. `http`/`reqwest` only transitive behind `iroh`.
- Kernel owns persist; host supplies Storage/keys/name. Current
  `RoomEventSender` inversion is debt for `add-library-ops`.
- Matrix errcode on `conduit::Error`. Embeddable = tokio-hosted.
- Room version 11 only (create and inbound), checked in the kernel.
- Amend `docs/architecture.md` to match the target and name HEAD debt.

## Impact

- Capabilities: ADDED `embeddable-kernel`
- ADRs: will amend `docs/architecture.md`

## User journey & surfaces

No new UI because the surfaces are the Rust crate API and the existing
Matrix CS/SS HTTP host. Element still talks HTTP to `conduit-server`.
An embedder constructs `Homeserver` + `Client` in-process after
`add-in-process-client`.

## Out of scope

- Moving persist/handlers (tracked as `add-library-ops`, `add-persist-gate`)
- Pdu vs Event (`add-pdu-wire`)
- In-process Client implementation (`add-in-process-client`)
- Splitting Postgres into a third crate (`conduit-6jr`)
- Feature-flags that compile axum into `conduit`
- Room versions other than 11 (`conduit-5gw`)
