## ADDED Requirements

### Requirement: Kernel has no HTTP types

The `conduit` crate SHALL NOT expose `axum`, `http`, or `reqwest` types
in its public API. `axum` SHALL NOT appear in `cargo tree -p conduit`
under any feature. `http` and `reqwest` MAY appear transitively behind
the `iroh` feature only. Kernel operations SHALL return typed values,
not `(u16, serde_json::Value)` HTTP-shaped pairs.

#### Scenario: axum is never a conduit dependency

- GIVEN the workspace at HEAD after this change's act
- WHEN someone runs `cargo tree -p conduit` with default features and
  with `--features iroh`
- THEN `axum` does not appear in either tree

### Requirement: Two crates

The homeserver SHALL ship as `conduit` (kernel) and `conduit-server`
(host: axum, Postgres, workers). Postgres SHALL NOT be a third crate
in this change. An embedder who wants durable Postgres SHALL depend on
the host or, later, `conduit-6jr` — not a feature on `conduit`.

#### Scenario: Kernel crate graph has no axum

- GIVEN a consumer depends only on `conduit`
- WHEN they compile default features
- THEN they do not link axum

### Requirement: Kernel owns persist; host supplies I/O

The kernel SHALL own build, sign, auth-check, and persist. The host
SHALL supply `Storage`, signing/minter keys, and server name. A
host-side `RoomEventSender` that calls HTTP-typed persist is debt
owned by `add-library-ops`. This requirement is the target; HEAD
still inverts it until that change lands.

#### Scenario: Stranger reads the architecture doc

- GIVEN `docs/architecture.md` after this change's act
- WHEN they look for who persists an event
- THEN the doc names the kernel as owner and names the current
  host-side `RoomEventSender` as debt for `add-library-ops`

### Requirement: Matrix errcode is a kernel type

`conduit::Error` SHALL carry Matrix `errcode` (for example
`M_FORBIDDEN`, `M_NOT_FOUND`, `M_UNKNOWN_TOKEN`). The host SHALL map
errcode to HTTP status. Kernel ops SHALL NOT return HTTP status codes.

#### Scenario: Forbidden is not a status integer

- GIVEN a library caller of `may_read_room` or send
- WHEN the user is not permitted
- THEN the error type names `M_FORBIDDEN` (or equivalent) without
  requiring `axum::http::StatusCode`

### Requirement: Room version 11 only

Room create **and inbound federation events** SHALL use room version
11. Other versions SHALL be rejected with a typed kernel error. The
check SHALL live in the kernel so an in-process client cannot bypass
it.

#### Scenario: v10 create fails

- GIVEN a create-room request with `room_version` `10`
- WHEN the kernel processes it
- THEN it returns an error and does not persist a create event

#### Scenario: inbound v10 PDU fails

- GIVEN a federation PDU whose room create version is not 11
- WHEN the kernel ingest path runs
- THEN the PDU is rejected with the same typed error

### Requirement: Embeddable means tokio-hosted

The kernel MAY depend on tokio. `Storage` MAY stay `async-trait`.
"Embeddable" SHALL mean embeddable in a tokio runtime, not
runtime-agnostic.

#### Scenario: Docs do not claim no-async

- GIVEN `docs/architecture.md` after this change's act
- WHEN a reader looks for runtime claims
- THEN they see tokio-hosted, not "no I/O loop in the library" as a
  claim that Storage is sync
