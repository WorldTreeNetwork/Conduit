# Learnings

Append-only. One line per hard-won fact. Dated, with a file reference.

- 2026-09-10 — `iroh` pulls `http`/`reqwest` transitively (iroh-relay); `axum` never in `cargo tree -p conduit`. Embeddable means tokio-hosted, not runtime-agnostic. (`openspec/specs/embeddable-kernel/spec.md`)
- 2026-10-13 — Federation v2 is a path prefix, not a suffix after the endpoint name. Share the production mount/auth builder with tests; signatures must cover `OriginalUri` through both nested routers. (`conduit-server/src/federation/server.rs`)
- 2026-10-13 — HTTP 200 from a federation transaction can contain per-event errors. Message fixtures need create/member auth state and must assert the PDU result before checking persistence. (`conduit-server/tests/federation_inbound.rs`)
- 2026-10-13 — Device-list changes and to-device queue IDs are independent streams. Delete queue entries only when the next request acknowledges their delivered cursor; premature deletion loses verification/encryption messages on retries. (`conduit-server/src/api/client/sync.rs`)
