# E01 — Storage Foundation

**Status:** 🔵 Not started
**Implementation guide:** [docs/features/storage.md](../docs/features/storage.md)
**Depends on:** —
**Blocks:** E02, E03 (transitively: everything)

## Scope

Pick a persistent backend, implement the `Storage` trait against it,
define the schemas for events, accounts, devices, tokens, signing keys,
and room state. Crash-consistent. Versioned schema.

## "Done" looks like

- A real backend implements `conduit::storage::Storage`.
- Schemas exist for events, accounts, devices, access tokens, signing
  keys, and current room state.
- Integration test puts events, restarts the process, gets them back.
- `MemoryStorage` retained for tests.

## Stories

- [ ] **E01-1**: Decision: SQLite vs RocksDB vs Postgres for the
      reference backend. (Recommended: SQLite for v0 — simplest ops.)
- [ ] **E01-2**: Flesh out the `Storage` trait — add accounts,
      devices, tokens, signing keys, room current_state methods.
- [ ] **E01-3**: Implement chosen backend behind the trait.
- [ ] **E01-4**: Schema: `events` (event_id PK, room_id, sender, type,
      content, state_key, origin_server_ts, stream_position).
- [ ] **E01-5**: Schema: `accounts`, `devices`, `access_tokens`.
- [ ] **E01-6**: Schema: `room_current_state` (room_id, type,
      state_key → event_id).
- [ ] **E01-7**: Schema: `server_signing_keys` (key_id, private,
      public, valid_until_ts).
- [ ] **E01-8**: Schema versioning + migration runner on startup.
- [ ] **E01-9**: Integration tests: round-trip across process restart.

## Open questions

- SQLite vs RocksDB for v0? SQLite has better operational properties
  (single file, sqlite tooling); RocksDB is what Conduit's predecessors
  used and is faster for the access pattern.

## Risks

- Schema lock-in is expensive — get the event indexing right before
  building features that depend on it.
