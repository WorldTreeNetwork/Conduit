# Storage

**Spec reference:** N/A (homeserver-internal)
**Default:** on
**Depends on:** —
**Depended on by:** everything

## What this is

Where events, room state, accounts, devices, access tokens, signing
keys, and uploaded media metadata live. Conduit defines storage as a
trait (`conduit::storage::Storage`) so the backend can be SQLite,
RocksDB, Postgres, or an in-memory map for tests.

## What the homeserver needs to do

- Persist Matrix events (PDUs) immutably, keyed by event ID.
- Look up events by ID, by room, and by stream position (for `/sync`).
- Maintain the current state of each room (the latest state event per
  `(type, state_key)` pair).
- Persist accounts, password hashes, devices, and access tokens.
- Persist server signing keys (private + published public).
- For media: store blobs (filesystem or object store) and metadata.
- Be crash-consistent. Matrix is a replicated state machine; a torn
  write is worse than a missing one.

## Recommended backends

| Backend     | When to pick it                                                      |
|-------------|----------------------------------------------------------------------|
| SQLite      | Single-process server; simple ops; up to a few thousand users.       |
| RocksDB     | What Conduit's predecessors used; embedded, fast.                    |
| PostgreSQL  | Larger deployments; logical backups; SQL ergonomics.                 |

## Implementation approach

1. Implement `Storage` for the backend of your choice.
2. Keep schema versioning explicit — Matrix evolves room versions and
   you'll want migrations.
3. Index events by `(room_id, depth)` for `/messages` and by stream
   position for `/sync`.
4. Don't store derived data you can recompute (e.g. event auth
   chains) unless query performance forces you to.

## Gotchas

- Event IDs are content hashes; you cannot rename an event after
  insert.
- The current state of a room is **computed**, not authoritative;
  cache it but be prepared to recompute via state-res when federation
  delivers new state.
- Access tokens are bearer credentials — store hashed if you can.
- Media bytes outgrow the database. Keep blobs out of the row store.
