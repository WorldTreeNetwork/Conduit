# Architecture

Conduit ships as two crates:

- **`conduit`** — pure library. No HTTP server, no I/O loop, no
  binary. All Matrix logic lives here: events, rooms, state, auth,
  storage trait, transport abstractions.
- **`conduit-server`** — thin host binary. Tokio + axum. Mounts HTTP
  routes onto an instance of the library and runs the I/O loop.

The split lets the library be embedded in non-HTTP hosts (tests, P2P
transports, alternative runtimes) without dragging in a webserver.

## Data flow (client → server)

```
HTTP request
  → axum route handler                 (conduit-server)
    → conduit::api::client handler     (conduit)
      → auth check                     (access token → user, device)
        → conduit::room operations     (state machine + auth rules)
          → conduit::storage           (persist event, update state)
```

## Data flow (federation in)

```
HTTPS request from a remote homeserver
  → axum route handler                 (conduit-server)
    → X-Matrix signature verification
      → conduit::api::federation       (conduit)
        → conduit::room::state_res     (resolve incoming state)
          → conduit::storage           (persist + reindex)
```

## Module map

| Module                       | Purpose                                          |
|------------------------------|--------------------------------------------------|
| `conduit::event`             | Matrix event types (PDUs)                        |
| `conduit::room`              | Room representation; applying state events       |
| `conduit::room::state_res`   | State Resolution v2                              |
| `conduit::auth` *(planned)*  | Access-token & device auth; auth rule checks     |
| `conduit::api::client`       | Client-Server API handlers and types             |
| `conduit::api::federation`   | Server-Server API handlers and types             |
| `conduit::storage`           | `Storage` trait + in-memory implementation       |
| `conduit::transport`         | Transport abstraction; HTTP is host-supplied     |
| `conduit::transport::iroh`   | iroh P2P transport (feature-gated)               |
| `conduit::config`            | Runtime configuration                            |
| `conduit::error`             | Top-level error type                             |

## Layering rules

1. **`storage` is a trait, not a concrete backend.** Tests use
   `MemoryStorage`; production picks SQLite or RocksDB and implements
   the trait. Nothing in `room` or `api` references a specific DB.
2. **No HTTP types in the library.** Handlers take typed request
   structs and return typed response structs. The host translates
   to/from HTTP.
3. **Federation is opt-in at runtime.** Disabling it must not crash
   handlers; they just return an appropriate error when asked to
   reach a remote.
4. **State resolution is a pure function.** No I/O, no clock, no
   randomness. Easy to test, easy to swap.
