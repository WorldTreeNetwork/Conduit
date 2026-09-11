# Architecture

Conduit ships as two crates:

- **`conduit`** — Matrix kernel. Events, rooms, v11 auth, state
  resolution, storage trait, signing, agency tokens, identity
  on-ramps. Depends on tokio. Embeddable means **tokio-hosted**, not
  runtime-agnostic. No `axum` in this crate's graph. Public API has
  no `axum` / `http` / `reqwest` types. The `iroh` feature may pull
  `http`/`reqwest` transitively through iroh-relay.
- **`conduit-server`** — host. Tokio + axum + Postgres + workers.
  Maps HTTP to kernel types. OIDC RP defaults to
  `https://auth.identikey.me` (identikey-core is AGPL; do not crate-dep
  the OP). Durable Postgres
  without axum is `conduit-6jr`, not a feature on `conduit`.

Room version **11 only**, checked in the kernel (create and inbound).

## Target data flow (client → server)

```
HTTP request
  → axum route handler                 (conduit-server)
    → conduit typed operation          (conduit)
      → biscuit verify / identikey-auth
        → room ops + check_auth
          → persist (kernel-owned)
```

**HEAD debt:** persist still lives in
`conduit-server` `build_sign_and_persist` (HTTP-typed) behind a
host `RoomEventSender`. Kernel *owns* that path as of
`add-library-ops`. Until then the inversion is named, not denied.

## Target data flow (federation in)

```
HTTPS from a remote homeserver
  → axum + X-Matrix                    (conduit-server)
    → conduit ingest                   (conduit)
        → state_res + check_auth
          → persist (kernel-owned)
```

## Homeserver split

| Kernel (`Homeserver`) | Host-only |
|---|---|
| `Storage` | OIDC issuer / JWKS |
| server signing key + biscuit minter | media blob disk |
| server name | CS/federation rate limit |
| stream broadcast | push worker process |
| txn cache | axum / TLS / bind |
| typing + presence | |
| `Config` (read, including `federation_enabled`) | |

## Module map

| Module | Purpose |
|---|---|
| `conduit::event` | PDU types |
| `conduit::agency` | Biscuit mint / verify |
| `conduit::identity` | identikey-auth on-ramp |
| `conduit::auth` | v11 authorization; `may_read_room`; `can_see` |
| `conduit::room` | create/join/send; v11 gate |
| `conduit::room::state_res` | State Resolution v2 (pure) |
| `conduit::storage` | `Storage` trait + MemoryStorage |
| `conduit::error` | domain error + Matrix errcode |
| `conduit::config` | runtime config (used) |
| `conduit::api` | typed CS/SS ops (`add-library-ops`) |

## Layering rules

1. **`storage` is a trait.** Tests use `MemoryStorage`. Host
   implements Postgres. Nothing in `room` references sqlx.
2. **No HTTP types in the kernel public API.** `axum` never in
   `cargo tree -p conduit`. Kernel returns typed `Result`; host maps
   `Error::errcode()` to HTTP status.
3. **Kernel owns build-sign-auth-persist.** Host supplies `Storage`,
   keys, server name.
4. **Federation opt-in.** `Config.federation_enabled` is read. Off
   means typed error, not a crash.
5. **State resolution is a pure function.** No I/O, no clock.
6. **Agency is Biscuits; identity is possession proof; data access
   is membership + Olm/Megolm.** Recrypt is not a kernel dep.
