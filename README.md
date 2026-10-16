# Conduit

A Matrix homeserver, as a pure Rust library — plus a thin webserver
binary to run it.

## Layout

- `conduit/` — the library. No HTTP server, no I/O loop, no binary.
  Bring your own host.
- `conduit-server/` — a basic webserver around `conduit`, built on
  Tokio + axum (axum sits on hyper).
- `web/` — the first-party client. Static SvelteKit, run with Bun.
  Not part of the Cargo workspace.

## Build

```sh
cargo build --workspace                            # default
cargo build --workspace --features conduit-server/iroh   # compile in the iroh transport (~30MB)
```

## Run

`conduit-server` requires a Postgres database. See [AGENTS.md](AGENTS.md)
for the database conventions.

```sh
createdb conduit                                                   # one-time
cargo run -p conduit-server                                        # :8008
```

On startup the server reads a `.env` file from the working directory or
a parent. Variables already set in the environment win. A missing file
is fine, and a malformed one stops startup. `DATABASE_URL` is still
required, from that file or the environment:

```
DATABASE_URL=postgresql://postgres@localhost/conduit
CONDUIT_SERVER_NAME=localhost
```

OIDC defaults to IdentiKey's hosted OP (`https://auth.identikey.me`).
Override with `CONDUIT_OIDC_ISSUER`; set it to `0` or `off` to disable.
`CONDUIT_OIDC_AUDIENCE` defaults to `CONDUIT_OIDC_CLIENT_ID` or
`CONDUIT_SERVER_NAME` and **must** equal the OP client id.

Browser SSO (`m.login.sso`, used by Element and by `web/`) also needs
`CONDUIT_OIDC_CLIENT_SECRET` matching a confidential client registered on
the OP. Redirect defaults to
`http://127.0.0.1:8008/_matrix/client/v3/login/identikey/callback`. Without
the secret, JWT-in-hand `io.identikey.oidc` still works, and neither client
shows an SSO button. `io.identikey.auth` (the Identikey wallet) stays
available either way.

Migrations under `conduit-server/migrations/` apply automatically on
startup. See [docs/element-bringup.md](docs/element-bringup.md) for
the Element-web verification flow.

## Web client

The UI is the static SvelteKit app in `web/`. Bun installs and runs it.
There is no client server: the browser calls the homeserver with a bearer
token.

```sh
cd web
bun install
bun run dev    # http://localhost:5173/?hs=http://127.0.0.1:8008
```

The signed-out screen offers Identikey when `GET /_matrix/client/v3/login`
lists `m.login.sso`. That button starts the homeserver SSO redirect. The
browser never calls `https://auth.identikey.me` and never sees
`CONDUIT_OIDC_CLIENT_SECRET`. A homeserver that does not offer SSO says
Identikey sign-in is turned off and that this page cannot sign anyone in.

Password fields, password change, other-device sign-out, and deactivation
stay off unless the command that runs `bun run dev` or `bun run build` has
`VITE_CONDUIT_PASSWORD` set to `1`, `true`, `on`, or `yes`. Restart that
command after changing it. The homeserver still accepts `m.login.password`.

Details: [docs/features/client.md](docs/features/client.md) and
[web/README.md](web/README.md).

## Status

The shape of a real Matrix homeserver is in. Working subsystems:

- **Storage** — PostgreSQL via sqlx; migrations `0001` through `0091` apply on startup; full `Storage` trait covers events, rooms, accounts, devices, tokens, signing keys, account data, receipts, media, push, app services, audit log.
- **Events & signing** — v11 PDUs, canonical JSON, content hash, event ID (reference hash), Ed25519 keypair generation with restart-stable persistence, sign/verify events, `GET /_matrix/key/v2/server`, remote key cache, key rotation with grace window.
- **Auth & state machine** — room v11 authorization rules, typed state-event content (create / member / power_levels / join_rules / history_visibility), auth-event lookup, `apply_state_event`, state resolution v2.
- **Client-Server API** — register / login / logout / whoami, createRoom + the initial-state cascade, membership ops (join / leave / kick / ban / unban / invite), send + state PUT/GET, /messages with pagination, **`/sync` with long-poll**, filters, profile, account data, typing, receipts, presence.
- **Media** — upload, download (legacy + authenticated), thumbnail generation (`image` crate), federation fetch + cache, safe headers (CSP sandbox / nosniff / Content-Disposition), retention policy.
- **End-to-end encryption support** — `/keys/upload`, `/query`, atomic `/claim`, `/changes`, fallback keys, `/sendToDevice`, cross-signing (master / self-signing / user-signing), `m.device_list_update` EDU, server-side room-keys backup.
- **Federation** — server discovery (`.well-known` + SRV + DNS), X-Matrix outgoing + incoming signed requests, send transactions with per-destination exponential-backoff queue, make_join + send_join, invite, state / state_ids, backfill, get_missing_events, query/profile + query/directory, federation `/send_to_device`, per-origin rate limiting, in-process Conduit↔Conduit roundtrip tests.
- **Push notifications** — pushers, push rules (CRUD + 10 default rules + evaluator: `event_match`, `room_member_count`, `sender_notification_permission`), notification queue + HTTP gateway delivery, notification counts in `/sync`.
- **Application services** — YAML registration loading, namespace enforcement, AS-authenticated calls, per-AS transaction queue.
- **Admin** — `/_matrix/conduit/admin/v1/...` for users / rooms / media / federation, with audit log.

**Tests:** `SQLX_OFFLINE=true DATABASE_URL=postgresql://postgres@localhost/postgres cargo test --workspace`.
PostgreSQL must permit `CREATE DATABASE`, and `psql` must be on `PATH`.
Storage and production HTTP tests create and remove isolated databases.
`conduit-server/tests/production_e2e.rs` launches the shipped binary, verifies
registration/login, profile, chat/sync, federation authentication, and to-device
retry/acknowledgement behavior, then restarts it to check durable state and keys.
Run it alone with `SQLX_OFFLINE=true cargo test -p conduit-server --test production_e2e`.

For isolated runtime automation, set `CONDUIT_LISTEN_ADDR=127.0.0.1:0` and
`CONDUIT_READY_FILE=/path/to/ready.json`. The server writes
`{"address":"127.0.0.1:<bound-port>"}` after migrations and socket binding;
automation can then probe `/health`. Defaults are `0.0.0.0:8008` and no readiness
file. Each restart must use a fresh or removed readiness file. These hooks use
the normal HTTP routes and authentication.

For the pinned live Synapse federation journey, run
`bash conduit-server/tests/peers/run_synapse_to_device.sh`. It requires PostgreSQL
with `CREATE DATABASE`, `psql`, `openssl`, Python 3.12+, `uv`, and the Rust
toolchain. The runner provisions the isolated peer environment and exercises
verified HTTPS, normal registration, bidirectional to-device delivery, retries,
restart recovery, and signed-origin checks. Failures are fatal and cleanup is
automatic. On Darwin 27 it uses LLVM's Mach-O linker and an installed 26.5 SDK
for the peer extension; `CONDUIT_PEER_SDK` can select another compatible SDK.

`CONDUIT_TLS_CA=/path/to/root.pem` adds a private PEM root for outbound HTTPS.
The default certificate/hostname verification and public trust roots remain
enabled. This supports private federation deployments and the peer test CA.

**Status caveats** — full Matrix compliance is not yet established. The initial
[requirement evidence register](docs/matrix-compliance.json) records verified
assertions and uncovered scope; the complete server/client effort is tracked in
`conduit-y99`. Known gaps include:

- v11 cryptographic bytes and redaction have independent protocol-vector tests. The separate PDU wire model (including unknown-field preservation) remains tracked as `conduit-embed-pdu`.
- AS ghost user auto-creation (`conduit-5vr`) and AS query endpoints (`conduit-dhd`) are stubbed.
- Some `/sync` streams are still scaffolding-only (presence federation, full filter implementation).
- Run `bd ready` to see the current backlog.

**Experimental** — the `iroh` feature is a stub module; story group `conduit-91r` will wire up real `iroh::Endpoint` peer-to-peer federation.

## Layout

- `conduit/` — pure library. No HTTP server, no I/O loop. All Matrix logic: events, rooms, state, auth, state resolution, signing, hashing, canonical JSON, storage trait + in-memory backend.
- `conduit-server/` — webserver binary. Tokio + axum + sqlx + PostgresStorage. Wires HTTP routes onto the library; carries `RemoteKeyCache`, `federation::Client`, `federation::Queue`, `PushWorker`, `BlobStore`, app-service workers in `AppState`.
- `web/` — static SvelteKit client (Bun). Protocol core in `web/src/core`. Screens in `web/src/lib`.
- `docs/` — per-feature implementation guides for any Matrix homeserver implementer.
- `epics/` (in `bd`): tracked via Steve Yegge's [beads](https://github.com/steveyegge/beads).

## Lineage

The name "Conduit" is reused on purpose. The original Conduit was the
first serious Rust Matrix homeserver; after it was archived the work
continued as `conduwuit`, and the actively maintained successor is now
[continuwuity]. This project is an independent reimplementation that
points at that lineage rather than borrowing from it — we work
primarily from the spec.

[continuwuity]: https://forgejo.ellis.link/continuwuation/continuwuity

## License

Apache-2.0 (placeholder — choose deliberately before publishing).

The separate room-PDU contract regression is
`python conduit-server/tests/peers/synapse_pdu_wire.py`, run from the pinned peer
venv after building Conduit. The integrated wire model accepts standard v11
PDUs without a local `event_id`, retains extensions and uses derived identities;
this journey verifies those assertions independently with Synapse. Broader PDU
and federation conformance remains tracked under the full protocol goal.
