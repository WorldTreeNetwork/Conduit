# Conduit

A Matrix homeserver, as a pure Rust library — plus a thin webserver
binary to run it.

## Layout

- `conduit/` — the library. No HTTP server, no I/O loop, no binary.
  Bring your own host.
- `conduit-server/` — a basic webserver around `conduit`, built on
  Tokio + axum (axum sits on hyper).

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
DATABASE_URL="postgresql://postgres@localhost/conduit" \
    CONDUIT_SERVER_NAME="localhost" \
    cargo run -p conduit-server                                    # :8008
```

Migrations under `conduit-server/migrations/` apply automatically on
startup. See [docs/element-bringup.md](docs/element-bringup.md) for
the full Element-web verification flow.

## Status

The shape of a real Matrix homeserver is in. Working subsystems:

- **Storage** — PostgreSQL via sqlx; migrations 0001–0005 in place; full `Storage` trait covers events, rooms, accounts, devices, tokens, signing keys, account data, receipts, media, push, app services, audit log.
- **Events & signing** — v11 PDUs, canonical JSON, content hash, event ID (reference hash), Ed25519 keypair generation with restart-stable persistence, sign/verify events, `GET /_matrix/key/v2/server`, remote key cache, key rotation with grace window.
- **Auth & state machine** — room v11 authorization rules, typed state-event content (create / member / power_levels / join_rules / history_visibility), auth-event lookup, `apply_state_event`, state resolution v2.
- **Client-Server API** — register / login / logout / whoami, createRoom + the initial-state cascade, membership ops (join / leave / kick / ban / unban / invite), send + state PUT/GET, /messages with pagination, **`/sync` with long-poll**, filters, profile, account data, typing, receipts, presence.
- **Media** — upload, download (legacy + authenticated), thumbnail generation (`image` crate), federation fetch + cache, safe headers (CSP sandbox / nosniff / Content-Disposition), retention policy.
- **End-to-end encryption support** — `/keys/upload`, `/query`, atomic `/claim`, `/changes`, fallback keys, `/sendToDevice`, cross-signing (master / self-signing / user-signing), `m.device_list_update` EDU, server-side room-keys backup.
- **Federation** — server discovery (`.well-known` + SRV + DNS), X-Matrix outgoing + incoming signed requests, send transactions with per-destination exponential-backoff queue, make_join + send_join, invite, state / state_ids, backfill, get_missing_events, query/profile + query/directory, federation `/send_to_device`, per-origin rate limiting, in-process Conduit↔Conduit roundtrip tests.
- **Push notifications** — pushers, push rules (CRUD + 10 default rules + evaluator: `event_match`, `room_member_count`, `sender_notification_permission`), notification queue + HTTP gateway delivery, notification counts in `/sync`.
- **Application services** — YAML registration loading, namespace enforcement, AS-authenticated calls, per-AS transaction queue.
- **Admin** — `/_matrix/conduit/admin/v1/...` for users / rooms / media / federation, with audit log.

**Tests:** ~180 across the workspace (unit + integration). `DATABASE_URL=postgresql://postgres@localhost/conduit cargo test --workspace`.

**Status caveats** — there are known gaps tracked as P2/P3 follow-ups in `bd`:

- Sign/verify uses simplified field-stripping (signatures + unsigned). Full v11 redaction (per-event-type content pruning) is filed as `conduit-sv4.11`.
- AS ghost user auto-creation (`conduit-5vr`) and AS query endpoints (`conduit-dhd`) are stubbed.
- Some `/sync` streams are still scaffolding-only (presence federation, full filter implementation).
- Run `bd ready` to see the current backlog.

**Experimental** — the `iroh` feature is a stub module; story group `conduit-91r` will wire up real `iroh::Endpoint` peer-to-peer federation.

## Layout

- `conduit/` — pure library. No HTTP server, no I/O loop. All Matrix logic: events, rooms, state, auth, state resolution, signing, hashing, canonical JSON, storage trait + in-memory backend.
- `conduit-server/` — webserver binary. Tokio + axum + sqlx + PostgresStorage. Wires HTTP routes onto the library; carries `RemoteKeyCache`, `federation::Client`, `federation::Queue`, `PushWorker`, `BlobStore`, app-service workers in `AppState`.
- `docs/` — per-feature implementation guides for any Matrix homeserver implementer.
- `epics/` (in `bd`): 12 epics tracked via Steve Yegge's [beads](https://github.com/steveyegge/beads).

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
