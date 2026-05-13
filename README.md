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
cargo build                       # default
cargo build --features iroh       # compile in the iroh transport (~30MB)
cargo run -p conduit-server       # serves on :8008
```

Once running, hit:

- `GET /health` → `ok`
- `GET /_matrix/client/versions` → JSON listing supported spec versions

## Status

Foundation only. The module skeleton is in place — event types, error
types, config, room/state-res hook, storage trait + in-memory impl,
transport abstraction, axum host with `/health` and
`/_matrix/client/versions`. Everything else is `TODO`. The Matrix
specification at <https://spec.matrix.org/> is the source of truth.

The `iroh` feature exists end-to-end as a flag but currently gates a
stub module — wire up `iroh::Endpoint` and add `iroh` as a real
optional dep when you're ready (see `conduit/src/transport/iroh.rs`).

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
