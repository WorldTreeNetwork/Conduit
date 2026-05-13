# Bringing up Element against this server

The integration tests (`cargo test --workspace`) cover the protocol end-to-end:
register, login, createRoom, join, send, /sync (with long-poll), whoami,
logout, kick. This doc is for the **visual** check — point a real Matrix
client at the server and watch the UI render a real conversation.

This is bd story `conduit-il0.19`. Close it when you've completed the flow.

## Prereqs

- Postgres running and the `conduit` database created (`createdb conduit`).
- `cargo build --workspace` clean.

## 1. Start the server

```sh
DATABASE_URL="postgresql://postgres@localhost/conduit" \
    CONDUIT_SERVER_NAME="localhost" \
    RUST_LOG="info,conduit_server=debug" \
    cargo run -p conduit-server
```

You should see:

```
INFO conduit_server: connected to postgres
INFO conduit_server: migrations applied
INFO conduit_server: server signing key ready key_id=ed25519:XXXXXX
INFO conduit_server: conduit-server listening addr=0.0.0.0:8008
```

Quick sanity:

```sh
curl -s localhost:8008/health
curl -s localhost:8008/_matrix/client/versions | jq
curl -s localhost:8008/_matrix/key/v2/server | jq
```

## 2. Run Element Web

The fastest path is Element's hosted dev tier (`https://app.element.io`) —
but it expects HTTPS, and our server is plain HTTP on localhost. Use a
local Element with a custom config that points at the unencrypted endpoint.

### Option A — Docker

```sh
# Create a config that overrides the homeserver
cat > /tmp/element-config.json <<'JSON'
{
  "default_server_config": {
    "m.homeserver": {
      "base_url": "http://localhost:8008",
      "server_name": "localhost"
    }
  },
  "disable_custom_urls": false,
  "disable_guests": true,
  "brand": "Element (Conduit dev)"
}
JSON

docker run --rm -d --name element \
    -p 8080:80 \
    -v /tmp/element-config.json:/app/config.json \
    vectorim/element-web:latest

# Open http://localhost:8080
```

### Option B — Hydrogen (lighter alternative)

[Hydrogen](https://github.com/element-hq/hydrogen-web) is a smaller Matrix
client that's easier to run for local development:

```sh
docker run --rm -d --name hydrogen -p 3000:3000 \
    ghcr.io/element-hq/hydrogen-web:latest
# Open http://localhost:3000, point it at http://localhost:8008
```

## 3. The verification flow

Two browser tabs (private windows, different sessions):

1. **Tab A**: register `alice` (password of your choice). Element will go
   through `m.login.dummy` UIA — single "Continue" click.
2. **Tab B**: register `bob` the same way.
3. **Tab A**: create a public room. Note the room ID/alias.
4. **Tab B**: join the room (via room directory or paste `!roomid:localhost`).
5. **Tab A**: type a message.
6. **Tab B**: confirm the message appears within a second or two (long-poll
   `/sync` wakes on the broadcast).
7. **Tab B**: reply.
8. **Tab A**: confirm the reply appears.

All eight steps working = il0.19 done. Close it:

```sh
bd close conduit-il0.19 --reason="Element web verified: register, createRoom, join, send, sync flow works end-to-end against the live server."
```

## Known limitations to expect

These are filed follow-ups; not bugs in the milestone:

- **Presence** doesn't update (`conduit-245`).
- **Typing indicators** aren't implemented (E06 — Presence Layer epic).
- **Read receipts** aren't implemented (E06).
- **E2EE** isn't wired (E10) — turn it OFF in Element for now.
- **Federation** is local-only (E08/E09 still ahead) — don't try to talk
  to matrix.org from this server yet.
- **Lazy-load members** is filed but not implemented (`conduit-bh6`); large
  rooms may be slow in Element.

If you hit something weird that isn't in this list, file a bd issue.
