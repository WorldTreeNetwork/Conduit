# Federation (Server-Server API)

**Spec reference:** [Server-Server API]
**Default:** on (runtime toggle: `federation_enabled` in config)
**Depends on:** [`events-and-signing`](events-and-signing.md), [`state-resolution`](state-resolution.md)
**Depended on by:** e2ee (for device-list distribution)

[Server-Server API]: https://spec.matrix.org/latest/server-server-api/

## What this is

The protocol homeservers speak to each other. Every Matrix homeserver
is its own DNS-resolvable entity, and rooms are replicated across the
servers whose users participate. Federation is what makes Matrix
federated.

This is roughly half the spec by volume. Split implementation into
outbound (easier, build first) and inbound (harder, build second).

## Outbound

What our server sends to others.

### Server discovery

Resolve a server name `example.org` → IP + port via, in order:

1. `.well-known/matrix/server` over HTTPS, or
2. SRV record `_matrix-fed._tcp.example.org`, or
3. direct DNS A/AAAA on the bare name.

Cache TTLs honestly; remote operators rely on it.

### Signed requests

Every S2S request carries an `Authorization: X-Matrix` header with the
sender server's signature over `(method, uri, origin, destination,
content_hash)`. Sign with your Ed25519 key; the remote verifies via
your published `/_matrix/key/v2/server`.

### Sending PDUs

`PUT /_matrix/federation/v1/send/{txnId}` carries a batch of PDUs and
EDUs. Each PDU is fanned out to every server with a member in the
room.

### Other outbound calls

| Endpoint                                  | Purpose                                |
|-------------------------------------------|----------------------------------------|
| `/make_join/{roomId}/{userId}`            | Half-build a join PDU on the remote.   |
| `/send_join/v2/{roomId}/{eventId}`        | Send the signed join + receive state.  |
| `/invite/v2/{roomId}/{eventId}`           | Invite a remote user.                  |
| `/state/{roomId}`, `/state_ids/{roomId}`  | Fetch state at a point.                |
| `/backfill/{roomId}`, `/event/{eventId}`  | DAG repair.                            |
| `/get_missing_events/{roomId}`            | Fill a gap between known events.       |
| `/query/profile`, `/query/directory`      | Directory lookups.                     |

## Inbound

What our server accepts from others.

### Verification

For every incoming request, verify the `X-Matrix` signature against
the origin server's published keys before doing any work.

### Accepting `send`

Each incoming PDU goes through:

1. Signature verification (event signatures, separate from request
   signature).
2. Auth check against the auth events listed in the PDU.
3. State resolution if the event changes state.
4. Persist + reindex.
5. Forward to local clients via `/sync`.

### Join handshake

A remote `/make_join` returns a half-built join PDU; the remote signs
it and sends it back via `/send_join/v2`; we run state-res and accept
both the new member and the resolved state.

### Backfill

A remote may ask for older events around a known ID
(`/get_missing_events`). Return them subject to history-visibility
rules.

## Implementation approach

1. **Build outbound first.** It's testable against existing federated
   servers — join `#test:matrix.org` and send a message.
2. **Then inbound.** Inbound is harder because misbehaving remotes
   are real; defensive parsing and timeouts are non-negotiable.
3. Treat `/send` as a queue, not a synchronous call. Retry with
   backoff. Track per-destination state so a dead remote doesn't
   block live ones.
4. Federation does not run on the same axum router as the
   client-server API in production — it has different auth, different
   error semantics, and different rate-limit needs.

## Gotchas

- **TLS:** federation requires TLS, and certificate validation is
  strict. Use a real cert (Let's Encrypt) or `delegate` to a host
  that has one.
- **Server-name vs. delegated-name:** `@user:example.org` may federate
  via `matrix.example.org:8448`. Get the delegation logic right or
  nothing will federate.
- **Rate limiting:** large rooms can generate thousands of `/send`
  transactions per second on event spikes. Without backpressure you
  OOM.
- **Auth chain explosion:** join handshakes can require pulling a
  large auth chain. Set bounds; reject obviously bad responses.
- Federation is **eventually consistent**. A message you send appears
  on remotes at varying delay. Don't surprise the user with stale state.
