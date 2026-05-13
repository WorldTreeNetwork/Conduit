# iroh Transport (Experimental)

**Spec reference:** none — non-standard
**Default:** **off** (Cargo feature: `iroh`)
**Depends on:** [`federation`](federation.md), [`events-and-signing`](events-and-signing.md)

## What this is

An experimental peer-to-peer transport for federation traffic, built
on [iroh] (QUIC + NAT-traversal + a relay network). Lets two
homeservers federate without DNS, public IPs, or TLS certificates —
just iroh node IDs.

This is **not** part of the Matrix spec. It's a Conduit-specific
extension; remotes need the same feature compiled in to talk to you
over iroh.

[iroh]: https://docs.rs/iroh

## What enabling this changes

- Adds the `iroh` crate (~30MB of compiled code) to the binary.
- Each Conduit instance gets an iroh node ID, derivable from its
  signing key.
- Federation traffic can be routed over iroh connections in addition
  to HTTPS — useful when one or both peers can't run a public
  webserver.

## Implementation approach

1. Replace the stub in `conduit/src/transport/iroh.rs` with a real
   `iroh::Endpoint`. Bind on startup; advertise the node ID alongside
   the server name via a custom well-known entry.
2. Add a federation client path that, given an iroh node ID for a
   remote, sends `/send/{txnId}`-style messages over a QUIC stream
   instead of HTTPS.
3. Mirror the inbound side: accept incoming iroh streams and dispatch
   into the same federation handlers as HTTPS-arriving requests.
4. Preserve the `X-Matrix` signature on every message — the transport
   doesn't replace event-level signing.

## Gotchas

- Two peers must both have `iroh` compiled in. Negotiate falling back
  to HTTPS gracefully.
- Iroh node IDs are cryptographic identities and need to be tied to
  the server's signing key for the federation auth model to make
  sense.
- This is **experimental**. Don't ship it as the only transport for
  a production server.
