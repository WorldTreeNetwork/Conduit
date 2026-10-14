# Separate Matrix wire PDUs from local event metadata

> **ACTIVE BUILD** — authorized by the user's ongoing autonomous full-protocol goal.

The current Event model requires a local event ID on federation input and loses
unknown top-level fields before content hashing. This blocks standard peers and
can redact valid extended events. Cryptographic bytes and database round trips
must retain their protocol meaning independently of local metadata.

Work and acceptance are tracked in beads `conduit-embed-pdu`, under the wider
Matrix compliance goal `conduit-y99`. This unit covers v11 wire boundaries,
unknown-field persistence, and cryptographic invariants. After the 2026-10-14
send-back it also covers: co-signing that leaves the PDU unchanged,
fetch-by-ID integrity, a check on legacy rows' event IDs, canonical-text
storage, a typed outbound boundary, and `send_join` sender/state_key/origin
validation. The second send-back adds U+0000-safe handling at every
PostgreSQL sink a PDU reaches (`transactions` and outbox payloads become
TEXT), refusal of `/invite` content-hash mismatches, per-endpoint fetch
expectations, and the v11 depth, size and field-length limits. Pre-join
`send_join` state, `make_join` `ver`, `/event_auth`, and EDU-sink U+0000
handling are filed as beads `conduit-y99.22.1` to `.4`. Additional room versions,
complete event authorization/state resolution, and client UI remain separate
required work. No new UI because this unit establishes room-event transport and
storage contracts used by future client features.
