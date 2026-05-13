# E08 — Federation: Outbound

**Status:** 🔵 Not started
**Implementation guide:** [docs/features/federation.md](../docs/features/federation.md)
**Depends on:** E02
**Blocks:** E09

## Scope

What our server *sends* to other Matrix servers. Build first because
it's testable against existing federated servers — point it at
matrix.org and watch.

## "Done" looks like

- A local user joins `#test:matrix.org` (or similar federated room)
  and sends a message that appears for remote users.
- Profile + directory lookups against remotes work.

## Stories

- [ ] **E08-1**: Server name resolution: `.well-known/matrix/server`.
- [ ] **E08-2**: SRV record fallback (`_matrix-fed._tcp.example.org`).
- [ ] **E08-3**: Direct DNS A/AAAA fallback.
- [ ] **E08-4**: X-Matrix outgoing signing
      (method, uri, origin, destination, content_hash).
- [ ] **E08-5**: `PUT /_matrix/federation/v1/send/{txnId}` sender.
- [ ] **E08-6**: Per-destination send queue + retry/backoff.
- [ ] **E08-7**: `/make_join` + `/send_join/v2` (joining remote rooms).
- [ ] **E08-8**: `/invite/v2` (inviting remote users).
- [ ] **E08-9**: `/state`, `/state_ids` outgoing.
- [ ] **E08-10**: `/backfill`, `/event/{eventId}`,
      `/get_missing_events`.
- [ ] **E08-11**: `/query/profile`, `/query/directory`.

## Open questions

- Same axum app for federation as CS-API, or separate? Production
  best practice is separate — different auth, error semantics,
  rate-limit profiles.

## Risks

- TLS validation strictness — federation requires real certificates.
  Document `.well-known` delegation for self-signed setups.
- Auth-chain pulling can balloon on join. Set bounds.
