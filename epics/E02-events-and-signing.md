# E02 — Events & Signing

**Status:** 🔵 Not started
**Implementation guide:** [docs/features/events-and-signing.md](../docs/features/events-and-signing.md)
**Depends on:** E01
**Blocks:** E03, E08

## Scope

Construct, hash, sign, and verify Matrix room events (PDUs) for room
version v11. Publish the server's signing keys; fetch and cache
remotes' keys.

## "Done" looks like

- Build a v11 PDU, sign it, recover the same event ID from canonical
  hashing — and verify our own signature off a roundtrip.
- A remote can hit `/_matrix/key/v2/server` and verify the response.
- Verify incoming events signed by any well-behaved Matrix server.

## Stories

- [ ] **E02-1**: Canonical JSON serializer (sorted keys, no
      whitespace, integer-only number rules).
- [ ] **E02-2**: Content hash (`hashes.sha256`).
- [ ] **E02-3**: Event ID = base64 reference hash of (event minus
      `signatures` + `unsigned`).
- [ ] **E02-4**: Ed25519 keypair generation + persist (in
      `server_signing_keys`).
- [ ] **E02-5**: Sign events; attach signature under
      `signatures[server_name][key_id]`.
- [ ] **E02-6**: Verify event signatures.
- [ ] **E02-7**: `GET /_matrix/key/v2/server` (and `/{keyId}`)
      handler; sign the response.
- [ ] **E02-8**: Remote key fetch + cache until `valid_until_ts`.
- [ ] **E02-9**: Key rotation: keep prior key for a grace window.

## Open questions

- Notary protocol (`/_matrix/key/v2/query/{server}`) — skip for v0?
  (Most clients don't need it; first impls usually punt.)

## Risks

- Canonical JSON edge cases (number ranges, escape rules) are easy to
  get wrong and silently break signature verification with peers.
