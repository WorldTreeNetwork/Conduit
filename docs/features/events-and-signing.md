# Events & Signing

**Spec reference:** [Room versions], [Signing JSON]
**Default:** on
**Depends on:** [`storage`](storage.md)
**Depended on by:** auth-and-state, federation

[Room versions]: https://spec.matrix.org/latest/rooms/
[Signing JSON]: https://spec.matrix.org/latest/appendices/#signing-json

## What this is

Matrix events are signed JSON objects shared between homeservers. The
event ID is itself a hash of the event's canonical form. This module
covers constructing, hashing, signing, and verifying PDUs (Persistent
Data Units — Matrix's name for room events).

## What the homeserver needs to do

- Construct PDUs with the correct field set for the room version
  (this implementation currently supports v11).
- Compute **canonical JSON**: sorted keys, no whitespace, integers
  only in `[-2^53+1, 2^53-1]`, no floats.
- Compute the event's **content hash** (`hashes.sha256`) over the full,
  unredacted event, excluding hashes, signatures, unsigned data, and the
  locally derived event ID.
- Compute the **event ID** as a base64-encoded reference hash of the
  redacted PDU minus its `signatures` and `unsigned` fields. The locally
  derived event ID is excluded from both hashing and signing.
- Sign events with the server's Ed25519 signing key, attaching the
  signature under `signatures[server_name][key_id]`.
- Verify incoming events' signatures using the originating server's
  public keys (fetched from `/_matrix/key/v2/server` on the remote).
- Publish our own server's public keys at `/_matrix/key/v2/server`,
  signed with the same key and an expiration time.
- Implement key rotation: keep old keys for a grace period to verify
  historical events.

## Endpoints / protocol surface

- `GET /_matrix/key/v2/server` — publish our keys (also responds to
  `/_matrix/key/v2/server/{keyId}` for legacy clients).
- `GET /_matrix/key/v2/query/{serverName}` — fetch a remote's keys
  via the notary protocol (optional for first impl).

## Implementation approach

1. Generate a long-lived Ed25519 keypair at first boot, persist the
   private key. Add a key ID like `ed25519:a_AbCd`.
2. Implement canonical JSON as a custom `serde_json` serializer, or
   recursively sort keys before serialization.
3. Compute the content hash, redact the event, remove `signatures` and
   `unsigned`, then sign and attach the signature to the original event.
4. For verification, fetch the remote's keys on demand and cache them
   until their `valid_until_ts`.

## Gotchas

- Canonical JSON is **not** the same as compact JSON. Sorting and
  number rules differ from most JSON libraries' defaults.
- The event ID format changed across room versions. v3+ uses the
  reference hash; v1/v2 used a separate `event_id` field. Targeting
  this implementation currently implements v11; additional room versions
  remain part of the protocol compliance work.
- Signatures cover the redacted canonical form minus `signatures` and
  `unsigned`. Content hashes cover unredacted contents. A valid signature
  with a mismatched content hash requires using the redacted event.
- Your server name appears in every signature; changing it later
  invalidates every event you've ever signed.

## Verification and remaining wire work

`cargo test -p conduit --test matrix_v11_crypto` checks independent
SHA-256/reference-hash/Ed25519 vectors, the v11 redaction table, optional
field omission, and signed events with mismatched content hashes. The
signature constant was generated with OpenSSL from the RFC 8032 test-1
seed; it is independent of Conduit's signing code.

`Pdu` is the federation wire type: it has no `event_id` and keeps every
other top-level key in `extensions`. `Event` is the local
`{event_id, pdu, unsigned}` view. A received PDU is stored as canonical
JSON and served again as those same bytes.
`production_pdu.rs::received_pdu_is_served_as_the_same_canonical_bytes`
fails if a field is dropped or `event_id` is injected. These
cryptographic tests do not establish complete federation or Matrix
protocol compliance.
