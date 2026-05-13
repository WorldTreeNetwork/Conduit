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
  (v11 is current).
- Compute **canonical JSON**: sorted keys, no whitespace, integers
  only in `[-2^53+1, 2^53-1]`, no floats.
- Compute the event's **content hash** (`hashes.sha256`).
- Compute the **event ID** as a base64-encoded reference hash of the
  event minus its `signatures` and `unsigned` fields.
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
3. Sign the event template (no `signatures`, no `unsigned`), then
   attach the signature.
4. For verification, fetch the remote's keys on demand and cache them
   until their `valid_until_ts`.

## Gotchas

- Canonical JSON is **not** the same as compact JSON. Sorting and
  number rules differ from most JSON libraries' defaults.
- The event ID format changed across room versions. v3+ uses the
  reference hash; v1/v2 used a separate `event_id` field. Targeting
  v10/v11 only is reasonable for a new server.
- Signatures cover the canonical form minus `signatures` and
  `unsigned` — but **content hashes are over a slightly different
  subset**. Read the spec carefully.
- Your server name appears in every signature; changing it later
  invalidates every event you've ever signed.
