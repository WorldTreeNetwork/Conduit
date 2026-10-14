# End-to-End Encryption (Server-Side Support)

**Spec reference:** [End-to-End Encryption]
**Default:** on
**Depends on:** [`client-server-api`](client-server-api.md), [`federation`](federation.md)

[End-to-End Encryption]: https://spec.matrix.org/latest/client-server-api/#end-to-end-encryption

## What this is

E2EE on Matrix is **client-side**. The actual cryptography (Olm for
1:1, Megolm for groups) runs in the client; the server's job is to
**carry keys** between clients reliably, including across federation.

That's still a lot of work, but it's much less than "implement crypto".

## What the homeserver needs to do

- Accept device-key uploads from clients.
- Serve device-key queries: which devices exist for a user, with
  their public keys.
- Issue **one-time keys** for Olm session setup: clients upload
  pools; the server hands one out per requester per device.
- Carry **to-device messages**: a client says "deliver this opaque
  blob to user X's device Y"; the server queues it and serves it via
  `/sync`.
- Federate device-list updates: when a user adds or removes a device,
  every server in any shared room must learn (via the
  `m.device_list_update` EDU).
- Federate to-device messages:
  `m.direct_to_device` EDUs through `PUT /_matrix/federation/v1/send/{txnId}`.
- Carry **cross-signing keys** (master / self-signing / user-signing)
  so devices can verify each other.

## Endpoints (Client-Server)

| Endpoint                                                      | Purpose                                  |
|---------------------------------------------------------------|------------------------------------------|
| `POST /_matrix/client/v3/keys/upload`                         | Device keys + one-time + fallback keys.  |
| `POST /_matrix/client/v3/keys/query`                          | Get a user's devices and keys.           |
| `POST /_matrix/client/v3/keys/claim`                          | Claim one-time keys for session setup.   |
| `POST /_matrix/client/v3/keys/changes`                        | What changed since a sync token.         |
| `PUT  /_matrix/client/v3/sendToDevice/{eventType}/{txnId}`    | Send a to-device message.                |
| `POST /_matrix/client/v3/keys/device_signing/upload`          | Cross-signing keys.                      |
| `POST /_matrix/client/v3/keys/signatures/upload`              | Cross-signing signatures.                |
| `… /_matrix/client/v3/room_keys/version`, etc.                | Server-side key backup.                  |

## Implementation approach

1. Build the key-upload / query / claim trio first — it's pure
   storage + lookup. Test with two clients on this server.
2. Layer in to-device messages — clients use these for the
   `m.key.verification.*` flows.
3. Wire device-list updates over federation. Watch out: when a
   remote server's device list changes for a user we know, we must
   notify *every local user* sharing a room with them.
4. Key backup (`/room_keys`) is essentially blob storage keyed by
   `(user, version, room, session)`. Implement late.

## SAS / `m.key.verification.*`

Emoji / decimal SAS verification is a pure client-side ceremony. Both
clients exchange `m.key.verification.start` → `accept` → `key` → `mac` →
`done` events over the to-device queue. The server's only job is to
deliver those opaque blobs to the right device.

Local: `PUT /sendToDevice` writes into each recipient device's queue. A `*`
target expands to all known devices for that user. `/sync` returns at most 100
pending messages in arrival order and retains them until a subsequent request
acknowledges the response's `next_batch` token. The `t` cursor tracks to-device
delivery independently of the `d` device-list cursor. Repeating a sync after a
lost response or process restart preserves unacknowledged messages. Older sync
tokens without `t` acknowledge no to-device messages.

Device-list changes are read through the captured batch boundary. The owning
device's one-time-key counts and `device_unused_fallback_key_types` are included
in sync, with an inventory fingerprint in the opaque token. Uploading keys or
claiming one-time/fallback keys wakes a sync when the inventory changes; an
unchanged inventory does not cause repeated immediate responses. Production
tests verify upload, depletion, fallback use, and acknowledgement.

Remote: the same `PUT /sendToDevice` handler groups any
remote-targeted user IDs by destination server and dispatches each
batch as a standard `m.direct_to_device` EDU inside a durable federation
transaction. The EDU retains the authenticated user's full Matrix ID and has
its own stable 32-codepoint-bounded message ID. Inbound delivery checks that
sender's domain against the signed origin and deduplicates by origin/message ID.
The nonstandard federation send-to-device route is no longer mounted.

Successful client room-send transactions are scoped by user, device, room,
event type and transaction ID. To-device transactions are scoped by user,
device, event type and transaction ID. PostgreSQL records the result together
with the event or the complete local/remote delivery set in one transaction.
Concurrent retries produce one effect; restarts reproduce the stored result;
wildcards are expanded once, so later devices do not receive retried messages.
Failed writes roll back both the effect and the deduplication marker.
Transaction guards serialize each authenticated identity across requests and
server instances. The first request body is saved before processing; successful
and definitive rejected responses are immutable. Retries after transient server
failures resume that body, not a changed retransmission. Interrupted transport
body reads remain retryable. Completed results are checked before later body
validation, and normal authentication still precedes any cached response.

Inbound federation `send` transactions also retain their original request and
final response by signed origin and HTTP transaction ID. A partially processed
EDU batch resumes after failure or restart: committed message IDs deduplicate,
and only unfinished original messages are delivered. Federation requests require
origin, timestamp and PDUs, enforce 50-PDU/100-EDU limits, and accept framed bodies
up to 16 MB so valid large batches do not hit the old 2 MB JSON default.

PostgreSQL lifetime advisory locks use a separate lazy pool of at most four
connections per storage instance, preserving data-pool capacity even when that
pool has one connection. Dropping/cancelling a guard rolls its lock transaction
back. MemoryStorage uses scoped owned mutex guards with weak registry entries.
Completed to-device retries also wake persisted pending outboxes, recovering a
commit whose caller was interrupted before worker notification.
Outbound device list churn (`keys/upload`,
`keys/device_signing/upload`) is similarly broadcast as
`m.device_list_update` EDUs to every remote server sharing a room
with the affected local user (conduit-6r1).

## Authenticated key identities (conduit-y99.14)

`key_identity.rs` holds the checks; `keys.rs` applies them before anything is
persisted.

- `keys/upload`: `device_keys.user_id`/`device_id` must be the authenticated
  user and device (`M_INVALID_PARAM`); the object must include
  `ed25519:<device_id>` and be signed by it (`M_INVALID_SIGNATURE`). Signed
  one-time and fallback keys must verify against the device key once it is
  known; key names must be `<algorithm>:<key_id>`; one fallback per algorithm.
  An identical re-upload records no device-list change.
- `keys/query` serves only device keys that name their own user/device and
  carry a valid self-signature, adds `unsigned.device_display_name`, and merges
  self-signing signatures into device keys and the owner's device signatures
  into the master key. User-signing keys, and signatures made with them, are
  returned only to their owner.
- `keys/device_signing/upload`: each key names the user, carries its usage,
  and has exactly one `ed25519:<public>` key whose ID is that key. Self- and
  user-signing keys must be signed by the accompanying (or stored) master key.
  A public key equal to one of the user's device IDs is `403 Key ID in use`.
  Replacing stored keys requires `m.login.password` UIA; first uploads and
  exact retries do not.
- `keys/signatures/upload` (body is `{user: {key_id: object}}`) accepts only
  signatures by the uploader: their self-signing key on their devices, their
  devices on their master key, their user-signing key on another user's master
  key. The signed object must equal the stored key; failures are reported per
  user and key ID.

## Device-list visibility (conduit-y99.14)

`device_lists.rs` computes `(changed, left)` from the device-list stream window
and the membership/encryption events committed in the same event window:

- Key updates are visible to the user themself and to users sharing a joined
  room (the `/keys/changes` rule).
- Joining an encrypted room, or encryption being enabled in a shared room,
  marks the newly shared members changed.
- A leave/ban in an encrypted room puts users who no longer share any
  encrypted room into `left`, for both the leaver and the remaining members.
- `device_lists` is only present on incremental syncs. `/keys/changes`
  requires `from`, treats `to` as a hint (unparsable means now) and applies
  the same rules.

## Gotchas

- One-time keys are **consumed**. Atomically check-and-decrement;
  serving the same OTK twice corrupts sessions.
- Device-list staleness is the #1 cause of E2EE breakage in
  production. If sync clients believe they have current device lists
  when they don't, messages get encrypted for stale devices and
  recipients can't decrypt.
- Fallback keys exist because OTKs can run out. Treat them as a
  separate pool, used only when OTKs are exhausted.
- Cross-signing signature math is fiddly; lean on test vectors.
- **The server never sees plaintext.** That's the whole point. Don't
  try to "help."
