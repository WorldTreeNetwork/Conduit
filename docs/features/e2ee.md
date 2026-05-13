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
  `PUT /_matrix/federation/v1/send_to_device/{txnId}`.
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
