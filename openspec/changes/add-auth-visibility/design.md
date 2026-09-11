# Design — auth visibility and IdentiKey agency

**Change:** `add-auth-visibility`
**Bead:** `conduit-embed-auth`

## Three layers. Do not collapse them.

From identikey-protocol `docs/standards/identikey-capability-v1.md`
(adopted 2026-08-26, holder-check amend 2026-09-10):

| Layer | Question | In Conduit |
|---|---|---|
| Identity | Who is this? | `identikey-auth` challenge/response, or password, or OIDC from a foreign identikey-core OP. Possession proof is not a grant. |
| Agency | What may this holder *do*? | Biscuit capability tokens. Attenuation is the delegation primitive. |
| Data access | Who can read this ciphertext? | **Not Recrypt.** Unencrypted PDUs: room membership + `can_see`. E2EE PDUs: Olm/Megolm (already a Matrix track). |

A Biscuit is not a proof of who you are. A recryption key is not a
right to `/sync`. Mixing any two is a protocol error.

## Recrypt: not this change

Recrypt is Apache-2.0 OR BSD-2-Clause-Patent (license-compatible). It
is still the wrong tier.

- History visibility is an authorization predicate (`can_see`), not
  encryption of stored events.
- Restricted joins are membership in another room, not re-encryption
  of ciphertext for a new member.
- Matrix E2EE already exists for content the server must not read.
  Putting PRE under the homeserver would compete with Olm/Megolm and
  would encrypt server-held plaintext that Element does not expect to
  be PRE-wrapped.
- identikey-capability-v1 §1 and §7.4: Recrypt stays data access for
  *our* ciphertext. Conduit is not storing Recrypt bulk data.

If a later change encrypts Conduit-held blobs (not Matrix event
content) with PRE, that change names Recrypt. This one does not.

## Crates and licenses

`conduit` is Apache-2.0.

| Dep | License | Use |
|---|---|---|
| `identikey-auth` (identikey-protocol) | Apache-2.0 OR BSD-2-Clause-Patent | Identity challenge/response in the kernel |
| `biscuit-auth` | Apache-2.0 | Agency tokens. identikey-protocol does not ship a biscuit crate; the format spec is `identikey-capability-v1` |
| identikey-core (`identikey-oidc`, `identikey-keys`, …) | **AGPL-3.0-or-later** | **Must not** be a crate dependency of `conduit` or `conduit-server`. Leverage as an external OpenID Provider: the HTTP host may verify an OP access token, then mint a Conduit Biscuit |

"Leverage identikey-core" means speak OIDC to it, not link it.

## Token shape

Today: 32 random bytes, SHA-256 hex stored, `lookup_token` on every
request (`conduit-server` `hash_token` / `AuthedUser`).

After: the homeserver (kernel) holds an Ed25519 **minter** key, distinct
from the Matrix server signing key. Login (password or identikey-auth
or verified OIDC) mints a root Biscuit whose authority facts include
at least:

- `user("<mxid>")`
- `device("<device_id>")`
- `server("<server_name>")`
- `epoch(<n>)` matching the stored session epoch for that device
- `right("cs")`

Authority signature is the minter Ed25519 key (identikey-capability-v1
§3.2). Identity keys do not sign Biscuit blocks.

TTL is a check in the authority or first attenuation block
(`check if time($t), $t < <exp>`). Verifier injects `time(<now>)`,
and for room-scoped ops `room("<room_id>")` and `operation("<op>")`.

**Matrix CS profile (Element):** `Authorization: Bearer <token>` where
`<token>` is URL-safe base64 of the Biscuit (optional `biscuit:`
prefix accepted). Possession of the bytes is sufficient. Holder-bound
proofs (capability-v1 §7) are **not** required; Element cannot sign
them. Logout / device revoke increments `epoch` so old biscuits fail
offline verify without a denylist.

**In-process / agent profile (later, `add-in-process-client`):** the
same root Biscuit; the client MAY attenuate (room subset, op subset,
shorter TTL). Cannot widen. Holder-bound checks MAY be added then;
not owed here.

Do not persist raw token bytes. Do not SHA-256 the Biscuit as the
primary lookup. Verify the authority chain and evaluate Datalog.
Store device epoch (and optional jti if we want session listing).

## Identity on-ramps

1. **Password** (existing Matrix CS). Success → mint Biscuit. Keep
   Argon2 hashes on accounts.
2. **identikey-auth.** Kernel issues a `Challenge` (audience =
   server_name). Client returns a `Response`. Verify with
   `VerifyPolicy` that matches the deployment (PQ optional at first).
   Map Blake3 fingerprint → local MXID (link at register or a first
   bind). Then mint.
3. **OIDC (host only).** `conduit-server` configured with an
   identikey-core issuer. Standard code+PKCE or token introspection /
   JWT validate against that OP's JWKS. `sub` is a XID (identikey-core
   ADR-001). Bind XID → MXID. Kernel still mints the Biscuit; the OP
   token is not the grant.

Password remains so Element works without an IdentiKey wallet.

## Room visibility (the original hole)

Library predicates, not axum `if`s:

- `may_read_room(user, room)` — joined (or invited, for invite-state)
  according to current membership.
- `can_see(history_visibility, user_position)` already exists; **call
  it** from timeline and sync. Compute `UserEventPosition` from
  membership events, not a guess.
- Restricted / knock_restricted `allow` conditions: if the referenced
  `room_id` is not this room's state map, **reject**. Delete the
  unit test that plants a foreign member event under this room's key.
  Full space membership is `conduit-jt5` after this fail-closed.
- Federation backfill / `get_missing_events`: filter with the same
  visibility rules against the origin server's membership, not
  `is_event_visible_to_server` → true.

CS GET `/state`, `/state/{type}`, `/joined_members`, `/messages`
SHALL use `may_read_room`. Unused `_authed` is a bug, not a style.

## Where the code lives

`conduit` (no HTTP types):

- `identikey-auth` challenge issue/verify
- Biscuit mint / verify / (optional) attenuate
- `may_read_room`, wired `can_see`, fail-closed restricted joins

`conduit-server`: Bearer extraction → library verify; optional OIDC
on-ramp; map `conduit::Error` to Matrix JSON. No SHA-256 token table
as the source of truth.

## Risks

- Element and other CS clients treat the access token as opaque. Base64
  biscuits are larger (~400–600 B). Fine for headers. Do not put them
  in URLs.
- Minter key is a new secret next to the Matrix server key. Persist
  it hashed-at-rest like signing keys; rotation = epoch bump.
- `biscuit-auth` Datalog is easy to get wrong. Keep the fact schema
  tiny (`user`, `device`, `server`, `epoch`, `right`, `room`,
  `operation`, `time`). No open-ended policy language in v1.
