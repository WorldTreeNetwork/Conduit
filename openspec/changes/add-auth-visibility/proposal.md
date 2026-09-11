# add-auth-visibility

> **ACTIVE BUILD**

Bead: `conduit-embed-auth`. Epic: `conduit-embed`. Depends on
`add-library-ops` for handler location; the predicates and token layer
belong in `conduit` either way.

## Why

Room reads ignore the authenticated user (`_authed` unused). History
visibility (`can_see`) is a pure function with zero call sites.
Restricted joins look green and check the wrong room. Access tokens are
opaque SHA-256 bearers with no attenuation. IdentiKey already split
identity / agency / data: challenge-response for who, Biscuits for what
you may do, Recrypt for who can read *our* ciphertext. Conduit should
take the first two and leave the third on the floor — Matrix membership
plus Olm/Megolm already answer data access.

## What

- ADD capability `auth-and-state`.
- Identity on-ramp: password (existing) and `identikey-auth`
  challenge/response (identikey-protocol, Apache). Optional: HTTP host
  accepts OIDC from an external identikey-core OP (no AGPL crate dep).
- Agency: replace opaque access tokens with Biscuits
  (`identikey-capability-v1`, `biscuit-auth`). Matrix CS presents them
  as Bearer; in-process clients may attenuate.
- Room visibility: membership required on CS GET state / messages /
  joined_members; `can_see` wired into `/messages` and `/sync`;
  restricted/knock_restricted fail closed until other-room membership
  is a real lookup; federation backfill is not always-true.
- Recrypt is not a dependency. See design.md.

## Impact

- Capabilities: ADDED `auth-and-state`
- ADRs: will amend `docs/architecture.md` (auth is no longer
  "planned"; tokens are Biscuits; three IdentiKey layers named)

## User journey & surfaces

No new UI because login, `/sync`, `/messages`, and room state already
exist. Element keeps sending `Authorization: Bearer <token>`; the
bytes become a Biscuit. The in-process client (`add-in-process-client`)
presents the same token type without HTTP. Failed path today: any
valid token reads any room. Off path: restricted rooms, history
visibility, federation backfill.

## Out of scope

- Recrypt / PRE / Gordian-envelope data capabilities — not warranted;
  tracked nowhere until a change that encrypts *Conduit-held*
  ciphertext (not Matrix E2EE, not history visibility)
- Crate dependency on identikey-core (AGPL) — host may speak OIDC to
  it as a foreign OP
- Holder-bound redeem profile (identikey-capability-v1 §7) — Matrix CS
  clients cannot sign a holder proof; that profile is for agent
  delegation later
- Full restricted-join `allow` against another room's membership
  (after fail-closed; `conduit-jt5` stays blocked until a follow-up)
- Sliding sync, guest access, email/phone UIA
- Migration of existing hashed opaque tokens (no production data)
- `add-library-ops` itself, `add-pdu-wire`, `add-in-process-client`
