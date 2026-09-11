## ADDED Requirements

### Requirement: Three auth layers stay uncollapsed

The kernel SHALL treat identity, agency, and data access as separate
layers. Identity SHALL be a possession proof (password, identikey-auth
`Response`, or a verified foreign OIDC token). Agency SHALL be a
Biscuit. Data access for room events SHALL be Matrix membership plus
history visibility, and for E2EE content SHALL remain Olm/Megolm. The
kernel SHALL NOT depend on Recrypt. The kernel SHALL NOT treat a
Biscuit as proof of identity or a recryption key as a right to an
operation.

#### Scenario: Password login yields a grant, not a hash lookup

- GIVEN a local account with an Argon2 password hash
- WHEN the user logs in with the correct password
- THEN the kernel mints a Biscuit bound to that MXID and device and
  does not require SHA-256 lookup of opaque token bytes to authorize
  the next request

#### Scenario: Recrypt is not on the send path

- GIVEN a client sending `m.room.message`
- WHEN the kernel authorizes and persists the event
- THEN no Recrypt crate is invoked and no PRE transform is applied

### Requirement: Agency tokens are Biscuits

Client-server agency SHALL use Biscuits as specified by
identikey-protocol identikey-capability-v1. The authority block SHALL
be signed with a homeserver Ed25519 **minter** key, not the Matrix
server signing key and not the user's identity key. A root token SHALL
assert `user`, `device`, `server`, `epoch`, and `right("cs")`, and
SHALL carry a time check. Verification SHALL check the authority
signature chain and evaluate Datalog against verifier-injected facts
(`time`, and `room` / `operation` when the request is scoped). A
holder MAY attenuate (narrower rights, shorter TTL, room subset) and
SHALL NOT widen. Matrix CS MAY present the token as
`Authorization: Bearer` with URL-safe base64 bytes and an optional
`biscuit:` prefix. Possession of the bytes SHALL suffice for the
Matrix CS profile; holder-bound proofs are not required on that
profile.

#### Scenario: Expired biscuit is rejected

- GIVEN a Biscuit whose time check is in the past
- WHEN a request presents it
- THEN the kernel returns unauthorized and does not consult a hashed
  token table as a fallback

#### Scenario: Epoch bump revokes without a denylist

- GIVEN a valid Biscuit minted at epoch 3 for a device
- WHEN that device is logged out and the stored epoch becomes 4
- THEN verification fails because injected `epoch` does not match

#### Scenario: Attenuation cannot add admin

- GIVEN a root Biscuit with `right("cs")` only
- WHEN a holder appends a block
- THEN a request that requires `right("admin")` still fails

### Requirement: identikey-auth is a first-class identity on-ramp

The kernel SHALL issue identikey-auth challenges with audience equal
to the server name and SHALL verify responses with a configured
`VerifyPolicy`. A verified fingerprint SHALL map to a local MXID
(linked at register or bind). A successful identikey-auth login SHALL
mint the same Biscuit agency token as password login. The kernel SHALL
depend on `identikey-auth` from identikey-protocol and SHALL NOT
depend on identikey-core crates.

#### Scenario: Challenge response mints a biscuit

- GIVEN a local MXID linked to an identikey-auth fingerprint
- WHEN the client completes a valid challenge/response
- THEN the kernel returns a Biscuit for that MXID and device

#### Scenario: Unlinked fingerprint does not create an account

- GIVEN a verified identikey-auth `Response` whose fingerprint is
  linked to no MXID
- WHEN the kernel processes it as a login
- THEN login fails, no account is created, and no Biscuit is minted.
  A link SHALL be created only by the registration endpoint under its
  existing policy, or by a bind that already requires a valid grant.

#### Scenario: Wrong audience fails closed

- GIVEN a response signed for a different audience
- WHEN the kernel verifies it
- THEN login fails and no Biscuit is minted

### Requirement: identikey-core is an external OP

When the HTTP host is configured with `CONDUIT_OIDC_ISSUER`, it SHALL
validate the OP JWT with `identikey-oidc-client` (Apache RP crate) and
then mint a Conduit Biscuit for the linked MXID. The OP token SHALL
NOT be used as the agency grant. `conduit` SHALL NOT depend on the
AGPL `identikey-oidc` provider. Unlinked OIDC subjects SHALL fail
login.

#### Scenario: Unconfigured host has no OIDC path

- GIVEN no OIDC issuer configured
- WHEN a client presents an identikey-core JWT as a Matrix access token
- THEN the kernel does not accept it as a Biscuit

#### Scenario: Configured host mints after JWT verify

- GIVEN `CONDUIT_OIDC_ISSUER` is set and `sub` is linked to an MXID
- WHEN the client logs in with `io.identikey.oidc` and a valid JWT
- THEN the host returns a Conduit Biscuit, not the OP token

### Requirement: Room reads require membership

CS GET of room state, a single state event, joined members, and
messages SHALL require `may_read_room` for the authenticated user.
A user who is not joined (and, for invite-state, not invited) SHALL
receive forbidden or not-found per Matrix, not the room contents. The
authenticated user parameter SHALL be used.

`may_read_room` SHALL pass a non-member when the room's
`history_visibility` is `world_readable`. That is peeking, not a hole
in agency: the request has already presented a valid grant before the
predicate runs, and an unauthenticated request never reaches it.

#### Scenario: Foreign token cannot read state

- GIVEN Alice joined to `!room` and Bob never a member
- WHEN Bob GETs `/rooms/!room/state` with a valid token
- THEN the kernel does not return the state event list

#### Scenario: World-readable room may be peeked by a non-member

- GIVEN history_visibility `world_readable` and Bob never a member
- WHEN Bob GETs `/rooms/!room/state` with a valid token
- THEN the state is returned

#### Scenario: Joined user reads state

- GIVEN Alice is joined
- WHEN Alice GETs `/rooms/!room/state`
- THEN the current state is returned

### Requirement: History visibility is enforced

`can_see` SHALL be applied to timeline events in `/messages` and
`/sync`. `UserEventPosition` SHALL be derived from membership events
in that room. Federation backfill and get_missing_events SHALL filter
events with the same rules against the requesting origin's
membership, and SHALL NOT treat every history_visibility value as
visible.

#### Scenario: joined-only hides pre-join events

- GIVEN history_visibility `joined` and Bob joined after event E
- WHEN Bob pages `/messages`
- THEN E is not included

#### Scenario: world_readable still requires a valid grant

- GIVEN history_visibility `world_readable`
- WHEN an unauthenticated request asks for `/messages`
- THEN it is rejected; world_readable does not skip agency

### Requirement: Restricted joins fail closed

When `m.room.join_rules` is `restricted` or `knock_restricted`, a join
SHALL be rejected unless an `allow` condition can be evaluated against
state the kernel actually has for **this** room. Membership in a
different room named by `allow[].room_id` SHALL NOT be proven by
inserting that other room's member event into this room's state map.
Until a real other-room membership lookup exists, such joins SHALL
fail closed.

#### Scenario: Foreign room_id in allow does not pass

- GIVEN join_rules restricted with `allow` naming `!space:server`
- AND the joiner is not a member of this room and has no invite
- WHEN they join
- THEN the join is rejected even if a member event whose `room_id`
  field is `!space:server` is present in this room's state map

#### Scenario: Invite still joins

- GIVEN the same restricted room and a valid invite for the joiner
- WHEN they join
- THEN the join is authorized by the invite path, not by the stub
  allow check
