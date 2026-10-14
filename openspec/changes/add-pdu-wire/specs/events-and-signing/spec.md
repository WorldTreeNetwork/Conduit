## ADDED Requirements

No living `events-and-signing` capability exists yet, so every requirement
here is ADDED. The `federation-automation` and `embeddable-kernel`
requirements are unaffected.

### Requirement: Wire/local event separation

The system SHALL represent v11 federation events as `Pdu`, which holds the v11
protocol fields and a flattened map of every other top-level key. `Pdu` SHALL
NOT hold an event ID or `unsigned`. `Event` SHALL own the derived ID, the
`Pdu`, and local unsigned data. Content hashing, reference hashing, ID
derivation, signing, co-signing and signature verification SHALL accept `Pdu`
only. No code path SHALL read a wire-supplied event ID as identity, and
Conduit-authored PDUs SHALL NOT carry an `event_id` key.

#### Scenario: Standard received event

- GIVEN a v11 PDU without `event_id` that carries an unknown top-level key
- WHEN it is decoded, verified and persisted
- THEN its ID is derived from the reference hash, and the unknown key is
  retained byte-for-byte through storage and re-emission

#### Scenario: Local metadata independence

- GIVEN a signed `Pdu` wrapped in an `Event`
- WHEN the `Event`'s `event_id` is set to any value
- THEN the content hash, reference hash and signature bytes of the `Pdu`
  are unchanged and the signature verifies

### Requirement: Received PDU validity

On receipt, before signature checks, the system SHALL:
- strip `unsigned` to `age` (any type) and `invite_room_state` /
  `knock_room_state` (`m.room.member` only);
- validate canonical JSON over the entire remaining object;
- enforce the v11 event format:
  - `auth_events` holds at most 10 entries, and `prev_events` at most 20;
  - `depth` is an integer in `[0, 2^53-1]`, inclusive at both ends;
  - the canonical PDU, including the allow-listed `unsigned` as received
    with `age`, is at most 65536 bytes;
  - `sender`, `room_id`, `type` and `state_key` are each at most 255 bytes
    of UTF-8;
  - `state_key` is either absent or a string;
  - there is no U+0000 in `sender`, `room_id`, `type`, `state_key`,
    `auth_events` or `prev_events`;
  - there is no top-level `event_id` key;
- require that re-encoding the decoded `Pdu` as canonical JSON reproduces
  the received object, minus `unsigned`.

Inbound federation request bodies that contain non-canonical values
already fail X-Matrix verification with `401 M_UNAUTHORIZED`, and that
behaviour SHALL be kept. The canonical-value drop therefore applies to
fetched responses and to direct decode.

A PDU that fails SHALL be dropped. The drop SHALL be deterministic and
SHALL NOT cause a 5xx. On `/send` the PDU SHALL be omitted from the `pdus`
result map, and the transaction's other PDUs and EDUs SHALL still be
processed. On `/send_join` and `/invite` the response SHALL be
`400 M_BAD_JSON`. Error strings SHALL NOT echo values taken from the PDU.

#### Scenario: Explicit event_id is invalid

- GIVEN a v11 PDU that carries a top-level `event_id` key, which the pinned
  Synapse also refuses (checked-in negative fixture)
- WHEN it arrives in a `/send` transaction
- THEN it is not persisted, the transaction still returns 200, and the
  `pdus` map has no entry for it

#### Scenario: Non-canonical values are dropped

- GIVEN PDUs carrying an integer of 2^53, a float, 11 `auth_events`, 21
  `prev_events`, `"state_key": null`, or a value that does not round-trip
- WHEN each is received
- THEN each is dropped and nothing is stored

#### Scenario: Depth bounds are inclusive

- GIVEN otherwise valid PDUs with `depth` -1, 0, 2^53-1 and 2^53
- WHEN each is received
- THEN the PDUs with depth 0 and 2^53-1 are accepted, and those with -1 and
  2^53 are dropped

#### Scenario: PDU size limit

- GIVEN otherwise valid PDUs whose canonical size is exactly 65536 bytes
  and 65537 bytes
- WHEN each is received
- THEN the 65536-byte PDU is accepted and the 65537-byte PDU is dropped

#### Scenario: Field byte limits

- GIVEN otherwise valid PDUs whose `sender`, `room_id`, `type` or
  `state_key` is 255 bytes, and others where that field is 256 bytes (using
  multi-byte UTF-8 so the counts are bytes, not code points)
- WHEN each is received
- THEN every 255-byte PDU is accepted and every 256-byte PDU is dropped

#### Scenario: U+0000 over /send

- GIVEN one `/send` transaction holding four items: a valid PDU with
  `\u0000` in a `content` string, a valid PDU with `\u0000` in `state_key`,
  an ordinary PDU, and an EDU
- WHEN it is PUT against PostgreSQL storage
- THEN:
  - the response is 200;
  - the content-NUL PDU has a success entry and is persisted, and federation
    `/event` and the client API read it back byte-exact;
  - the state_key-NUL PDU has no result entry and is not stored;
  - the ordinary PDU and the EDU are processed;
  - a replay of the same transaction ID returns the identical stored
    response

#### Scenario: Remote unsigned allow-list

- GIVEN an `m.room.message` PDU whose `unsigned` holds `age`,
  `invite_room_state` and `foo`
- WHEN it is persisted
- THEN only the local `age_ts` derived from `age` is stored

### Requirement: Required signers and event-time key validity

Signature verification SHALL require a signature from each required
server:
- **The sender's server.** A 3rd-party-invite membership (`m.room.member`,
  `membership` `invite`, `content.third_party_invite` present) is exempt
  from this requirement.
- **The authorising server.** For `m.room.member` joins whose content
  carries `join_authorised_via_users_server`, the server of that user is
  also required.

A signing key SHALL be eligible for an event only when its effective
validity is at least the event's `origin_server_ts`:
- for `verify_keys`, the effective validity is
  `min(valid_until_ts, fetched_at + 7 days)`;
- for `old_verify_keys`, it is `expired_ts`.

The system SHALL refetch a key that is unknown or not eligible before it
decides, and wall-clock cache expiry SHALL NOT make a key eligible. For
each required server, every signature made with an eligible key SHALL
verify, and at least one SHALL remain. Otherwise the PDU SHALL be dropped.

These rules SHALL apply equally to `/send`, `/send_join`, `/invite`, and
every fetched PDU, auth events included. A non-join `m.room.member` event
that carries `join_authorised_via_users_server` without a valid signature
from that user's server SHALL be rejected by the auth rules (v11 rule 4.2),
not dropped.

#### Scenario: Key validity boundary

- GIVEN a key with `valid_until_ts` T, fetched more than 7 days before T
  was reached
- WHEN events signed with it at `origin_server_ts` T and T+1 are received
- THEN the event at T verifies, and the event at T+1 is dropped with no
  eligible signature, unless a refetch renews the key

#### Scenario: Seven-day cap

- GIVEN a key published with `valid_until_ts` one year ahead and fetched at
  time F
- WHEN events signed with it at `F + 7d` and `F + 7d + 1` are received, and
  the refetch returns no renewal
- THEN the first verifies and the second is dropped

#### Scenario: Historical event after rotation

- GIVEN a server that rotated its key at R, with the old key listed in
  `old_verify_keys` and `expired_ts` R
- WHEN events signed with the old key at R-1 and R+1 are received
- THEN the event at R-1 verifies and the event at R+1 is dropped

#### Scenario: Restricted join signatures

- GIVEN three checked-in v11 joins carrying `join_authorised_via_users_server`:
  one signed only by the sender's server, one with an invalid authoriser
  signature, and one validly co-signed by the authorising server
- WHEN each is received over `/send`, and each is fetched as an auth event
- THEN the first two are dropped and not stored in both paths, the third
  is admitted, and each verdict equals the recorded Synapse verdict

#### Scenario: Third-party invite exemption

- GIVEN an `m.room.member` invite carrying `third_party_invite`, signed by a
  server other than the sender's
- WHEN it is received
- THEN it passes the signature stage, and the same event without
  `third_party_invite` is dropped

### Requirement: Cryptographic and redaction invariants

Content hashing SHALL cover the `Pdu`, including its extensions, and SHALL
exclude `hashes`, `signatures` and `unsigned`, exactly as the spec specifies.
In particular, `age_ts`, `outlier` and `destinations` SHALL NOT be excluded.
Reference hashing and signatures SHALL use exact v11 redaction, which clears
all extensions, including `origin`, `membership` and `prev_state`. On a
content-hash mismatch, after signature validation, the system SHALL keep the
redacted `Pdu` with the same derived ID and unchanged `hashes` and
`signatures`.

#### Scenario: Extension affects only the content hash

- GIVEN two otherwise identical `Pdu`s, one with an extra top-level key
- WHEN both are hashed
- THEN their content hashes differ and their reference hashes are equal

#### Scenario: Hash mismatch redacts without changing identity

- GIVEN a validly signed PDU whose content was altered after hashing
- WHEN it is received
- THEN the stored form is the v11 redaction, under the same derived ID, with
  the original `hashes` and `signatures`

#### Scenario: Synapse-authored fixture

- GIVEN the checked-in PDU authored by Synapse 1.162.0, with an extension key
  and no `event_id`, together with its signing key and the ID Synapse
  computed
- WHEN `cargo test` decodes it, checks the content hash, derives the ID and
  verifies the signature, with no Docker or network
- THEN every step succeeds and the derived ID equals Synapse's

### Requirement: Co-signing preserves the author's PDU

The system SHALL provide `add_signature`. It SHALL add one signature over the
v11-redacted bytes and SHALL leave `hashes` and every other field unchanged.
The system SHALL co-sign foreign PDUs only with `add_signature`. Before it
co-signs or persists an inbound `/invite` PDU, the system SHALL require all
of the following:
- the required signatures verify under event-time key validity;
- the content hash matches; inbound `/invite` SHALL NOT take the
  redact-on-mismatch path;
- the derived ID equals the path `eventId`;
- the sender's server name equals the authenticated origin, except for a
  3rd-party-invite membership.

A failure SHALL return `400 M_INVALID_PARAM`, with nothing co-signed and
nothing persisted. On success, the returned event SHALL be the received
`Pdu` with exactly one signature added.

#### Scenario: Co-sign is hash-neutral

- GIVEN an inviter-signed invite PDU
- WHEN Conduit co-signs it
- THEN `hashes` and the derived ID are byte-identical to the inviter's, and
  both signatures verify

#### Scenario: Forged invite is refused before co-sign

- GIVEN an invite PDU whose inviter signature does not verify, or whose
  derived ID differs from the path `eventId`, or whose sender is not on the
  requesting origin
- WHEN it is PUT to `/v2/invite`
- THEN the response is `400 M_INVALID_PARAM`, no signature is added, and
  nothing is stored

#### Scenario: Invite with a content-hash mismatch is refused

- GIVEN an invite PDU that is validly signed but whose content was changed
  after its content hash was computed
- WHEN it is PUT to `/v2/invite`
- THEN the response is `400 M_INVALID_PARAM`, no signature is added, and
  nothing is stored, in either redacted or unredacted form

### Requirement: Fetch-by-ID integrity

Every remote PDU that Conduit receives as the answer to a federation request
SHALL be decoded as a `Pdu`. Before it is persisted, the PDU SHALL pass the
received-PDU validity checks and signature verification, and it SHALL then
meet its endpoint's expectation:

- **`Exactly(id)`**: the derived ID equals the requested ID. This applies to
  `GET /event/{id}`, including auth-event fetches, the outbound `/invite`
  response, and the `/send_join` response `event`. For the `/invite` and
  `/send_join` `event` responses, `hashes` SHALL also be unchanged, and the
  co-signing server's signature (invitee or resident) SHALL verify.
- **`/state_ids`**: SHALL persist nothing. Its `pdu_ids ∪ auth_chain_ids`
  SHALL become the expected set for `/state` about the same room and event.
- **`/state`**: the derived ID is in that set, a `/state_ids` call SHALL
  precede it, and each event SHALL be a state event whose `room_id` is the
  requested room.
- **`/send_join` response `state`**: no expected ID. Each event's ID is
  derived and its signatures verified. Each SHALL be a state event of the
  joined room. A duplicate `(type, state_key)` SHALL fail the whole join
  and store nothing from the response.
- **`/send_join` response `auth_chain`**: the derived ID is in the
  `auth_events` closure of `state ∪ {join}`.
- **`backfill` and `get_missing_events`**: the derived ID is a requested
  seed, or is named in `prev_events` by an event already admitted from the
  same response or held locally. Admission SHALL repeat until no new event
  is admitted, and SHALL NOT depend on response order. The seeds are the
  requested `v` IDs for `backfill`, and the `prev_events` of the requested
  `latest_events` for `get_missing_events`; those events are in hand but
  not necessarily persisted.

Response events that are outside the expectation SHALL NOT be stored. A
fetched event whose content hash mismatches SHALL be stored in redacted form
under its derived ID.

#### Scenario: Substituted event is refused

- GIVEN a peer that answers `GET /event/$A` with a different event `$B` that
  is validly signed
- WHEN Conduit fetches `$A` as a missing auth event
- THEN the fetch fails with an ID mismatch and storage holds neither `$A`
  nor `$B`

#### Scenario: Unreferenced extra event is not stored

- GIVEN a `get_missing_events` response that holds the requested ancestor
  chain plus one extra, validly signed event that nothing in the chain or in
  local storage references
- WHEN Conduit admits the response
- THEN every event in the chain is stored, and the extra event is not

#### Scenario: Auth chain outside the closure is not stored

- GIVEN a `/send_join` response whose `auth_chain` holds an event outside
  the `auth_events` closure of `state ∪ {join}`
- WHEN Conduit admits the response
- THEN that event is not stored, and the in-closure events are stored

#### Scenario: Fetched event redacted on receipt

- GIVEN a peer that answers `GET /event/$A` with `$A`, validly signed, whose
  content hash mismatches
- WHEN Conduit fetches `$A`
- THEN the redacted form is stored under `$A`

### Requirement: Received join validation

On `/v2/send_join`, the system SHALL require `type` `m.room.member`,
`membership` `join`, `state_key == sender`, a sender server name equal to the
authenticated origin, valid signatures, and a derived ID equal to the path
`eventId`. When `join_authorised_via_users_server` is present, its server
SHALL be this server, and the system SHALL co-sign with `add_signature`
before it verifies. Any of these failures SHALL return
`400 M_INVALID_PARAM`. An auth-rule failure SHALL return `403 M_FORBIDDEN`.
`make_join` templates SHALL NOT contain `event_id`.

#### Scenario: Join for another user is refused

- GIVEN a join PDU whose `state_key` differs from its `sender`, or whose
  sender is not on the requesting origin
- WHEN it is PUT to `/v2/send_join`
- THEN the response is `400 M_INVALID_PARAM` and nothing is stored

### Requirement: Durable wire preservation

PostgreSQL SHALL store each event's `Pdu` as canonical JSON text, which is
authoritative. The existing columns SHALL be projections only. Every `events`
read SHALL go through one row decoder.

Migrations SHALL NOT rewrite any table:
- the `events` column additions SHALL be metadata-only and in their own
  migration;
- `transactions` and `fed_outbound_queue` SHALL gain new nullable `TEXT`
  columns, with fallback reads of their legacy JSONB columns, rather than a
  column type change;
- each migration SHALL set a `lock_timeout`.

No spec-valid PDU SHALL fail on a U+0000 at any PostgreSQL sink:
- new `transactions` request/result and `fed_outbound_queue` payload
  values SHALL be written as lossless JSON text (`serde_json`), never with
  the Matrix canonical encoder. Floats in client bodies SHALL therefore
  round-trip;
- the JSONB projections of `content`, `hashes` and `signatures` SHALL map
  U+0000 to U+FFFD, and reads SHALL NOT decode them;
- an unsigned value containing U+0000 SHALL be dropped;
- U+0000 in `room_id`, `sender`, `type`, `state_key`, `auth_events` or
  `prev_events` SHALL be refused at decode;
- on `/send`, an EDU whose persistence fails with a PostgreSQL data
  exception (SQLSTATE class 22) SHALL be dropped without failing the
  transaction. Each EDU SHALL be isolated in its own statement or
  `SAVEPOINT`.

A legacy-row check SHALL recompute the reference hash and the content hash
of every legacy row. It SHALL classify each row as `verified`,
`content_mismatch` or `id_mismatch`, report the counts and each ID mismatch,
and SHALL NOT rewrite any primary key. The check SHALL NOT block startup,
and a federation read of an unchecked row SHALL classify that row inline.
Over federation, `id_mismatch` rows SHALL NOT be served, and
`content_mismatch` rows SHALL be served only as their v11 redaction. That
redaction SHALL be computed at serve time. Classification SHALL NOT change
what client reads return: retained history keeps the same `Pdu` before and
after inline classification and the sweep.

#### Scenario: Pool restart

- GIVEN a persisted PDU with extensions, a string containing `\u0000`, and
  the integer 2^53-1
- WHEN storage is reopened, the PDU is read through every public `Storage`
  event read, on both PostgreSQL and memory, and it is emitted over
  federation
- THEN the `Pdu` and its content hash are unchanged, and the wire object has
  no `event_id`

#### Scenario: Legacy row with a non-reproducible ID

- GIVEN an `events` row hashed the way the code before `56498e3` hashed it
  (reference hash including `"event_id": ""`)
- WHEN the integrity check runs
- THEN the row is marked `id_mismatch` and logged with both IDs, its primary
  key is unchanged, and federation `/event` for it returns 404

#### Scenario: Lossy legacy row is served redacted

- GIVEN a legacy remote row whose ID reproduces but whose content hash does
  not, and which the background sweep has not yet reached
- WHEN a peer requests it with federation `/event`
- THEN the row is classified `content_mismatch` inline, and the response is
  its v11 redaction under the same derived ID

#### Scenario: Client history survives classification

- GIVEN a lossy legacy remote message row, with its ID intact and its
  content hash mismatched
- WHEN client reads are taken before classification, after inline
  classification triggered by federation `/event`, and after the background
  sweep
- THEN all three client reads are byte-identical and still carry the body,
  while federation `/event` returns the redaction

#### Scenario: Migrations do not rewrite tables

- GIVEN `events`, `transactions` and `fed_outbound_queue` holding
  pre-migration rows
- WHEN the migrations run
- THEN each table's `relfilenode` is unchanged, legacy JSONB rows still
  replay and drain, and new rows use the `TEXT` columns

#### Scenario: Client float survives replay storage

- GIVEN a client to-device `PUT` whose content holds `1.5`
- WHEN it is stored and the same transaction ID is replayed
- THEN the replay is identical and the delivered content still holds `1.5`

#### Scenario: Local NUL content federates

- GIVEN a local state event whose `topic` content contains `\u0000`
- WHEN it is persisted and enqueued for a remote destination
- THEN the outbox payload reads back byte-exact and the event is sent

### Requirement: Typed outbound boundary

Every federation emitter SHALL take `WirePdu`, never `Event` or a bare
`Pdu`, in its function signature. That covers transaction send, the
outbound queue envelope, the `state`, `backfill`, `event`,
`get_missing_events`, `send_join` and `invite` responses, and the outbound
`invite` and `send_join` bodies.

Only the following SHALL construct a `WirePdu`:
- authoring (`sign_authored`);
- co-signing a checked received PDU;
- `get_wire_pdu`, which applies the integrity class;
- `classify_legacy_snapshot`.

New outbox envelopes SHALL hold wire PDUs only. Legacy flattened envelopes
SHALL be read-only, and each snapshot SHALL be classified against its saved
local ID before emission:
- `verified` is sent;
- `content_mismatch` is sent as its redaction;
- `id_mismatch` is withheld and logged.

A legacy snapshot SHALL NEVER be re-signed into a new identity.

#### Scenario: No local ID on the wire

- GIVEN a room with stored events
- WHEN each federation response and outbound body listed above is serialised
- THEN no PDU object in it has a top-level `event_id` key

#### Scenario: Pending legacy outbox envelope (pre-56498e3 hashing)

- GIVEN a pending outbox row in the legacy flattened layout, holding one
  snapshot whose ID was computed with `"event_id": ""` included and one
  verifiable snapshot
- WHEN the queue drains it
- THEN only the verifiable PDU is sent, the other is withheld and logged
  with both IDs, nothing appears under a new event ID, and both events'
  integrity classes are recorded
