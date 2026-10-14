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
- enforce the v11 event format, including `auth_events` of at most 10,
  `prev_events` of at most 20, `depth` below 2^53-1, and the absence of a
  top-level `event_id` key.

A PDU that fails SHALL be dropped. On `/send` it SHALL be omitted from the
`pdus` result map. On `/send_join` and `/invite` the response SHALL be
`400 M_BAD_JSON`.

#### Scenario: Explicit event_id is invalid

- GIVEN a v11 PDU that carries a top-level `event_id` key, which the pinned
  Synapse also refuses (checked-in negative fixture)
- WHEN it arrives in a `/send` transaction
- THEN it is not persisted, the transaction still returns 200, and the
  `pdus` map has no entry for it

#### Scenario: Non-canonical values are dropped

- GIVEN PDUs carrying an integer of 2^53, a float, 11 `auth_events`, or 21
  `prev_events`
- WHEN each is received
- THEN each is dropped and nothing is stored

#### Scenario: Remote unsigned allow-list

- GIVEN an `m.room.message` PDU whose `unsigned` holds `age`,
  `invite_room_state` and `foo`
- WHEN it is persisted
- THEN only the local `age_ts` derived from `age` is stored

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
co-signs or persists an inbound `/invite` PDU, the system SHALL verify the
inviter's signatures and content hash, and SHALL require that the derived ID
equals the path `eventId`. A failure SHALL return `400 M_INVALID_PARAM` with
nothing persisted.

#### Scenario: Co-sign is hash-neutral

- GIVEN an inviter-signed invite PDU
- WHEN Conduit co-signs it
- THEN `hashes` and the derived ID are byte-identical to the inviter's, and
  both signatures verify

#### Scenario: Forged invite is refused before co-sign

- GIVEN an invite PDU whose inviter signature does not verify, or whose
  derived ID differs from the path `eventId`
- WHEN it is PUT to `/v2/invite`
- THEN the response is `400 M_INVALID_PARAM`, no signature is added, and
  nothing is stored

### Requirement: Fetch-by-ID integrity

Every remote PDU that Conduit fetched by ID, or received as an answer to a
request naming IDs, SHALL be decoded as a `Pdu`. Before it is persisted, its
derived ID SHALL equal the requested ID, or be in the referenced set, and its
signatures SHALL verify. This covers `/event`, auth-event fetches,
`get_missing_events`, `backfill`, `state`, the `send_join` response `state`
and `auth_chain`, and the `invite` response.

#### Scenario: Substituted event is refused

- GIVEN a peer that answers `GET /event/$A` with a different event `$B` that
  is validly signed
- WHEN Conduit fetches `$A` as a missing auth event
- THEN the fetch fails with an ID mismatch and storage holds neither `$A`
  nor `$B`

### Requirement: Received join validation

On `/v2/send_join`, the system SHALL require `type` `m.room.member`,
`membership` `join`, `state_key == sender`, a sender server name equal to the
authenticated origin, valid signatures, and a derived ID equal to the path
`eventId`. Any failure SHALL return `400 M_INVALID_PARAM`. An auth-rule
failure SHALL return `403 M_FORBIDDEN`. `make_join` templates SHALL NOT
contain `event_id`.

#### Scenario: Join for another user is refused

- GIVEN a join PDU whose `state_key` differs from its `sender`, or whose
  sender is not on the requesting origin
- WHEN it is PUT to `/v2/send_join`
- THEN the response is `400 M_INVALID_PARAM` and nothing is stored

### Requirement: Durable wire preservation

PostgreSQL SHALL store each event's `Pdu` as canonical JSON text, which is
authoritative. The existing columns SHALL be projections only. Every `events`
read SHALL go through one row decoder. The migration SHALL add its columns
without rewriting the table. A one-shot check SHALL recompute the reference
hash and the content hash of every legacy row. It SHALL classify each row as
`verified`, `content_mismatch` or `id_mismatch`, report the counts and each ID
mismatch, and SHALL NOT rewrite any primary key. Rows that are not `verified`
SHALL NOT be served over federation.

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

### Requirement: Typed outbound boundary

Every federation emitter SHALL take `&Pdu` or `Vec<Pdu>`, never `Event`, in
its function signature. That covers transaction send, the outbound queue
envelope, the `state`, `backfill`, `event`, `get_missing_events`,
`send_join` and `invite` responses, and the outbound `invite` and
`send_join` bodies. New outbox envelopes SHALL hold wire `Pdu`s only. Legacy
flattened envelopes SHALL be read-only and converted to `Pdu` before sending.

#### Scenario: No local ID on the wire

- GIVEN a room with stored events
- WHEN each federation response and outbound body listed above is serialised
- THEN no PDU object in it has a top-level `event_id` key
