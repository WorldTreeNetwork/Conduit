# PDU contract

Amended 2026-10-14 after the send-back in
`reviews/2026-10-14-advise.md`. The section "Review disposition" at the end
records how each amendment and note was handled, with spec citations. The
sections before it are the contract that `act` implements.

## Types

`Pdu` holds the v11 protocol fields (`auth_events, content, depth, hashes,
origin_server_ts, prev_events, room_id, sender, signatures, state_key, type`)
plus `extensions: BTreeMap<String, Value>`, a flattened map of every other
top-level key. `unsigned` is not part of `Pdu`: it is local, unprotected
data and lives on `Event`.

`Event` is `{ event_id: String, pdu: Pdu, unsigned: Option<Value> }`. The
derived ID exists only on `Event`. `Event: Deref<Target = Pdu>` is allowed for
reads. Every function that puts bytes on the wire takes `&Pdu` or `&[Pdu]`
(see "Outbound wire"), so `Deref` cannot cause a leak.

Cryptographic functions accept only `&Pdu`:

| fn | input bytes | mutates |
|---|---|---|
| `content_hash(&Pdu)` | Pdu + extensions, minus `hashes`, `signatures` (unsigned is never in Pdu) | no |
| `reference_hash(&Pdu)` / `event_id(&Pdu)` | `redact(Pdu)` minus `signatures` | no |
| `sign_authored(&mut Pdu, key, server)` | sets `hashes.sha256 = content_hash`, then signs the redacted bytes | `hashes`, `signatures` |
| `add_signature(&mut Pdu, key, server)` | signs the redacted bytes | `signatures[server][key_id]` only |
| `verify_signatures(&Pdu, lookup)` | redacted bytes | no |
| `check_received(Pdu, lookup) -> Received` | as below | no |

`sign_authored` is only for PDUs this server authors: local sends, and
`make_join` templates that we complete for an outbound join. Co-signing a
foreign PDU always uses `add_signature`. `add_signature` never touches
`hashes`, so the content hash and the derived ID of a co-signed PDU are
byte-identical to what the author produced.

## Wire decode ("is a valid event")

Server-server API, "Checks performed on receipt of a PDU", step 1 says that
an invalid event is dropped. An event is valid when it complies with the event
format of its room version. Inbound decode runs these steps in order.

1. Strip remote `unsigned` to an allow-list. `age` is kept for every type.
   `invite_room_state` and `knock_room_state` are kept only when
   `type == "m.room.member"`. A non-object `unsigned` becomes `{}`. This
   matches Synapse `_strip_unsigned_values`. `age` is converted to a local
   `age_ts = received_ts - age` when it is an integer; otherwise it is
   dropped. Other remote unsigned keys are never persisted.
2. Validate canonical JSON over the whole remaining object, including
   `hashes`, `signatures`, extensions and the kept unsigned values. Integers
   must lie in `[-(2^53)+1, 2^53-1]`; floats, NaN and infinities are refused
   (Appendices, Canonical JSON; room v11 "Servers MUST strictly enforce the
   JSON format ... discarding of events over federation").
3. Enforce the v11 format. All required fields are present and correctly
   typed. `auth_events.len() <= 10`, `prev_events.len() <= 20`, and
   `depth < 2^53 - 1` (room v11 event format). A top-level `event_id` key is
   refused: room v3+ "When events are sent over federation, the `event_id`
   field is no longer included", and Synapse >= 1.155 (pinned peer 1.162.0)
   refuses it ("v2/v3 events must not have an explicit event_id",
   `rust/src/events/formats/v2v3.rs`). See disposition A1.
4. Every other unknown top-level key goes into `extensions` verbatim.

A decode failure is a typed `PduDecodeError`. On `/send`, the PDU is skipped:
it gets no entry in the `pdus` result map, because its ID cannot be trusted,
and the error is logged. This is what Synapse does in `_handle_pdus_in_txn`.
On `/send_join` and `/invite` the request fails with `400 M_BAD_JSON`.

## Received-event checks

`check_received(pdu, lookup)` runs signature verification first. A failure
means the PDU is dropped (spec step 2). It then derives the ID from the
unmodified Pdu. Then it checks the content hash. On a mismatch it returns the
redacted Pdu, keeping `hashes` and `signatures`, and the same derived ID (spec
"Validating hashes and signatures on received events": "use the redacted copy
it calculated"). The result is `Received { event_id, pdu, redacted_on_receipt:
bool }`. Nothing reads a wire-provided ID anywhere.

### Fetch-by-ID

Every remote PDU that Conduit asked for by ID is admitted only through
`admit_fetched(pdu, Expect::Exactly(id) | Expect::OneOf(&set), lookup)`. That
function runs `check_received` and requires `derived == requested`, or that
the derived ID is in the referenced set. It runs before any `put_event`. This
covers:

- `client.event()`. It now returns `Pdu` and never `Event`, so the caller has
  to derive the ID.
- the auth-event fetch in `pipeline.rs::fetch_missing_auth_events`. This is
  the only fetch whose result is persisted today, and it is DAG poisoning.
- `get_missing_events`, `backfill`, `state`, the `send_join` response
  `state`/`auth_chain`, and the `invite` response. These fetch clients return
  `Vec<Pdu>`. No result is persisted until it is admitted. Results from
  `state` and `auth_chain` use `Expect::OneOf`, with the set taken from the
  matching `state_ids` response or from the auth references of the events
  that requested them. Results from `get_missing_events` and `backfill` must
  be named by the `prev_events` of an event that is already admitted, or
  returned as direct ancestors in the requested range.

A mismatch is `FetchError::IdMismatch { requested, derived }`. Nothing is
stored and the peer's answer is discarded. Deep recursive auth verification
of fetched events stays with `conduit-g12` / `conduit-embed-persist`. This
change requires only the ID and signature gate.

### `/invite` (inbound, v2)

1. Decode as Pdu (see "Wire decode").
2. Check `room_id` against the path, `type == m.room.member`,
   `membership == invite`, and that the `state_key` is on our server.
3. Run `check_received` with the inviter's keys. A signature failure is
   refused with `400 M_INVALID_PARAM`.
4. Require `derived ID == path :eventId`. A mismatch gets
   `400 M_INVALID_PARAM`, matching Synapse "Invite event ID must match event
   ID specified in the federation `/invite` request".
5. Run `add_signature(&mut original_pdu, our_key, our_name)` on the Pdu as
   received. Spec: "The event with the invited server's signature added. All
   other fields of the events should remain untouched."
6. Persist the received form. That is the redacted form when the hash did not
   match, still under the derived ID, now carrying our co-signature. Return
   `{"event": original_pdu_with_cosignature}`.

The add_signature co-signature is identical over the redacted and the
unredacted form, because signatures cover the redacted bytes. Step 5 is
therefore valid for whichever form a peer ends up holding.

### `/send_join` (inbound, v2)

1. Decode as Pdu.
2. Check `room_id` against the path, `type == m.room.member` and
   `membership == join`. Require `state_key == sender`, and require that the
   sender's server name equals the authenticated X-Matrix origin. Each
   failure gets `400 M_INVALID_PARAM` (spec send_join v2, 400 response).
3. Run `check_received`. A signature failure gets `400 M_INVALID_PARAM`.
   Require `derived ID == path :eventId`, or `400 M_INVALID_PARAM`.
4. Run the pipeline auth check. A failure gets `403 M_FORBIDDEN`.
5. Respond with `event`, `state` and `auth_chain` as `Pdu`s. `state` is still
   the current state; the pre-join snapshot the spec requires is tracked as
   `conduit-y99.22.1`.

Step 2's sender, state_key and origin checks are folded into this change. The
handler is rewritten for Pdu decode and the path-ID check anyway, the checks
are three comparisons on the same 400 path, and leaving `state_key != sender`
open would leave a membership-forgery hole in a handler this lane owns.

### `make_join`

The template omits `event_id` (the `"$placeholder"` key is removed),
`hashes` and `signatures`. Repeated `ver` parameters are not part of this
change; see `conduit-y99.22.2`.

## Outbound wire

These all take `&Pdu` or `Vec<Pdu>` in their signature, never `Event`:
`FedClient::send_transaction`, `send_join`, `invite`, the outbound queue
`enqueue`, and every federation response builder for `state`, `backfill`,
`event`, `get_missing_events`, `send_join` and `invite`. Responses are built
through one helper, `wire_pdus(&[Event]) -> Vec<&Pdu>`, or by calling `.pdu`
directly. The outbound Pdu carries no `unsigned`. Remote-supplied unsigned is
local metadata, and the spec makes `unsigned` optional. One test serialises
every response and every outbound body and asserts that no PDU object carries
a top-level `event_id` key.

The outbox: new envelopes are `{"pdus": [Pdu...], "edus": [...]}`, holding
wire Pdus only, because the destination derives the ID. Legacy envelopes
written before this change hold flattened Event snapshots. They are decoded by
a legacy reader that removes the top-level `event_id`. Pre-change snapshots
could never hold a wire `event_id`, because v3+ wire PDUs have none, so in
that layout the key is always the local ID. The result is converted to Pdu
before signing and sending. The flattened layout is read-only. Any new
persisted `Event` envelope nests as `{"event_id": ..., "pdu": {...}}`.

## Storage (PostgreSQL)

The authoritative bytes are text. The migration takes the next free number
at implementation time.

```sql
ALTER TABLE events ADD COLUMN pdu_json TEXT;                 -- NULL = legacy row
ALTER TABLE events ADD COLUMN id_integrity TEXT NOT NULL DEFAULT 'unchecked';
```

Both adds are metadata-only on PostgreSQL 11 and later: a nullable column,
and a constant default. Neither rewrites the table. CI runs postgres:16.

- `pdu_json` is the canonical JSON of the Pdu, with extensions and without
  `unsigned`. It is the authoritative wire form. The existing columns
  (`content`, `hashes`, `signatures`, `auth_events`, ...) become projections
  that are kept for SQL predicates. Text was chosen over a JSONB extension
  map because PostgreSQL JSONB rejects the `\u0000` escape ("unsupported
  Unicode escape sequence"), while canonical JSON allows U+0000 in strings. A
  spec-valid event with a NUL in its content would otherwise be refused at
  the database, and every event naming it would then be stuck. In text, the
  NUL stays the six ASCII characters `\u0000`.
- The `content` JSONB projection replaces U+0000 with U+FFFD, in the
  projection only. The only SQL readers of `content` are the
  `content->>'membership' = 'join'` predicates, and a membership value that
  contains NUL is not `join` either way. Reads never decode from this
  projection when `pdu_json` is present.
- The `unsigned` JSONB column holds only local, allow-listed unsigned data. An
  unsigned value that contains U+0000 is dropped with a warning: `unsigned`
  is unprotected ("Keys under `unsigned` can be modified by other servers").
- Numbers: after decode step 2 only safe integers remain, and JSONB stores
  them exactly, so the projections lose nothing. `pdu_json` is canonical text
  anyway.

### One row decoder

Every `events` read in `storage_pg.rs` goes through
`fn event_from_row(row: EventRow) -> Result<Event, StorageError>`. There are
nine hand-built `Event { .. }` literals today, at lines 227, 294, 828, 864,
894, 1035, 1097, 1144 and 1210. Each query selects one shared column list
(a `const EVENT_COLUMNS`). When `pdu_json` is present the decoder parses it.
When it is NULL the decoder rebuilds a Pdu from the projection columns with
empty extensions. MemoryStorage stores `Event` unchanged. One test writes a
Pdu that has extensions, a `\u0000` string in content, and an integer of
2^53-1, and reads it back through every public `Storage` method that returns
events. It runs on both PG and memory, and asserts that the Pdu is equal and
that `content_hash` is unchanged.

### ID-integrity check for legacy rows

Legacy rows cannot be trusted to reproduce their own IDs.

- Local rows written before `56498e3` were content-hashed over the redacted
  event, and reference-hashed with `event_id: ""` included and without
  redaction (see `git show 56498e3 -- conduit/src/hashing.rs`).
- Remote rows lost their unknown top-level keys at ingest.
- Remote auth events were stored unverified, under the wire ID.

A one-shot startup task, `verify_legacy_event_ids`, walks the rows where
`id_integrity = 'unchecked'` in batches of 1000 by `stream_position`. For
each row it rebuilds the Pdu from the projections, recomputes the reference
hash and the content hash, and writes one of the following.

- `verified`: the reference hash equals the `event_id` primary key and the
  content hash matches. `pdu_json` is backfilled from the rebuilt Pdu.
- `content_mismatch`: the ID matches but the content hash does not. Either
  the row lost extensions, or it was legitimately redacted on receipt; the
  two cannot be told apart. `pdu_json` stays NULL.
- `id_mismatch`: the reference hash differs from the primary key.
  `pdu_json` stays NULL.

The task logs a count for each class, and logs every `id_mismatch` row at
WARN with both IDs. It never rewrites a primary key or any reference to one.
Rows written after this change are inserted with `pdu_json` set and
`id_integrity = 'verified'`.

Never serve: federation emitters read through `Storage::get_wire_pdu(id) ->
Option<Pdu>`. It returns `None` unless `id_integrity = 'verified'`. A row
that is not verified behaves like a missing event: `/event` returns 404, and
`/state`, `/backfill` and `/get_missing_events` omit it. Client-facing reads
are unchanged; local history stays visible to local users. Re-fetching
`content_mismatch` rows from their origin through `admit_fetched` is
possible, but it is not part of this change.

## Redaction

`redact(&Pdu) -> Pdu` keeps exactly the v11 top-level keys a Pdu can carry:
`type, room_id, sender, state_key, content, hashes, signatures, depth,
prev_events, auth_events, origin_server_ts`. It clears `extensions`. That
includes `origin`, `membership` and `prev_state`, which "are no longer
protected from redaction" in v11, and any `age_ts`, `outlier` or
`destinations`. It prunes `content` with the existing per-type allow-list:
create keeps all content, and member keeps `third_party_invite.signed`. The
existing OpenSSL and Python vectors in `conduit/tests/matrix_v11_crypto.rs`
stay byte-identical.

## Content hash divergence from Synapse (recorded, not mirrored)

Synapse `compute_content_hash` (`synapse/crypto/event_signing.py`) also pops
the top-level keys `age_ts`, `outlier` and `destinations`. The spec removes
only `unsigned`, `signatures` and `hashes` ("Calculating the content hash").
Conduit follows the spec: those keys are ordinary extensions, and the content
hash covers them. Conduit never authors them. When a PDU from an adversary
carries one of these keys, Conduit and Synapse can disagree about whether the
content hash matches. Whichever side sees a mismatch redacts the PDU. It does
not reject it. The reference hash strips extensions, so both sides derive the
same ID, and the DAG converges. The fixture suite includes such a PDU and
asserts Conduit's spec behaviour.

## Fixtures and tests (acceptance for act)

- A checked-in Synapse-authored fixture,
  `conduit/tests/fixtures/synapse_v11_pdu.json`. It is generated once from
  the pinned 1.162.0 peer venv with a fixed ed25519 seed through
  `synapse.crypto.event_signing.add_hashes_and_signatures`. It holds a v11
  `m.room.message` that carries an extension key and has no `event_id`, the
  ID Synapse computed (`event.event_id`), and the seed and public key. A
  plain `cargo test` asserts that the decode → content-hash match → derived
  ID → signature verify sequence reproduces Synapse's values without Docker.
  A second fixture records that Synapse refuses the same PDU with an
  `event_id` key added; it stores the error string. A third PDU carries an
  `outlier` extension to pin the divergence above. The generator script is
  checked in next to the fixture.
- Property tests:
  - an extension changes the content hash but not the reference hash;
  - a content-hash mismatch yields a redacted Pdu with the same derived ID
    and the same `hashes`;
  - after `add_signature`, `hashes` and the derived ID are byte-identical to
    the input;
  - a `{event_id, pdu}` Event that wraps a signed Pdu verifies whatever its
    `event_id` holds.
- Fetch-by-ID: a peer that answers `/event/$A` with a different event that is
  validly signed is refused with `IdMismatch`, and storage is unchanged.
- `/invite`: a forged inviter signature is refused before co-sign and before
  persist. A path-ID mismatch gets `M_INVALID_PARAM`. The returned event's
  `hashes` equal the request's.
- `/send_join`: `state_key != sender`, a sender domain other than the
  origin, and a path-ID mismatch each get `400 M_INVALID_PARAM`.
- Decode: a top-level `event_id` gets `PduDecodeError::ExplicitEventId`, and
  on `/send` it is skipped with no result entry. Out-of-range integers,
  floats, 11 `auth_events` and 21 `prev_events` are refused. Disallowed
  unsigned keys are not persisted.
- Storage: the round-trip test across all reads described above, and a
  legacy-row integrity test. That test seeds rows the way the pre-`56498e3`
  code hashed them, plus one lossy remote row, and asserts the
  classification and that federation returns 404 for them.
- The live Synapse check `conduit-server/tests/peers/synapse_pdu_wire.py`
  stays.

## Out-of-scope findings (beads under conduit-y99.22)

These are not wire-format work. Only the `send_join` sender/state_key/origin
checks are folded in (see above).

- `conduit-y99.22.1`: `send_join` v2 `state` must be "the resolved current room state prior to
  the join event". Today it is the post-join current state. This needs state
  at an event, which is state-resolution work.
- `conduit-y99.22.2`: `make_join` ignores repeated `ver` and never returns `400
  M_INCOMPATIBLE_ROOM_VERSION` with `room_version`. The spec default is
  `[1]`. Peers in the wild always advertise 11, so there is no interop break
  today.
- `conduit-y99.22.3`: `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}` is missing. The
  spec marks it Required, and Synapse calls it during auth-chain repair.

## Review disposition (2026-10-14 send-back)

**A1. Wire `event_id`: partly rebutted, partly adopted.** The reviewer's
premise is that a v11 PDU carrying a top-level `event_id` is well formed and
that Synapse accepts it. Neither holds today.

- Spec: room v3 Event format says "When events are sent over federation, the
  `event_id` field is no longer included. A server receiving an event should
  compute the relevant event ID for itself." Later versions, v11 included,
  inherit that format. The v11 PDU field table has no `event_id`.
  Server-server "Checks performed on receipt of a PDU", step 1: an event must
  comply with its room version's event format, "otherwise it is dropped".
- The redaction keep-list still names `event_id`. That list is marked
  "Unchanged from v2" in the v3 spec. The entry is vestigial from the v1/v2
  format, where `event_id` was a wire field. It is not evidence that v3+ PDUs
  may carry the key.
- Synapse: since the Rust event port (`9e2a076144`, "Port Event class to
  Rust", included in v1.155.0 and later, so also in our pinned peer 1.162.0),
  `EventFormatV2V3::validate`, which covers rooms 3 through 11, bails with
  "v2/v3 events must not have an explicit event_id". It is called from
  `event_dict_from_json_str` on every event construction. On `/send`, Synapse
  then logs "Ignoring PDU for failing to deserialize" and skips the PDU
  (`federation_server.py`). Synapse's Rust `redact()` still lists `EVENT_ID`
  in `allowed_keys`; for v3+ that is unreachable, for the reason above.

So rejecting the key does not partition Conduit from the room. It keeps
Conduit on the same side as the dominant implementation and the pinned peer.
Accepting the key would partition Conduit the other way: it would hold events
that Synapse refuses, and build on them. Recorded risk: an older Synapse
(before 1.155) or another implementation could accept such an event. If the
live peer suite or a field report shows a real emitter, we revisit this.

Adopted from A1: the derived ID lives only on `Event`. No code path reads a
wire ID as identity. Conduit-authored PDUs never carry `event_id`. New
persisted envelopes nest `{event_id, pdu}` or store the Pdu alone. The
flattened snapshot layout is read-only and legacy, and it is unambiguous,
because a v3+ wire PDU has no `event_id` key that it could be confused with.
The requested vector "a PDU that carries an `event_id` key, with
Synapse-computed hashes" cannot be produced by current Synapse. It is
replaced by the negative fixture: Synapse's refusal is recorded, and Conduit
must refuse the same PDU.

**A2. Authoring vs co-signing: adopted.** `add_signature` is added and
`sign_authored` is renamed from `sign_event`. `/invite` runs decode, then
`check_received`, then the path-ID check, then `add_signature`, then persist,
in that order. A scenario asserts that `hashes` and the derived ID are
unchanged after a co-sign. The restricted-join resident signature, when it
lands, uses `add_signature`.

**A3. Fetch-by-ID: adopted.** `admit_fetched`, with `Expect::Exactly` and
`Expect::OneOf`, gates every persisted remote fetch. The fetch clients return
`Pdu` so that skipping the derive step is a type error. A scenario covers the
`/event/$A` answered with `$B` case.

**A4. Legacy ID-integrity check: adopted, adapted.** The check runs as
reviewed, with three classes because "lossy remote" and "redacted on receipt"
both show up as a content mismatch with a correct ID, and both must not be
served. The reviewer's `extensions JSONB NOT NULL DEFAULT '{}'` becomes
`pdu_json TEXT` (NULL marks a legacy row) plus `id_integrity TEXT NOT NULL
DEFAULT 'unchecked'`. Both adds are metadata-only on PostgreSQL 11 and later.
The text column is A6's resolution.

**A5. One PG row decoder: adopted.** `event_from_row` and `EVENT_COLUMNS`
are used at all nine sites. The extension round trip is tested across every
public `Storage` read method on PG and memory.

**A6. JSONB limits: adopted, text option chosen.** The authoritative store is
canonical text. The JSONB projections are documented as lossy for U+0000
only, and reads never use them. Refusing at ingest would let any room member
wedge Conduit with a spec-valid event.

**A7. Typed outbound boundary: adopted.** The emitter signatures take
`&Pdu`/`Vec<Pdu>`, all serialisation goes through `wire_pdus`, and one test
covers every response and body.

**Notes 1–6.**

1. The Synapse content-hash pops are recorded and not mirrored.
2. Canonical JSON is validated over the whole object, and the type-dependent
   unsigned allow-list matches Synapse.
3. The `send_join` sender/state_key/origin checks are folded in. Pre-join
   `state` and `make_join` `ver` become beads.
4. `/event_auth` becomes a bead.
5. The Synapse fixture is checked in.
6. The property tests listed under "Fixtures and tests" replace the trivial
   "sign, fill, verify" check.
