# PDU contract

Amended twice on 2026-10-14: after the send-back in
`reviews/2026-10-14-advise.md` (A1–A7), and after the second send-back in
`reviews/2026-10-14-advise-2.md` (B1–B4). The "Review disposition" sections
at the end record how each amendment and note was handled, with citations.
The sections before them are the contract that `act` implements.

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
3. Enforce the v11 format and its limits. Each failure has its own
   `PduDecodeError` variant:
   - All required fields are present and correctly typed. `state_key` is
     either absent or a string; `"state_key": null` is refused, as Synapse
     does with `AllowMissing<Box<str>>`.
   - `auth_events.len() <= 10` and `prev_events.len() <= 20`.
   - `depth` is an integer in `[0, 2^53-1]`, inclusive at both ends. The
     v11 text reads "less than the maximum", then "If the room's depth is at
     the limit, the depth must be set to the limit", so `2^53-1` is legal.
     Synapse refuses `depth < 0` and `depth > MAX_DEPTH`, where
     `MAX_DEPTH = 2^53-1` (`federation_base.py:362-369`,
     `api/constants.py`).
   - The whole PDU is at most 65536 bytes. Measure the canonical JSON of the
     received object after the unsigned allow-list, without `unsigned.age`
     or `age_ts`. This is what Synapse measures in `_check_size_limits` with
     `get_pdu_json()` and `MAX_PDU_SIZE`.
   - `sender`, `room_id`, `type`, and `state_key` when present, are each at
     most 255 bytes of UTF-8. A byte limit also bounds the code-point count,
     so Synapse's code-point check is covered. For v11 Synapse treats all of
     these as `unpersistable` (`event_auth.py:451-501`, and
     `strict_event_byte_limits_room_versions` for V11) and drops the PDU.
   - No U+0000 in `sender`, `room_id`, `type`, `state_key`, or any entry of
     `auth_events` or `prev_events`. These values reach PostgreSQL `TEXT` /
     `TEXT[]` key columns, which cannot hold NUL (see B1 sink table).
     Synapse on PostgreSQL cannot persist them either, so refusing them keeps
     Conduit on Synapse's side of the drop/accept line.
   - A top-level `event_id` key is refused: room v3+ "When events are sent
     over federation, the `event_id` field is no longer included", and
     Synapse >= 1.155 (pinned peer 1.162.0) refuses it ("v2/v3 events must
     not have an explicit event_id", `rust/src/events/formats/v2v3.rs`). See
     disposition A1.
4. Every other unknown top-level key goes into `extensions` verbatim.
5. Round-trip identity: `canonical(decoded Pdu)` must equal `canonical(the
   received object minus unsigned)`. Otherwise decode fails with
   `PduDecodeError::NonRoundTrip`. This one check catches any
   normalisation by the typed fields, which would otherwise change both
   hashes without anyone noticing.

A decode failure is a typed `PduDecodeError`. The failure is deterministic:
the same bytes always fail the same way, and a decode failure is never a
500. On `/send` the PDU is skipped and gets no entry in the `pdus` result
map, because its ID cannot be trusted. The error is logged, and the other
PDUs and EDUs in the transaction are processed normally. This is what
Synapse does in `_handle_pdus_in_txn`. Synapse checks size limits later, in
auth, and so may report an error entry under the derived ID; both servers
leave the PDU unpersisted. On `/send_join` and `/invite` a decode failure
returns `400 M_BAD_JSON`.

`PduDecodeError` messages and every other per-PDU error string have a fixed
vocabulary: the variant name, a field name, and numeric limits. They never
echo a value taken from the PDU.

## Received-event checks

`check_received(pdu, lookup)` runs signature verification first. A failure
means the PDU is dropped (spec step 2). It then derives the ID from the
unmodified Pdu. Then it checks the content hash. On a mismatch it returns the
redacted Pdu, keeping `hashes` and `signatures`, and the same derived ID (spec
"Validating hashes and signatures on received events": "use the redacted copy
it calculated"). The result is `Received { event_id, pdu, redacted_on_receipt:
bool }`. Nothing reads a wire-provided ID anywhere.

### Fetch-by-ID

Every remote PDU that Conduit receives as the answer to a request is
persisted only after it passes `admit_fetched`. The fetch clients return
`Pdu` or `Vec<Pdu>`, never `Event`, so the caller cannot skip deriving the
ID. `admit_fetched` decodes the PDU (see "Wire decode"), runs
`check_received` (signatures, derived ID, content hash), and then applies
the expectation for that endpoint from the table below. Only then can
`put_event` run.

An event that was redacted on receipt is still admitted. Its derived ID
equals the unredacted ID, so `Exactly` passes, and the redacted form is what
gets stored.

| endpoint (client fn) | expectation | how a response event is accepted |
|---|---|---|
| `GET /event/{id}` (`client.event`) | `Exactly(id)` | `derived == id`. This includes the auth-event fetch in `pipeline.rs::fetch_missing_auth_events`, the only fetch that is persisted today. |
| `PUT /v2/invite` response (`client.invite`, outbound) | `Exactly(our_invite_id)` | `derived == id`. `hashes` must be byte-identical to what we sent, and the invitee server's signature must be present and must verify. |
| `PUT /v2/send_join` response `event` (restricted join, resident co-signed) | `Exactly(our_join_id)` | `derived == id`, `hashes` unchanged, and the resident server's signature verifies. |
| `GET /state_ids?event_id=E` (`client.state_ids`) | none (IDs only) | Returns `pdu_ids` and `auth_chain_ids` and stores nothing. Those sets become the expectation for the follow-up `/state` or `/event` calls about the same `(room, E)`. |
| `GET /state?event_id=E` (`client.state`) | `OneOf(state_ids ∪ auth_chain_ids)` | A `state_ids` call for the same `(room, E)` must come first. Events in `pdus` must also be state events (they have a `state_key`) and have `room_id == room`. |
| `PUT /v2/send_join` response `state` | `Asserted` (no expected ID) | Each event's ID is derived and its signatures verified. Each must be a state event with `room_id == room`, and at most one may exist per `(type, state_key)`. The resident server is asserting this state; we did not request any of these IDs. |
| `PUT /v2/send_join` response `auth_chain` | `Closure(auth_events of state ∪ {join})` | Admitted by walking the closure: start from the `auth_events` of the admitted `state` and of our join, admit any `auth_chain` event whose derived ID is in the frontier, add that event's `auth_events`, and repeat until nothing changes. |
| `GET /backfill?v=..&limit=` (`client.backfill`) | `Closure(prev_events from v)` | Seeds are the requested `v` IDs. A response event is admitted if its derived ID is a seed, or is named in `prev_events` by an event already admitted from this response or held locally. Same fixed-point walk. |
| `POST /get_missing_events` (`client.get_missing_events`) | `Closure(prev_events from latest_events)` | Seeds are the `prev_events` of the requested `latest_events`, which we hold. The walk stops at `earliest_events`. Same fixed-point walk. |

The closure walk does not depend on the order of the response. It repeats
until no new event is admitted. Anything left over is not stored: an event
that nothing references, or one outside the closure. It is logged once per
response with a count. A failure on `Exactly` or `OneOf` is
`FetchError::IdMismatch { requested, derived }`. Nothing from that answer is
stored, and the peer's answer is discarded. The closure is cut off at the
spec page sizes (`limit`) and at 10 `auth_events` / 20 `prev_events` per
event, so a peer cannot make it grow without bound.

Deep recursive auth verification of fetched events stays with `conduit-g12`
and `conduit-embed-persist`. This change requires only the decode,
signature, ID and expectation gate.

### `/invite` (inbound, v2)

1. Decode as Pdu (see "Wire decode"). A failure returns `400 M_BAD_JSON`.
2. Check `room_id` against the path, `type == m.room.member`,
   `membership == invite`, that the `state_key` is on our server, and that
   the sender's server name equals the authenticated X-Matrix origin. A
   failure returns `400 M_INVALID_PARAM`.
3. Verify the inviter's signatures. A failure returns
   `400 M_INVALID_PARAM`.
4. Require `derived ID == path :eventId`. A mismatch returns
   `400 M_INVALID_PARAM`, matching Synapse's "Invite event ID must match
   event ID specified in the federation `/invite` request".
5. Require the content hash to match. A mismatch returns
   `400 M_INVALID_PARAM`; nothing is co-signed and nothing is persisted.
6. Run `add_signature(&mut pdu, our_key, our_name)`. Spec: "The event with
   the invited server's signature added. All other fields of the events
   should remain untouched."
7. Persist the co-signed Pdu under the derived ID, then return
   `{"event": pdu}`.

The `/invite` path never takes the redact-on-mismatch route. A PDU that
reaches step 6 is byte-identical to what was received, apart from the one
signature that step adds. This differs from Synapse, which redacts and
continues (B2 disposition).

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

Error codes are a deliberate choice. Synapse returns `403` for a sender that
is not on the origin, and `400 M_BAD_JSON` for `state_key != sender`. We
return `400 M_INVALID_PARAM` for both. The v1.19 `send_join` v2 400 response
names `M_INVALID_PARAM` for exactly these cases, and peers treat any 4xx
from `send_join` as a failed join.

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
ALTER TABLE transactions       ALTER COLUMN request TYPE TEXT USING request::text;
ALTER TABLE transactions       ALTER COLUMN result  TYPE TEXT USING result::text;
ALTER TABLE fed_outbound_queue ALTER COLUMN payload TYPE TEXT USING payload::text;
```

- **`events` adds.** Both are metadata-only on PostgreSQL 11 and later (a
  nullable column, and a constant default), so neither rewrites the table.
  CI runs postgres:16.
- **Column type changes.** These rewrite `transactions` and
  `fed_outbound_queue`. Both are bounded caches, not history: replay
  results, and an outbox whose `sent` rows can be collected. A short
  exclusive lock on them during the migration is acceptable.
- **Existing JSONB text.** JSONB rows cannot contain U+0000, so `::text`
  always produces valid JSON.
- **Constraints.** The `transaction_has_request_or_result` CHECK keeps
  working unchanged on TEXT.

Text was chosen over JSONB as the authoritative form because PostgreSQL
JSONB refuses the `\u0000` escape ("unsupported Unicode escape sequence",
SQLSTATE 22P05), while canonical JSON allows U+0000 in strings. In text, a
NUL is the six ASCII characters `\u0000`; Conduit's canonical encoder and
serde_json both escape it that way. PostgreSQL `TEXT` refuses only a raw
0x00 byte (SQLSTATE 22021), which escaped JSON text never contains.

#### PostgreSQL sinks that PDU strings reach (B1)

Each sink lists its rule for U+0000. "Refuse at decode" means a
deterministic per-PDU drop from the decode step, never a database error.

| sink | holds | rule for U+0000 |
|---|---|---|
| `transactions.request` | the whole inbound `/send` body (and client txn bodies), stored by `Replay::body` before any PDU is parsed | TEXT holding the canonical JSON of the body. Never refuses a spec-valid body. |
| `transactions.result` | the `/send` response, including per-PDU error strings | TEXT canonical JSON. Error strings use the fixed vocabulary and never echo PDU values. |
| `fed_outbound_queue.payload` | outbox envelope `{"pdus": [Pdu], "edus": [...]}`, and to-device envelopes | TEXT canonical JSON. A local event with a NUL in its content (e.g. `topic`) federates. |
| `fed_outbound_queue.last_error` | transport error text | Passed through `pg_safe_text`, which maps U+0000 to U+FFFD. It is diagnostic only. |
| `events.pdu_json` | authoritative Pdu, without `unsigned` | TEXT canonical JSON. Stored exactly. |
| `events.content` (JSONB) | projection for SQL predicates | U+0000 becomes U+FFFD in strings and keys, in the projection only. The only SQL readers are `content->>'membership' = 'join'`, and a membership value containing NUL is not `join` either way. Reads decode `pdu_json`. |
| `events.hashes`, `events.signatures` (JSONB) | projections | Same U+FFFD projection. No SQL predicate reads them, and reads decode `pdu_json`. Unverified signature entries from third servers may carry NUL and are kept exactly in `pdu_json`. |
| `events.unsigned` (JSONB) | local allow-listed unsigned | An unsigned value that contains U+0000 is dropped with a warning. `unsigned` is unprotected ("Keys under `unsigned` can be modified by other servers"). |
| `events.room_id`, `sender`, `type`, `state_key` (TEXT) | key projections | Refused at decode (decode step 3). A U+FFFD substitution here could merge two distinct state keys into one `room_current_state` key. |
| `events.auth_events`, `prev_events` (TEXT[]) | ID projections | Refused at decode. A derived ID is URL-safe base64, so an ID containing NUL can never refer to a real event. |
| `events.event_id` (TEXT PK) | derived ID | Cannot contain NUL: it is `$` plus URL-safe base64. |
| `room_current_state(room_id, type, state_key, event_id)` | current-state key | Covered by the decode refusals above, plus the derived ID. |
| client-authored PDUs | `PUT /rooms/{id}/state/{type}/{stateKey}`, `/send/{type}` | A NUL in `type` or `state_key` is refused with `400 M_INVALID_PARAM` before the event is built. A NUL in `content` is stored under the projection rules above. |

Numbers: after decode step 2 only safe integers remain. JSONB stores those
exactly, so the projections lose nothing, and `pdu_json` is canonical text
anyway.

EDU sinks (`to_device_queue`, `receipts`, presence, device lists) are not
PDU sinks. One rule is folded in because it belongs to the same `/send`
wedge. If persisting an EDU fails with SQLSTATE class 22 (a data exception,
such as 22P05 or 22021), the failure is deterministic: that EDU is dropped
and logged, and the transaction goes on. Only transient errors (connection
loss, serialization failure, and the like) still return 500, so that the
origin retries. Per-sink NUL handling for EDUs is filed as
`conduit-y99.22.4`.

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

One function, `classify_legacy_row`, rebuilds the Pdu from the projection
columns, recomputes the reference hash and the content hash, and writes one
of the following.

- `verified`: the reference hash equals the `event_id` primary key and the
  content hash matches. `pdu_json` is backfilled from the rebuilt Pdu.
- `content_mismatch`: the ID matches but the content hash does not. Either
  the row lost extensions, or it was legitimately redacted on receipt; the
  two cannot be told apart. `pdu_json` is backfilled with
  `canonical(redact(rebuilt Pdu))`.
- `id_mismatch`: the reference hash differs from the primary key.
  `pdu_json` stays NULL.

It runs in two ways, so the check never blocks startup and never leaves a
window where history is invisible.

- **Background sweep.** `verify_legacy_event_ids` starts after the listener
  is up and walks `id_integrity = 'unchecked'` rows in batches of 1000 by
  `stream_position`. It logs a count for each class, and logs every
  `id_mismatch` row at WARN with both IDs.
- **On demand.** When `get_wire_pdu` meets an `unchecked` row, it runs
  `classify_legacy_row` inline, persists the class, and answers from the
  result. Federation never answers 404 just because the sweep has not
  reached a row yet.

Neither path ever rewrites a primary key or any reference to one. Rows
written after this change are inserted with `pdu_json` set and
`id_integrity = 'verified'`. That includes rows redacted on receipt, which
store the redacted form. For those rows `verified` means "ID verified and
`pdu_json` authoritative". It does not mean the content hash matches.

Serving rule: federation emitters read through `Storage::get_wire_pdu(id) ->
Option<Pdu>`.

- `verified` returns the `pdu_json` Pdu.
- `content_mismatch` returns its redaction (the stored `pdu_json`). A peer
  that receives it sees a hash mismatch, redacts, and derives the same ID.
  That is the same outcome as for a post-change row redacted on receipt, so
  auth-chain members are not withheld for nothing.
- `id_mismatch` returns `None`. The row behaves like a missing event:
  `/event` returns 404, and `/state`, `/backfill` and `/get_missing_events`
  omit it.

Client-facing reads are unchanged, so local history stays visible to local
users. Re-fetching `content_mismatch` rows in full from their origin through
`admit_fetched` is possible, but it is not part of this change.

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
- Fetch-by-ID:
  - A peer that answers `/event/$A` with a different event that is validly
    signed is refused with `IdMismatch`, and storage is unchanged.
  - A fetched event whose content hash does not match is stored in redacted
    form under the requested ID.
  - A `get_missing_events` response that also contains a validly signed
    event that nothing references stores every referenced event and not
    the extra one.
  - A `send_join` `auth_chain` event that lies outside the closure is not
    stored.
  - `/state` without a prior `state_ids` is refused.
- `/invite`:
  - A forged inviter signature, a path-ID mismatch, a content-hash mismatch,
    or a sender that is not on the origin each get `400 M_INVALID_PARAM`,
    with no co-sign and no persist.
  - On success the returned event's `hashes` and derived ID equal the
    request's.
- `/send_join`: `state_key != sender`, a sender domain other than the
  origin, and a path-ID mismatch each get `400 M_INVALID_PARAM`.
- Decode:
  - A top-level `event_id` gets `PduDecodeError::ExplicitEventId`, and on
    `/send` it is skipped with no result entry.
  - These are refused: out-of-range integers, floats, 11 `auth_events`,
    21 `prev_events`, `depth` of -1 and of 2^53, a 65537-byte PDU, a
    256-byte `sender`, `room_id`, `type` or `state_key`, `"state_key": null`,
    and a PDU that does not round-trip.
  - These are accepted: `depth` of 0 and of 2^53-1, a PDU of exactly 65536
    bytes, and fields of exactly 255 bytes.
  - Disallowed unsigned keys are not persisted.
- U+0000 over `/send`, against real PostgreSQL:
  - A transaction with one PDU that has `\u0000` in `content`, one with
    `\u0000` in `state_key`, one ordinary PDU and one EDU returns 200.
  - The content-NUL PDU is persisted, and both `/event` and the client API
    read it back byte-exact.
  - The state_key-NUL PDU has no result entry and is not stored.
  - The ordinary PDU and the EDU are processed.
  - A replay of the same txn ID returns the identical stored response.
  - A local state event with `\u0000` in `topic` is enqueued and its
    outbox payload reads back byte-exact.
- Storage:
  - The round-trip test across all reads described above.
  - A legacy-row integrity test. It seeds rows the way the pre-`56498e3`
    code hashed them, plus one lossy remote row. It asserts the
    classification, that federation returns 404 for `id_mismatch` rows, and
    that it returns the redaction for the `content_mismatch` row.
  - A `get_wire_pdu` call on an `unchecked` row classifies it inline.
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

## Review disposition, round 2 (2026-10-14 advise-2 send-back)

The round-1 disposition above is kept as history. Where round 2 changes it,
the contract sections above win. Two such places: `/invite` now refuses a
hash mismatch (this changes A2's flow), and `content_mismatch` rows are
served as their redaction (this changes A4's "must not be served").

**A1 rebuttal: upheld by the reviewer.** No change.

**B1. U+0000 in every PostgreSQL sink: adopted.** The design now lists every
sink that PDU strings reach, each with a rule.

- **TEXT canonical JSON** for the replay-cache columns
  `transactions.request` and `transactions.result`, and for
  `fed_outbound_queue.payload`. These are column type changes that rewrite
  only those bounded tables.
- **U+FFFD in projections only** for `events.content`, `hashes` and
  `signatures`. Reads decode `pdu_json`.
- **Drop with a warning** for unsigned values.
- **Deterministic per-PDU refusal at decode** for NUL in `room_id`,
  `sender`, `type`, `state_key`, `auth_events` and `prev_events`. Synapse on
  PostgreSQL cannot persist these either.
- **Client API refusal** (`400 M_INVALID_PARAM`) for NUL in an authored
  `type` or `state_key`.
- **Fixed-vocabulary error strings** that never echo PDU values.
- **EDU data errors (SQLSTATE class 22)** drop that EDU instead of returning
  500 for the whole transaction. Wider EDU-sink work is `conduit-y99.22.4`.

The new `/send` scenario covers a content-NUL PDU that is persisted and
readable, a state_key-NUL PDU dropped with no result entry, and the
remaining PDUs and EDUs processed normally.

**B2. `/invite` hash mismatch: refuse.** A content-hash mismatch on inbound
`/invite` returns `400 M_INVALID_PARAM`, with no co-sign and no persist. The
design and the delta now say the same thing, and each has a scenario.

- Why refuse is safe: an invite is freshly authored by the inviting server,
  so a mismatch means that server is broken or an intermediary changed the
  PDU, and the inviter gets an explicit error. Refusing creates no DAG
  partition: the inviter does not send the invite on unless we answer, and
  if Conduit is already in the room, any copy of the event that arrives
  over `/send` goes through the normal redact-on-mismatch path.
- Divergence from Synapse, recorded: Synapse's `on_invite_request` runs
  `_check_sigs_and_hash`, redacts, and co-signs the redacted copy.
- Why not mirror Synapse: returning a redacted event would break the spec's
  "All other fields of the events should remain untouched".

**B3. Per-endpoint `admit_fetched` expectations: adopted.** The fetch-by-ID
table defines the expectation for each endpoint.

- `Exactly`: `/event`, the auth fetch, the outbound `invite` response, and
  the `send_join` `event`.
- `state_ids`: stores nothing. It defines the set for `/state`, which uses
  `OneOf(state_ids ∪ auth_chain_ids)` and requires `state_ids` to come
  first.
- `send_join` `state`: `Asserted`. The ID is derived and the signatures
  verified. Each event must be a state event in this room, with no
  duplicate `(type, state_key)`.
- `send_join` `auth_chain`: `Closure` over `auth_events` of state ∪
  {join}.
- `backfill` and `get_missing_events`: a `Closure` over `prev_events`
  seeded from the requested IDs. The fixed-point walk does not depend on
  response order.

Extras that nothing references are not stored. That has a scenario
(`get_missing_events` with an unreferenced, validly signed extra event).

**B4. v11 limits: adopted.**
- `depth` is an integer in `[0, 2^53-1]`, inclusive, and both ends are
  tested.
- The canonical PDU is at most 65536 bytes, measured as Synapse's
  `get_pdu_json()` measures it.
- `sender`, `room_id`, `type` and `state_key` are each at most 255 bytes of
  UTF-8.

All of these sit in decode step 3, are dropped deterministically, and have
a scenario each, with boundary values on both sides.

**Non-blocking notes (round 2), as decisions:**

1. **Serve `content_mismatch` rows as their redaction: adopted.** The design
   now documents that `verified` also covers post-change rows redacted on
   receipt, and why.
2. **Startup blocking: decided against.** The legacy check is a background
   sweep plus an inline check on demand in `get_wire_pdu`. Startup is not
   blocked, and there is no 404 window.
3. **Round-trip identity at decode: adopted** as decode step 5
   (`NonRoundTrip`). `"state_key": null` is refused.
4. **Outbound `invite` response: adopted.** `Exactly(id)`, unchanged
   `hashes`, and the invitee server's signature present and verified.
   Inbound `/invite` now requires the sender's server to be the X-Matrix
   origin, with `400 M_INVALID_PARAM`.
5. **`send_join` error codes: recorded as deliberate.** We use the spec's
   `M_INVALID_PARAM` rather than Synapse's 403 / `M_BAD_JSON`.
6. **Fetched results redacted on receipt: adopted.** They are stored
   redacted under the requested ID, with a test assertion.
