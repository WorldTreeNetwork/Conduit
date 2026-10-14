# PDU contract

Amended three times on 2026-10-14:
- after the send-back in `reviews/2026-10-14-advise.md` (A1–A7);
- after the second send-back in `reviews/2026-10-14-advise-2.md` (B1–B4);
- after the accept in `reviews/2026-10-14-advise-3.md`, whose notes 1, 2, 4
  and 5 are folded in, and the cross-family send-back in
  `reviews/2026-10-14-advise-4-codex.md` (C1–C5).

The "Review disposition" sections at the end record how each amendment and
note was handled, with citations. The sections before them are the contract
that `act` implements, and they win wherever an earlier disposition says
otherwise.

## Types

`Pdu` holds the v11 protocol fields (`auth_events, content, depth, hashes,
origin_server_ts, prev_events, room_id, sender, signatures, state_key, type`)
plus `extensions: BTreeMap<String, Value>`, a flattened map of every other
top-level key. `unsigned` is not part of `Pdu`: it is local, unprotected
data and lives on `Event`.

`Event` is `{ event_id: String, pdu: Pdu, unsigned: Option<Value> }`. The
derived ID exists only on `Event`. `Event: Deref<Target = Pdu>` is allowed for
reads. Every function that puts bytes on the wire takes `&WirePdu` or
`Vec<WirePdu>`, a newtype that only the integrity-checked sources can
construct (see "Outbound wire"). So neither `Deref` nor a stray `.pdu` can
cause a leak or emit an unchecked legacy row.

Cryptographic functions accept only `&Pdu`:

| fn | input bytes | mutates |
|---|---|---|
| `content_hash(&Pdu)` | Pdu + extensions, minus `hashes`, `signatures` (unsigned is never in Pdu) | no |
| `reference_hash(&Pdu)` / `event_id(&Pdu)` | `redact(Pdu)` minus `signatures` | no |
| `sign_authored(&mut Pdu, key, server)` | sets `hashes.sha256 = content_hash`, then signs the redacted bytes | `hashes`, `signatures` |
| `add_signature(&mut Pdu, key, server)` | signs the redacted bytes | `signatures[server][key_id]` only |
| `verify_signatures(&Pdu, &EligibleKeys) -> SignedBy` | redacted bytes | no |
| `check_received(Pdu, &EligibleKeys) -> Received` | as below | no |

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

   Where this per-PDU drop actually fires: the X-Matrix middleware already
   signs and verifies the canonical JSON of every inbound federation
   request body (`federation/middleware.rs`). A `/send`, `/send_join` or
   `/invite` body that holds a float or an out-of-range integer therefore
   fails with `401 M_UNAUTHORIZED` before any handler runs. That behaviour
   predates this change and is kept: a conformant sender cannot sign such a
   body, because X-Matrix signs canonical JSON. So the step-2 drop applies
   to federation responses fetched through `admit_fetched`, which carry no
   request signature, and to decode run directly in unit tests. Client
   request bodies are not X-Matrix signed. `Replay::body` stores them before
   any value is validated, so the replay sinks must accept floats (see the
   sink table).
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
     received object after the unsigned allow-list, keeping the allow-listed
     `unsigned` exactly as received, `age` included. The client-server spec
     sets the limit "when formatted with the federation event format,
     including any signatures".

     Synapse measures something slightly different. Its `_check_size_limits`
     encodes `get_pdu_json()`, which still holds `unsigned` with `age`
     rewritten to `age_ts = received_time - age`. That value depends on
     receive time, so exact parity is impossible. Counting `age` as
     received narrows the gap to a few bytes, and the residue is recorded
     under "Recorded divergences from Synapse".

     Authored PDUs keep a margin: `sign_authored` refuses a PDU whose
     canonical size exceeds 65472 bytes (65536 minus 64) with the kernel's
     `M_TOO_LARGE` error. This stops Synapse from dropping our own
     near-limit events once their `unsigned` grows in transit.
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

`check_received(pdu, keys)` runs signature verification first. A failure
means the PDU is dropped (spec step 2). It then derives the ID from the
unmodified Pdu. Then it checks the content hash. On a mismatch it returns the
redacted Pdu, keeping `hashes` and `signatures`, and the same derived ID (spec
"Validating hashes and signatures on received events": "use the redacted copy
it calculated"). The result is `Received { event_id, pdu, redacted_on_receipt:
bool, signed_by: SignedBy }`. Nothing reads a wire-provided ID anywhere.
`admit_fetched` uses `check_received`, so every rule below applies equally
to fetched auth events and to every other fetched PDU.

### Required signers

The set of servers that must have signed the event is computed from the
Pdu alone. The set is evaluated on the form being checked; redaction keeps
`content.membership`, `content.join_authorised_via_users_server`, and
`third_party_invite.signed`, so a redacted copy yields the same set.

- **Sender's server.** The server name of `sender` is required. Exception:
  a 3rd-party-invite membership, meaning `type == m.room.member`,
  `membership == invite`, and `content.third_party_invite` present, does
  not require the sender's server signature. Server-server API: "unless the
  event is a 3rd party invite ... the sender must already match the 3rd
  party invite, and the server which actually sends the event may be a
  different server". This matches Synapse `_is_invite_via_3pid` /
  `_check_sigs_on_pdu`. Such an invite is still subject to auth rule 4.4,
  which checks the `third_party_invite.signed` block against the
  `m.room.third_party_invite` public keys. That check belongs to the auth
  rules, not to this signature stage.
- **Authorising server of a restricted join.** When
  `type == m.room.member`, `membership == join`, and
  `content.join_authorised_via_users_server` is present, the server name of
  that user ID is required too. A missing or invalid signature from it
  drops the PDU at the signature stage. That matches Synapse
  `_check_sigs_on_pdu` (rooms with `restricted_join_rule`) and covers v11
  auth rule 4.2 ("If `content` has a `join_authorised_via_users_server`
  key: If the event is not validly signed by the homeserver of the user ID
  denoted by the key, reject") for joins. A value that is not a valid user
  ID drops the PDU.
- **Other memberships carrying the key.** Rule 4.2 is written for every
  `m.room.member` event, but Synapse enforces it only on joins, and only at
  the signature stage. To stay on Synapse's side of drop and accept,
  non-join events are not dropped. Instead, `SignedBy` records exactly which
  servers produced a valid eligible signature. The auth check
  (`conduit::auth`, rule 4.2) then rejects any `m.room.member` event whose
  `join_authorised_via_users_server` server is not in `SignedBy`. A rejected
  event is stored as rejected, not dropped.
- **Other servers' signatures.** They are checked only when the server is
  required. A signature from a server that is not required is ignored,
  whether valid or not. It does not count toward `SignedBy`, and it is
  preserved exactly in `pdu_json`.

### Signing-key validity (event-time)

`EligibleKeys` answers `(server, key_id, origin_server_ts) -> Option<key>`.
The old wall-clock `(server, key_id) -> bytes` lookup is replaced. Room v11
"Signing key validity period" requires two things:

- "servers MUST enforce the `valid_until_ts` property from a key request is
  at least as large as the `origin_server_ts` for the event being
  validated";
- "Servers MUST use the lesser of `valid_until_ts` and 7 days into the
  future when determining if a key is valid."

Every cached key stores `fetched_at_ts` and an `effective_until_ts`:

- `verify_keys` entries:
  `effective_until_ts = min(valid_until_ts, fetched_at_ts + 7 days)`. The
  7 days are measured from when we obtained the response, so a published
  `valid_until_ts` years ahead cannot pin a key beyond a week of our own
  observation.
- `old_verify_keys` entries: `effective_until_ts = expired_ts`. Server-server
  API: signatures from keys "known to have expired prior to the event's
  `origin_server_ts` are ignored". `remote_keys.rs` does not parse
  `old_verify_keys` today; this change adds it.

A key is eligible for an event when `effective_until_ts >= origin_server_ts`.
When the key is unknown, or cached but not eligible, the lookup fetches
again before deciding. It uses `GET /_matrix/key/v2/server` today. When the
notary path (`conduit-y99.22`) lands, `POST /_matrix/key/v2/query` will use
`minimum_valid_until_ts = origin_server_ts`. A refetch is attempted at most
once per `(server, key_id)` per 5 minutes, so an adversary cannot use the
lookup to amplify traffic. Wall-clock cache expiry only decides when to
refetch. It never makes a key eligible.

Verification rule for each required server:

- Take that server's signatures whose key is eligible for this event's
  `origin_server_ts`.
- Signatures from unknown keys, and from keys that were not eligible after
  the refetch, are skipped. They are "ignored", not failures.
- Every remaining eligible signature must verify. Spec: "If all signatures
  from known unexpired keys from the originating server(s) are found to be
  valid". One invalid eligible signature drops the PDU.
- At least one eligible signature must remain. Otherwise the PDU is dropped
  with `VerifyError::NoEligibleSignature { server }`.

This replaces the current first-valid-signature-wins loop in
`signing.rs::verify_event`, which also accepts keys without any timestamp
check. `pipeline.rs::build_key_cache` becomes `EligibleKeys::for_event(&pdu)`.

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
| `PUT /v2/send_join` response `state` | `Asserted` (no expected ID) | Each event's ID is derived and its signatures verified. Each must be a state event with `room_id == room`. A duplicate `(type, state_key)` fails the whole join (`FetchError::DuplicateState`) and stores nothing from the response; it does not drop one entry. The resident server is asserting this state; we did not request any of these IDs. |
| `PUT /v2/send_join` response `auth_chain` | `Closure(auth_events of state ∪ {join})` | Admitted by walking the closure: start from the `auth_events` of the admitted `state` and of our join, admit any `auth_chain` event whose derived ID is in the frontier, add that event's `auth_events`, and repeat until nothing changes. |
| `GET /backfill?v=..&limit=` (`client.backfill`) | `Closure(prev_events from v)` | Seeds are the requested `v` IDs. A response event is admitted if its derived ID is a seed, or is named in `prev_events` by an event already admitted from this response or held locally. Same fixed-point walk. |
| `POST /get_missing_events` (`client.get_missing_events`) | `Closure(prev_events from latest_events)` | Seeds are the `prev_events` of the requested `latest_events`. Those events are in hand (the PDU being processed) but not necessarily persisted. The walk stops at `earliest_events`. Same fixed-point walk. |

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
   failure returns `400 M_INVALID_PARAM`. A 3rd-party-invite membership
   (one with `content.third_party_invite`) is exempt from the origin check,
   because "the server which actually sends the event may be a different
   server".
3. Verify signatures under "Required signers", using event-time key
   validity. A failure, including `NoEligibleSignature`, returns
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
3. Restricted join. If `content.join_authorised_via_users_server` is
   present:
   - Its server must be this server. Otherwise the request gets
     `400 M_INVALID_PARAM`. Synapse returns the same refusal: "We can only
     authorise requests from our own homeserver".
   - Conduit then runs `add_signature` with its own key before step 4. As
     resident it is the authorising server, and the joining server cannot
     have obtained this signature yet.
   - Whether that user may authorise the join is auth rule 4.3.5.2, which
     belongs to the auth check in step 5, not to this step.
4. Run `check_received`, which applies "Required signers": the sender's
   server, plus the authorising server, now satisfied by our own
   co-signature. A signature failure gets `400 M_INVALID_PARAM`. Require
   `derived ID == path :eventId`, or `400 M_INVALID_PARAM`.
5. Run the pipeline auth check. A failure gets `403 M_FORBIDDEN`.
6. Respond with `event` (the join, including our co-signature when step 3
   added one), `state` and `auth_chain`, all as `WirePdu`s. `state` is still
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

### `WirePdu`: the only emittable type

Every emitter takes `&WirePdu` or `Vec<WirePdu>` in its signature, never
`Event` or a bare `Pdu`. The emitters are:
- `FedClient::send_transaction`, `send_join` and `invite`;
- the outbound queue `enqueue`;
- every federation response builder for `state`, `backfill`, `event`,
  `get_missing_events`, `send_join` and `invite`.

`WirePdu` is a newtype around `Pdu`. Its constructor is private to the
module that owns these sources, and nothing else can create one:

| source | constructor | when |
|---|---|---|
| A PDU this server just authored | `WirePdu::authored(pdu)`, returned by `sign_authored` | local sends; completing a `make_join` template |
| A PDU this server just co-signed | `WirePdu::cosigned(pdu)`, returned by `add_signature` after `check_received` | the `/invite` response |
| A stored event | `Storage::get_wire_pdu(id) -> Option<WirePdu>` (and `get_wire_pdus`) | every federation response built from storage |
| A legacy outbox snapshot | `classify_legacy_snapshot(event_id, snapshot) -> Option<WirePdu>` | draining queue rows written before this change |

There is no `From<Pdu>` and no `wire_pdus(&[Event])` helper. Emitting
`event.pdu` directly is a type error, so every stored or legacy PDU on the
wire has passed the integrity gate. `WirePdu` serialises as the Pdu, with no
`unsigned`. Remote-supplied unsigned is local metadata, and the spec makes
`unsigned` optional. One test serialises every response and every outbound
body and asserts that no PDU object carries a top-level `event_id` key.

### The outbox

New envelopes are `{"pdus": [WirePdu...], "edus": [...]}`, holding wire
Pdus only, because the destination derives the ID. They are written as
lossless JSON text (see the sink table).

Legacy envelopes, written before this change, hold flattened Event
snapshots with the local `event_id`. Pre-change snapshots could never hold a
wire `event_id`, because v3+ wire PDUs have none, so in that layout the key
is always the local ID. The flattened layout is read-only.

Draining a legacy envelope never just strips metadata. For each snapshot
the drain calls `classify_legacy_snapshot(saved_event_id, snapshot)`. That
call rebuilds the Pdu without `event_id`, then runs the same
`classify_legacy_row` logic against the saved ID:

- **`verified`:** the reference hash equals the saved ID and the content
  hash matches. The PDU is emitted as it is.
- **`content_mismatch`:** the ID matches but the content hash does not. The
  PDU is emitted as its v11 redaction, which is the same rule as
  `get_wire_pdu`.
- **`id_mismatch`:** the PDU is withheld. It is removed from the envelope
  and logged at WARN with both IDs. If that leaves the envelope with no
  PDUs and no EDUs, the row is marked `sent`, with `last_error` set to
  "withheld: legacy id_mismatch".

A withheld snapshot is never re-signed, re-hashed, or sent under a new
identity. Re-signing would mint a different event ID for content that local
history and other servers' `prev_events` know under the old one.

Each classification also writes the event's `id_integrity`, so the
`events` row and the queue agree. The snapshot is checked by itself
because the queue may hold a snapshot whose bytes differ from the current
`events` row. Any new persisted `Event` envelope nests as
`{"event_id": ..., "pdu": {...}}`.

## Storage (PostgreSQL)

### Migrations: metadata-only first, no rewrites anywhere

Each step is its own migration file. sqlx runs each file in its own
transaction, so no lock outlives its own step. Each file begins with
`SET LOCAL lock_timeout = '5s'`, so the migration fails fast instead of
queueing all traffic behind a long-running query. The numbers are the next
free ones at implementation time.

**Migration E (`events`):**

```sql
SET LOCAL lock_timeout = '5s';
ALTER TABLE events ADD COLUMN pdu_json TEXT;                       -- NULL = legacy row
ALTER TABLE events ADD COLUMN id_integrity TEXT NOT NULL DEFAULT 'unchecked';
```

Both statements are metadata-only on PostgreSQL 11 and later: a nullable
column, and a constant default. PG docs, ALTER TABLE notes: a non-volatile
default "is evaluated at the time of the statement and the result stored in
the table's metadata". The `ACCESS EXCLUSIVE` lock is held only for the
catalog update. Nothing else is in this transaction. CI runs postgres:16.

**Migration T (`transactions` and `fed_outbound_queue`), staged, with no
type change:**

```sql
SET LOCAL lock_timeout = '5s';
ALTER TABLE transactions       ADD COLUMN request_text TEXT;
ALTER TABLE transactions       ADD COLUMN result_text  TEXT;
ALTER TABLE transactions       DROP CONSTRAINT transaction_has_request_or_result;
ALTER TABLE transactions       ADD CONSTRAINT transaction_has_request_or_result
    CHECK (request IS NOT NULL OR result IS NOT NULL
           OR request_text IS NOT NULL OR result_text IS NOT NULL) NOT VALID;
ALTER TABLE fed_outbound_queue ADD COLUMN payload_text TEXT;
ALTER TABLE fed_outbound_queue ALTER COLUMN payload DROP NOT NULL;
```

Every statement here is catalog-only:
- the column adds are nullable with no default;
- `DROP CONSTRAINT` and `DROP NOT NULL` do not scan;
- adding the CHECK as `NOT VALID` skips the scan of existing rows.

There is no `ALTER COLUMN ... TYPE`, so neither table is rewritten.
Downtime is bounded by the catalog lock, not by table size. That is why no
row-count measurement is needed. After this change:

- **Writers** write only `request_text`, `result_text` and `payload_text`.
- **Readers** prefer the `_text` column and fall back to the legacy JSONB
  column for rows written before the migration.
- **Retirement.** The legacy JSONB columns, and the fallback reads, are
  retired by a later migration once no row uses them. That needs
  `transactions` retention and outbox `sent`-row collection, which do not
  exist today. Both are filed as `conduit-y99.22.5`.
  - Retention is not added here because it changes the client-API
    transaction-idempotency window. That is a behaviour decision for the
    replay owner, and the staged design does not need it to be safe.
  - Until retirement, the fallback costs one `COALESCE`-style branch in two
    read paths.
- **Validating the CHECK.** It can be validated later with
  `VALIDATE CONSTRAINT`, which takes only `SHARE UPDATE EXCLUSIVE`, or
  dropped at retirement.

Text was chosen over JSONB because PostgreSQL JSONB refuses the `\u0000`
escape ("unsupported Unicode escape sequence", SQLSTATE 22P05), while
canonical JSON allows U+0000 in strings. In JSON text a NUL is the six
ASCII characters `\u0000`. PostgreSQL `TEXT` refuses only a raw 0x00 byte
(SQLSTATE 22021), and escaped JSON text never contains one.

### Encoders: lossless JSON vs canonical JSON

Two text encodings are used, and they are not interchangeable.

- **`events.pdu_json`** holds Matrix canonical JSON
  (`conduit::canonical_json::to_canonical_string`) of a decoded Pdu. Decode
  step 2 has already validated the values, so the encoder cannot fail.
- **`transactions.request_text`, `result_text` and
  `fed_outbound_queue.payload_text`** hold lossless JSON text from
  `serde_json::to_string`, read back with `serde_json::from_str`. These
  never use the canonical encoder. It refuses floats and out-of-range
  integers (`canonical_json.rs:66-90`), and `Replay::body` stores client
  bodies before any value is validated. A client to-device body with a
  float would otherwise make the canonical encoder 500 the whole request,
  where JSONB accepts it today. `serde_json` escapes U+0000 as `\u0000` and
  keeps floats.

#### PostgreSQL sinks that PDU strings reach (B1)

Each sink lists its rule for U+0000. "Refuse at decode" means a
deterministic per-PDU drop from the decode step, never a database error.

| sink | holds | rule for U+0000 |
|---|---|---|
| `transactions.request_text` | the whole inbound `/send` body, and client txn bodies, stored by `Replay::body` before any PDU is parsed | Lossless JSON text. Never refuses a body the request layer accepted. |
| `transactions.result_text` | the response, including per-PDU error strings | Lossless JSON text. Error strings use the fixed vocabulary and never echo PDU values. |
| `fed_outbound_queue.payload_text` | outbox envelope `{"pdus": [WirePdu], "edus": [...]}`, and to-device envelopes | Lossless JSON text. A local event with a NUL in its content (e.g. `topic`) federates. |
| `fed_outbound_queue.last_error` | transport error text | Passed through `pg_safe_text`, which maps U+0000 to U+FFFD. It is diagnostic only. |
| `events.pdu_json` | authoritative Pdu, without `unsigned` | Canonical JSON text. Stored exactly. |
| `events.content` (JSONB) | projection for SQL predicates and indexes | U+0000 becomes U+FFFD in strings and keys, in the projection only. Reads decode `pdu_json`. Every SQL reader is checked in the projection-reader audit below. |
| `events.hashes`, `events.signatures` (JSONB) | projections | Same U+FFFD projection. No SQL predicate reads them, and reads decode `pdu_json`. Signature entries from servers that are not required may carry NUL, and are kept exactly in `pdu_json`. |
| `events.unsigned` (JSONB) | local allow-listed unsigned | An unsigned value that contains U+0000 is dropped with a warning. `unsigned` is unprotected ("Keys under `unsigned` can be modified by other servers"). |
| `events.room_id`, `sender`, `type`, `state_key` (TEXT) | key projections | Refused at decode (decode step 3). A U+FFFD substitution here could merge two distinct state keys into one `room_current_state` key. |
| `events.auth_events`, `prev_events` (TEXT[]) | ID projections | Refused at decode. A derived ID is URL-safe base64, so an ID containing NUL can never refer to a real event. |
| `events.event_id` (TEXT PK) | derived ID | Cannot contain NUL: it is `$` plus URL-safe base64. |
| `room_current_state(room_id, type, state_key, event_id)` | current-state key | Covered by the decode refusals above, plus the derived ID. |
| client-authored PDUs | `PUT /rooms/{id}/state/{type}/{stateKey}`, `/send/{type}` | A NUL in `type` or `state_key` is refused with `400 M_INVALID_PARAM` before the event is built. A NUL in `content` is stored under the projection rules above. |

Numbers: after decode step 2 only safe integers remain. JSONB stores those
exactly, so the projections lose nothing, and `pdu_json` is canonical text
anyway.

#### Projection-reader audit (`events.content`, as of `8175d10`)

Each SQL reader of the `content` projection is listed with why the U+FFFD
mapping gives the same answer as the authoritative value, or why the
difference is acceptable. A new reader of a projection column must be added
to this table in the change that introduces it.

| reader | location | effect of U+0000 → U+FFFD |
|---|---|---|
| `content->>'membership' = 'join'` | `storage_pg.rs` 908, 3182, 3197, 3343 | None. A value containing NUL is not `join` either way. |
| `join_rule = 'public'`, `history_visibility = 'world_readable'` (user directory) | 3356, 3358 | None, for the same equality reason. |
| `displayname`, `avatar_url` returned by the user directory | 3338-3339 | The display string shows U+FFFD where the event has NUL. Accepted, because it is a display-only projection. |
| `content->>'redacts' = ANY($2)` (serve-time redactions; index `events_redaction_target`, `0020`) | 3450 | None. A `redacts` value containing NUL cannot equal a real event ID, which is URL-safe base64, in either form. |
| `m.relates_to.event_id = ANY($2)` and `rel_type IS NOT NULL` / `= 'm.thread'` (relations and threads; `events_relates_to` and the thread index, `0020`) | 3474-3475, 3490-3496 | None. The ID argument is the same as for `redacts`. `IS NOT NULL` has the same truth value, and equality with `m.thread` fails in both forms. |
| full-text search over `body`, `name` and `topic` (`to_tsvector`, GIN indexes in `0020`) | 3572-3581 | Tokenisation splits at U+FFFD where it would have split at NUL. Search is approximate by nature, so this is accepted. Results are rendered from `pdu_json`, not from the projection. |

Rows returned by these queries are decoded through `event_from_row`, never
from the projection columns.

#### EDU sinks

EDU sinks (`to_device_queue`, `receipts`, presence, device lists) are not
PDU sinks. One rule is folded in because it belongs to the same `/send`
wedge:

- **Isolation.** Each EDU is persisted in its own statement, or under its
  own `SAVEPOINT` when it shares a transaction. A failed statement inside a
  shared PostgreSQL transaction would otherwise abort every later statement
  ("current transaction is aborted"). That would surface as SQLSTATE 25P02
  and a 500.
- **Class-22 failures.** If an EDU's persist fails with SQLSTATE class 22
  (a data exception, such as 22P05 or 22021), the failure is deterministic.
  That EDU is dropped and logged, and the transaction goes on.
- **Transient failures.** Only transient errors (connection loss,
  serialization failure, and the like) still return 500, so that the origin
  retries.
- **Keeping the SQLSTATE.** `map_sqlx` keeps the SQLSTATE in `StorageError`,
  so the class-22 test can assert it.

Per-sink NUL handling for EDUs is filed as `conduit-y99.22.4`.

### One row decoder

Every `events` read in `storage_pg.rs` goes through
`fn event_from_row(row: EventRow) -> Result<Event, StorageError>`. At
`8175d10` there are eleven hand-built `Event { .. }` literals, at lines 228,
295, 829, 865, 895, 1036, 1098, 1145, 1211, 3610 and 3730. The last two were
added by the room-content lane. Each query selects one shared column list
(a `const EVENT_COLUMNS`).

The decoder chooses its source as follows:

- **`pdu_json` present:** parse it.
- **`pdu_json` NULL:** rebuild a Pdu from the projection columns with empty
  extensions.

The rebuild path is exactly what pre-change reads returned, and C4 relies
on this. MemoryStorage stores `Event` unchanged.

One test writes a Pdu that has extensions, a `\u0000` string in content,
and an integer of 2^53-1. It reads the Pdu back through every public
`Storage` method that returns events, on both PG and memory. It asserts that
the Pdu is equal and that `content_hash` is unchanged.

### ID-integrity check for legacy rows

Legacy rows cannot be trusted to reproduce their own IDs:

- Local rows written before `56498e3` were content-hashed over the redacted
  event. They were reference-hashed with `event_id: ""` included and without
  redaction (see `git show 56498e3 -- conduit/src/hashing.rs`).
- Remote rows lost their unknown top-level keys at ingest.
- Remote auth events were stored unverified, under the wire ID.

#### Classification

One function, `classify_legacy_row`, rebuilds the Pdu from the projection
columns, recomputes the reference hash and the content hash, and writes one
of three classes. Retained history is never replaced: `pdu_json` always
holds the same Pdu that client reads produced before classification.

| class | condition | `pdu_json` |
|---|---|---|
| `verified` | The reference hash equals the `event_id` primary key and the content hash matches. | Backfilled with the rebuilt Pdu. |
| `content_mismatch` | The ID matches but the content hash does not. Either the row lost extensions, or it was legitimately redacted on receipt; the two cannot be told apart. | Backfilled with the rebuilt, unredacted Pdu, not with its redaction, so client reads stay byte-identical. |
| `id_mismatch` | The reference hash differs from the primary key. | Stays NULL. The decoder keeps rebuilding from the projections, exactly as before. |

#### When it runs

The check never blocks startup and never leaves a window where history is
invisible. It runs in two ways:

- **Background sweep.** `verify_legacy_event_ids` starts after the listener
  is up. It walks `id_integrity = 'unchecked'` rows in batches of 1000 by
  `stream_position`. It logs a count for each class, and logs every
  `id_mismatch` row at WARN with both IDs.
- **On demand.** When `get_wire_pdu` or `classify_legacy_snapshot` meets an
  `unchecked` row, it runs `classify_legacy_row` inline. It persists the
  class, then answers from the result. Federation never answers 404 just
  because the sweep has not reached a row yet.

Neither path ever rewrites a primary key or any reference to one.

#### Rows written after this change

Rows written after this change are inserted with `pdu_json` set and
`id_integrity = 'verified'`. That includes rows redacted on receipt. For
those, the stored form is the redaction, because the spec says "the
receiving server should use the redacted copy it calculated". So for these
rows `verified` means "ID verified and `pdu_json` authoritative", not
"content hash matches".

#### Two read paths

Retained history and federation serving are separate read paths.

- **Client reads.** All non-federation `Storage` reads go through
  `event_from_row` and return the retained Pdu. That is unchanged before
  classification, after inline classification, and after the sweep, for
  every class. Serve-time redaction by `m.room.redaction` events is the room
  content lane's concern, and it is unaffected.
- **Federation serving.** `Storage::get_wire_pdu(id) -> Option<WirePdu>`
  reads the class and decides:
  - `verified` serves `pdu_json` as stored.
  - `content_mismatch` serves `redact(pdu_json)`. The redaction is computed
    at serve time and is never written back. A peer that receives it sees a
    hash mismatch, redacts, and derives the same ID. That is the same
    outcome as for a post-change row that was redacted on receipt, so
    auth-chain members are not withheld for nothing.
  - `id_mismatch` returns `None`. The row behaves like a missing event:
    `/event` returns 404, and `/state`, `/backfill` and
    `/get_missing_events` omit it.

Re-fetching `content_mismatch` rows in full from their origin through
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

## Recorded divergences from Synapse (not mirrored)

**Content hash.** Synapse `compute_content_hash` (`synapse/crypto/event_signing.py`) also pops
the top-level keys `age_ts`, `outlier` and `destinations`. The spec removes
only `unsigned`, `signatures` and `hashes` ("Calculating the content hash").
Conduit follows the spec: those keys are ordinary extensions, and the content
hash covers them. Conduit never authors them. When a PDU from an adversary
carries one of these keys, Conduit and Synapse can disagree about whether the
content hash matches. Whichever side sees a mismatch redacts the PDU. It does
not reject it. The reference hash strips extensions, so both sides derive the
same ID, and the DAG converges. The fixture suite includes such a PDU and
asserts Conduit's spec behaviour.

**PDU size measure.** Conduit counts the received allow-listed `unsigned`,
`age` included. Synapse counts `unsigned.age_ts`, which depends on its
receive time. A PDU within a few bytes of 65536 can therefore be accepted by
one side and treated as unpersistable by the other. Building one takes a
near-64 KiB event, and exact parity is impossible because the Synapse
measure moves with time. Conduit-authored PDUs keep a 64-byte margin.

**`/invite` content-hash mismatch.** Conduit refuses it (B2). Synapse
redacts the invite and co-signs it.

**`send_join` error codes.** Conduit follows the spec's `M_INVALID_PARAM`.
Synapse returns 403 or `M_BAD_JSON`.

**Rule 4.2 for non-join memberships.** Synapse checks the authorising
server only on joins. Conduit drops joins that lack the signature, as
Synapse does. For non-join memberships it applies rule 4.2 as an auth
rejection, which is what the spec text says.

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
  - A `send_join` `state` that holds a duplicate `(type, state_key)` fails
    the whole join and stores nothing.
  - These tests drive `admit_fetched` directly with canned responses, not
    through a wiring test. Today `client.state`, `state_ids`, `backfill`,
    `get_missing_events` and `send_join` have no callers, and only
    `fetch_missing_auth_events` persists anything.
- Signing-key validity (C1):
  - A `verify_keys` key with `valid_until_ts` 3 days ahead verifies an
    event whose `origin_server_ts` equals `valid_until_ts`, and an event 1
    ms later fails with `NoEligibleSignature`.
  - A key published with `valid_until_ts` 1 year ahead and fetched at time
    F verifies an event at `F + 7d`, and does not verify one at
    `F + 7d + 1`. That fails unless a refetch, which the test mocks, renews
    the key.
  - After rotation the old key appears in `old_verify_keys` with
    `expired_ts = R`. It still verifies a historical event at `R - 1`, and
    the same key does not verify an event at `R + 1`.
  - A signature from an unknown key that stays unknown after the refetch
    is ignored when another eligible signature from the same server
    verifies.
  - An invalid signature from an eligible key fails the PDU even when
    another eligible signature verifies.
  - Wall-clock cache expiry alone never makes an expired key eligible.
- Restricted-join signatures (C2), as checked-in vectors generated by the
  same pinned-Synapse script as the fixture. Each vector records Synapse's
  `_check_sigs_on_pdu` verdict.
  - A join with `join_authorised_via_users_server`, signed only by the
    sender's server, is dropped.
  - A join whose authoriser signature is invalid, or comes from an
    ineligible key, is dropped.
  - A join validly co-signed by the authorising server is admitted, with
    `SignedBy` = {sender's server, authoriser's server}.
  - The same three cases arrive as a fetched auth event through
    `admit_fetched`, with the same verdicts.
  - A non-join `m.room.member` that carries the key with no authoriser
    signature is admitted at the signature stage and rejected by auth rule
    4.2.
  - A 3rd-party-invite membership (`membership: invite` with
    `third_party_invite`) that lacks the sender's server signature passes
    the signature stage. The same event without `third_party_invite` is
    dropped.
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
  - Client history (C4): for one lossy legacy remote row, client reads
    (`get_event`, timeline, `/context`) are byte-identical at three points:
    before classification, after inline classification triggered by
    federation `/event`, and after the background sweep. Over the same
    period, federation `/event` returns the redaction and `pdu_json` holds
    the unredacted rebuilt Pdu.
- Legacy outbox (C3): a pending `fed_outbound_queue` row holds an envelope
  in the pre-`56498e3` layout, a flattened snapshot whose ID was computed
  with `"event_id": ""` included, next to one verifiable legacy snapshot.
  Draining it:
  - sends only the verifiable PDU;
  - withholds the other and logs it with both IDs;
  - never re-signs it, so no event under a new ID appears in the outgoing
    body or in `events`;
  - marks both events' `id_integrity`.
  An envelope that holds only the bad snapshot is marked `sent` and carries
  the withheld note.
- Migrations (C5): a test runs migrations E and T against a database whose
  `transactions`, `fed_outbound_queue` and `events` tables hold rows. It
  asserts:
  - no table rewrite happens: `pg_class.relfilenode` is unchanged for all
    three tables;
  - pre-migration JSONB `transactions` and outbox rows still replay and
    drain through the fallback reads;
  - new rows land only in the `_text` columns.
- Lossless replay text (advise-3 note 1):
  - A client to-device `PUT` whose content holds `1.5` is stored, replays
    identically, and is delivered with the float intact.
  - An EDU-only `/send` that carries a float is refused at the X-Matrix
    layer with `401`. That is the existing middleware behaviour, now pinned
    by a test.
  - Calling `decode` on a PDU holding `1.5` drops it per PDU.
  - An EDU persist failing with class 22 inside the shared transaction
    drops only that EDU, and the remaining EDUs and PDUs commit, which
    exercises the `SAVEPOINT`.
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
- `conduit-y99.22.4`: EDU PostgreSQL sinks still reject U+0000. This change
  folds only the generic class-22 drop.
- `conduit-y99.22.5`: there is no retention or GC for `transactions` or for
  `sent` outbox rows. It blocks retiring the legacy JSONB columns after
  migration T.

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


## Review disposition, round 3 (advise-3 accept notes; advise-4 codex send-back)

Where this round changes an earlier disposition, the contract sections
above win. Three earlier statements are superseded:

- **Round 2's `content_mismatch` backfill.** That backfill stored the
  redaction. It now stores the unredacted rebuilt Pdu, and federation
  computes the redaction at serve time (C4).
- **B1's `ALTER COLUMN ... TYPE TEXT` conversions.** These are replaced by
  staged `_text` columns (C5).
- **The "canonical JSON" wording for the replay and outbox sinks.** That
  wording now reads "lossless JSON text" (advise-3 note 1).

**Advise-3 notes folded into the contract:**

1. **Lossless JSON text.** `transactions.request_text`, `result_text` and
   `fed_outbound_queue.payload_text` use `serde_json`, never the canonical
   encoder. Float tests were added.
   - Codex qualified the float example, and that qualification is recorded
     in decode step 2: federation bodies with floats already fail X-Matrix
     verification with a 401. That behaviour is kept and pinned by a test.
   - The per-PDU drop applies to fetched responses, and the replay sinks
     must accept client floats.
2. **Size measure.** Conduit now counts the allow-listed `unsigned` as
   received, `age` included. The claim "this is what Synapse measures" is
   removed. The residual gap is listed under "Recorded divergences".
   Authored PDUs keep a 64-byte margin (65472 bytes, `M_TOO_LARGE`).
3. **Stale reader claim (also codex's non-blocking note).** This is now the
   projection-reader audit table:
   - the membership predicates;
   - the user directory reads, added in `150d9ca`;
   - the `redacts` lookup at `storage_pg.rs:3450`;
   - the relation and thread queries;
   - full-text search, all added in `de3d1b9`.

   Each row says why the U+FFFD projection is harmless or acceptable. New
   readers must be added to the table.
4. **EDU class-22 drop.** Each EDU is persisted in its own statement or
   `SAVEPOINT`, and `map_sqlx` keeps the SQLSTATE.
5. **Delta and design gaps closed.**
   - The `send_join` response `event` row now requires unchanged `hashes`
     and a verified resident signature.
   - `/state` events must be state events of the room.
   - The `get_missing_events` seed is defined.
   - A duplicate `(type, state_key)` in `send_join` `state` fails the whole
     join.

   The delta now matches the design.
6. **Not folded:** note 6 (B3 tests drive `admit_fetched` directly) and
   note 7 (line numbers). Both are recorded in "Fixtures and tests" and
   "One row decoder", and the line list is updated to the 11 sites at
   `8175d10`.

**Codex C1. Signing-key validity: adopted.**

- `EligibleKeys` is keyed by the event's `origin_server_ts`.
- A key is eligible when
  `effective_until_ts = min(valid_until_ts, fetched_at_ts + 7d)` is at or
  after `origin_server_ts`. This applies room v11 "Signing key validity
  period": the `valid_until_ts` rule and "the lesser of `valid_until_ts`
  and 7 days into the future".
- For `old_verify_keys`, `effective_until_ts = expired_ts`. Server-server
  API: keys "known to have expired prior to the event's `origin_server_ts`
  are ignored".
- A key that is unknown or not eligible triggers a refetch, rate-limited,
  before the decision is made.
- Every eligible signature from a required server must verify, and at least
  one must remain. Otherwise the result is `NoEligibleSignature`. This
  replaces the first-valid-signature-wins loop and the wall-clock-only
  cache check.
- Tests cover the boundary at `valid_until_ts` and one millisecond past it,
  the 7-day cap, a historical event after rotation through
  `old_verify_keys`, an unknown key that is ignored, and an invalid
  eligible signature.

**Codex C2. Authorising-server signature: adopted.**

- "Required signers" requires the server of
  `join_authorised_via_users_server` on `m.room.member` joins. It drops a
  join that lacks a valid eligible signature from that server. This matches
  Synapse `_check_sigs_on_pdu` and covers v11 auth rule 4.2 for joins.
- The same signature stage runs in `admit_fetched`, so fetched auth events
  are covered.
- Non-join memberships that carry the key are rejected by the auth rule
  using `SignedBy`, not dropped. That follows the spec text, while staying
  on Synapse's side of drop and accept.
- Inbound `send_join` with the key requires that the authoriser is on our
  server, and Conduit co-signs before verification, as Synapse does.
- Checked-in vectors cover three cases: sender-only, invalid authoriser,
  and valid co-signed. Each runs both inbound and as a fetched auth event,
  and records Synapse's verdict.

**Codex C3. Legacy outbound integrity: adopted.**

- Emitters take `WirePdu`. Only `sign_authored`, `add_signature` (after
  `check_received`), `get_wire_pdu` and `classify_legacy_snapshot` can
  construct one. Direct `.pdu` emission and `wire_pdus(&[Event])` are
  removed.
- Legacy queue snapshots are classified against their saved local ID before
  emission:
  - `verified` is sent as it is;
  - `content_mismatch` is sent as its redaction;
  - `id_mismatch` is withheld.

  Nothing is re-signed into a new identity.
- A test drains a pending pre-`56498e3` envelope.

**Codex C4. Retained history vs federation serving: adopted.**

- `content_mismatch` rows keep the unredacted rebuilt Pdu in `pdu_json`.
- `get_wire_pdu` computes the redaction at serve time and never writes it
  back.
- `id_mismatch` rows keep `pdu_json` NULL and decode from the projections,
  exactly as before.
- Client reads are therefore byte-identical before and after both inline
  classification and the sweep, and a test asserts this at all three
  points.
- Post-change rows that were redacted on receipt still store the redaction.
  That is the spec's rule for received events, not a migration side effect.

**Codex C5. Migration locks: adopted, staged.**

- **Migration E** holds only the two metadata-only `events` column adds.
- **Migration T** adds nullable `_text` columns and drops `NOT NULL` on the
  outbox payload. It swaps the `transactions` CHECK for one that covers the
  new columns, added `NOT VALID`.
- Every statement is catalog-only, so no table is rewritten in either
  migration. Each file is its own transaction with
  `lock_timeout = '5s'`.
- Writers write only the `_text` columns. Readers fall back to the legacy
  JSONB columns.
- A test asserts that `relfilenode` is unchanged and that legacy rows still
  replay and drain.
- No row-count bound is needed, because nothing scales with table size.
- Retention and GC for `transactions` and sent outbox rows, and the later
  removal of the JSONB columns, are filed as `conduit-y99.22.5`. Retention
  changes the client txn-idempotency window, which is the replay owner's
  decision, and the staged design is safe without it.

**Codex non-blocking notes:**

- **Crypto bytes.** The correctness of the content hash, reference hash,
  co-sign bytes and redaction list is acknowledged. The wire `event_id`
  decision is not reopened.
- **Advise-3 wording.** The lossless-JSON and size-measure corrections are
  retained as contract wording (see above).
- **Projection-reader audit.** Updated (see above).
- **3rd-party-invite exception.** Documented in "Required signers": the
  sender's server signature is not required for a 3rd-party-invite
  membership. Inbound `/invite` also exempts such invites from the
  sender-equals-origin check. The `third_party_invite.signed` block is
  checked by auth rule 4.4.
