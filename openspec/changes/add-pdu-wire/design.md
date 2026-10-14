# PDU contract

`Pdu` owns v11 protocol fields and a flattened map of extension fields. `Event`
owns `event_id` and `pdu`; dereferencing an Event accesses its Pdu fields while
local serialized snapshots retain their existing flattened layout. Cryptographic
functions accept only `Pdu`. A local event ID can never affect protocol bytes.

Wire deserialization rejects `event_id` and invalid typed required fields. Unknown
top-level fields survive content hashing and storage. Serializer validation rejects
extension keys that collide with known fields or local metadata. Redaction retains
the exact v11 top-level/content subset, clears all extensions and unsigned data,
and preserves hashes/signatures. Existing independent OpenSSL/Python vectors stay
unchanged. Incoming PDUs derive their local ID before hash-mismatch redaction.

PostgreSQL migration adds an opaque JSONB extension map. Existing rows receive an
empty map; the protocol columns retain their current values. Every event projection
and writer includes extensions; the SQLX cache is regenerated. Legacy persisted
outbox envelopes are decoded as local Event snapshots, then converted to Pdu
before HTTP signing/sending. Newly emitted federation events omit event IDs.

Federation /send, /send_join, /invite and auth-event fetches decode Pdu and derive
IDs; outbound transaction/join/invite/state/backfill/event responses emit Pdu.
Path-provided join/invite IDs must equal derived IDs. make_join templates omit
event_id. Client-facing Event snapshots may retain local IDs; a later client wire
projection audit remains tracked under the full protocol goal.

Acceptance includes Pdu-without-ID parsing, unknown-field content/reference hash
behavior, sign/derive-ID/verify, hash-mismatch redaction without changing the ID,
PG reopen persistence, wire responses without local IDs, and independently signed
room-event checks against the live Synapse peer. Reject malformed canonical values
at received-event validation, keeping unsigned data out of hashes/signatures.
