## ADDED Requirements

### Requirement: Wire/local event separation

The system SHALL represent v11 federation events as Pdu without local event_id.
Event SHALL own the derived ID separately from Pdu. Hashing, signing, reference
ID derivation and signature verification SHALL accept Pdu rather than Event.

#### Scenario: Standard received event

- GIVEN a v11 PDU without event_id and with unknown extension fields
- WHEN it is decoded, verified and persisted
- THEN its local ID is derived and the original extension data survives storage

### Requirement: Cryptographic and redaction invariants

Content hashing SHALL include unredacted content and retained extensions while
excluding hashes/signatures/unsigned. Reference hashing and signatures SHALL use
exact v11 redaction with no extensions or local metadata. Hash mismatch SHALL
redact only after signature validation while retaining the derived event ID.

#### Scenario: Local metadata independence

- GIVEN a signed Pdu and a local Event wrapping it
- WHEN the local ID is assigned or changed
- THEN the signature and protocol hash bytes remain unchanged

### Requirement: Durable and HTTP wire preservation

PostgreSQL event reads/writes SHALL retain the extension map in JSONB. Federation
HTTP events SHALL serialize Pdu and SHALL NOT leak local event IDs. Received join
and invite path IDs SHALL match derived IDs.

#### Scenario: Pool restart

- GIVEN a persisted extended PDU
- WHEN storage is reopened and the event is emitted over federation
- THEN extensions are retained and event_id is absent from the wire object
