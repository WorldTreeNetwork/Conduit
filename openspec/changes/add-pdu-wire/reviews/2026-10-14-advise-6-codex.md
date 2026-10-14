<!-- READER: codex (cross-family). SPAWN: codex exec -s read-only, 2026-10-14. -->

# ADVISE: accept

No required amendments. C2 and C3 are resolved; `df682f1` introduces no new blocking problem within the requested scope.

**Implementation notes**

- **C2:** Non-join authoriser signatures now enter `SignedBy` after verification; missing or invalid signatures cause auth rejection without dropping the PDU. This satisfies [Matrix v1.19, v11 rule 4.2.1](https://spec.matrix.org/v1.19/rooms/v11/#authorisation-rules). See [design.md:182](/Users/dukejones/work/WorldTree/Conduit/openspec/changes/add-pdu-wire/design.md:182) and the receipt/fetch vectors at [spec.md:193](/Users/dukejones/work/WorldTree/Conduit/openspec/changes/add-pdu-wire/specs/events-and-signing/spec.md:193). Passing 4.2 must still leave the remaining auth rules applicable.

- **C3:** Snapshot and stored-row classifications now use their own bytes, with snapshot verdicts confined to the queue. Emission preserves the saved identity and redacts content mismatches, consistent with [Matrix hash validation](https://spec.matrix.org/v1.19/server-server-api/#validating-hashes-and-signatures-on-received-events). See [design.md:416](/Users/dukejones/work/WorldTree/Conduit/openspec/changes/add-pdu-wire/design.md:416) and [spec.md:518](/Users/dukejones/work/WorldTree/Conduit/openspec/changes/add-pdu-wire/specs/events-and-signing/spec.md:518).

- **Minor wording:** “The drain does not change `events.id_integrity`” at [spec.md:515](/Users/dukejones/work/WorldTree/Conduit/openspec/changes/add-pdu-wire/specs/events-and-signing/spec.md:515) should mean snapshot classification cannot change it. Independent row classification through `get_wire_pdu` may legitimately persist a verdict, as [design.md:675](/Users/dukejones/work/WorldTree/Conduit/openspec/changes/add-pdu-wire/design.md:675) specifies.

The three-day fixture and lock-timeout wording corrections are sound. This verdict reviews the amended contract, not implemented behavior.