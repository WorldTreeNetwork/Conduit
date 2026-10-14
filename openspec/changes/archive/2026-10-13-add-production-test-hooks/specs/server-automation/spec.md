## ADDED Requirements

### Requirement: Isolated production process startup

The server SHALL accept `CONDUIT_LISTEN_ADDR` as a socket address, including port
zero, and SHALL default to `0.0.0.0:8008`. Invalid or unavailable addresses SHALL
fail startup. When `CONDUIT_READY_FILE` is set, the server SHALL write JSON
containing the actual bound `address` after migrations and socket binding. An
unwritable readiness file SHALL fail startup. Hooks SHALL NOT bypass HTTP auth.

#### Scenario: Unattended production journey

- GIVEN an empty isolated PostgreSQL database and a loopback port-zero address
- WHEN automation starts the production binary and waits for readiness
- THEN migrations run, the bound address is reported, and authenticated clients
  can register, join a room, send a message, and receive it through sync

#### Scenario: Durable restart

- GIVEN accounts, tokens, rooms, and messages created through production HTTP
- WHEN the process restarts against the same database
- THEN tokens remain usable and persisted room messages remain readable
