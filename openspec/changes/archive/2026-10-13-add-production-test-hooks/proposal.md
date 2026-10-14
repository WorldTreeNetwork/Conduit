# Production server test hooks

> **ARCHIVED** — folded into `openspec/specs/server-automation/spec.md`; production journeys and startup-failure checks pass.

Exercise the production binary and its PostgreSQL backend without shared ports,
databases, or human startup. `CONDUIT_LISTEN_ADDR` configures the bind address;
`CONDUIT_READY_FILE` reports the actual address after binding. Defaults remain
`0.0.0.0:8008` with no readiness file. Authentication follows the usual HTTP flow.

Work and acceptance live in beads `conduit-y99.4.1`. No new UI because these
hooks configure the homeserver process and unattended test infrastructure.
