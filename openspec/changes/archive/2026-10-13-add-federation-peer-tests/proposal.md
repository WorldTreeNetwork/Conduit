# Verified TLS federation peer automation

> **ARCHIVED** — folded into `openspec/specs/federation-automation/spec.md`; live peer and startup assertions pass.

Run the shipped binary against pinned Synapse on loopback with generated TLS
certificates, isolated stores, normal Matrix authentication, and bounded startup
and delivery deadlines. `CONDUIT_TLS_CA` adds an operator-provided PEM root to
outbound HTTPS trust while retaining certificate, hostname, and X-Matrix checks.

No new UI because this unit configures peer test automation and the homeserver
HTTP client. Work and acceptance are tracked in beads `conduit-y99.10.1`.
