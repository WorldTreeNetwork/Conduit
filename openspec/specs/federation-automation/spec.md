## ADDED Requirements

### Requirement: Verified private-CA HTTPS

The host SHALL accept `CONDUIT_TLS_CA` as a PEM root certificate path for its
outbound HTTP client. A missing or invalid configured certificate SHALL fail
startup. Default public roots SHALL remain trusted. Certificate and hostname
verification SHALL remain enabled; this option SHALL NOT bypass Matrix signing.

#### Scenario: Independent peer delivery

- GIVEN Conduit and pinned Synapse with generated loopback TLS certificates
- WHEN normal authenticated clients exchange to-device messages
- THEN both peers authenticate the server signatures and return the original
  sender, event type, and Unicode contents through sync

### Requirement: Unattended durable delivery verification

The peer journey SHALL fail on missing prerequisites, startup failures, delivery
timeouts, or failed assertions. It SHALL clean up processes, stores, and
certificates automatically. The journey SHALL verify successful transaction
replay across restart, queued delivery recovery, EDU-ID deduplication, Unicode
message-ID bounds, and rejection of sender domains outside the signed origin.

#### Scenario: Delivery interrupted before dispatch

- GIVEN a remote peer temporarily responds with HTTP 503
- WHEN Conduit commits a to-device delivery and restarts before successful send
- THEN boot recovery sends the persisted standard EDU once to the restored peer
