# E10 — 🚦 E2EE Infrastructure

**Status:** 🔵 Not started
**Implementation guide:** [docs/features/e2ee.md](../docs/features/e2ee.md)
**Depends on:** E09
**Blocks:** —

## Scope

Server-side support for end-to-end encryption. The crypto runs in
clients; we carry keys and to-device messages reliably, across
federation.

## "Done" looks like

- Two Element clients on different homeservers verify each other and
  exchange E2EE messages in a room hosted by either side.
- Cross-signing trust establishes between devices of the same user.

## Stories

### Local

- [ ] **E10-1**: `POST /keys/upload` (device keys, OTKs, fallback).
- [ ] **E10-2**: `POST /keys/query` (devices + keys for a user list).
- [ ] **E10-3**: `POST /keys/claim` (atomic OTK consumption — must
      be exactly-once).
- [ ] **E10-4**: `POST /keys/changes` (delta since a sync token).
- [ ] **E10-5**: Fallback key pool (used only when OTKs exhausted).
- [ ] **E10-6**: `PUT /sendToDevice/{eventType}/{txnId}` (local).
- [ ] **E10-7**: Surface to-device messages in `/sync`.

### Cross-signing

- [ ] **E10-8**: `POST /keys/device_signing/upload` (master /
      self-signing / user-signing).
- [ ] **E10-9**: `POST /keys/signatures/upload`.

### Federation

- [ ] **E10-10**: `PUT /_matrix/federation/v1/send_to_device/{txnId}`.
- [ ] **E10-11**: `m.device_list_update` EDU emit + handle.
- [ ] **E10-12**: Notify all local users sharing a room when a
      remote's device list changes.

### Backup (optional)

- [ ] **E10-13**: `/_matrix/client/v3/room_keys/version` + storage.

## Open questions

- Server-side key backup (`/room_keys`) — implement now or after
  federation E2EE works end-to-end?

## Risks

- OTK double-spend is catastrophic for sessions. Atomic
  check-and-decrement is mandatory.
- Device-list staleness is the #1 production E2EE bug. Test it
  explicitly: device added on one server, message sent from another,
  decryption succeeds.
