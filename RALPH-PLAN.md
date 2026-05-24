# Conduit — Ralph's Priority Upgrade Plan

**Date:** 2026-05-25
**DRXR Efficiency:** 74/100
**Target:** 88/100

**41 open issues** (2 P1, 18 P2, 19 P3, 2 P4).
**165 closed.** The skeleton is done. Now we fill depth.

---

## Phase 1 — Federation Blockers (Week 1)

These block production interop. Fix nothing else until these land.

### 1.1 — Redaction Engine (conduit-sv4.11)
**File:** `conduit/src/redaction.rs` (new)
**Effort:** ~250 lines, 2-3 hours
**What:** Pure function `redact_event(event: Event) -> Event` that strips all fields not on the spec's allowed-per-event-type list. Currently signing strips only `signatures+unsigned`. Full v11 redaction keeps only: `event_id`, `room_id`, `sender`, `origin_server_ts`, `type`, `state_key`, `hashes`, `depth`, `prev_events`, `auth_events`, `unsigned`, and per-type content fields (e.g. `m.room.member` keeps `membership`, `m.room.power_levels` keeps `users`,`events`,`state_default`,`events_default`,`notifications`,`ban`,`kick`,`redact`,`invite`).
**Fixes:** Federation interop, signing correctness, hashing correctness. **The single most impactful change.**

### 1.2 — Restricted Join Rules (conduit-jt5)
**File:** `conduit/src/auth.rs` (patch)
**Effort:** ~150 lines, 1 hour
**What:** Today `restricted` and `knock_restricted` join rules are simplified to "require invite." Spec says the `allow` conditions in the `join_authorised_via_users_server` field must be evaluated. Add `check_allow_conditions(event, state) -> bool` that walks the `allow` list and matches against sender state.
**Fixes:** Auth correctness for rooms using restricted join rules (common in modern Matrix).

### 1.3 — Full Auth-Chain Resolution (conduit-s6m + conduit-g12)
**File:** `conduit-server/src/federation/pipeline.rs` + `conduit/src/room/state_res.rs` (patch)
**Effort:** ~400 lines, 3-4 hours
**What:** Today the federation pipeline uses heuristic depth+ts+id instead of full recursive auth-event verification for inbound PDUs. Wire the existing `state_res.rs` pure function into the federation inbound pipeline so every incoming PDU gets full state resolution v2, not the heuristic.
**Fixes:** Federation correctness against adversarial peers.

---

## Phase 2 — Client Interop (Week 2)

These make Conduit work with real clients.

### 2.1 — Element Bring-up (conduit-il0.19)
**Files:** Config + docs + minor handler fixes
**Effort:** 1-2 hours
**What:** Point real Element web at Conduit. Register, create room, chat, sync. Identify what breaks. Likely hits: room alias resolution for `/join`, `/capabilities`/`/turnServer` probes, device list stream in sync. Fix each.
**Fixes:** Confirms the server actually works. Today you're guessing.

### 2.2 — Room Model Extraction
**File:** `conduit/src/room/mod.rs` (rewrite)
**Effort:** ~500 lines, 4-5 hours
**What:** Today `room/mod.rs` is 41 lines — `Room { room_id: String }` with `new()` and a pass-through. All room logic (create, join, leave, invite, send, state read) lives in handler code in `conduit-server`. Extract into `Room` struct methods: `create()`, `join()`, `apply_event()`, `current_state()`, `timeline()`, `authorize()`.
**Fixes:** Library testability. Without this, the library crate can't be tested independently.

### 2.3 — Room Alias Resolution (conduit-e95)
**File:** `conduit-server/src/api/client/rooms.rs` (patch)
**Effort:** ~100 lines, 1 hour
**What:** `/join/{roomIdOrAlias}` currently only handles room IDs. Add alias lookup: detect `#` prefix, call `storage.get_room_for_alias()`, redirect to the resolved room. Requires alias table which `conduit-v0y` already created.
**Fixes:** Element web's "join room by alias" flow.

---

## Phase 3 — Maturation (Week 3-4)

### 3.1 — Transport Trait Generalization
**File:** `conduit/src/transport/mod.rs` (rewrite)
**Effort:** ~200 lines, 2 hours
**What:** Today `Transport` is a marker trait with `fn name()`. Generalize to functional interface: `fn send()`, `fn receive()`, `fn connect()`, `fn disconnect()`. Wire iroh transport behind the same trait. Current iroh module is 88 lines of stub — connect the endpoint binding.
**Fixes:** Enables non-HTTP deployments (P2P, CLI, WASM).

### 3.2 — broadcast_device_list_update Index (conduit-e0e)
**File:** `conduit-server/src/api/client/keys.rs` (patch)
**Effort:** ~200 lines, 1-2 hours
**What:** Today walks `list_rooms(0, 10000)` and `get_current_state` per room on every device-key upload. Add a `user_room_servers` materialized mapping backed by membership changes. O(1) instead of O(rooms × members).
**Fixes:** Performance at scale.

### 3.3 — AS Ghost Users (conduit-5vr)
**File:** `conduit-server/src/app_service.rs` (patch)
**Effort:** ~150 lines, 1 hour
**What:** Stubbed. Wire auto-creation when a request arrives for a user ID within an AS namespace.
**Fixes:** App service interop.

### 3.4 — Sliding Sync (conduit-8sg)
**File:** `conduit-server/src/api/client/sync.rs` (extension)
**Effort:** ~500 lines, 5-7 hours
**What:** MSC3575 sliding-window `/sync`. Modern Element prefers this. Legacy `/sync` works but is slower for big accounts. Build subscription model: room list + window + required_state + timeline limits.
**Fixes:** Performance for large accounts, Element web experience.

---

## File Manifest

| Phase | File | Action | Est Lines | Priority |
|-------|------|--------|-----------|----------|
| 1.1 | `conduit/src/redaction.rs` | CREATE | 250 | CRITICAL |
| 1.1 | `conduit/src/signing.rs` | PATCH — wire redaction into signing_bytes | 20 | CRITICAL |
| 1.1 | `conduit/src/hashing.rs` | PATCH — wire redaction into content_hash | 20 | CRITICAL |
| 1.2 | `conduit/src/auth.rs` | PATCH — add check_allow_conditions | 150 | HIGH |
| 1.3 | `conduit-server/src/federation/pipeline.rs` | PATCH — wire full state res | 400 | HIGH |
| 2.1 | Various handler files | PATCH — fix Element bring-up failures | 200+ | HIGH |
| 2.2 | `conduit/src/room/mod.rs` | REWRITE — Room struct with methods | 500 | HIGH |
| 2.3 | `conduit-server/src/api/client/rooms.rs` | PATCH — alias resolution | 100 | HIGH |
| 3.1 | `conduit/src/transport/mod.rs` | REWRITE — functional transport trait | 200 | MEDIUM |
| 3.1 | `conduit/src/transport/iroh.rs` | FILL — wire endpoint to trait | 150 | MEDIUM |
| 3.2 | `conduit-server/src/api/client/keys.rs` | PATCH — device_list index | 200 | MEDIUM |
| 3.3 | `conduit-server/src/app_service.rs` | PATCH — ghost user creation | 150 | MEDIUM |
| 3.4 | `conduit-server/src/api/client/sync.rs` | EXTEND — sliding sync | 500 | MEDIUM |

---

## Expected Outcome

| Metric | Before | After (Phase 1 done) | After (all phases) |
|--------|--------|---------------------|-------------------|
| DRXR Efficiency | 74/100 | 82/100 | 88/100 |
| Federation interop | RED (redacted events break) | GREEN (redaction engine active) | GREEN |
| Auth correctness | YELLOW (restricted rooms broken) | GREEN (allow conditions checked) | GREEN |
| Federation auth resolution | RED (shallow heuristic) | GREEN (full state res v2) | GREEN |
| Library testability | RED (room logic in server) | RED (room logic in server) | GREEN |
| Transport | RED (marker trait) | RED (marker trait) | YELLOW (functional) |
| P1 issues | 2 | 2 | 0 |
| P2 issues | 18 | 16 | 10 |
| Open issues | 41 | 39 | 28 |

## Current Status (2026-05-25)

**Phase 1.1 (REDACTION ENGINE):** ✅ DONE
- Created `conduit/src/redaction.rs` (341 lines) — full v11 redaction engine
- Wired into `signing.rs` — `signing_bytes()` and `signing_bytes_for_verify()` now redact before signing
- Wired into `hashing.rs` — `content_hash()` and `event_id()` now redact before hashing
- 7 new redaction tests pass
- **63 library tests pass, 0 fail**

**Phase 1.2 (RESTRICTED JOIN RULES):** ✅ DONE
- Added `check_allow_conditions()` in `auth.rs`
- Wire into `check_member()` — restricted joins check allow conditions before rejecting
- 3 new auth tests pass (satisfied allow, unsatisfied allow, empty allow)

**Phase 1.3 (AUTH-CHAIN RESOLUTION):** ✅ DONE
- Replaced shallow depth+ts+id heuristic with full `state_res::resolve()` call
- Added `build_auth_chain()` helper — recursively walks auth_events to build auth chain
- Added `build_auth_state_from_resolved()` — extracts auth-event keys from resolved state
- Added `PipelineError::MissingAuthEvent` for spec-compliant error handling
- Auth check now runs against the fully resolved state (not just direct auth_events)
- Closes conduit-s6m and conduit-g12
- All 7 federation_inbound integration tests pass
- All 9 state_res unit tests pass
- Full workspace builds clean (0 errors, pre-existing warnings only)
**Phase 2-3:** 🔲 PENDING

## How to Execute

```bash
# Phase 1 all at once (they're independent)
cargo build --workspace  # after each file change
cargo test --workspace   # verify nothing regressed

# Phase 2 requires Element web running
# After changes: cargo run -p conduit-server, point Element at localhost:8008

# Phase 3 — same build+test loop
```

Begin with Phase 1.1 (redaction engine). It's 250 lines, 2-3 hours, and unlocks every other fix.
