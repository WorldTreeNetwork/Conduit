# DRXR Protocol Analysis: Conduit

**Analyst:** Dr XR — 10x Recursive Upgrade Architect  
**Date:** 2026-05-25  
**Protocols Applied:** BARE METAL (P4), NEXUS (P2), CHAR (P9)

---

## Build Plan Overview

Conduit is a clean-room Matrix homeserver in Rust split across two crates:

- **`conduit/`** (pure library, ~16 source files, ~1,200 LOC in state_res.rs alone) — events, signing, auth, storage trait, state resolution, canonical JSON, transport abstraction
- **`conduit-server/`** (axum webserver, ~39 source files, + ~18 test files) — HTTP handlers, Postgres storage impl, federation client/server, push worker, app services, admin API, media storage

---

## DRXR Efficiency Rating: **74/100**

Breakdown:

| Protocol | Score | Assessment |
|----------|-------|------------|
| **P4 (BARE METAL)** | 78 | Strong foundations, but several "TODO" black holes and simplified implementations |
| **P2 (NEXUS)** | 68 | Good storage trait, but no cross-cutting generalization patterns active |
| **P9 (CHAR)** | 62 | Identity persistence exists but no upgrade/versioning protocol for stored data |
| **Overall** | **74** | Structurally sound, not yet production-tough |

---

## Protocol 4 — BARE METAL Analysis

### What's Built From First Principles (Good)

| Component | Lines | Verdict |
|-----------|-------|---------|
| **State Resolution v2** | `state_res.rs` — 1,238 lines | **Excellent.** Pure function, zero I/O, deterministic, non-panicking. Auth chain cycle detection. Mainline ordering. Kahn's algorithm with priority tiebreaking. This is spec-grade. |
| **v11 Authorization** | `auth.rs` — 1,097 lines | **Strong.** Full rule set: create rules, membership transitions, power level checks, join rule enforcement, restricted room stub. Error types cover every spec rejection reason. |
| **Canonical JSON** | `canonical_json.rs` — 284 lines | **Correct.** Sorted keys, safe integer range [-(2^53-1), 2^53-1], minimal RFC 8259 escaping, UTF-8 verbatim for non-ASCII. |
| **Hashing/Event IDs** | `hashing.rs` — 196 lines | **Spec-compliant.** content_hash (standard base64) vs event_id (URL-safe base64) with correct field stripping per spec. |
| **Signing** | `signing.rs` — 503 lines | **Solid.** sign_event and verify_event with key lookup closure. Preserves multi-server signatures. Tests for tamper detection, wrong keys, round-trip. |
| **Storage trait** | `storage.rs` — 2,416 lines | **Massive.** 70+ methods across events, accounts, devices, tokens, signing keys, room state, pagination, E2EE keys, OTKs, fallback keys, cross-signing, to-device queue, device list changes, room key backup, push, federation outbound, DLQ, admin audit. |

### What's BARE METAL Debt (Rebuild Required)

1. **`signing.rs` uses simplified field-stripping** (`signatures` + `unsigned` only)
   - Full v11 redaction (per-event-type allowed content fields) is **not implemented**
   - Currently functions: `signing_bytes()` strips `signatures` + `unsigned`
   - Required: real redaction engine that keeps only spec-allowed fields per event type before signing hashes
   - **This is the highest-leverage single upgrade** — without it, federation interop will break on redacted events

2. **`room/mod.rs` is empty** — 0 LOC room management logic
   - Room creation, room aliases, room upgrades, room tombstoning all live in handler code
   - Should be a `Room` struct in the library crate with methods like `create()`, `join()`, `leave()`, `invite()`, `send()`, `upgrade()`
   - Currently: `mod.rs` exists but no code

3. **`auth.rs` restricted join_rule is a stub**
   - Lines 418-428: "Simplified: require invite (full restricted-room join requires checking allow conditions — deferred to follow-up)"
   - `restricted` and `knock_restricted` join rules are **not properly implemented**
   - This blocks real-world federated rooms with restricted join rules

4. **Event struct has no typed content** (`event.rs` — 40 lines)
   - `content: Value` — opaque JSON for everything
   - `state_events.rs` has typed structs for `m.room.create`, `m.room.member`, `m.room.power_levels`, `m.room.join_rules`, `m.room.history_visibility` (191 lines)
   - But these are only used for *parsing* — the pipeline still passes raw `Value`
   - There's even a comment: "The eventual choice is between fleshing these out against the spec or pulling in ruma"

5. **Transport abstraction is a marker trait** (`transport/mod.rs` — 15 lines)
   - `trait Transport: Send + Sync + 'static { fn name(&self) -> &'static str; }`
   - No `send_event`, `receive_event`, `connect`, `disconnect` methods
   - The iroh module is feature-gated but disconnected from the main pipeline

### BARE METAL Build Efficiency: 78/100

**Good foundations but critical gaps around redaction (federation-breaking), room model (logic in handlers), and typed events (content as Value).**

---

## Protocol 2 — NEXUS Analysis (Multi-Level Generalization)

### What Generalizes Well

1. **`Storage` trait as pure abstraction** — The entire data layer is behind `#[async_trait] pub trait Storage`. In-memory impl exists for tests. Postgres impl is a separate dependency (`conduit-server`). This is textbook NEXUS. A sqlite or rocksdb backend would be straightforward.

2. **`StateMap<Event>` type alias** — `pub type StateMap<T> = HashMap<(String, String), T>` used across auth, state res, and event pipeline. Consistent key model. Good.

3. **Compile-time-checked SQL via sqlx** — `query!` macros ensure SQL correctness. `.sqlx/` offline cache committed. Migration conventions documented (forward-fix only, no IF NOT EXISTS, BRIN on monotonic columns, partial indexes on sparse, jsonb for opaque content).

4. **Compound sync token format** — `"s{events}_d{device}_a{acct}_r{rcpts}"` with backward-compatible parser. Forward-compatible (unknown segments ignored). This is NEXUS-forward thinking.

5. **Error type hierarchy** — `conduit::error::Error` with `Storage(String)`, `InvalidEvent(String)`, `NotFound`, `Forbidden`, `Io`, `Serde`. Domain-specific error types like `AuthError`, `StateResError`, `SigningError`, `VerifyError`.

### Where NEXUS is Weak

1. **No room model generalization** — Room operations are scattered across handler files (`rooms.rs`, `event_pipeline.rs`, `sync.rs`). No `Room` struct that encapsulates a room's state machine. NEXUS demands a room be a first-class object with `room.current_state()`, `room.authorize(event)`, `room.resolve_state(sets)`.

2. **Auth state machine embedded in handler code** — `AuthState` trait has 9 associated methods. This should be a self-contained auth middleware layer, not mixed with AppState.

3. **No typed event content hierarchy** — The choice between embedding `ruma` or building custom typed content is deferred. Until it's resolved, every handler deserializes from raw `Value` with ad-hoc `.as_str()`, `.get()`, error handling. NEXUS score drops without type safety at the event content boundary.

4. **Push rules engine is tight to the handler** — `push/rules.rs` exists but the evaluator and the HTTP API are interleaved. Could be a standalone `PushEvaluator` that takes `(Event, Vec<PushRule>) -> Vec<Action>`.

### NEXUS Efficiency Rating: 68/100

**Excellent storage generalization but the room model, event types, and auth middleware need generalization passes.**

---

## Protocol 9 — CHAR Analysis (Identity Persistence & Upgrade)

### Existing Identity Mechanisms

1. **Postgres migrations** — 7 migrations (`0001_initial.sql` through `0007_room_aliases.sql`), forward-fix only. Good for schema evolution.

2. **Signing key persistence** — `load_or_generate()` in `conduit-server/src/keys.rs`. Key is stored in DB and reloaded on restart. Key rotation interface exists (`set_signing_key_expiry`).

3. **Access tokens** — Stored hashed. Token owner lookup works. Expiry supported.

4. **Device persistence** — Upsert semantics. IP and last_seen_ts tracked.

### Where CHAR is Missing

1. **No schema versioning in library crate** — Storage trait has no `schema_version()` method. No migration strategy for the trait itself. If a new Storage impl adds methods, old impls silently break at runtime.

2. **No event schema version** — Events are `serde_json::Value` blobs. If the content format changes (e.g. room v11 → v12), there's no schema migration path. Old events are opaque.

3. **No upgrade protocol** — What happens when Conduit upgrades its event format? State resolution algorithm? Auth rules? There's no `room_version` upgrade pathway. The `RoomKeyBackup` has versioning, but core event processing doesn't.

4. **No data migration tooling** — Forward-fix migrations work for schema but there's no tool for data backfill (e.g. re-hashing all events with new redaction rules, re-deriving event IDs).

5. **No blue/green deployment support** — The server starts, applies migrations, serves. No canary mode, no gradual rollback capability.

### CHAR Efficiency Rating: 62/100

**Identities persist (keys, tokens, devices, migrations) but the upgrade protocol for evolving event formats, storage trait methods, and core algorithms is absent.**

---

## Recursion Depth Assessment

| Depth | Level | Description | Example |
|-------|-------|-------------|---------|
| **0** | Monolith crates | conduit + conduit-server as two crates | Workspace members |
| **1** | Module-level | api/client/*, api/admin, federation/*, push_worker | Good module isolation |
| **2** | Abstraction layer | Storage trait, Transport trait, AuthState trait | Present but Transport is skeletal |
| **3** | Meta-architecture | Room model, typed event framework, plugin system | **Absent** — highest gap |

The project sits at recursion depth 1.5 — it has clean module boundaries and a good storage abstraction (depth 2-ish), but room model, event typing, and transport generalization are depth 1 (embedded in handlers).

---

## What Must Be Rebuilt vs Extended

### MUST REBUILD (faulty foundation)

1. **Event redaction engine** (`conduit/src/redaction.rs` — doesn't exist yet)
   - Full v11 per-event-type content pruning
   - Must replace the `signatures`+`unsigned` strip in `signing.rs`
   - Impacts: `signing.rs`, `hashing.rs`, `event_pipeline.rs`
   - **This is the highest-leverage single upgrade — without it, federation is broken for redacted events**

2. **`room/mod.rs`** — currently empty
   - Must build `Room` struct with `new()`, `authorize()`, `current_state()`, `timeline()`, `members()`
   - Extract room logic from `rooms.rs` handler code (which is ~500+ lines of inline room management)

3. **Transport trait** — must extend from marker to functional interface
   - Methods needed: `send_pdu()`, `send_edu()`, `query_state()`, `query_backfill()`, `make_join()`, `send_join()`

### CAN EXTEND (solid foundation, add capacity)

1. **Storage trait** — add more methods as needed; existing 70+ are well-factored
2. **State Resolution** — handle room v1-v10 edge cases, add fuzzing tests
3. **Auth engine** — implement restricted join_rule `allow` conditions
4. **Canonical JSON** — already correct; can add fuzz testing
5. **Migrations** — continue forward-fix pattern
6. **Federation pipeline** — already has queue, backoff, DLQ; add more EDU types
7. **Test suite** — 180+ tests existing; add property-based tests for state res

---

## Single Highest-Leverage Upgrade

### Implement Full v11 Event Redaction

**Priority:** CRITICAL  
**Current state:** `signing_bytes()` in `signing.rs` strips only `signatures` and `unsigned`. The README explicitly flags this as incomplete.

**What it requires:**
1. A new `conduit/src/redaction.rs` module (~200-300 lines)
2. Per-event-type allowed content fields (the spec defines which keys survive for each `m.room.*` type and `m.*` namespace)
3. A `redact_event(event: &Event) -> Event` function that returns the redacted form
4. Replace field stripping in `signing.rs` lines 106-113 and `hashing.rs` with calls to this function

**Why highest leverage:**
- Federation interop literally cannot work without it
- The entire signing/verification chain depends on correct redaction
- It's a contained change (one new module, touch two existing files) with outsized impact
- Everything else (auth, state res, storage) is built correctly *assuming* this foundation

**Effort estimate:** 2-3 days for implementation + test vectors

---

## Summary

Conduit's skeleton is **good**. The core Matrix algorithms (state res v2, auth rules, canonical JSON, signing, event IDs) are built from first principles and demonstrably correct. The two-crate architecture is clean. The Storage trait is a genuine abstraction win.

The weaknesses are at the boundaries: untyped event content, incomplete redaction (federation-breaking), empty room model, skeletal transport trait, missing upgrade protocol. These are all *extensions of existing structure* rather than fundamental rewrites — which is why the DRXR rating is 74 (solid but not yet production-tough).

**Build plan (weeks 1-4):**
- Week 1: Full redaction engine + signing/hashing update
- Week 2: Room model extraction from handlers → `room/mod.rs`
- Week 3: Typed event content (adopt ruma or custom hierarchy)
- Week 4: Restricted join_rules + transport trait generalization + NEXUS pass
