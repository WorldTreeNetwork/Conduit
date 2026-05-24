# Conduit × DFP Spatial Rendering Stack — Mapping

Conduit's data-ordering patterns applied to the NKOLAGE 11-phase rendering engine.

## The Core Pattern

Conduit separates **state resolution** (pure function, no side effects) from **state application** (I/O, GPU commands). Your DFP stack currently conflates them. Apply this split to 5 subsystems:

| Subsystem | Today | Conduit Pattern | Impact |
|-----------|-------|-----------------|--------|
| Nanite LOD (P2) | Ad-hoc priority storm | Topo sort + power tiebreak | No LOD pop |
| 4D GS streaming (P3) | Full-state broadcast | Compound diff cursors | 70% less bandwidth |
| CRDT scene merge (P7) | Simple LWW, ghost entities | Power/content op split | Correct 3+ peer merge |
| Anchor sharing (P6) | No signing, forgeable | ed25519 + canonical JSON | Anti-spoof |
| Scene schema migration (P9) | `??` fallback chains | Forward-fix migration chain | Clean defaults |

## 1. Nanite LOD Resolution (Phase 2)

**Problem:** `LODSelector` picks meshlet clusters from a DAG. Concurrent camera movement + velocity inputs cause conflicting LOD transition signals within a single frame.

**Fix — reverse-topological power ordering:**
- Build topo order of cluster DAG (parent → child dependencies)
- Classify inputs by power level: camera movement = 3, viewport resize = 2, player velocity = 1
- Resolve highest-power input first in each frame

~80 lines in `dfp/virtual-geometry.ts`. No new dependencies.

## 2. Gaussian Splat Diffs (Phase 3)

**Problem:** `4DGStreamer` sends full `(mean, cov, color, opacity)` per cluster every tick even when only covariance changed.

**Fix — compound cursors:**
- Each splat cluster has `s{version}_m{meanVer}_c{covVer}_o{opacityVer}`
- Send only changed components: `{ cluster: "r3-c7", t: "s124_m42_c32", cov_delta: [...] }`
- Receiver fills unchanged components from local cache

## 3. CRDT Merge with Power Ops (Phase 7)

**Problem:** LWW on scene operations causes ghost entities — delete can't kill an entity that was concurrently moved.

**Fix — split power/content events:**

Power ops (create, delete, transfer-ownership):
- Resolve first
- Delete always wins over concurrent add

Content ops (set-position, set-color, set-property):
- Resolve after power ops
- Only apply to surviving entities

~50 lines in `multiplayer/scene-replicator.ts`.

## 4. Scene Operation Signing (Phase 6/7)

**Problem:** Peers share spatial anchors over WebRTC with no signing. Any peer can forge `anchor-claim`.

**Fix — canonical JSON + ed25519:**
1. Canonicalize operation JSON: sorted keys, no whitespace, safe ints `[-(2^53-1), 2^53-1]`
2. Sign with sender's Ed25519 key
3. Verify on receipt before applying

~100 lines TypeScript. Uses `tweetnacl` or `@noble/ed25519`.

## 5. Scene Schema Migrations (Phase 9)

**Problem:** Adding a new `SceneNode` property means `??` fallbacks everywhere. No audit trail of when/why a default changed.

**Fix — numbered migration chain:**
1. Scene saved with `scene_version` field
2. On load, check version and apply outstanding migrations sequentially
3. Each migration is a pure function: `(scene: StoredScene) => StoredScene`
4. No `??` fallbacks needed — migration writes explicit defaults

## Source

Conduit (WorldTreeNetwork/Conduit) — cloned at `~/Conduit/`.
