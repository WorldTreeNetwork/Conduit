# Project context

Conduit — a Matrix homeserver as an embeddable Rust library, plus a thin
HTTP host. The kernel is Apache-2.0. HTTP is a host, not a layer.

This file is conventions. It is not a requirements store. Requirements live
in `openspec/specs/` (what is built) and `openspec/changes/` (what should
change). Reasoning that is not a requirement lives in `docs/` and
`docs/architecture.md`, and must name a change-id when it implies work.

Issue tracking is **bd** (beads). Beads are the work graph. OpenSpec is
what is true and what should change. `bd ready` is not the OpenSpec
ready-set.

## Where work lands

| Kind of work | Lands in |
|---|---|
| New or changed behavior | `openspec/changes/<verb-led-id>/` |
| Restore intended behavior, typo, pin, comment, test for existing spec | Direct fix. No change. |
| Why the system is shaped this way | `docs/architecture.md` (amend, do not delete) |
| Hard-won fact | `docs/LEARNINGS.md` (create if missing) |
| Work-graph state | beads (`.beads/issues.jsonl`) |

A change is the right landing zone when you can write a `#### Scenario:` that
fails today and passes after.

## Disposition banners

The first non-empty line of `proposal.md` after the title heading is a
banner. Status lives in the file because retrieval strips paths.

```
> **PENDING**
> **ACTIVE BUILD**
> **PARKED** — revive when <condition>
```

Agents draft PENDING. Humans replace it with ACTIVE BUILD (or you are
reading an activation in chat). PARKED is not available work.
