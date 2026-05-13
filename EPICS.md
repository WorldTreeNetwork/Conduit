# Epics

The work plan for Conduit. Each epic is an iterable chunk: it produces
a testable milestone, and later epics build on earlier ones.

For the *how* (implementation guidance per feature), see [docs/](docs/).
This file and `epics/` are the *what & when* — work tracking, not
technical explanation.

## Status legend

- 🔵 **Not started**
- 🟡 **In progress**
- 🟢 **Done**
- ⏸️ **Blocked**

## Milestones

Three big user-visible 🚦 checkpoints:

- **E04** — first usable local server (two clients can chat)
- **E09** — federation works (remote users can join)
- **E10** — E2EE works (cross-server encrypted chat)

## The plan

| # | Epic | Status | Depends on |
|---|------|--------|------------|
| [E01](epics/E01-storage.md) | Storage foundation | 🔵 | — |
| [E02](epics/E02-events-and-signing.md) | Events & signing | 🔵 | E01 |
| [E03](epics/E03-auth-and-state.md) | Auth rules & state machine | 🔵 | E02 |
| [E04](epics/E04-local-chat-mvp.md) | 🚦 Local chat MVP | 🔵 | E03 |
| [E05](epics/E05-state-resolution.md) | State Resolution v2 | 🔵 | E03 |
| [E06](epics/E06-presence-layer.md) | Presence layer | 🔵 | E04 |
| [E07](epics/E07-media.md) | Media repository | 🔵 | E04 |
| [E08](epics/E08-federation-outbound.md) | Federation: outbound | 🔵 | E02 |
| [E09](epics/E09-federation-inbound.md) | 🚦 Federation: inbound | 🔵 | E05, E08 |
| [E10](epics/E10-e2ee.md) | 🚦 E2EE infrastructure | 🔵 | E09 |
| [E11](epics/E11-push-as-admin.md) | Push + AS + admin | 🔵 | E04 |
| [E12](epics/E12-iroh-transport.md) | Iroh experimental transport | 🔵 | E09 |

## Workflow

- To update status: edit both this table and the epic file's status line.
- Stories inside each epic use `- [ ]` / `- [x]` task syntax.
- New work outside the planned epics goes in a new epic file; don't
  let it accrete inside an existing one.
