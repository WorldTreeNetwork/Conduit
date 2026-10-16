# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->


## Build & Test

```bash
# Build everything
cargo build --workspace

# With iroh transport compiled in (~30MB heavier)
cargo build --workspace --features conduit-server/iroh

# Run the server (Postgres required; see AGENTS.md → Database Conventions)
# Reads .env from the working directory or a parent. Shell vars win.
createdb conduit                                                   # once
cargo run -p conduit-server                                        # :8008

# Verify endpoints
curl localhost:8008/health
curl localhost:8008/_matrix/client/versions

# Test (when there are tests)
cargo test --workspace

# Web client (web/, Bun; see docs/features/client.md)
cd web && bun install
bun run check       # svelte-check
bun run test        # protocol core and UI helper unit tests
bun run build       # static files in build/
bun run e2e         # Playwright vs real conduit-server + fresh Postgres (DATABASE_URL admin)
bun run dev         # http://localhost:5173/?hs=http://127.0.0.1:8008
```

The default web build signs in with Identikey only. Password fields,
password change, other-device sign-out, and deactivation appear when
`VITE_CONDUIT_PASSWORD` is `1`, `true`, `on`, or `yes`. The protocol core
still speaks `m.login.password`. When the homeserver does not list
`m.login.sso` and password sign-in is off, the page says Identikey sign-in
is turned off and how to proceed. It does not describe a wallet sign-in it
does not perform.

## Architecture Overview

Two Rust crates: `conduit` (Matrix kernel) and `conduit-server` (axum
host, Postgres, Identikey as the OIDC relying party). The first-party UI
is `web/`, a static SvelteKit SPA run with Bun. See
[docs/architecture.md](docs/architecture.md) and
[docs/features/client.md](docs/features/client.md).

## Conventions & Patterns

See [AGENTS.md](AGENTS.md). Shared rules for all agents (Claude or
otherwise) live there:

- Database conventions (Postgres + sqlx, migration rules, schema
  taste, storage layout)
- Non-interactive shell command forms
- Beads workflow + session-completion protocol

For implementation guidance on Matrix features, see
[docs/](docs/) — one focused doc per feature module.

## Intention

Work loop: intend → steer → change → advise → act → fold.
Tracker is beads (`bd`; DAG nodes are `--type node`). Living specs are
`openspec/specs/`; in-flight work is `openspec/changes/`. Read
[`openspec/AGENTS.md`](openspec/AGENTS.md) before changing behavior.
