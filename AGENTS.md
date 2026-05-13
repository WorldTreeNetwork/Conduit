# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd prime` for full workflow context.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data to remote
```

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

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

## Database Conventions

This project uses **PostgreSQL** as the primary store, accessed via
**sqlx** (async, compile-time-checked SQL).

### Migrations

Migrations live in `conduit-server/migrations/` as numbered up-only
SQL files: `0001_initial.sql`, `0002_add_pushers.sql`, ... Applied on
startup via `sqlx::migrate!().run(&pool).await?`. State tracked in the
`_sqlx_migrations` table.

**Rules — not optional:**

- **No down migrations.** Forward-fix only. If `0041` was wrong, write
  `0042_fix_0041.sql`. Down migrations on production-scale event
  tables are a footgun; we don't keep the option open.
- **One file = one transaction.** sqlx wraps each migration in
  `BEGIN/COMMIT`. Either the whole thing lands or none of it does.
- **No `IF NOT EXISTS` in migrations.** A migration should fail loudly
  on re-run. If state tracking is broken, we want to know now.

### Schema conventions

- Token-shaped credentials (access tokens, AS tokens, push secrets)
  are stored **hashed**. Raw values live only in client headers.
- Monotonic columns used as stream cursors get a **BRIN** index
  (e.g. `events.stream_position`).
- Sparse columns get **partial indexes** (e.g. `events.state_key` —
  most events are not state events).
- Opaque client-controlled JSON (event content, account_data) goes in
  **`jsonb`**, not `json` or `text`.
- Denormalize aggressively where the access pattern is point-lookup
  for state (`room_current_state` is the canonical example).

### Storage layout

The pure `conduit` library exposes a `Storage` trait — backends live
elsewhere. The PG impl + migrations currently live in `conduit-server`.
A future split into a dedicated `conduit-storage-postgres` crate is
filed in bd but deferred until there's a second `Storage` implementor.
