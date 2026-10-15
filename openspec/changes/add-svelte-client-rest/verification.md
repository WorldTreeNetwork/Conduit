# Worker verification

The port is implemented, but the real browser journey is **not verified**.
The task boxes remain open. The conductor owns persistence and final acceptance.

Committed references were read with `git show HEAD:client/src/ui/<name>.tsx`:
Settings, Account, RoomSettings, Media, MemberPanel, Directory, ThreadPanel,
Presence, and ConnectionBanner. The unrelated dirty React files were not copied
or edited. The existing dirty proposal was left intact.

Implemented in `web/`: settings/profile with load retry and save feedback; local
system/day/night theme; session facts; device rename and password-confirmed
removal; password change and account deactivation; soft logout reauthentication;
authenticated image thumbnails/full image and file download; attachment sending;
joined/invited members and roles; sync presence and typing; public directory
search/pagination/join; invite user suggestions; room settings; thread loading,
sending, failed-send retry and local echo; persistent sync line status and a
reconnect banner/countdown/manual retry. The banner is visible on mobile home
as well as in a conversation. Matrix operations use the existing session/core.

Passed:

- `bun run --cwd web check`: zero errors and zero warnings.
- `bun test --cwd web`: 17 passed, 70 assertions.
- `bun run --cwd web build`: static adapter wrote `web/build/`.
- `git diff --check -- web openspec/changes/add-svelte-client-rest`.

Focused acceptance command (with both services running outside this sandbox):

```bash
cd web
CONDUIT_TEST_HS=http://localhost:8008 WEB_BASE_URL=http://localhost:5173 bun tests/rest-journey.ts
```

The focused script registers two unique accounts and asserts profile/theme
persistence, device rename, decoded blob image preview, members, presence from
real sync, public directory join, two-person threads, thread retry with the same
transaction, room settings, reconnect/recovery at the sync transport boundary,
and mobile navigation. It reuses the existing Playwright installation and
cleans up its browser and macOS idle-sleep guard. The CI switch is untouched.

Infrastructure failures observed:

- PostgreSQL via TCP and `/tmp/.s.PGSQL.5432`: `Operation not permitted`.
- Vite dev server at `127.0.0.1:5174`: `listen EPERM`.
- Chromium launch (smoke attempt, then focused journey):
  `bootstrap_check_in org.chromium.Chromium.MachPortRendezvousServer…:
  Permission denied (1100)`; process exits before any journey assertion.

The focused journey therefore returns exit 1 with disposition `infra-red`.
No browser, visual, accessibility, or real-homeserver pass is claimed. An
exploratory direct TypeScript invocation over the standalone journey also could
not resolve the existing pnpm Playwright declarations through the relative
runtime import; journeys are run by Bun, as with the existing web journeys.
