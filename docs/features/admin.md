# Admin API

**Spec reference:** none — homeserver-specific (Synapse defined the de-facto shape)
**Default:** on
**Depends on:** [`client-server-api`](client-server-api.md)

## What this is

Endpoints for the server operator: list users, suspend accounts,
purge media, force-leave rooms, manage federation, inspect health.

There is no Matrix-wide spec for admin APIs. Synapse's admin API is
the de-facto reference; Conduit and continuwuity expose a smaller
surface focused on operator essentials.

## What the homeserver needs to do

- Authenticate admin calls — typically a separate role or capability
  on a normal account (`admin: true`), checked against the access
  token.
- Expose listing and mutation endpoints for the core entities: users,
  rooms, media, federation peers.
- Be careful about destructive operations — most admin actions are
  irreversible.

## Recommended endpoint shape

Conduit's predecessors used a chat-command interface (`!admin` in a
private room) on top of normal sending. That's nicer than HTTP for
ops use and easier to authenticate. Choose one:

- HTTP under `/_matrix/admin/...` — easy to automate.
- Chat commands in a private admin room — easy to use ad hoc.

Both work; many servers offer both.

## Useful operations

| Area         | Operations                                                       |
|--------------|------------------------------------------------------------------|
| Users        | List, deactivate, reset password, promote to admin.              |
| Rooms        | List, force purge (delete events + state), force leave.          |
| Media        | List by user, delete by media ID, quota check.                   |
| Federation   | List peers, disable specific destinations.                       |
| Server       | Refresh keys, rotate signing key, hot-reload config.             |

## Implementation approach

1. Reuse CS-API auth — admin is a flag on the account, not a parallel
   credential system.
2. For destructive operations, require a confirmation token or a
   second roundtrip ("really?").
3. Log every admin call. Operators benefit; auditors require.

## Gotchas

- Account deactivation is partial — Matrix accounts can't be fully
  deleted because their events live in rooms federated to other
  servers. "Deactivate" means "disable login + scrub profile";
  past events stay.
- Force-leave on a federated room only affects local participation.
  The room continues to exist on other servers.
- "Purge" of a room is an irreversible local action. Have a "are you
  sure" gate.
