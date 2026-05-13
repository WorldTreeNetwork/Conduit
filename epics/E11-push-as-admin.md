# E11 — Push + Application Services + Admin

**Status:** 🔵 Not started
**Implementation guides:**
[push](../docs/features/push.md) ·
[app-services](../docs/features/app-services.md) ·
[admin](../docs/features/admin.md)
**Depends on:** E04
**Blocks:** —

## Scope

Three loosely-related but each-fairly-independent feature areas that
together turn a working chat server into something operable. Push so
phones ring; AS so bridges work; admin so the operator can manage.

## "Done" looks like

- A pusher delivers a notification to a phone via a push gateway.
- An application service (e.g. a bridge) connects and relays messages.
- An operator can list, suspend, and deactivate users; force-purge
  rooms; manage media.

## Stories

### Push

- [ ] **E11-P1**: `POST /_matrix/client/v3/pushers/set` + listing.
- [ ] **E11-P2**: Push rules storage + edit endpoints
      (`/pushrules/...`).
- [ ] **E11-P3**: Default push rules per spec.
- [ ] **E11-P4**: Rule evaluator (`event_match`,
      `room_member_count`, `sender_notification_permission`).
- [ ] **E11-P5**: Notification queue + gateway POSTer.
- [ ] **E11-P6**: Notification counts in `/sync`.

### Application services

- [ ] **E11-AS1**: AS registration loading from config
      (`registration.yaml`).
- [ ] **E11-AS2**: Namespace enforcement (users, aliases, rooms).
- [ ] **E11-AS3**: AS-authenticated CS-API calls (`as_token` +
      `?user_id=`).
- [ ] **E11-AS4**: Ghost user auto-creation on first send.
- [ ] **E11-AS5**: AS transaction pusher (
      `PUT /transactions/{txnId}` to AS).
- [ ] **E11-AS6**: AS query endpoints (`/users/{}`, `/rooms/{}`).
- [ ] **E11-AS7**: Per-AS retry queue.

### Admin

- [ ] **E11-AD1**: Admin role flag on accounts.
- [ ] **E11-AD2**: User management (list, deactivate, reset password,
      promote).
- [ ] **E11-AD3**: Room management (list, force purge, force leave).
- [ ] **E11-AD4**: Media management (list, delete, quota).
- [ ] **E11-AD5**: Federation management (list peers, disable
      destination).
- [ ] **E11-AD6**: Audit log of admin calls.

## Open questions

- HTTP admin under `/_matrix/admin/...` vs chat-command admin in a
  private room? Both are fine; pick one for v0.

## Risks

- Push rule evaluator burns CPU on busy rooms. Compile rules per user
  and cache.
- AS tokens are bridge-keys-to-the-kingdom. Treat as secret.
- "Account deactivation" is misleading — federated events persist
  on other servers. Document the user-facing semantics carefully.
