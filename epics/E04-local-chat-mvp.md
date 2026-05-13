# E04 — 🚦 Local Chat MVP

**Status:** 🔵 Not started
**Implementation guide:** [docs/features/client-server-api.md](../docs/features/client-server-api.md)
**Depends on:** E03
**Blocks:** E06, E07, E11

## Scope

The first user-facing milestone. Implement enough Client-Server API to
let two Element clients on this server register, create a room, and
exchange messages. No federation, no E2EE, no media yet.

## "Done" looks like

- Two browser Element clients connect to `conduit-server`, register
  accounts, create a room together, and chat.
- `/sync` long-polls correctly and ships deltas.

## Stories

### Identity & auth

- [ ] **E04-1**: `POST /_matrix/client/v3/register` (password flow).
- [ ] **E04-2**: `POST /_matrix/client/v3/login` (password).
- [ ] **E04-3**: `POST /_matrix/client/v3/logout`.
- [ ] **E04-4**: `GET /_matrix/client/v3/account/whoami`.
- [ ] **E04-5**: Access token issuance + lookup (hash before storing).
- [ ] **E04-6**: UIA state machine for sensitive flows.

### Rooms

- [ ] **E04-7**: `POST /_matrix/client/v3/createRoom` (bundle initial
      state events as a coherent snapshot).
- [ ] **E04-8**: `POST /join/{roomIdOrAlias}` (local rooms only).
- [ ] **E04-9**: Membership ops: `/leave`, `/kick`, `/ban`,
      `/unban`, `/invite`.
- [ ] **E04-10**: `PUT /rooms/{}/send/{type}/{txnId}` (with
      idempotency via txn cache).
- [ ] **E04-11**: `PUT /rooms/{}/state/{type}/{stateKey}`.
- [ ] **E04-12**: `GET /rooms/{}/state`, `/joined_members`.
- [ ] **E04-13**: `GET /rooms/{}/messages` (timeline pagination,
      tokens).

### Sync

- [ ] **E04-14**: `GET /sync` v0 — full sync without filters.
- [ ] **E04-15**: `/sync` long-poll with `since` + `timeout`.
- [ ] **E04-16**: `/sync` filters (room, event, lazy load members).
- [ ] **E04-17**: Stream-position token format that encodes positions
      across all streams.

### Verification

- [ ] **E04-18**: End-to-end test: register two accounts, join a
      room, send + receive a message.
- [ ] **E04-19**: Bring up Element web; complete the flow manually.

## Open questions

- Lazy-load members in `/sync` from day one, or fix later? (Element
  is very slow without it on rooms > a few hundred members.)

## Risks

- `/sync` is the single hardest endpoint in the spec. Underestimating
  it is a classic mistake. Build it small and grow.
