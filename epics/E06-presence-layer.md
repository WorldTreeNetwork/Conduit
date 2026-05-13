# E06 — Presence Layer

**Status:** 🔵 Not started
**Implementation guide:** [docs/features/presence-layer.md](../docs/features/presence-layer.md)
**Depends on:** E04
**Blocks:** —

## Scope

The lightweight signals that make Element feel alive: profiles, account
data, typing, receipts, presence. Surface them via `/sync` so clients
see them without polling.

## "Done" looks like

- Element shows displayname + avatar correctly.
- Typing indicators show up for the other user.
- Read receipts render.
- Per-room and global account data round-trips through clients.

## Stories

- [ ] **E06-1**: `GET/PUT /profile/{userId}/displayname`.
- [ ] **E06-2**: `GET/PUT /profile/{userId}/avatar_url`.
- [ ] **E06-3**: Global account data:
      `GET/PUT /user/{}/account_data/{type}`.
- [ ] **E06-4**: Per-room account data:
      `GET/PUT /user/{}/rooms/{}/account_data/{type}`.
- [ ] **E06-5**: Typing: `PUT /rooms/{}/typing/{userId}` + in-memory
      TTL store + EDU emission.
- [ ] **E06-6**: Receipts: `POST /rooms/{}/receipt/m.read/{eventId}`,
      plus `m.read.private` variant.
- [ ] **E06-7**: Presence: `GET/PUT /presence/{userId}/status`.
- [ ] **E06-8**: Emit `m.typing`, `m.receipt`, `m.presence` EDUs in
      `/sync`.

## Open questions

- Federate presence, or local-only? (Most large servers disable
  federation for presence. Recommend: local-only for v0.)

## Risks

- Presence at scale is fanout-heavy. Keep it simple and bounded.
