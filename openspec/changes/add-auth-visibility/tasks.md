# Tasks

- [x] Add `identikey-auth` (identikey-protocol) and `biscuit-auth` to the `conduit` crate. Do not add identikey-core crates.
- [x] Persist a Biscuit minter Ed25519 key (distinct from the Matrix server signing key). Load-or-generate on boot.
- [x] Mint a root Biscuit at password login / register: facts `user`, `device`, `server`, `epoch`, `right("cs")`; TTL check. Return the token as URL-safe base64 (accept optional `biscuit:` prefix on the way in).
- [x] Replace `hash_token` / `lookup_token` as the request-path source of truth with Biscuit verify (authority chain + Datalog). Store device epoch; logout and device revoke bump epoch.
- [x] identikey-auth login: issue `Challenge` (audience = server_name), verify `Response`, map fingerprint → MXID, mint Biscuit. Typed library API; HTTP host maps it.
- [ ] Optional host-only OIDC: if `CONDUIT_OIDC_ISSUER` (identikey-core or any OP) is set, validate the OP token and mint a Conduit Biscuit. No AGPL dep.
- [x] `may_read_room` in `conduit`; CS GET state / state event / joined_members / messages call it. Unused `_authed` gone.
- [x] Wire `can_see` into `/messages` and `/sync` with a real `UserEventPosition` from membership history.
- [x] Restricted / knock_restricted: fail closed when `allow` names another room. Remove the false-green unit test.
- [x] Federation backfill and get_missing_events use visibility against the origin server, not always-true.
- [x] Tests in `conduit`: mint/verify/expire/epoch-bump; attenuate cannot widen; password and identikey-auth on-ramps; membership denial; `can_see` on a joined-only room; restricted fail-closed.

Not done in this landing:

- **OIDC on-ramp.** The delta only requires that an unconfigured host
  reject an identikey-core JWT, which it does — such a token is not a
  Biscuit and fails verification. The configured path (issuer, JWKS,
  introspection) is not built, so the box stays unchecked.

Out of scope (bullets, not boxes): Recrypt; identikey-core as a crate; holder-bound §7 proofs; full cross-room restricted joins; opaque-token migration; `add-library-ops` / `add-in-process-client`.
