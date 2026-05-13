# E12 — Iroh Experimental Transport

**Status:** 🔵 Not started
**Implementation guide:** [docs/features/iroh-transport.md](../docs/features/iroh-transport.md)
**Depends on:** E09
**Blocks:** —

## Scope

Carry federation traffic over [iroh](https://docs.rs/iroh) (QUIC + NAT
traversal + relay network) in addition to / instead of HTTPS. Off by
default behind Cargo feature `iroh`.

This is a Conduit-specific extension — not part of the Matrix spec.
Two peers must both opt in.

## "Done" looks like

- Two Conduit instances behind NAT, both built `--features iroh`,
  federate purely over iroh — no public DNS, no public IPs, no
  managed TLS cert.
- Existing HTTPS federation still works for non-iroh peers.

## Stories

- [ ] **E12-1**: Add the `iroh` crate as an optional dep; flip the
      feature in `Cargo.toml` to `iroh = ["dep:iroh"]`.
- [ ] **E12-2**: Real `iroh::Endpoint` bound at startup.
- [ ] **E12-3**: Derive iroh node ID from the server signing key
      (so federation identity = transport identity).
- [ ] **E12-4**: Custom well-known entry advertising the iroh node
      ID alongside the server name.
- [ ] **E12-5**: Outbound: send `/send/{txnId}` over QUIC streams to
      iroh-known peers.
- [ ] **E12-6**: Inbound: accept iroh streams, dispatch into the same
      federation handlers as HTTPS-arriving requests.
- [ ] **E12-7**: HTTPS fallback negotiation: if a peer doesn't
      advertise iroh, use classic federation.
- [ ] **E12-8**: Integration test: two Conduit nodes peer over iroh.

## Open questions

- Should iroh replace HTTPS entirely for peers that support it, or
  always run both in parallel? (Recommend: prefer iroh if both
  endpoints have it; fall back to HTTPS.)

## Risks

- Experimental. Don't ship as the only transport.
- Iroh node ID must be cryptographically tied to the signing key, or
  the federation auth model gets a confused-deputy problem.
- Binary size +30MB; some operators won't tolerate it.
