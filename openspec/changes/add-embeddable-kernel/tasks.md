# Tasks

- [x] Amend `docs/architecture.md`: two crates; kernel owns persist; host supplies Storage/keys/name; `RoomEventSender` inversion named as `add-library-ops` debt; errcode on `conduit::Error`; Homeserver split table; tokio-hosted; v11-only in kernel; iroh may pull `http`/`reqwest` transitively, `axum` never.
- [ ] Add living capability file via fold of this delta (`embeddable-kernel`).
- [x] CI/check: `cargo tree -p conduit` and `cargo tree -p conduit --features iroh` contain no `axum`. Document that `http`/`reqwest` are iroh-only.
- [x] Reject non-v11 `room_version` at create **and inbound** with a typed kernel error; host maps it.
- [ ] Matrix `errcode` on `conduit::Error` (accessor or variant payload) carrying at least `M_FORBIDDEN`, `M_NOT_FOUND`, `M_UNSUPPORTED_ROOM_VERSION`; host maps errcode → status. The v11 reject in the previous box is the first carrier. (Added by fable-5.1-arch-review advise2: delta requirement had no task.)

Out of scope (bullets): moving the event pipeline (`add-library-ops`); Pdu split; in-process Client body; postgres crate split (`conduit-6jr`).

Send-back (fable-5.1-arch-review) — spec/ADR text amended this wave:

- [x] S1: reword delta "Kernel has no HTTP types" to the public-API form; `axum` never in `cargo tree -p conduit`, `http`/`reqwest` tolerated only behind `iroh`.
- [x] S2: reword "Host is replaceable" to crate-graph truth at HEAD; in-process scenario belongs to `add-in-process-client`.
- [x] S3: ADR + delta state kernel owns persist; host-side `RoomEventSender` is `add-library-ops` debt.
- [x] ADR: Matrix `errcode` lives on `conduit::Error`.
- [x] Task 4 covers inbound room_version.
- [x] ADR: Homeserver split table.
- [x] ADR: embeddable means tokio-hosted.
