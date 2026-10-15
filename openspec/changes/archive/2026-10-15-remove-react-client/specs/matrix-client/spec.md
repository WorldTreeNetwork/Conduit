## MODIFIED Requirements

### Requirement: Bun proves the client
<!-- base: 4264c4b8f10a5fa6478b2405a039d1ebc02d10fc openspec/specs/matrix-client/spec.md -->

CI SHALL install `web/` with Bun and run the Playwright journeys against a real Conduit homeserver on Chromium, Firefox, and WebKit. Unit tests for the protocol core and the UI helpers SHALL run under Bun.

#### Scenario: The browser suite

- GIVEN the SvelteKit CI job
- WHEN it runs
- THEN Playwright signs in with a password, exchanges a message, and the job is green on all three engines

## REMOVED Requirements

### Requirement: React client remains until the proof is green
<!-- base: 4264c4b8f10a5fa6478b2405a039d1ebc02d10fc openspec/specs/matrix-client/spec.md -->

The React client in `client/` SHALL remain the CI client until the SvelteKit browser proof passes. Removing it SHALL be a separate change.

#### Scenario: Both trees exist

- GIVEN this contract has landed and the proof change has not
- WHEN CI runs
- THEN it still builds the React client

## ADDED Requirements

### Requirement: One client

The repository SHALL contain one first-party UI, the SvelteKit app in `web/`. Docs SHALL tell a person to run it with Bun. The React package SHALL NOT be what CI builds.

#### Scenario: A person follows the docs

- GIVEN the client docs after this change
- WHEN a person follows them
- THEN they start `web/` with Bun and do not install the React package
