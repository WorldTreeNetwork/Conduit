## ADDED Requirements

### Requirement: Bun proves the client

CI SHALL install `web/` with Bun and run the Playwright journeys against a real Conduit homeserver on Chromium, Firefox, and WebKit. Unit tests for the protocol core and the UI helpers SHALL run under Bun. The React CI job SHALL stay until the remove change lands.

#### Scenario: The browser suite

- GIVEN the SvelteKit CI job
- WHEN it runs
- THEN Playwright signs in with a password, exchanges a message, and the job is green on all three engines
