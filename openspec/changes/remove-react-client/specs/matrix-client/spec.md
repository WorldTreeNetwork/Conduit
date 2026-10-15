## ADDED Requirements

### Requirement: One client

The repository SHALL contain one first-party UI, the SvelteKit app in `web/`. Docs SHALL tell a person to run it with Bun. The React package SHALL NOT be what CI builds.

#### Scenario: A person follows the docs

- GIVEN the client docs after this change
- WHEN a person follows them
- THEN they start `web/` with Bun and do not install the React package
