## ADDED Requirements

### Requirement: Signed-out screen

The SvelteKit app SHALL serve a signed-out screen from `bun run dev`. The homeserver address SHALL come from the `hs` query parameter, then from the build's homeserver env var, then from `http://localhost:8008`. A pinned `hs` query parameter SHALL hide the field.

#### Scenario: Default local homeserver

- GIVEN the dev server and no query parameter
- WHEN a person opens the signed-out screen
- THEN the homeserver field shows `http://localhost:8008`

#### Scenario: Pinned homeserver

- GIVEN the URL includes `?hs=` set to a homeserver
- WHEN the signed-out screen renders
- THEN the field is hidden and that homeserver is the one the client will call
