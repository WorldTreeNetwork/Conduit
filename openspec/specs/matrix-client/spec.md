## ADDED Requirements

### Requirement: Static SvelteKit client

The first-party UI SHALL be a SvelteKit application in `web/`, installed and run with Bun, and built as a static single-page app. It SHALL NOT ship an application server. The homeserver SHALL remain the only backend the client calls.

#### Scenario: Local development

- GIVEN a migrated Conduit homeserver
- WHEN a person runs the client with Bun
- THEN a browser can open the signed-out screen and point it at that homeserver

#### Scenario: Production files

- GIVEN a production build of `web/`
- WHEN those files are served as static assets
- THEN the signed-out shell loads and the client calls the homeserver directly with a bearer token

### Requirement: Type

The client SHALL set titles in Bricolage Grotesque at width 100 (`wdth` 100) and a semibold weight, and body text in Atkinson Hyperlegible Next. Numerals SHALL use the body face's tabular figures. All shipped faces SHALL be self-hosted, with no third-party font CDN. Tactic Sans SHALL NOT be shipped: the files on hand are marked personal use only, which is not a web-embedding license.

#### Scenario: A room title

- GIVEN a signed-in client showing a room name
- WHEN the title is rendered
- THEN it uses Bricolage Grotesque at width 100

#### Scenario: A count

- GIVEN an unread count
- WHEN it is rendered
- THEN the digits are tabular figures of the body face

### Requirement: Component base

The client SHALL use shadcn-svelte primitives for button, input, dialog, scroll area, dropdown menu, and avatar. Timeline, room list, and message layout SHALL be custom. Color SHALL start from the existing ground, ink, and brass palette.

#### Scenario: A dialog

- GIVEN a person opens create-room or join-room
- WHEN the dialog renders
- THEN its frame, field, and buttons are shadcn-svelte primitives, and the timeline behind it is not

### Requirement: Identikey sign-in

The client SHALL offer Identikey only when `GET /_matrix/client/v3/login` lists `m.login.sso`. Choosing it SHALL follow the homeserver SSO redirect. The OIDC client secret SHALL remain on the homeserver. Before leaving, the client SHALL write a pending-SSO record in `sessionStorage` naming the homeserver it is about to leave for, and SHALL include that same homeserver on `redirectUrl`. On return, the client SHALL remove `loginToken` from the address bar with `history.replaceState` before it renders. It SHALL spend that token once through `m.login.token` only when the pending record exists and its homeserver equals the `hs` on the return URL. If the record is missing, the homeservers differ, or the return has no `hs`, the client SHALL strip the token, SHALL NOT call any homeserver, and SHALL show the signed-out screen. An expired or reused token SHALL return to the signed-out screen with a retry. The password form SHALL always be available. It SHALL be the primary action when `m.login.sso` is absent, and a secondary action when Identikey is offered.

#### Scenario: Continue with Identikey

- GIVEN a homeserver whose login flows list `m.login.sso`
- WHEN a person chooses Identikey
- THEN the browser follows the homeserver SSO redirect and returns with a Matrix session on that same homeserver

#### Scenario: The token is spent once

- GIVEN the browser returns with `loginToken` in the query
- WHEN the signed-out screen loads
- THEN `loginToken` is already gone from the address bar, the client has called `m.login.token` once, and a second visit with the same token stays on the signed-out screen with a retry

#### Scenario: A homeserver without SSO

- GIVEN `GET /login` does not list `m.login.sso`
- WHEN the signed-out screen renders
- THEN there is no Identikey button and the password form is the way to sign in

#### Scenario: Secret stays off the client

- GIVEN the built client assets
- WHEN they are inspected
- THEN they do not contain the OIDC client secret

#### Scenario: The suite proves the return leg without the hosted provider

- GIVEN a test homeserver and a browser tab whose `sessionStorage` already holds a pending-SSO record for that homeserver
- WHEN the suite mints a login token with `POST /_matrix/client/v1/login/get_token` and opens the client with `?hs=` for that homeserver and `loginToken`
- THEN the signed-in shell appears, the token is gone from the location, and opening the same token again is refused

#### Scenario: A token this tab did not request is not spent

- GIVEN a fresh tab with no pending-SSO record
- WHEN it is opened with `?hs=` and `loginToken`
- THEN the token is removed from the address bar, no login request is sent, and the signed-out screen is shown

#### Scenario: A test account uses a password

- GIVEN the automated browser suite
- WHEN it registers a user
- THEN it completes `m.login.password` or registration UIA without calling the hosted Identikey provider

### Requirement: React client remains until the proof is green

The React client in `client/` SHALL remain the CI client until the SvelteKit browser proof passes. Removing it SHALL be a separate change.

#### Scenario: Both trees exist

- GIVEN this contract has landed and the proof change has not
- WHEN CI runs
- THEN it still builds the React client

### Requirement: Protocol core stays framework-free

The Matrix protocol core SHALL stay free of UI-framework imports. The SvelteKit app SHALL use that core rather than matrix-js-sdk.

#### Scenario: Core imports

- GIVEN the protocol core sources
- WHEN they are checked for a UI-framework import
- THEN none is present

### Requirement: Accessibility and the test hook

The client SHALL meet WCAG 2.2 AA for contrast, keyboard use, and focus. An automated axe check SHALL report zero serious violations. The `window.__conduitClient` test hook SHALL be installed only in a dev build or when the build sets the test-hook flag. A production bundle SHALL NOT install it.

#### Scenario: A production bundle

- GIVEN a production build
- WHEN the signed-out screen loads
- THEN `window.__conduitClient` is absent

#### Scenario: Keyboard and contrast

- GIVEN the signed-in shell
- WHEN axe runs against it
- THEN there are no serious violations

### Requirement: One token source

shadcn-svelte MAY bring Tailwind. Tailwind's theme SHALL be generated from the same CSS variables the custom timeline uses. Those variables SHALL be the only color source.

#### Scenario: A brass button and a custom message

- GIVEN the signed-in shell
- WHEN a primary button and a message are both on screen
- THEN both take their brass and ink from the same CSS variables

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

### Requirement: A person can open and close a session

The signed-in shell SHALL appear after Identikey SSO returns a Matrix access token, and after a password login. Sign out SHALL remove that session. A reload SHALL restore a session that was not signed out, and SHALL NOT restore one that was.

#### Scenario: Identikey returns a session

- GIVEN the homeserver Identikey SSO flow completes
- WHEN the browser returns to the client
- THEN the person is signed in and the shell shows their display name

#### Scenario: Sign out

- GIVEN a signed-in session
- WHEN the person signs out
- THEN the signed-out screen is shown and a reload does not restore the session

#### Scenario: Password test account

- GIVEN the automated suite
- WHEN it registers and signs in with a password
- THEN it reaches the signed-in shell without the hosted Identikey provider

### Requirement: Two people can talk

A signed-in person SHALL create a room, invite another person, and exchange messages. The timeline SHALL show an unsent message with a retry. The room list SHALL show joined rooms. A route that points at a room the person is no longer in SHALL return home.

#### Scenario: Create, invite, and send

- GIVEN two signed-in accounts on one homeserver
- WHEN the first creates a room, invites the second, and sends a message
- THEN both timelines show that message

#### Scenario: A failed send can be retried

- GIVEN a message the homeserver did not accept
- WHEN the sender retries it from the timeline
- THEN the message is sent and the failure state clears

#### Scenario: A left room is not a destination

- GIVEN the person has left a room
- WHEN they open a hash that names that room
- THEN the shell shows home and the room is not in the list
