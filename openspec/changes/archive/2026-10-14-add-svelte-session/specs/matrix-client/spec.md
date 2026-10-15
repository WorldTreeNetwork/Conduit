## ADDED Requirements

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
