## ADDED Requirements

### Requirement: The rest of the current client

The SvelteKit app SHALL cover the remaining surfaces of the current client: settings and display name, image preview, member list, directory, threads, presence, and the reconnect banner. It SHALL NOT add a Matrix feature the current client does not have.

#### Scenario: The connection drops

- GIVEN a signed-in client whose homeserver stops answering
- WHEN sync fails
- THEN a banner says the client is disconnected, and sync resumes when the homeserver answers again

#### Scenario: An image in the timeline

- GIVEN a room with an image message
- WHEN the person opens that room
- THEN the timeline shows a preview of the image
