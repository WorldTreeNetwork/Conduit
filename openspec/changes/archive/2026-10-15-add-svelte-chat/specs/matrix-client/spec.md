## ADDED Requirements

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
