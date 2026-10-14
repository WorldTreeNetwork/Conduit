-- Purging the latest event must not move a client's global stream backwards.
CREATE TABLE retired_event_positions (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    position BIGINT NOT NULL
);
INSERT INTO retired_event_positions (singleton, position) VALUES (true, 0);
CREATE INDEX retired_event_positions_brin ON retired_event_positions USING BRIN (position);
