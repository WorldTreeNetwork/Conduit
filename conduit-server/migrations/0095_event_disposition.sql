-- Rejected and soft-failed federation PDUs stay in the DAG without
-- becoming current state. `kind` is `rejected` or `soft_failed`.
CREATE TABLE event_disposition (
    event_id TEXT PRIMARY KEY REFERENCES events (event_id),
    kind     TEXT NOT NULL
);
