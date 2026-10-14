CREATE TABLE client_filters (
    user_id TEXT NOT NULL,
    filter_id TEXT NOT NULL,
    definition JSONB NOT NULL,
    PRIMARY KEY (user_id, filter_id)
);
