-- User-Interactive Authentication sessions outlive the process that
-- created them. expires_at is Unix seconds. A restart must still be
-- able to finish the exchange.
CREATE TABLE uia_sessions (
    session_id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    user_id TEXT,
    flows JSONB NOT NULL,
    params JSONB NOT NULL,
    completed JSONB NOT NULL,
    threepid JSONB,
    expires_at BIGINT NOT NULL
);
