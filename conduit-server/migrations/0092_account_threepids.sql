-- Homeserver-validated contact addresses (client-server 3PID add) and
-- the validation sessions that prove them. Identity-server bindings
-- stay in threepid_id_server_bindings.

CREATE TABLE threepid_validation_sessions (
    sid           TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    medium        TEXT NOT NULL,
    address       TEXT NOT NULL,
    purpose       TEXT NOT NULL,
    send_attempt  INTEGER NOT NULL,
    token_hash    TEXT NOT NULL,
    validated_at  BIGINT,
    created_at    BIGINT NOT NULL
);

CREATE UNIQUE INDEX threepid_validation_client
    ON threepid_validation_sessions (medium, address, client_secret);

CREATE TABLE account_threepids (
    medium       TEXT NOT NULL,
    address      TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    added_at     BIGINT NOT NULL,
    validated_at BIGINT NOT NULL,
    PRIMARY KEY (medium, address)
);

CREATE INDEX account_threepids_user ON account_threepids (user_id);
