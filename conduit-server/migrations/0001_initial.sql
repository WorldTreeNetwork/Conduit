-- 0001_initial.sql
--
-- Initial schema for the Conduit Matrix homeserver.
-- See AGENTS.md → "Database Conventions" for the rules behind these
-- choices (no IF NOT EXISTS, no down migrations, etc).

-- The PDU log. Append-only. The hot table.
CREATE TABLE events (
    event_id          TEXT        PRIMARY KEY,
    room_id           TEXT        NOT NULL,
    sender            TEXT        NOT NULL,
    type              TEXT        NOT NULL,
    state_key         TEXT,
    content           JSONB       NOT NULL,
    auth_events       TEXT[]      NOT NULL,
    prev_events       TEXT[]      NOT NULL,
    signatures        JSONB       NOT NULL,
    hashes            JSONB       NOT NULL,
    unsigned          JSONB,
    origin_server_ts  BIGINT      NOT NULL,
    depth             BIGINT      NOT NULL,
    stream_position   BIGSERIAL   UNIQUE,
    received_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX events_room_stream    ON events (room_id, stream_position);
CREATE INDEX events_room_depth     ON events (room_id, depth);
CREATE INDEX events_stream_brin    ON events USING BRIN (stream_position);
CREATE INDEX events_state_partial  ON events (room_id, type, state_key)
    WHERE state_key IS NOT NULL;

-- Denormalized current state per room. Updated eagerly when a state
-- event is inserted.
CREATE TABLE room_current_state (
    room_id    TEXT NOT NULL,
    type       TEXT NOT NULL,
    state_key  TEXT NOT NULL,
    event_id   TEXT NOT NULL REFERENCES events(event_id),
    PRIMARY KEY (room_id, type, state_key)
);

CREATE TABLE accounts (
    user_id        TEXT         PRIMARY KEY,
    password_hash  TEXT,
    is_admin       BOOLEAN      NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deactivated_at TIMESTAMPTZ
);

CREATE TABLE devices (
    user_id       TEXT    NOT NULL REFERENCES accounts(user_id),
    device_id     TEXT    NOT NULL,
    display_name  TEXT,
    last_seen_ts  BIGINT,
    last_seen_ip  INET,
    PRIMARY KEY (user_id, device_id)
);

-- Bearer tokens stored as hashes. Raw values only ever live in
-- client Authorization headers.
CREATE TABLE access_tokens (
    token_hash  TEXT         PRIMARY KEY,
    user_id     TEXT         NOT NULL,
    device_id   TEXT         NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id)
);

CREATE TABLE server_signing_keys (
    key_id          TEXT         PRIMARY KEY,
    private_key     BYTEA        NOT NULL,
    public_key      BYTEA        NOT NULL,
    valid_until_ts  BIGINT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
