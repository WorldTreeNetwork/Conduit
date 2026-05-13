-- 0003_presence.sql
--
-- E06 — Presence Layer: profile fields, account data, and receipts.
-- Typing and presence are in-memory only (ephemeral, TTL-based).

-- Profile fields on accounts.
ALTER TABLE accounts
    ADD COLUMN displayname TEXT,
    ADD COLUMN avatar_url  TEXT;

-- Account data: per-user (room_id IS NULL) and per-room.
CREATE TABLE account_data (
    user_id            TEXT NOT NULL,
    room_id            TEXT,                  -- NULL for global
    event_type         TEXT NOT NULL,
    content            JSONB NOT NULL,
    stream_pos         BIGSERIAL UNIQUE,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX account_data_global_pk
    ON account_data (user_id, event_type) WHERE room_id IS NULL;
CREATE UNIQUE INDEX account_data_per_room_pk
    ON account_data (user_id, room_id, event_type) WHERE room_id IS NOT NULL;

-- Read receipts.
CREATE TABLE receipts (
    room_id      TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    receipt_type TEXT NOT NULL,                -- "m.read", "m.read.private"
    event_id     TEXT NOT NULL,
    ts           BIGINT NOT NULL,              -- unix-ms when sent
    stream_pos   BIGSERIAL UNIQUE,
    PRIMARY KEY (room_id, user_id, receipt_type)
);
