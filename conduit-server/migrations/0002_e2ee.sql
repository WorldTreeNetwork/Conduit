-- 0002_e2ee.sql
--
-- E2EE Infrastructure: device keys, OTKs, fallback keys, cross-signing,
-- to-device queue, device list change log, and room key backup.

-- Device identity keys (curve25519 + ed25519) per device.
CREATE TABLE device_keys (
    user_id    TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    keys       JSONB NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

-- One-time keys: per (user_id, device_id, key_id). Consumed exactly once.
CREATE TABLE one_time_keys (
    user_id     TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    key_id      TEXT NOT NULL,
    algorithm   TEXT NOT NULL,
    key_json    JSONB NOT NULL,
    PRIMARY KEY (user_id, device_id, key_id)
);

-- Fallback keys: single-slot per (user_id, device_id, algorithm). Replaceable.
CREATE TABLE fallback_keys (
    user_id     TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    algorithm   TEXT NOT NULL,
    key_id      TEXT NOT NULL,
    key_json    JSONB NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (user_id, device_id, algorithm)
);

-- Cross-signing keys (master / self_signing / user_signing) per user.
CREATE TABLE cross_signing_keys (
    user_id     TEXT NOT NULL,
    key_type    TEXT NOT NULL,
    key_json    JSONB NOT NULL,
    PRIMARY KEY (user_id, key_type)
);

-- Signatures linking cross-signing keys + device keys.
CREATE TABLE cross_signing_signatures (
    signer_user_id   TEXT NOT NULL,
    signer_key_id    TEXT NOT NULL,
    target_user_id   TEXT NOT NULL,
    target_key_id    TEXT NOT NULL,
    signature        TEXT NOT NULL,
    PRIMARY KEY (signer_user_id, signer_key_id, target_user_id, target_key_id)
);

-- Pending to-device messages awaiting delivery via /sync.
CREATE TABLE to_device_queue (
    id              BIGSERIAL PRIMARY KEY,
    target_user     TEXT NOT NULL,
    target_device   TEXT NOT NULL,
    sender          TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    content         JSONB NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX to_device_queue_target ON to_device_queue (target_user, target_device, id);

-- Device list change log for /keys/changes deltas + sync.
-- Uses its own BIGSERIAL as the stream cursor (independent from events.stream_position).
-- Clients track this via the "d{pos}" part of the combined sync token "s{e}_d{d}".
CREATE TABLE device_list_changes (
    id              BIGSERIAL PRIMARY KEY,
    user_id         TEXT NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX device_list_changes_user ON device_list_changes (user_id, id);

-- Room-key server-side backup (mrm.13).
CREATE TABLE room_keys_backup (
    user_id     TEXT NOT NULL,
    version     TEXT NOT NULL,
    room_id     TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    key_data    JSONB NOT NULL,
    PRIMARY KEY (user_id, version, room_id, session_id)
);

CREATE TABLE room_keys_versions (
    user_id      TEXT NOT NULL,
    version      TEXT NOT NULL,
    algorithm    TEXT NOT NULL,
    auth_data    JSONB NOT NULL,
    count        BIGINT NOT NULL DEFAULT 0,
    etag         TEXT NOT NULL,
    deleted      BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (user_id, version)
);
