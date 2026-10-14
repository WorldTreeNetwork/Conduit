-- 0061_push_delivery.sql (conduit-y99.31)
--
-- pushkey_ts: unix seconds when the pushkey was last set, sent to gateways.
ALTER TABLE pushers ADD COLUMN pushkey_ts BIGINT NOT NULL DEFAULT 0;
UPDATE pushers SET pushkey_ts = EXTRACT(EPOCH FROM created_at)::BIGINT;

-- Durable queue of push gateway requests, one per (pusher, event), retried
-- with exponential backoff until delivered or expired.
CREATE TABLE push_outbox (
    id              BIGSERIAL PRIMARY KEY,
    user_id         TEXT   NOT NULL,
    app_id          TEXT   NOT NULL,
    pushkey         TEXT   NOT NULL,
    room_id         TEXT   NOT NULL,
    event_id        TEXT   NOT NULL,
    actions         JSONB  NOT NULL,
    attempts        INT    NOT NULL DEFAULT 0,
    next_attempt_ms BIGINT NOT NULL,
    created_ms      BIGINT NOT NULL,
    UNIQUE (user_id, app_id, pushkey, event_id)
);
CREATE INDEX push_outbox_due ON push_outbox (next_attempt_ms);
