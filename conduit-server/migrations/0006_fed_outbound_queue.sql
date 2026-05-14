-- 0006_fed_outbound_queue.sql
--
-- Durable outbound federation send queue (conduit-5n3).
--
-- Backs `conduit_server::federation::Queue`. One row per outbound
-- transaction (PDU batch) or to-device delivery. The per-destination
-- worker drains rows ordered by `id`, claims pending work via
-- `SELECT ... FOR UPDATE SKIP LOCKED`, retries with exponential
-- backoff up to a cap, then marks rows `dead` for manual inspection.

CREATE TABLE fed_outbound_queue (
    id                BIGSERIAL   PRIMARY KEY,
    destination       TEXT        NOT NULL,
    -- 'transaction' = PDU+EDU batch via PUT /send/{txnId}
    -- 'to_device'   = single delivery via PUT /send_to_device/{type}/{txnId}
    kind              TEXT        NOT NULL CHECK (kind IN ('transaction', 'to_device')),
    txn_id            TEXT        NOT NULL,
    -- Opaque payload — exact shape depends on `kind`:
    --   transaction:  { "pdus": [...], "edus": [...] }
    --   to_device:    { "event_type": "...", "messages": { ... } }
    payload           JSONB       NOT NULL,
    attempts          INT         NOT NULL DEFAULT 0,
    next_attempt_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error        TEXT,
    -- 'pending' = ready or waiting on backoff
    -- 'sent'    = delivered successfully (kept for audit; can be GC'd later)
    -- 'dead'    = exceeded attempt cap
    status            TEXT        NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'sent', 'dead')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at           TIMESTAMPTZ
);

-- Workers query: pending rows for a destination, oldest first, ready now.
CREATE INDEX fed_outbound_queue_pending
    ON fed_outbound_queue (destination, next_attempt_at, id)
    WHERE status = 'pending';

-- Recovery scan on boot: which destinations have pending work?
CREATE INDEX fed_outbound_queue_destinations_pending
    ON fed_outbound_queue (destination)
    WHERE status = 'pending';
