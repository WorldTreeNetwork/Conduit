-- Application service transaction push (conduit-y99.34) and
-- identity-server 3PID bindings (conduit-y99.36).

-- Per-AS push cursors over the event and receipt streams.  A cursor
-- advances in the same transaction that freezes the next AS transaction,
-- so a restart neither loses nor duplicates events.  next_txn_id is
-- durable so a txnId is never reused with different contents.
CREATE TABLE appservice_stream (
    as_id       TEXT PRIMARY KEY,
    event_pos   BIGINT NOT NULL,
    receipt_pos BIGINT NOT NULL,
    next_txn_id BIGINT NOT NULL DEFAULT 1
);

-- Frozen, not yet acknowledged transactions.  Retries resend the exact
-- body under the same txnId (spec: the homeserver MUST NOT alter the
-- events of a transaction on retry).
CREATE TABLE appservice_txns (
    as_id      TEXT NOT NULL REFERENCES appservice_stream (as_id),
    txn_id     BIGINT NOT NULL,
    body       JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (as_id, txn_id)
);

-- 3PIDs a user bound on an identity server through
-- POST /account/3pid/bind, so unbind and delete know which server to ask.
CREATE TABLE threepid_id_server_bindings (
    user_id   TEXT NOT NULL,
    medium    TEXT NOT NULL,
    address   TEXT NOT NULL,
    id_server TEXT NOT NULL,
    PRIMARY KEY (user_id, medium, address, id_server)
);
