-- 0090_events_pdu_json.sql (add-pdu-wire, migration E)
--
-- The authoritative wire form of every event becomes canonical-JSON text
-- (`pdu_json`, without `unsigned`). JSONB cannot hold the `\u0000` escape
-- (SQLSTATE 22P05) that canonical JSON allows in strings; in text a NUL is
-- the six ASCII characters `\u0000`. The existing columns stay as projections
-- for SQL predicates. NULL marks a legacy row, decoded from the projections.
--
-- `id_integrity` records whether a row's bytes reproduce its event_id:
-- 'unchecked' (legacy, until the sweep or an on-demand check), 'verified',
-- 'content_mismatch' (served over federation only as its v11 redaction),
-- or 'id_mismatch' (never served over federation).
--
-- Both statements are catalog-only on PostgreSQL 11+ (a nullable column and
-- a constant default): no table rewrite, no scan. lock_timeout bounds only
-- how long we wait to acquire the lock, so the migration fails fast instead
-- of queueing all traffic behind a long-running query.
SET LOCAL lock_timeout = '5s';
ALTER TABLE events ADD COLUMN pdu_json TEXT;
ALTER TABLE events ADD COLUMN id_integrity TEXT NOT NULL DEFAULT 'unchecked';
