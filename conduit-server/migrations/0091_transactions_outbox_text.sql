-- 0091_transactions_outbox_text.sql (add-pdu-wire, migration T)
--
-- Replay bodies/results and outbox payloads move to lossless JSON text
-- (serde_json), which keeps U+0000 as `\u0000` and floats as written; JSONB
-- refuses the former (SQLSTATE 22P05), which would 500 a whole /send
-- transaction before any PDU is parsed.
--
-- Staged, with no type change: new nullable TEXT columns that writers use
-- from now on, while readers fall back to the legacy JSONB columns for rows
-- written before this migration. Every statement is catalog-only (nullable
-- columns without defaults, DROP CONSTRAINT / DROP NOT NULL, a NOT VALID
-- CHECK), so neither table is rewritten or scanned. Retiring the JSONB
-- columns needs retention/GC (conduit-y99.22.5).
SET LOCAL lock_timeout = '5s';
ALTER TABLE transactions ADD COLUMN request_text TEXT;
ALTER TABLE transactions ADD COLUMN result_text TEXT;
ALTER TABLE transactions DROP CONSTRAINT transaction_has_request_or_result;
ALTER TABLE transactions ADD CONSTRAINT transaction_has_request_or_result
    CHECK (request IS NOT NULL OR result IS NOT NULL
           OR request_text IS NOT NULL OR result_text IS NOT NULL) NOT VALID;
ALTER TABLE fed_outbound_queue ADD COLUMN payload_text TEXT;
ALTER TABLE fed_outbound_queue ADD COLUMN legacy_snapshot_verdicts TEXT;
ALTER TABLE fed_outbound_queue ALTER COLUMN payload DROP NOT NULL;
