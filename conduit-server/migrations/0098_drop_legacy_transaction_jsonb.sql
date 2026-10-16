-- 0098_drop_legacy_transaction_jsonb.sql (conduit-y99.22.5)
--
-- Replay and outbox rows now live in the TEXT columns from 0091. Copy any
-- JSONB-only rows across, replace the client event-id index (it cited
-- `result`), and drop the JSONB columns. DROP COLUMN and CREATE INDEX do
-- not rewrite the heap. The UPDATEs do not change relfilenode.
SET LOCAL lock_timeout = '5s';

UPDATE transactions
SET request_text = request::text
WHERE request_text IS NULL AND request IS NOT NULL;

UPDATE transactions
SET result_text = result::text
WHERE result_text IS NULL AND result IS NOT NULL;

UPDATE fed_outbound_queue
SET payload_text = payload::text
WHERE payload_text IS NULL AND payload IS NOT NULL;

ALTER TABLE transactions DROP CONSTRAINT transaction_has_request_or_result;

CREATE INDEX transactions_client_event_text
    ON transactions (owner, (substring(result_text from '"event_id":"([^"]+)"')))
    WHERE scope = 'client' AND result_text IS NOT NULL;

ALTER TABLE transactions DROP COLUMN request;
ALTER TABLE transactions DROP COLUMN result;

ALTER TABLE transactions ADD CONSTRAINT transaction_has_request_or_result
    CHECK (request_text IS NOT NULL OR result_text IS NOT NULL) NOT VALID;

ALTER TABLE fed_outbound_queue DROP COLUMN payload;
