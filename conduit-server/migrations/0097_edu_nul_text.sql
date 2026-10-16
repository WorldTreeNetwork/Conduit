-- 0097_edu_nul_text.sql (conduit-y99.22.4)
--
-- EDU sinks that must deliver U+0000. PostgreSQL rejects that character in
-- both JSONB (SQLSTATE 22P05) and TEXT (22021). serde_json text stores it as
-- the six ASCII characters `\u0000`, which TEXT accepts.
--
-- to_device_queue.content_text is the delivered content. The JSONB column
-- stays a U+FFFD projection and is not what /sync reads.
-- receipts.event_id_text and thread_id_text hold a JSON string only when the
-- value contains U+0000. The TEXT columns keep a U+FFFD projection so the
-- existing key still fits.
--
-- Nullable columns with no default are catalog-only. No table rewrite.
SET LOCAL lock_timeout = '5s';
ALTER TABLE to_device_queue ADD COLUMN content_text TEXT;
ALTER TABLE receipts ADD COLUMN event_id_text TEXT;
ALTER TABLE receipts ADD COLUMN thread_id_text TEXT;
