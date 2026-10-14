-- Threaded read receipts (conduit-y99.15).
--
-- A receipt is scoped by thread: unthreaded, the main timeline ("main"), or
-- a thread root event ID. Scopes coexist, so the key gains thread_id. Matrix
-- thread IDs are never empty, so '' denotes the unthreaded receipt and keeps
-- the key a plain (NOT NULL) primary key.
ALTER TABLE receipts ADD COLUMN thread_id TEXT NOT NULL DEFAULT '';
ALTER TABLE receipts DROP CONSTRAINT receipts_pkey;
ALTER TABLE receipts ADD PRIMARY KEY (room_id, user_id, receipt_type, thread_id);
