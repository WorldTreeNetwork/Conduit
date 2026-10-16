-- Separate user uploads, remote cache, and URL-preview rehosts.
-- Preview images are not remote cache: remote retention must not delete them.
-- Existing rows with no uploader are remote cache (previews were not
-- distinguished before this column). New inserts default to user uploads;
-- remote fetches and preview rehosts set purpose after insert.
ALTER TABLE media ADD COLUMN purpose TEXT NOT NULL DEFAULT 'upload';
UPDATE media SET purpose = 'remote' WHERE uploader IS NULL;
