-- Keep the first authenticated request across interrupted processing. A null
-- result means retry the saved request; final responses remain immutable.
ALTER TABLE transactions ADD COLUMN request JSONB;
ALTER TABLE transactions ALTER COLUMN result DROP NOT NULL;
ALTER TABLE transactions ADD CONSTRAINT transaction_has_request_or_result
    CHECK (request IS NOT NULL OR result IS NOT NULL);
