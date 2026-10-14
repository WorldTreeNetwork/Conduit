-- Monotonic sync cursors use BRIN alongside their unique B-tree indexes.
CREATE INDEX account_data_stream_brin ON account_data USING BRIN (stream_pos);
CREATE INDEX receipts_stream_brin ON receipts USING BRIN (stream_pos);
CREATE INDEX device_list_changes_stream_brin ON device_list_changes USING BRIN (id);
