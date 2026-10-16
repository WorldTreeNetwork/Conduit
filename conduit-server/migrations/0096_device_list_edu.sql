-- Outbound m.device_list_update chain tip, and inbound stream ids
-- already applied for a remote user. prev_id cites the previous tip.
-- An unrecognised prev_id is not a row here, so the receiver resyncs.
CREATE TABLE device_list_edu_out (
    user_id   TEXT PRIMARY KEY,
    stream_id BIGINT NOT NULL
);

CREATE TABLE device_list_edu_seen (
    user_id   TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, stream_id)
);
