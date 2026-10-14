-- 0020_room_content.sql
--
-- Room content endpoints (conduit-y99.19): redactions, relations, threads,
-- timestamp lookup, full-text search, forgotten rooms and content reports.
--
-- Redactions and relations are derived from the immutable event log rather
-- than maintained by a write-path hook, so events arriving over federation
-- are indexed exactly like locally authored ones.

-- m.room.redaction events by target (room v11 carries `redacts` in content).
CREATE INDEX events_redaction_target ON events (room_id, (content->>'redacts'))
    WHERE type = 'm.room.redaction';

-- Child events by parent (`m.relates_to.event_id`). Sparse: most events
-- carry no relation.
CREATE INDEX events_relates_to ON events (room_id, (content->'m.relates_to'->>'event_id'), stream_position)
    WHERE content ? 'm.relates_to';

-- Thread listing scans m.thread children per room.
CREATE INDEX events_thread_children ON events (room_id, stream_position)
    WHERE content->'m.relates_to'->>'rel_type' = 'm.thread';

-- /timestamp_to_event.
CREATE INDEX events_room_ts ON events (room_id, origin_server_ts, stream_position);

-- Server-side search over the three spec keys. One partial GIN index per
-- key so `keys` selects which index participates.
CREATE INDEX events_search_body ON events
    USING GIN (to_tsvector('english', content->>'body'))
    WHERE type = 'm.room.message';
CREATE INDEX events_search_name ON events
    USING GIN (to_tsvector('english', content->>'name'))
    WHERE type = 'm.room.name';
CREATE INDEX events_search_topic ON events
    USING GIN (to_tsvector('english', content->>'topic'))
    WHERE type = 'm.room.topic';

-- POST /rooms/{roomId}/forget. The marker names the departure it forgot:
-- a later membership event (rejoin, re-leave) un-forgets the room without
-- any write-path hook.
CREATE TABLE room_forgotten (
    user_id             TEXT        NOT NULL,
    room_id             TEXT        NOT NULL,
    membership_event_id TEXT        NOT NULL,
    forgotten_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, room_id)
);

-- Event, room and user reports, retained for server administrators.
CREATE TABLE content_reports (
    id             BIGSERIAL   PRIMARY KEY,
    kind           TEXT        NOT NULL CHECK (kind IN ('event', 'room', 'user')),
    reporter       TEXT        NOT NULL,
    room_id        TEXT,
    event_id       TEXT,
    target_user_id TEXT,
    reason         TEXT,
    received_ts    BIGINT      NOT NULL
);
