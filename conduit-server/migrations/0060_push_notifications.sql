-- 0060_push_notifications.sql (conduit-y99.30)
--
-- Push rules: server-default rules now live in code. Rows with
-- is_default = true are user overlays (enabled/actions) of a default rule.
-- Earlier builds seeded every default into this table; drop the seeds that
-- carry nothing the user chose (default enabled state) and rules removed
-- from the v1.19 default set.
DELETE FROM push_rules
WHERE is_default
  AND (
    rule_id NOT IN (
        '.m.rule.master', '.m.rule.suppress_notices', '.m.rule.invite_for_me',
        '.m.rule.member_event', '.m.rule.is_user_mention', '.m.rule.is_room_mention',
        '.m.rule.tombstone', '.m.rule.reaction', '.m.rule.room.server_acl',
        '.m.rule.suppress_edits', '.m.rule.call', '.m.rule.encrypted_room_one_to_one',
        '.m.rule.room_one_to_one', '.m.rule.message', '.m.rule.encrypted'
    )
    OR (rule_id = '.m.rule.master' AND NOT enabled)
    OR (rule_id <> '.m.rule.master' AND enabled)
  );

-- Events up to this stream position have been evaluated for push. Starts at
-- the current head so an upgrade does not notify about old history.
CREATE TABLE push_cursor (
    singleton  BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    stream_pos BIGINT  NOT NULL
);
INSERT INTO push_cursor (singleton, stream_pos)
SELECT true, COALESCE(MAX(stream_position), 0) FROM events;

-- One row per (user, event) the user's push rules said to notify about.
CREATE TABLE push_notifications (
    user_id    TEXT    NOT NULL,
    room_id    TEXT    NOT NULL,
    event_id   TEXT    NOT NULL,
    stream_pos BIGINT  NOT NULL,
    thread_id  TEXT,
    actions    JSONB   NOT NULL,
    highlight  BOOLEAN NOT NULL,
    ts         BIGINT  NOT NULL,
    PRIMARY KEY (user_id, event_id)
);
-- Unread counts: per user and room after a receipt position.
CREATE INDEX push_notifications_room_pos ON push_notifications (user_id, room_id, stream_pos);
-- GET /notifications pages newest first; only=highlight is sparse.
CREATE INDEX push_notifications_user_pos ON push_notifications (user_id, stream_pos DESC);
CREATE INDEX push_notifications_highlight ON push_notifications (user_id, stream_pos DESC) WHERE highlight;

-- A user's own latest event per room and thread scope ('main' or a thread
-- root) marks everything before it in that scope read, like a receipt.
CREATE TABLE push_read_marks (
    user_id    TEXT   NOT NULL,
    room_id    TEXT   NOT NULL,
    scope      TEXT   NOT NULL,
    stream_pos BIGINT NOT NULL,
    PRIMARY KEY (user_id, room_id, scope)
);
