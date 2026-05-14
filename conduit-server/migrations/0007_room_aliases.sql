-- 0007_room_aliases.sql
--
-- Room alias directory (conduit-v0y).
--
-- A simple flat mapping: alias → room_id. Aliases are globally unique
-- per server (the spec requires that within a server, an alias points
-- to exactly one room at a time). The same room may have many aliases.

CREATE TABLE room_aliases (
    alias       TEXT        PRIMARY KEY,
    room_id     TEXT        NOT NULL,
    creator     TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Reverse lookup: which aliases point at this room? (used by leave/kick
-- and CS-API /rooms/{roomId}/aliases endpoints).
CREATE INDEX room_aliases_room_id ON room_aliases (room_id);
