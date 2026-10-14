-- 0030_room_directory.sql
--
-- Published room directory (conduit-y99.20, subsumes conduit-wwy).
--
-- `room_directory` is the server's own published-room list
-- (`PUT /directory/list/room/{roomId}`, `createRoom` with
-- `visibility: public`). Presence of a row means "public".
--
-- `appservice_room_directory` holds the per-network lists that
-- application services maintain through
-- `PUT /directory/list/appservice/{networkId}/{roomId}`. They are only
-- listed by `/publicRooms` when `include_all_networks` or a matching
-- `third_party_instance_id` is requested.

CREATE TABLE room_directory (
    room_id       TEXT        PRIMARY KEY,
    published_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE appservice_room_directory (
    appservice_id TEXT        NOT NULL,
    network_id    TEXT        NOT NULL,
    room_id       TEXT        NOT NULL,
    published_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (appservice_id, network_id, room_id)
);

CREATE INDEX appservice_room_directory_room ON appservice_room_directory (room_id);
