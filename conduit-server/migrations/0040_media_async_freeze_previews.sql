-- Media lane (conduit-y99.21): asynchronous uploads, the unauthenticated
-- media freeze, and the URL preview cache.

-- POST /_matrix/media/v1/create reserves an mxc:// URI before its bytes
-- exist. The row is consumed (deleted) in the same transaction that
-- inserts the `media` row on PUT /_matrix/media/v3/upload/{server}/{id}.
CREATE TABLE media_pending (
    media_id        TEXT NOT NULL,
    origin_server   TEXT NOT NULL,
    creator         TEXT NOT NULL,       -- only this user may upload the content
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL, -- unused_expires_at returned to the client
    PRIMARY KEY (media_id, origin_server)
);
-- Pending-upload quota: count a creator's unexpired reservations.
CREATE INDEX media_pending_creator ON media_pending (creator, expires_at);

-- Spec v1.11+: deprecated unauthenticated endpoints are "frozen": media
-- stored before the freeze stays reachable through them, media stored
-- after (local upload or remote cache fill) is served only through the
-- authenticated /_matrix/client/v1/media endpoints. Existing rows keep
-- legacy access; new rows default to frozen.
ALTER TABLE media ADD COLUMN unauthenticated_access BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE media ALTER COLUMN unauthenticated_access SET DEFAULT false;

-- URL preview cache. One row per fetch so `ts` can select the newest
-- preview generated at or before a requested time.
CREATE TABLE url_previews (
    url             TEXT NOT NULL,
    fetched_at      TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    og              JSONB NOT NULL,
    PRIMARY KEY (url, fetched_at)
);
CREATE INDEX url_previews_fetched_at ON url_previews USING BRIN (fetched_at);

-- Thumbnails are now never smaller than requested (unless the source is)
-- and never upscaled; drop cached thumbnails sized under the old rules so
-- they regenerate.
DELETE FROM media_thumbnails;
