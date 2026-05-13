-- E07: Media Repository metadata tables.
-- Local + cached-remote media metadata.
CREATE TABLE media (
    media_id        TEXT NOT NULL,       -- the mxc path component
    origin_server   TEXT NOT NULL,       -- our server for locally uploaded, else remote
    uploader        TEXT,                -- user_id of uploader; NULL for remote-cached
    content_type    TEXT,
    upload_name     TEXT,                -- original filename if client provided
    file_size       BIGINT NOT NULL,
    sha256          TEXT NOT NULL,       -- hex-encoded; lets us dedupe + name on disk
    storage_path    TEXT NOT NULL,       -- relative to media root, e.g. "ab/cd/abcd1234..."
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_accessed   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (media_id, origin_server)
);

-- Cached thumbnails: keyed by (origin, media_id, width, height, method).
CREATE TABLE media_thumbnails (
    media_id        TEXT NOT NULL,
    origin_server   TEXT NOT NULL,
    width           INT NOT NULL,
    height          INT NOT NULL,
    method          TEXT NOT NULL,       -- "scale" or "crop"
    content_type    TEXT NOT NULL,
    file_size       BIGINT NOT NULL,
    storage_path    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (media_id, origin_server, width, height, method),
    FOREIGN KEY (media_id, origin_server) REFERENCES media (media_id, origin_server) ON DELETE CASCADE
);
