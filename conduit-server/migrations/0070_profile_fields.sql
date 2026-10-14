-- Extended profile fields (conduit-y99.38, Matrix v1.16+).
--
-- displayname and avatar_url stay on accounts (member events and the
-- user directory read them).  Every other key - m.tz and namespaced
-- custom keys - lives here, one row per key, value as client-supplied
-- JSON.  The 64 KiB whole-profile limit is enforced by the handler.
CREATE TABLE profile_fields (
    user_id  TEXT  NOT NULL REFERENCES accounts(user_id),
    key      TEXT  NOT NULL,
    value    JSONB NOT NULL,
    PRIMARY KEY (user_id, key)
);
