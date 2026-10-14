-- Account & device management (conduit-y99.18).

-- Guest accounts (POST /register?kind=guest) are restricted to the guest
-- subset of the client-server API until they upgrade.
ALTER TABLE accounts ADD COLUMN is_guest BOOLEAN NOT NULL DEFAULT false;

-- Set when a deactivating user asked for erasure.  Kept so history
-- visibility can serve redacted copies to later joiners.
ALTER TABLE accounts ADD COLUMN erased_at TIMESTAMPTZ;

-- Shown by GET /devices and /admin/whois.
ALTER TABLE devices ADD COLUMN last_seen_user_agent TEXT;

-- Capability tokens verify against the device row's epoch.  When a
-- device is deleted its last epoch is kept here so a device recreated
-- with the same ID starts past it: tokens minted for the deleted device
-- can never verify again.
CREATE TABLE retired_device_epochs (
    user_id    TEXT   NOT NULL,
    device_id  TEXT   NOT NULL,
    epoch      BIGINT NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

-- Refresh tokens, hashed like every other bearer credential.  A token
-- is valid only while its device still sits at the epoch it was issued
-- at, so logout and re-login with the same device ID revoke it too.
CREATE TABLE refresh_tokens (
    token_hash   TEXT        PRIMARY KEY,
    user_id      TEXT        NOT NULL,
    device_id    TEXT        NOT NULL,
    epoch        BIGINT      NOT NULL,
    parent_hash  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (user_id, device_id) REFERENCES devices (user_id, device_id) ON DELETE CASCADE
);

CREATE INDEX refresh_tokens_parent_idx ON refresh_tokens (parent_hash) WHERE parent_hash IS NOT NULL;
CREATE INDEX refresh_tokens_device_idx ON refresh_tokens (user_id, device_id);
