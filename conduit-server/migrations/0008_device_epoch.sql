-- Agency layer: capability tokens replace opaque bearer tokens.
--
-- A Biscuit verifies offline against the minter's public key, so
-- revocation cannot be "delete the row".  Instead each device carries a
-- session epoch: tokens assert the epoch they were minted at, the
-- verifier injects the epoch on this row, and logout / device deletion
-- advances it.  Every outstanding token for that device dies at once,
-- with no denylist to garbage-collect.
ALTER TABLE devices ADD COLUMN epoch BIGINT NOT NULL DEFAULT 0;

-- Identity layer: identikey-auth fingerprint -> local MXID.
--
-- A link is what makes a challenge/response into a login.  An unlinked
-- fingerprint fails login rather than creating an account, so this
-- table is only ever written at registration or at a bind that already
-- required a valid grant.
CREATE TABLE identikey_links (
    fingerprint TEXT        PRIMARY KEY,
    user_id     TEXT        NOT NULL REFERENCES accounts(user_id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX identikey_links_user_idx ON identikey_links (user_id);

-- The Biscuit minter key.
--
-- Private key bytes, deliberately not hashed: the schema convention to
-- hash token-shaped credentials applies to bearer secrets we compare,
-- not to keys we sign with.  It lives in its own table rather than
-- alongside the Matrix server signing keys so it is never published at
-- /_matrix/key/v2/server and never selected as a current signing key.
-- Rotating it is a global epoch bump.
CREATE TABLE biscuit_minter_keys (
    key_id      TEXT        PRIMARY KEY,
    private_key BYTEA       NOT NULL,
    public_key  BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
