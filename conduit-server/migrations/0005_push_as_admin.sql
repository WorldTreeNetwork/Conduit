-- 0005_push_as_admin.sql
--
-- Push, Application Services, and Admin tables for E11.
-- See AGENTS.md → "Database Conventions" for migration rules.

-- ---------------------------------------------------------------------------
-- Push: pushers + push_rules
-- ---------------------------------------------------------------------------

CREATE TABLE pushers (
    user_id             TEXT        NOT NULL REFERENCES accounts(user_id),
    pushkey             TEXT        NOT NULL,
    app_id              TEXT        NOT NULL,
    app_display_name    TEXT,
    device_display_name TEXT,
    kind                TEXT        NOT NULL,
    lang                TEXT        NOT NULL DEFAULT 'en',
    profile_tag         TEXT,
    url                 TEXT,
    format              TEXT,
    data                JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, pushkey, app_id)
);

CREATE TABLE push_rules (
    user_id     TEXT        NOT NULL REFERENCES accounts(user_id),
    scope       TEXT        NOT NULL,
    kind        TEXT        NOT NULL,
    rule_id     TEXT        NOT NULL,
    priority    INT         NOT NULL,
    enabled     BOOLEAN     NOT NULL DEFAULT true,
    conditions  JSONB       NOT NULL DEFAULT '[]'::jsonb,
    actions     JSONB       NOT NULL,
    pattern     TEXT,
    is_default  BOOLEAN     NOT NULL DEFAULT false,
    PRIMARY KEY (user_id, scope, kind, rule_id)
);

-- ---------------------------------------------------------------------------
-- Application Services: registration is loaded from YAML files at startup,
-- but we store a record per AS for foreign-key purposes and AS-owned accounts.
-- ---------------------------------------------------------------------------

-- as_id column on accounts to mark ghost users.
ALTER TABLE accounts ADD COLUMN as_id TEXT;

-- ---------------------------------------------------------------------------
-- Admin audit log
-- ---------------------------------------------------------------------------

CREATE TABLE admin_audit (
    id          BIGSERIAL   PRIMARY KEY,
    admin_user  TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    target      TEXT,
    detail      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX admin_audit_ts ON admin_audit (ts DESC);
