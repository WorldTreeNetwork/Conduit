-- Account locking and suspension (conduit-y99.43, Matrix v1.18 admin API).
--
-- Both are reversible and leave sessions intact: a locked account gets
-- 401 M_USER_LOCKED (soft_logout) everywhere but logout, a suspended one
-- 403 M_USER_SUSPENDED on the actions that would add activity.  Only
-- moderated accounts have a row; the auth path does one point lookup.
CREATE TABLE account_moderation (
    user_id       TEXT        PRIMARY KEY REFERENCES accounts(user_id),
    locked_at     TIMESTAMPTZ,
    suspended_at  TIMESTAMPTZ
);
