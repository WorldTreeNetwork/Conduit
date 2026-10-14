-- Persist successful transaction results together with their effects.
-- Scope contains no raw credentials; client owners are [user_id, device_id].
CREATE TABLE transactions (
    scope TEXT NOT NULL,
    owner TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    txn_id TEXT NOT NULL,
    result JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, owner, endpoint, txn_id)
);
