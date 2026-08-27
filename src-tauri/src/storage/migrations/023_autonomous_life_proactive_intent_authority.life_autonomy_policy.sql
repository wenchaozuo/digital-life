CREATE TABLE life_autonomy_policy (
    life_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(life_id)) > 0),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    dnd INTEGER NOT NULL CHECK (dnd IN (0, 1)),
    max_ready_per_window INTEGER NOT NULL CHECK (max_ready_per_window BETWEEN 0 AND 32),
    window_seconds INTEGER NOT NULL CHECK (window_seconds BETWEEN 60 AND 86400),
    min_gap_seconds INTEGER NOT NULL CHECK (min_gap_seconds BETWEEN 0 AND 86400),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    policy_version INTEGER NOT NULL CHECK (policy_version = 1),
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);
