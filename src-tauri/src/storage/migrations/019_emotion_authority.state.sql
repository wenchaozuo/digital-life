CREATE TABLE emotion_state (
    life_id TEXT PRIMARY KEY,
    valence INTEGER NOT NULL CHECK (valence BETWEEN -1000 AND 1000),
    activation INTEGER NOT NULL CHECK (activation BETWEEN -1000 AND 1000),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    last_applied_at TEXT NOT NULL CHECK (last_applied_at <> ''),
    updated_at TEXT NOT NULL CHECK (updated_at <> ''),
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);