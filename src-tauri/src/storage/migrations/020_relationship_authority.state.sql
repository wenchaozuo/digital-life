CREATE TABLE relationship_state (
    life_id TEXT NOT NULL,
    subject_id TEXT NOT NULL CHECK (subject_id <> ''),
    familiarity INTEGER NOT NULL CHECK (familiarity BETWEEN 0 AND 1000),
    trust INTEGER NOT NULL CHECK (trust BETWEEN -1000 AND 1000),
    emotional_closeness INTEGER NOT NULL CHECK (emotional_closeness BETWEEN 0 AND 1000),
    collaboration INTEGER NOT NULL CHECK (collaboration BETWEEN 0 AND 1000),
    safety INTEGER NOT NULL CHECK (safety BETWEEN -1000 AND 1000),
    dependency_tendency INTEGER NOT NULL CHECK (dependency_tendency BETWEEN 0 AND 1000),
    boundary_comfort INTEGER NOT NULL CHECK (boundary_comfort BETWEEN -1000 AND 1000),
    tension INTEGER NOT NULL CHECK (tension BETWEEN 0 AND 1000),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    last_applied_at TEXT NOT NULL CHECK (last_applied_at <> ''),
    updated_at TEXT NOT NULL CHECK (updated_at <> ''),
    PRIMARY KEY (life_id, subject_id),
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);
