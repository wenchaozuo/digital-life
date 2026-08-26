CREATE TABLE life_goal (
    goal_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(goal_id)) BETWEEN 1 AND 128),
    life_id TEXT NOT NULL CHECK (length(trim(life_id)) > 0),
    title TEXT NOT NULL CHECK (length(trim(title)) BETWEEN 1 AND 256),
    objective TEXT NOT NULL CHECK (length(trim(objective)) BETWEEN 1 AND 4096),
    status TEXT NOT NULL CHECK (status IN ('active', 'completed', 'cancelled')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_by_kind TEXT NOT NULL CHECK (created_by_kind = 'user_explicit'),
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    closed_at TEXT NULL,
    goal_version INTEGER NOT NULL CHECK (goal_version = 1),
    CHECK (
        (status = 'active' AND closed_at IS NULL)
        OR (status IN ('completed', 'cancelled') AND closed_at IS NOT NULL)
    ),
    UNIQUE (goal_id, life_id),
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);