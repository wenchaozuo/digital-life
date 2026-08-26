CREATE TABLE life_plan (
    plan_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(plan_id)) BETWEEN 1 AND 128),
    life_id TEXT NOT NULL CHECK (length(trim(life_id)) > 0),
    goal_id TEXT NOT NULL CHECK (length(trim(goal_id)) > 0),
    title TEXT NOT NULL CHECK (length(trim(title)) BETWEEN 1 AND 256),
    status TEXT NOT NULL CHECK (status IN ('draft', 'active', 'completed', 'cancelled')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    closed_at TEXT NULL,
    plan_version INTEGER NOT NULL CHECK (plan_version = 1),
    CHECK (
        (status IN ('draft', 'active') AND closed_at IS NULL)
        OR (status IN ('completed', 'cancelled') AND closed_at IS NOT NULL)
    ),
    UNIQUE (plan_id, life_id),
    FOREIGN KEY (goal_id, life_id)
        REFERENCES life_goal(goal_id, life_id) ON DELETE CASCADE,
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);