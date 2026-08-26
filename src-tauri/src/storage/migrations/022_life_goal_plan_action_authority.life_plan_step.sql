CREATE TABLE life_plan_step (
    step_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(step_id)) BETWEEN 1 AND 128),
    life_id TEXT NOT NULL CHECK (length(trim(life_id)) > 0),
    plan_id TEXT NOT NULL CHECK (length(trim(plan_id)) > 0),
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    summary TEXT NOT NULL CHECK (length(trim(summary)) BETWEEN 1 AND 4096),
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'skipped', 'cancelled')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    closed_at TEXT NULL,
    step_version INTEGER NOT NULL CHECK (step_version = 1),
    CHECK (
        (status = 'pending' AND closed_at IS NULL)
        OR (status IN ('completed', 'skipped', 'cancelled') AND closed_at IS NOT NULL)
    ),
    UNIQUE (plan_id, ordinal),
    UNIQUE (step_id, life_id),
    FOREIGN KEY (plan_id, life_id)
        REFERENCES life_plan(plan_id, life_id) ON DELETE CASCADE,
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);