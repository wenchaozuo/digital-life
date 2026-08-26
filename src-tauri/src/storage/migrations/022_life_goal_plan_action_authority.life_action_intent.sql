CREATE TABLE life_action_intent (
    action_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(action_id)) BETWEEN 1 AND 128),
    life_id TEXT NOT NULL CHECK (length(trim(life_id)) > 0),
    step_id TEXT NOT NULL CHECK (length(trim(step_id)) > 0),
    execution_class TEXT NOT NULL CHECK (
        execution_class IN ('internal_intent', 'agent_task_proposal', 'tool_operation_proposal')
    ),
    summary TEXT NOT NULL CHECK (length(trim(summary)) BETWEEN 1 AND 4096),
    status TEXT NOT NULL CHECK (status IN ('proposed', 'dismissed')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    closed_at TEXT NULL,
    action_version INTEGER NOT NULL CHECK (action_version = 1),
    CHECK (
        (status = 'proposed' AND closed_at IS NULL)
        OR (status = 'dismissed' AND closed_at IS NOT NULL)
    ),
    UNIQUE (action_id, life_id),
    FOREIGN KEY (step_id, life_id)
        REFERENCES life_plan_step(step_id, life_id) ON DELETE CASCADE,
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);