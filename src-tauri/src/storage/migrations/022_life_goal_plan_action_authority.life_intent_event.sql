CREATE TABLE life_intent_event (
    event_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(event_id)) BETWEEN 1 AND 128),
    life_id TEXT NOT NULL CHECK (length(trim(life_id)) > 0),
    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('goal', 'plan', 'step', 'action')),
    goal_id TEXT NULL,
    plan_id TEXT NULL,
    step_id TEXT NULL,
    action_id TEXT NULL,
    from_status TEXT NOT NULL CHECK (length(trim(from_status)) > 0),
    to_status TEXT NOT NULL CHECK (length(trim(to_status)) > 0),
    expected_revision INTEGER NOT NULL
        CHECK (expected_revision >= 1 AND expected_revision < 9223372036854775807),
    applied_revision INTEGER NOT NULL CHECK (applied_revision = expected_revision + 1),
    actor_kind TEXT NOT NULL CHECK (actor_kind = 'user_explicit'),
    occurred_at TEXT NOT NULL CHECK (length(trim(occurred_at)) > 0),
    event_version INTEGER NOT NULL CHECK (event_version = 1),
    CHECK (from_status <> to_status),
    CHECK (
        (entity_kind = 'goal' AND goal_id IS NOT NULL
            AND plan_id IS NULL AND step_id IS NULL AND action_id IS NULL)
        OR (entity_kind = 'plan' AND plan_id IS NOT NULL
            AND goal_id IS NULL AND step_id IS NULL AND action_id IS NULL)
        OR (entity_kind = 'step' AND step_id IS NOT NULL
            AND goal_id IS NULL AND plan_id IS NULL AND action_id IS NULL)
        OR (entity_kind = 'action' AND action_id IS NOT NULL
            AND goal_id IS NULL AND plan_id IS NULL AND step_id IS NULL)
    ),
    FOREIGN KEY (goal_id, life_id)
        REFERENCES life_goal(goal_id, life_id) ON DELETE CASCADE,
    FOREIGN KEY (plan_id, life_id)
        REFERENCES life_plan(plan_id, life_id) ON DELETE CASCADE,
    FOREIGN KEY (step_id, life_id)
        REFERENCES life_plan_step(step_id, life_id) ON DELETE CASCADE,
    FOREIGN KEY (action_id, life_id)
        REFERENCES life_action_intent(action_id, life_id) ON DELETE CASCADE
);