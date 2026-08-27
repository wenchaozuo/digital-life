CREATE TABLE life_proactive_intent (
    intent_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(intent_id)) BETWEEN 1 AND 128),
    life_id TEXT NOT NULL CHECK (length(trim(life_id)) > 0),
    goal_id TEXT NOT NULL CHECK (length(trim(goal_id)) BETWEEN 1 AND 128),
    intent_kind TEXT NOT NULL CHECK (intent_kind = 'goal_check_in'),
    importance INTEGER NOT NULL CHECK (importance BETWEEN 0 AND 1000),
    user_relevance INTEGER NOT NULL CHECK (user_relevance BETWEEN 0 AND 1000),
    self_desire INTEGER NOT NULL CHECK (self_desire BETWEEN 0 AND 1000),
    interruption_cost INTEGER NOT NULL CHECK (interruption_cost BETWEEN 0 AND 1000),
    focus_state TEXT NOT NULL CHECK (focus_state IN ('unknown', 'available', 'focused', 'dnd')),
    acceptance_score INTEGER NULL CHECK (acceptance_score IS NULL OR acceptance_score BETWEEN 0 AND 1000),
    recent_interaction_seconds INTEGER NULL CHECK (recent_interaction_seconds IS NULL OR recent_interaction_seconds >= 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'ready', 'deferred', 'stored_silently', 'cancelled', 'expired', 'consumed')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_by_kind TEXT NOT NULL CHECK (created_by_kind = 'autonomy_policy'),
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    not_before TEXT NULL CHECK (not_before IS NULL OR length(trim(not_before)) > 0),
    expires_at TEXT NULL CHECK (expires_at IS NULL OR length(trim(expires_at)) > 0),
    closed_at TEXT NULL CHECK (closed_at IS NULL OR length(trim(closed_at)) > 0),
    intent_version INTEGER NOT NULL CHECK (intent_version = 1),
    UNIQUE (intent_id, life_id),
    CHECK (
        (status IN ('pending', 'ready') AND not_before IS NULL)
        OR (status = 'deferred' AND not_before IS NOT NULL)
        OR (status IN ('stored_silently', 'cancelled', 'expired', 'consumed') AND not_before IS NULL)
    ),
    CHECK (
        (status IN ('pending', 'ready', 'deferred') AND closed_at IS NULL)
        OR (status IN ('stored_silently', 'cancelled', 'expired', 'consumed') AND closed_at IS NOT NULL)
    ),
    FOREIGN KEY (goal_id, life_id)
        REFERENCES life_goal(goal_id, life_id) ON DELETE CASCADE,
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);
