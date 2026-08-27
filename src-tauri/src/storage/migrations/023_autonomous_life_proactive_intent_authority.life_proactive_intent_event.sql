CREATE TABLE life_proactive_intent_event (
    event_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(event_id)) BETWEEN 1 AND 128),
    life_id TEXT NOT NULL CHECK (length(trim(life_id)) > 0),
    intent_id TEXT NOT NULL CHECK (length(trim(intent_id)) BETWEEN 1 AND 128),
    from_status TEXT NOT NULL CHECK (from_status IN ('pending', 'ready', 'deferred', 'stored_silently', 'cancelled', 'expired', 'consumed')),
    to_status TEXT NOT NULL CHECK (to_status IN ('pending', 'ready', 'deferred', 'stored_silently', 'cancelled', 'expired', 'consumed')),
    expected_revision INTEGER NOT NULL CHECK (expected_revision >= 1 AND expected_revision < 9223372036854775807),
    applied_revision INTEGER NOT NULL CHECK (applied_revision = expected_revision + 1),
    not_before_after TEXT NULL CHECK (not_before_after IS NULL OR length(trim(not_before_after)) > 0),
    actor_kind TEXT NOT NULL CHECK (actor_kind = 'autonomy_policy'),
    occurred_at TEXT NOT NULL CHECK (length(trim(occurred_at)) > 0),
    event_version INTEGER NOT NULL CHECK (event_version = 1),
    CHECK (from_status <> to_status),
    FOREIGN KEY (intent_id, life_id)
        REFERENCES life_proactive_intent(intent_id, life_id) ON DELETE CASCADE
);
