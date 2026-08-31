CREATE TABLE life_screen_vision_outbound_policy_event (
    event_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(event_id)) BETWEEN 1 AND 128),
    life_id TEXT NOT NULL CHECK (length(trim(life_id)) > 0),
    old_screen_vision_outbound_enabled INTEGER NOT NULL CHECK (old_screen_vision_outbound_enabled IN (0, 1)),
    new_screen_vision_outbound_enabled INTEGER NOT NULL CHECK (new_screen_vision_outbound_enabled IN (0, 1)),
    expected_revision INTEGER NOT NULL CHECK (expected_revision >= 1 AND expected_revision < 9223372036854775807),
    applied_revision INTEGER NOT NULL CHECK (applied_revision = expected_revision + 1),
    actor_kind TEXT NOT NULL CHECK (actor_kind = 'user_explicit'),
    occurred_at TEXT NOT NULL CHECK (length(trim(occurred_at)) > 0),
    event_version INTEGER NOT NULL CHECK (event_version = 1),
    CHECK (old_screen_vision_outbound_enabled <> new_screen_vision_outbound_enabled),
    FOREIGN KEY (life_id) REFERENCES life_screen_vision_outbound_policy(life_id) ON DELETE CASCADE
);
