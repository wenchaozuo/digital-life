CREATE TABLE life_screen_vision_outbound_policy (
    life_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(life_id)) > 0),
    screen_vision_outbound_enabled INTEGER NOT NULL CHECK (screen_vision_outbound_enabled IN (0, 1)),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    policy_version INTEGER NOT NULL CHECK (policy_version = 1),
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);
