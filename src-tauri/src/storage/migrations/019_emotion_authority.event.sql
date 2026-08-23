CREATE TABLE emotion_event (
    event_id TEXT PRIMARY KEY,
    life_id TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind <> ''),
    source_ref TEXT NOT NULL CHECK (source_ref <> ''),
    valence_delta INTEGER NOT NULL CHECK (valence_delta BETWEEN -1000 AND 1000),
    activation_delta INTEGER NOT NULL CHECK (activation_delta BETWEEN -1000 AND 1000),
    result_valence INTEGER NOT NULL CHECK (result_valence BETWEEN -1000 AND 1000),
    result_activation INTEGER NOT NULL CHECK (result_activation BETWEEN -1000 AND 1000),
    applied_revision INTEGER NOT NULL CHECK (applied_revision > 0),
    event_time TEXT NOT NULL CHECK (event_time <> ''),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    created_at TEXT NOT NULL CHECK (created_at <> ''),
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE,
    UNIQUE (life_id, source_kind, source_ref),
    UNIQUE (life_id, applied_revision)
);