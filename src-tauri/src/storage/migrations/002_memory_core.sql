CREATE TABLE memory_record (
    id TEXT PRIMARY KEY,
    life_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (
        kind IN ('experience', 'preference', 'fact', 'relationship', 'goal', 'skill', 'other')
    ),
    status TEXT NOT NULL CHECK (status IN ('candidate', 'confirmed')),
    content TEXT NOT NULL CHECK (length(trim(content)) > 0),
    summary TEXT,
    source_type TEXT NOT NULL CHECK (source_type IN ('manual', 'conversation', 'system', 'import')),
    source_ref TEXT,
    source_created_at TEXT NOT NULL,
    importance REAL NOT NULL CHECK (importance >= 0.0 AND importance <= 1.0),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    is_sensitive INTEGER NOT NULL CHECK (is_sensitive IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    confirmed_at TEXT,
    FOREIGN KEY (life_id) REFERENCES life_identity(id)
);

CREATE INDEX idx_memory_record_life_status
    ON memory_record(life_id, status);
CREATE INDEX idx_memory_record_life_kind
    ON memory_record(life_id, kind);
CREATE INDEX idx_memory_record_created_at
    ON memory_record(created_at);
