ALTER TABLE memory_record
ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0);

CREATE TABLE memory_revision (
    id TEXT PRIMARY KEY,
    life_id TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    kind TEXT NOT NULL CHECK (
        kind IN ('experience', 'preference', 'fact', 'relationship', 'goal', 'skill', 'other')
    ),
    content TEXT NOT NULL CHECK (length(trim(content)) > 0),
    summary TEXT,
    is_sensitive INTEGER NOT NULL CHECK (is_sensitive IN (0, 1)),
    change_type TEXT NOT NULL CHECK (
        change_type IN ('confirmed', 'edited', 'sensitivity_changed')
    ),
    created_at TEXT NOT NULL,
    UNIQUE (memory_id, revision),
    FOREIGN KEY (life_id) REFERENCES life_identity(id),
    FOREIGN KEY (memory_id) REFERENCES memory_record(id) ON DELETE CASCADE
);

CREATE INDEX idx_memory_revision_life_memory
ON memory_revision(life_id, memory_id, revision DESC);

INSERT INTO memory_revision (
    id, life_id, memory_id, revision, kind, content, summary,
    is_sensitive, change_type, created_at
)
SELECT
    'memory-revision-' || id || '-1', life_id, id, 1, kind, content, summary,
    is_sensitive, 'confirmed', COALESCE(confirmed_at, updated_at)
FROM memory_record
WHERE status = 'confirmed';
