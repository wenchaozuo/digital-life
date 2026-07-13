CREATE TABLE IF NOT EXISTS memory_vector_sync_settings (
    life_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);
