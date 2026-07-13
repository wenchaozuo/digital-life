CREATE TABLE IF NOT EXISTS memory_vector_sync_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    life_id TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    desired_action TEXT NOT NULL CHECK (desired_action IN ('upsert', 'delete')),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'processing', 'retry_wait', 'blocked', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TEXT,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error_code TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (life_id, memory_id)
);

CREATE INDEX IF NOT EXISTS idx_memory_vector_sync_claim
ON memory_vector_sync_outbox (life_id, state, next_attempt_at, created_at);
