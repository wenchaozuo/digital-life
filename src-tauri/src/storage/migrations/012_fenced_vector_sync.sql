-- D-9D1: durable, fenced, single-event vector synchronization metadata.
-- This migration intentionally quarantines pre-012 upserts: their historical
-- revision/hash binding did not exist and must never be reconstructed from
-- current authority data.
ALTER TABLE memory_vector_sync_outbox
    ADD COLUMN mutation_sequence INTEGER NOT NULL DEFAULT 0 CHECK (mutation_sequence >= 0);
ALTER TABLE memory_vector_sync_outbox
    ADD COLUMN target_revision INTEGER;
ALTER TABLE memory_vector_sync_outbox
    ADD COLUMN target_content_hash TEXT;
ALTER TABLE memory_vector_sync_outbox
    ADD COLUMN claimed_generation_id TEXT;
ALTER TABLE memory_vector_sync_outbox
    ADD COLUMN lease_fence_epoch INTEGER;
ALTER TABLE memory_vector_sync_outbox
    ADD COLUMN last_send_disposition TEXT CHECK (last_send_disposition IN ('definitely_not_sent', 'possibly_sent') OR last_send_disposition IS NULL);
ALTER TABLE memory_vector_sync_outbox
    ADD COLUMN migration_disposition TEXT CHECK (migration_disposition IN ('legacy_upsert_rebuild_required') OR migration_disposition IS NULL);

CREATE TABLE memory_vector_sync_mutation_clock (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0)
);

-- `id` is INTEGER PRIMARY KEY in the legacy table, therefore this is its
-- stable rowid order.  It carries no content and is deterministic.
UPDATE memory_vector_sync_outbox
SET mutation_sequence = id
WHERE mutation_sequence = 0;

INSERT INTO memory_vector_sync_mutation_clock (singleton, last_sequence)
SELECT 1, COALESCE(MAX(mutation_sequence), 0)
FROM memory_vector_sync_outbox;

-- A legacy upsert has no immutable source binding.  It is deliberately not
-- made runnable; D-9D3 generation rebuild owns its future resolution.
UPDATE memory_vector_sync_outbox
SET state = 'blocked',
    target_revision = NULL,
    target_content_hash = NULL,
    claimed_generation_id = NULL,
    last_send_disposition = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL,
    lease_fence_epoch = NULL,
    migration_disposition = 'legacy_upsert_rebuild_required'
WHERE desired_action = 'upsert';

-- Deletes need no historic content binding.  An old processing lease cannot
-- be a valid post-012 fence, so only that state is safely released.
UPDATE memory_vector_sync_outbox
SET target_revision = NULL,
    target_content_hash = NULL,
    claimed_generation_id = NULL,
    last_send_disposition = NULL,
    lease_owner = NULL,
    lease_expires_at = NULL,
    lease_fence_epoch = NULL,
    migration_disposition = NULL,
    state = CASE WHEN state = 'processing' THEN 'pending' ELSE state END
WHERE desired_action = 'delete';

CREATE TABLE memory_vector_generation (
    generation_id TEXT PRIMARY KEY,
    descriptor_hash TEXT NOT NULL,
    dimension INTEGER NOT NULL CHECK (dimension > 0),
    state TEXT NOT NULL CHECK (state IN ('building', 'active', 'retired', 'failed')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE memory_vector_generation_item (
    generation_id TEXT NOT NULL,
    life_id TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    memory_revision INTEGER NOT NULL CHECK (memory_revision > 0),
    content_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (generation_id, life_id, memory_id),
    FOREIGN KEY (generation_id) REFERENCES memory_vector_generation(generation_id) ON DELETE CASCADE
);

CREATE TABLE memory_vector_sync_runtime_lease (
    lease_name TEXT PRIMARY KEY CHECK (lease_name = 'memory-vector-single-event-consumer'),
    owner_id TEXT,
    fence_epoch INTEGER NOT NULL DEFAULT 0 CHECK (fence_epoch >= 0),
    expires_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_memory_vector_sync_single_claim
ON memory_vector_sync_outbox (state, migration_disposition, next_attempt_at, mutation_sequence, id);
