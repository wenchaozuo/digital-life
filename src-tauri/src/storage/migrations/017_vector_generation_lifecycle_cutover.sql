-- D-9D3-A Schema 17 lifecycle-authority objects.
--
-- The authoritative upgrade is executed by migration.rs inside the existing
-- single-transaction coordinator.  The outbox ALTER, legacy validation, and
-- deterministic backfills intentionally remain there so their failure points
-- cannot expose a partial schema.

-- The first authority, binding, and store-witness tables are installed by the
-- coordinator before this remainder. This separates the two migration phases
-- for deterministic rollback fault injection while retaining this file as the
-- canonical Schema-17 DDL for its later objects and guards.

CREATE TABLE memory_vector_generation_rebuild_job (
    job_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    generation_id TEXT NOT NULL UNIQUE,
    source_active_generation_id TEXT NULL,
    source_active_authority_epoch INTEGER NULL,
    candidate_authority_epoch INTEGER NOT NULL CHECK (candidate_authority_epoch >= 1),
    status TEXT NOT NULL CHECK (status IN ('registered', 'snapshotting', 'bulk_building', 'catching_up', 'verifying', 'ready', 'completed', 'failed', 'cancelled')),
    snapshot_sequence INTEGER NULL CHECK (snapshot_sequence >= 0),
    catchup_target_sequence INTEGER NULL CHECK (catchup_target_sequence >= 0),
    caught_up_sequence INTEGER NULL CHECK (caught_up_sequence >= 0),
    promotion_operation_id TEXT NULL UNIQUE,
    promotion_sequence INTEGER NULL CHECK (promotion_sequence >= 0),
    snapshot_item_count INTEGER NOT NULL DEFAULT 0 CHECK (snapshot_item_count >= 0),
    applied_item_count INTEGER NOT NULL DEFAULT 0 CHECK (applied_item_count >= 0),
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1)),
    lease_owner TEXT NULL,
    lease_fence INTEGER NOT NULL DEFAULT 0 CHECK (lease_fence >= 0),
    lease_expires_at TEXT NULL,
    last_error_code TEXT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT NULL,
    FOREIGN KEY (generation_id) REFERENCES memory_vector_generation(generation_id),
    FOREIGN KEY (source_active_generation_id) REFERENCES memory_vector_generation(generation_id)
);

CREATE TABLE memory_vector_generation_rebuild_item (
    job_id TEXT NOT NULL,
    life_id TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    memory_revision INTEGER NOT NULL CHECK (memory_revision > 0),
    content_hash TEXT NOT NULL,
    canonical_document TEXT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'processing', 'applied', 'uncertain')),
    io_phase TEXT NOT NULL CHECK (io_phase IN ('not_started', 'reserved', 'embedding_started', 'vector_write_started', 'finalized')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
    attempt_id TEXT NULL,
    attempt_fence INTEGER NOT NULL DEFAULT 0 CHECK (attempt_fence >= 0),
    last_send_disposition TEXT NULL CHECK (last_send_disposition IS NULL OR last_send_disposition IN ('definitely_not_sent', 'possibly_sent')),
    last_error_code TEXT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (job_id, life_id, memory_id),
    FOREIGN KEY (job_id) REFERENCES memory_vector_generation_rebuild_job(job_id)
);

CREATE TABLE memory_vector_generation_rebuild_resolution (
    resolution_id INTEGER PRIMARY KEY,
    job_id TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('outbox', 'late_delete')),
    source_row_id INTEGER NOT NULL,
    life_id TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    mutation_sequence INTEGER NOT NULL CHECK (mutation_sequence > 0),
    source_generation_id TEXT NULL,
    source_generation_authority_epoch INTEGER NULL,
    disposition TEXT NOT NULL CHECK (disposition IN ('resolved_by_rebuild', 'legacy_rebuild_resolved', 'failed_generation_requeued')),
    replacement_mutation_sequence INTEGER NULL,
    created_at TEXT NOT NULL,
    UNIQUE (job_id, source_kind, source_row_id, mutation_sequence),
    FOREIGN KEY (job_id) REFERENCES memory_vector_generation_rebuild_job(job_id),
    FOREIGN KEY (source_generation_id) REFERENCES memory_vector_generation(generation_id)
);

CREATE UNIQUE INDEX memory_vector_generation_one_active
    ON memory_vector_generation(state) WHERE state = 'active';
CREATE UNIQUE INDEX memory_vector_generation_one_building
    ON memory_vector_generation(state) WHERE state = 'building';
CREATE UNIQUE INDEX memory_vector_generation_rebuild_job_one_nonterminal
    ON memory_vector_generation_rebuild_job((1))
    WHERE status IN ('registered', 'snapshotting', 'bulk_building', 'catching_up', 'verifying', 'ready');

CREATE TRIGGER memory_vector_generation_authority_active_insert_guard
BEFORE INSERT ON memory_vector_generation_authority
WHEN NEW.active_generation_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM memory_vector_generation WHERE generation_id = NEW.active_generation_id AND state = 'active')
BEGIN
    SELECT RAISE(ABORT, 'GENERATION_AUTHORITY_POINTER_INVALID');
END;

CREATE TRIGGER memory_vector_generation_authority_active_update_guard
BEFORE UPDATE OF active_generation_id ON memory_vector_generation_authority
WHEN NEW.active_generation_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM memory_vector_generation WHERE generation_id = NEW.active_generation_id AND state = 'active')
BEGIN
    SELECT RAISE(ABORT, 'GENERATION_AUTHORITY_POINTER_INVALID');
END;

CREATE TRIGGER memory_vector_generation_active_pointer_state_guard
BEFORE UPDATE OF state ON memory_vector_generation
WHEN NEW.state <> 'active'
 AND EXISTS (SELECT 1 FROM memory_vector_generation_authority WHERE active_generation_id = OLD.generation_id)
BEGIN
    SELECT RAISE(ABORT, 'GENERATION_AUTHORITY_POINTER_INVALID');
END;

CREATE TRIGGER memory_vector_generation_binding_immutable_update_guard
BEFORE UPDATE ON memory_vector_generation_binding
BEGIN
    SELECT RAISE(ABORT, 'GENERATION_BINDING_IMMUTABLE');
END;

CREATE TRIGGER memory_vector_generation_binding_immutable_delete_guard
BEFORE DELETE ON memory_vector_generation_binding
BEGIN
    SELECT RAISE(ABORT, 'GENERATION_BINDING_IMMUTABLE');
END;
