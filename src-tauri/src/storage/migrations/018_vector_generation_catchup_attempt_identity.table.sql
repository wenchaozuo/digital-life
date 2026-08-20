CREATE TABLE memory_vector_generation_rebuild_catchup_item (
    job_id TEXT NOT NULL,
    source_outbox_id INTEGER NOT NULL,
    life_id TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    mutation_sequence INTEGER NOT NULL CHECK (mutation_sequence > 0),
    desired_action TEXT NOT NULL CHECK (desired_action IN ('upsert','delete')),
    target_revision INTEGER NULL,
    target_content_hash TEXT NULL,
    canonical_document TEXT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','processing','applied','uncertain','superseded')),
    io_phase TEXT NOT NULL CHECK (io_phase IN ('not_started','reserved','embedding_started','vector_write_started','finalized')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
    attempt_id TEXT NULL,
    attempt_fence INTEGER NOT NULL DEFAULT 0 CHECK (attempt_fence >= 0),
    last_send_disposition TEXT NULL CHECK (last_send_disposition IS NULL OR last_send_disposition IN ('definitely_not_sent','possibly_sent')),
    last_error_code TEXT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (job_id, source_outbox_id, mutation_sequence),
    UNIQUE (job_id, life_id, memory_id, mutation_sequence),
    FOREIGN KEY (job_id) REFERENCES memory_vector_generation_rebuild_job(job_id),
    CHECK ((desired_action='upsert' AND target_revision IS NOT NULL AND target_revision>0 AND target_content_hash IS NOT NULL AND target_content_hash<>'')
        OR (desired_action='delete' AND target_revision IS NULL AND target_content_hash IS NULL AND canonical_document IS NULL))
)