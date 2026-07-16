CREATE TABLE candidate_extraction_run (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    life_id TEXT NOT NULL CHECK (length(life_id) BETWEEN 1 AND 128),
    conversation_id TEXT NOT NULL CHECK (length(conversation_id) BETWEEN 1 AND 128),
    conversation_revision INTEGER NOT NULL CHECK (conversation_revision >= 0),
    extractor_id TEXT NOT NULL CHECK (length(trim(extractor_id)) BETWEEN 1 AND 128),
    extractor_version TEXT NOT NULL CHECK (length(trim(extractor_version)) BETWEEN 1 AND 64),
    policy_version TEXT NOT NULL CHECK (length(trim(policy_version)) BETWEEN 1 AND 512),
    snapshot_hash TEXT,
    eligible_message_count INTEGER NOT NULL CHECK (eligible_message_count >= 0),
    selected_message_count INTEGER NOT NULL CHECK (selected_message_count BETWEEN 1 AND 64),
    selected_first_sequence_no INTEGER NOT NULL CHECK (selected_first_sequence_no > 0),
    selected_last_sequence_no INTEGER NOT NULL CHECK (selected_last_sequence_no >= selected_first_sequence_no),
    selected_utf8_bytes INTEGER NOT NULL CHECK (selected_utf8_bytes BETWEEN 1 AND 131072),
    snapshot_truncated INTEGER NOT NULL CHECK (snapshot_truncated IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('processing','retry_wait','completed','failed','snapshot_invalidated')),
    attempt_sequence INTEGER NOT NULL CHECK (attempt_sequence BETWEEN 1 AND 3),
    lease_token_digest TEXT,
    lease_expires_at_epoch_s INTEGER,
    next_attempt_at_epoch_s INTEGER,
    total_proposal_count INTEGER NOT NULL DEFAULT 0 CHECK (total_proposal_count >= 0),
    created_count INTEGER NOT NULL DEFAULT 0 CHECK (created_count >= 0),
    evidence_merged_count INTEGER NOT NULL DEFAULT 0 CHECK (evidence_merged_count >= 0),
    ignored_count INTEGER NOT NULL DEFAULT 0 CHECK (ignored_count >= 0),
    hard_secret_blocked_count INTEGER NOT NULL DEFAULT 0 CHECK (hard_secret_blocked_count >= 0),
    sensitive_blocked_count INTEGER NOT NULL DEFAULT 0 CHECK (sensitive_blocked_count >= 0),
    conflict_blocked_count INTEGER NOT NULL DEFAULT 0 CHECK (conflict_blocked_count >= 0),
    same_batch_duplicate_count INTEGER NOT NULL DEFAULT 0 CHECK (same_batch_duplicate_count >= 0),
    last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE (life_id, conversation_id, conversation_revision),
    CHECK (snapshot_hash IS NULL OR (length(snapshot_hash) = 64 AND snapshot_hash NOT GLOB '*[^0-9a-f]*')),
    CHECK (lease_token_digest IS NULL OR (length(lease_token_digest) = 64 AND lease_token_digest NOT GLOB '*[^0-9a-f]*')),
    CHECK (lease_expires_at_epoch_s IS NULL OR lease_expires_at_epoch_s > 0),
    CHECK (next_attempt_at_epoch_s IS NULL OR next_attempt_at_epoch_s > 0),
    CHECK (eligible_message_count >= selected_message_count),
    CHECK (snapshot_truncated = CASE WHEN eligible_message_count > selected_message_count THEN 1 ELSE 0 END),
    CHECK (
        (status = 'processing' AND snapshot_hash IS NOT NULL AND lease_token_digest IS NOT NULL AND lease_expires_at_epoch_s IS NOT NULL AND next_attempt_at_epoch_s IS NULL AND last_error_code IS NULL AND completed_at IS NULL)
        OR (status = 'retry_wait' AND snapshot_hash IS NOT NULL AND lease_token_digest IS NULL AND lease_expires_at_epoch_s IS NULL AND next_attempt_at_epoch_s IS NOT NULL AND last_error_code IS NOT NULL AND attempt_sequence BETWEEN 1 AND 2 AND completed_at IS NULL)
        OR (status = 'completed' AND snapshot_hash IS NULL AND lease_token_digest IS NULL AND lease_expires_at_epoch_s IS NULL AND next_attempt_at_epoch_s IS NULL AND last_error_code IS NULL AND completed_at IS NOT NULL)
        OR (status = 'failed' AND snapshot_hash IS NULL AND lease_token_digest IS NULL AND lease_expires_at_epoch_s IS NULL AND next_attempt_at_epoch_s IS NULL AND last_error_code IS NOT NULL AND completed_at IS NOT NULL)
        OR (status = 'snapshot_invalidated' AND snapshot_hash IS NULL AND lease_token_digest IS NULL AND lease_expires_at_epoch_s IS NULL AND next_attempt_at_epoch_s IS NULL AND last_error_code = 'CANDIDATE_EXTRACTION_SNAPSHOT_INVALIDATED' AND completed_at IS NOT NULL)
    ),
    CHECK (status <> 'completed' OR (total_proposal_count <= 5 AND total_proposal_count = created_count + evidence_merged_count + ignored_count + hard_secret_blocked_count + sensitive_blocked_count + conflict_blocked_count + same_batch_duplicate_count)),
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE,
    FOREIGN KEY (conversation_id, life_id) REFERENCES conversation(id, life_id) ON DELETE CASCADE
);

CREATE TABLE candidate_extraction_snapshot_message (
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 128),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 63),
    message_id TEXT NOT NULL CHECK (length(message_id) BETWEEN 1 AND 128),
    sequence_no INTEGER NOT NULL CHECK (sequence_no > 0),
    PRIMARY KEY (run_id, ordinal),
    UNIQUE (run_id, message_id),
    UNIQUE (run_id, sequence_no),
    FOREIGN KEY (run_id) REFERENCES candidate_extraction_run(id) ON DELETE CASCADE
);

CREATE TABLE candidate_extraction_audit (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 128),
    attempt_sequence INTEGER NOT NULL CHECK (attempt_sequence BETWEEN 1 AND 3),
    event TEXT NOT NULL CHECK (event IN ('attempt_started','lease_taken_over','retry_scheduled','completed','failed','snapshot_invalidated','descriptor_unavailable')),
    safe_error_code TEXT CHECK (safe_error_code IS NULL OR length(safe_error_code) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL,
    CHECK ((event IN ('attempt_started','lease_taken_over','completed') AND safe_error_code IS NULL) OR (event IN ('retry_scheduled','failed','snapshot_invalidated','descriptor_unavailable') AND safe_error_code IS NOT NULL)),
    FOREIGN KEY (run_id) REFERENCES candidate_extraction_run(id) ON DELETE CASCADE
);

CREATE INDEX idx_candidate_extraction_run_claim ON candidate_extraction_run (status, next_attempt_at_epoch_s, lease_expires_at_epoch_s, updated_at, id);
CREATE INDEX idx_candidate_extraction_run_conversation ON candidate_extraction_run (life_id, conversation_id, conversation_revision);
CREATE INDEX idx_candidate_extraction_snapshot_message_id ON candidate_extraction_snapshot_message (message_id, run_id);
CREATE INDEX idx_candidate_extraction_audit_run ON candidate_extraction_audit (run_id, created_at, id);

CREATE TRIGGER candidate_extraction_descriptor_immutable
BEFORE UPDATE OF extractor_id, extractor_version, policy_version ON candidate_extraction_run
WHEN NEW.extractor_id IS NOT OLD.extractor_id
  OR NEW.extractor_version IS NOT OLD.extractor_version
  OR NEW.policy_version IS NOT OLD.policy_version
BEGIN
    SELECT RAISE(ABORT, 'candidate extraction descriptor is immutable');
END;
