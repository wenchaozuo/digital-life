CREATE TABLE candidate_memory (
    id TEXT PRIMARY KEY,
    life_id TEXT NOT NULL,
    subject_id TEXT NOT NULL CHECK (length(trim(subject_id)) > 0),
    kind TEXT NOT NULL CHECK (
        kind IN ('experience', 'preference', 'fact', 'relationship', 'goal', 'skill', 'other')
    ),
    content TEXT,
    summary TEXT,
    source_type TEXT NOT NULL CHECK (
        source_type IN (
            'manual',
            'explicit_user_request',
            'conversation',
            'life_event',
            'reflection',
            'agent_proposal',
            'plugin_proposal',
            'import'
        )
    ),
    source_id TEXT,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    importance REAL NOT NULL CHECK (importance >= 0.0 AND importance <= 1.0),
    is_sensitive INTEGER NOT NULL CHECK (is_sensitive IN (0, 1)),
    inference_status TEXT NOT NULL CHECK (
        inference_status IN ('explicit', 'extracted', 'inferred')
    ),
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'accepted', 'rejected', 'expired', 'superseded')
    ),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    dedup_fingerprint TEXT,
    proposed_at TEXT NOT NULL,
    expires_at TEXT,
    reviewed_at TEXT,
    last_user_edit_at TEXT,
    confirmed_memory_id TEXT UNIQUE,
    accepted_request_id TEXT UNIQUE,
    rejection_reason_code TEXT,
    superseded_by_candidate_id TEXT,
    conflicts_with_memory_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (status = 'pending'
            AND content IS NOT NULL
            AND length(trim(content)) > 0
            AND confirmed_memory_id IS NULL)
        OR
        (status IN ('accepted', 'rejected', 'expired', 'superseded')
            AND content IS NULL
            AND (
                (status = 'accepted' AND confirmed_memory_id IS NOT NULL)
                OR
                (status <> 'accepted' AND confirmed_memory_id IS NULL)
            ))
    ),
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE,
    FOREIGN KEY (confirmed_memory_id) REFERENCES memory_record(id) ON DELETE CASCADE,
    FOREIGN KEY (superseded_by_candidate_id) REFERENCES candidate_memory(id) ON DELETE SET NULL,
    FOREIGN KEY (conflicts_with_memory_id) REFERENCES memory_record(id) ON DELETE SET NULL
);

CREATE TABLE candidate_memory_evidence (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    life_id TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (
        source_type IN (
            'manual',
            'explicit_user_request',
            'conversation',
            'life_event',
            'reflection',
            'agent_proposal',
            'plugin_proposal',
            'import'
        )
    ),
    source_id TEXT,
    conversation_id TEXT,
    message_id TEXT,
    observed_at TEXT NOT NULL,
    FOREIGN KEY (candidate_id) REFERENCES candidate_memory(id) ON DELETE CASCADE,
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE,
    FOREIGN KEY (conversation_id) REFERENCES conversation(id) ON DELETE CASCADE,
    FOREIGN KEY (message_id) REFERENCES conversation_message(id) ON DELETE CASCADE
);

CREATE TABLE candidate_memory_audit (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    life_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (length(trim(action)) > 0),
    actor_type TEXT NOT NULL CHECK (length(trim(actor_type)) > 0),
    request_id TEXT,
    result_status TEXT NOT NULL CHECK (length(trim(result_status)) > 0),
    created_at TEXT NOT NULL,
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);

CREATE INDEX idx_candidate_memory_life_status
ON candidate_memory (life_id, status);
CREATE INDEX idx_candidate_memory_life_proposed
ON candidate_memory (life_id, proposed_at DESC, id ASC);
CREATE INDEX idx_candidate_memory_life_kind
ON candidate_memory (life_id, kind);
CREATE INDEX idx_candidate_memory_life_sensitive
ON candidate_memory (life_id, is_sensitive);
CREATE INDEX idx_candidate_memory_life_source
ON candidate_memory (life_id, source_type);
CREATE INDEX idx_candidate_memory_life_inference
ON candidate_memory (life_id, inference_status);
CREATE INDEX idx_candidate_memory_confirmed_memory
ON candidate_memory (confirmed_memory_id);
CREATE INDEX idx_candidate_memory_conflicts_with_memory
ON candidate_memory (conflicts_with_memory_id);
CREATE INDEX idx_candidate_memory_expires_at
ON candidate_memory (expires_at);
CREATE INDEX idx_candidate_memory_updated_at
ON candidate_memory (updated_at);
CREATE UNIQUE INDEX idx_candidate_memory_pending_dedup
ON candidate_memory (life_id, subject_id, kind, dedup_fingerprint)
WHERE status = 'pending' AND dedup_fingerprint IS NOT NULL;

CREATE INDEX idx_candidate_memory_evidence_candidate
ON candidate_memory_evidence (candidate_id);
CREATE INDEX idx_candidate_memory_evidence_conversation
ON candidate_memory_evidence (conversation_id);
CREATE INDEX idx_candidate_memory_evidence_message
ON candidate_memory_evidence (message_id);
CREATE INDEX idx_candidate_memory_audit_life_created
ON candidate_memory_audit (life_id, created_at);

CREATE TRIGGER candidate_memory_confirmed_memory_insert
BEFORE INSERT ON candidate_memory
WHEN NEW.confirmed_memory_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM memory_record
    WHERE id = NEW.confirmed_memory_id
      AND status = 'confirmed'
      AND life_id = NEW.life_id
 )
BEGIN
    SELECT RAISE(ABORT, 'candidate_memory confirmed_memory_id must reference confirmed memory in the same life');
END;

CREATE TRIGGER candidate_memory_confirmed_memory_update
BEFORE UPDATE OF life_id, confirmed_memory_id ON candidate_memory
WHEN NEW.confirmed_memory_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM memory_record
    WHERE id = NEW.confirmed_memory_id
      AND status = 'confirmed'
      AND life_id = NEW.life_id
 )
BEGIN
    SELECT RAISE(ABORT, 'candidate_memory confirmed_memory_id must reference confirmed memory in the same life');
END;

CREATE TRIGGER candidate_memory_conflict_memory_insert
BEFORE INSERT ON candidate_memory
WHEN NEW.conflicts_with_memory_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM memory_record
    WHERE id = NEW.conflicts_with_memory_id
      AND status = 'confirmed'
      AND life_id = NEW.life_id
 )
BEGIN
    SELECT RAISE(ABORT, 'candidate_memory conflicts_with_memory_id must reference confirmed memory in the same life');
END;

CREATE TRIGGER candidate_memory_conflict_memory_update
BEFORE UPDATE OF life_id, conflicts_with_memory_id ON candidate_memory
WHEN NEW.conflicts_with_memory_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM memory_record
    WHERE id = NEW.conflicts_with_memory_id
      AND status = 'confirmed'
      AND life_id = NEW.life_id
 )
BEGIN
    SELECT RAISE(ABORT, 'candidate_memory conflicts_with_memory_id must reference confirmed memory in the same life');
END;

CREATE TRIGGER candidate_memory_superseded_candidate_insert
BEFORE INSERT ON candidate_memory
WHEN NEW.superseded_by_candidate_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM candidate_memory
    WHERE id = NEW.superseded_by_candidate_id
      AND life_id = NEW.life_id
 )
BEGIN
    SELECT RAISE(ABORT, 'candidate_memory superseded_by_candidate_id must reference candidate memory in the same life');
END;

CREATE TRIGGER candidate_memory_superseded_candidate_update
BEFORE UPDATE OF life_id, superseded_by_candidate_id ON candidate_memory
WHEN NEW.superseded_by_candidate_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM candidate_memory
    WHERE id = NEW.superseded_by_candidate_id
      AND life_id = NEW.life_id
 )
BEGIN
    SELECT RAISE(ABORT, 'candidate_memory superseded_by_candidate_id must reference candidate memory in the same life');
END;

CREATE TRIGGER candidate_memory_evidence_life_insert
BEFORE INSERT ON candidate_memory_evidence
WHEN NOT EXISTS (
    SELECT 1 FROM candidate_memory
    WHERE id = NEW.candidate_id
      AND life_id = NEW.life_id
)
BEGIN
    SELECT RAISE(ABORT, 'candidate_memory_evidence candidate must belong to the same life');
END;

CREATE TRIGGER candidate_memory_evidence_life_update
BEFORE UPDATE OF candidate_id, life_id ON candidate_memory_evidence
WHEN NOT EXISTS (
    SELECT 1 FROM candidate_memory
    WHERE id = NEW.candidate_id
      AND life_id = NEW.life_id
)
BEGIN
    SELECT RAISE(ABORT, 'candidate_memory_evidence candidate must belong to the same life');
END;

INSERT INTO candidate_memory (
    id, life_id, subject_id, kind, content, summary, source_type, source_id,
    confidence, importance, is_sensitive, inference_status, status, revision,
    dedup_fingerprint, proposed_at, expires_at, reviewed_at, last_user_edit_at,
    confirmed_memory_id, accepted_request_id, rejection_reason_code,
    superseded_by_candidate_id, conflicts_with_memory_id, created_at, updated_at
)
SELECT
    id,
    life_id,
    'primary_user',
    kind,
    content,
    summary,
    CASE source_type
        WHEN 'manual' THEN 'manual'
        WHEN 'conversation' THEN 'conversation'
        WHEN 'import' THEN 'import'
        WHEN 'system' THEN 'reflection'
        ELSE 'reflection'
    END,
    source_ref,
    confidence,
    importance,
    is_sensitive,
    CASE source_type
        WHEN 'manual' THEN 'explicit'
        ELSE 'extracted'
    END,
    'pending',
    1,
    NULL,
    source_created_at,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    created_at,
    updated_at
FROM memory_record
WHERE status = 'candidate';

DELETE FROM memory_record WHERE status = 'candidate';
