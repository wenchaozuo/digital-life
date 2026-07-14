DELETE FROM candidate_memory_evidence
WHERE rowid NOT IN (
    SELECT MIN(rowid)
    FROM candidate_memory_evidence
    GROUP BY
        candidate_id,
        source_type,
        source_id IS NULL,
        COALESCE(source_id, ''),
        conversation_id IS NULL,
        COALESCE(conversation_id, ''),
        message_id IS NULL,
        COALESCE(message_id, '')
);

CREATE UNIQUE INDEX idx_candidate_memory_evidence_identity
ON candidate_memory_evidence (
    candidate_id,
    source_type,
    (source_id IS NULL),
    COALESCE(source_id, ''),
    (conversation_id IS NULL),
    COALESCE(conversation_id, ''),
    (message_id IS NULL),
    COALESCE(message_id, '')
);
