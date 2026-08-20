CREATE TRIGGER memory_vector_generation_rebuild_catchup_identity_immutable
BEFORE UPDATE OF job_id, source_outbox_id, life_id, memory_id, mutation_sequence,
                 desired_action, target_revision, target_content_hash
ON memory_vector_generation_rebuild_catchup_item
BEGIN
    SELECT RAISE(ABORT, 'GENERATION_REBUILD_CATCHUP_IDENTITY_IMMUTABLE');
END