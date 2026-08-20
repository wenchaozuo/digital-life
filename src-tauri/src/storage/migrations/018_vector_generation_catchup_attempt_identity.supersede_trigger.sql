CREATE TRIGGER memory_vector_generation_rebuild_catchup_supersede_guard
BEFORE UPDATE OF state ON memory_vector_generation_rebuild_catchup_item
WHEN NEW.state='superseded'
 AND (OLD.state='uncertain'
      OR OLD.io_phase IN ('embedding_started','vector_write_started')
      OR OLD.last_send_disposition='possibly_sent')
BEGIN
    SELECT RAISE(ABORT, 'GENERATION_REBUILD_CATCHUP_SUPERSEDE_UNSAFE');
END