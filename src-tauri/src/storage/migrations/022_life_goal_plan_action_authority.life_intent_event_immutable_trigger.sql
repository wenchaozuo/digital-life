CREATE TRIGGER life_intent_event_immutable_guard
BEFORE UPDATE ON life_intent_event
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_INTENT_EVENT_IMMUTABLE');
END;