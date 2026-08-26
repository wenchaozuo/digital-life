CREATE TRIGGER life_action_intent_immutable_guard
BEFORE UPDATE ON life_action_intent
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_ACTION_INTENT_IMMUTABLE');
END;