CREATE TRIGGER life_autonomy_policy_event_immutable_guard
BEFORE UPDATE ON life_autonomy_policy_event
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_AUTONOMY_POLICY_EVENT_IMMUTABLE');
END;
