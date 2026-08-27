CREATE TRIGGER life_perception_policy_event_immutable_guard
BEFORE UPDATE ON life_perception_policy_event
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_PERCEPTION_POLICY_EVENT_IMMUTABLE');
END;
