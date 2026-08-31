CREATE TRIGGER life_screen_vision_outbound_policy_event_immutable_guard
BEFORE UPDATE ON life_screen_vision_outbound_policy_event
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_SCREEN_VISION_OUTBOUND_POLICY_EVENT_IMMUTABLE');
END;
