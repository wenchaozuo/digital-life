CREATE TRIGGER life_screen_vision_outbound_policy_immutable_guard
BEFORE UPDATE ON life_screen_vision_outbound_policy
WHEN digital_life_writer_epoch() IS 1
 AND (
     NEW.life_id IS NOT OLD.life_id
     OR NEW.created_at IS NOT OLD.created_at
     OR NEW.policy_version IS NOT OLD.policy_version
 )
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_SCREEN_VISION_OUTBOUND_POLICY_IMMUTABLE');
END;
