CREATE TRIGGER life_autonomy_policy_immutable_guard
BEFORE UPDATE ON life_autonomy_policy
WHEN digital_life_writer_epoch() IS 1
 AND (
     NEW.life_id IS NOT OLD.life_id
     OR NEW.created_at IS NOT OLD.created_at
     OR NEW.policy_version IS NOT OLD.policy_version
 )
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_AUTONOMY_POLICY_IMMUTABLE');
END;
