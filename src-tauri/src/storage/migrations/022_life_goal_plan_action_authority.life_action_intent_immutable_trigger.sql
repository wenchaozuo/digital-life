CREATE TRIGGER life_action_intent_immutable_guard
BEFORE UPDATE ON life_action_intent
WHEN digital_life_writer_epoch() IS 1
 AND (
     NEW.action_id IS NOT OLD.action_id
     OR NEW.life_id IS NOT OLD.life_id
     OR NEW.step_id IS NOT OLD.step_id
     OR NEW.execution_class IS NOT OLD.execution_class
     OR NEW.summary IS NOT OLD.summary
     OR NEW.created_at IS NOT OLD.created_at
     OR NEW.action_version IS NOT OLD.action_version
 )
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_ACTION_INTENT_IMMUTABLE');
END;