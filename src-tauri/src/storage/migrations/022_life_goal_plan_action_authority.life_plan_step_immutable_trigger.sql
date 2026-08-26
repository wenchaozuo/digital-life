CREATE TRIGGER life_plan_step_immutable_guard
BEFORE UPDATE ON life_plan_step
WHEN digital_life_writer_epoch() IS 1
 AND (
     NEW.step_id IS NOT OLD.step_id
     OR NEW.life_id IS NOT OLD.life_id
     OR NEW.plan_id IS NOT OLD.plan_id
     OR NEW.ordinal IS NOT OLD.ordinal
     OR NEW.summary IS NOT OLD.summary
     OR NEW.created_at IS NOT OLD.created_at
     OR NEW.step_version IS NOT OLD.step_version
 )
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_PLAN_STEP_IMMUTABLE');
END;