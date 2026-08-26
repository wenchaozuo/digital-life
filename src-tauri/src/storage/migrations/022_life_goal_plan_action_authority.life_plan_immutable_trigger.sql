CREATE TRIGGER life_plan_immutable_guard
BEFORE UPDATE ON life_plan
WHEN digital_life_writer_epoch() IS 1
 AND (
     NEW.plan_id IS NOT OLD.plan_id
     OR NEW.life_id IS NOT OLD.life_id
     OR NEW.goal_id IS NOT OLD.goal_id
     OR NEW.title IS NOT OLD.title
     OR NEW.created_at IS NOT OLD.created_at
     OR NEW.plan_version IS NOT OLD.plan_version
 )
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_PLAN_IMMUTABLE');
END;