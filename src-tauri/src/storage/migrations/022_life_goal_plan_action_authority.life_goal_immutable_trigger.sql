CREATE TRIGGER life_goal_immutable_guard
BEFORE UPDATE ON life_goal
WHEN digital_life_writer_epoch() IS 1
 AND (
     NEW.goal_id IS NOT OLD.goal_id
     OR NEW.life_id IS NOT OLD.life_id
     OR NEW.title IS NOT OLD.title
     OR NEW.objective IS NOT OLD.objective
     OR NEW.created_by_kind IS NOT OLD.created_by_kind
     OR NEW.created_at IS NOT OLD.created_at
     OR NEW.goal_version IS NOT OLD.goal_version
 )
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_GOAL_IMMUTABLE');
END;