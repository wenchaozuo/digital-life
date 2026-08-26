CREATE TRIGGER life_goal_immutable_guard
BEFORE UPDATE ON life_goal
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_GOAL_IMMUTABLE');
END;