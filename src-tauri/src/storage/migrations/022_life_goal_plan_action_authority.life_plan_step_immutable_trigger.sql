CREATE TRIGGER life_plan_step_immutable_guard
BEFORE UPDATE ON life_plan_step
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_PLAN_STEP_IMMUTABLE');
END;