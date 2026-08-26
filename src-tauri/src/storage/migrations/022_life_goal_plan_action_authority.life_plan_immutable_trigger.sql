CREATE TRIGGER life_plan_immutable_guard
BEFORE UPDATE ON life_plan
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_PLAN_IMMUTABLE');
END;