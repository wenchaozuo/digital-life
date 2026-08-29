CREATE TRIGGER body_package_immutable_guard
BEFORE UPDATE ON body_package
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'BODY_PACKAGE_IMMUTABLE');
END;
