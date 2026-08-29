CREATE TRIGGER live2d_core_component_immutable_guard
BEFORE UPDATE ON live2d_core_component
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'LIVE2D_CORE_COMPONENT_IMMUTABLE');
END;