CREATE TRIGGER body_package_asset_immutable_guard
BEFORE UPDATE ON body_package_asset
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'BODY_PACKAGE_ASSET_IMMUTABLE');
END;
