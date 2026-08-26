CREATE TRIGGER experience_episode_immutable_guard
BEFORE UPDATE ON experience_episode
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'EXPERIENCE_EPISODE_IMMUTABLE');
END;
