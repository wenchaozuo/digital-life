CREATE TRIGGER emotion_state_life_insert_initializer
AFTER INSERT ON life_identity
BEGIN
    INSERT INTO emotion_state
        (life_id, valence, activation, revision, policy_version, last_applied_at, updated_at)
    VALUES
        (NEW.id, 0, 0, 0, 1,
         strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
         strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
END