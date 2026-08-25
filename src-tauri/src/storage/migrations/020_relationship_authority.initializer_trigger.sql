CREATE TRIGGER relationship_state_life_insert_initializer
AFTER INSERT ON life_identity
BEGIN
    INSERT INTO relationship_state
        (life_id, subject_id, familiarity, trust, emotional_closeness,
         collaboration, safety, dependency_tendency, boundary_comfort, tension,
         revision, policy_version, last_applied_at, updated_at)
    VALUES
        (NEW.id, 'primary_user', 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
         strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
         strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
END
