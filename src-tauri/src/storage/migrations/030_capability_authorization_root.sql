CREATE TABLE life_capability_authorization (
    life_id TEXT NOT NULL CHECK (length(trim(life_id)) > 0),
    capability_id TEXT NOT NULL CHECK (
        length(capability_id) BETWEEN 1 AND 128
        AND capability_id NOT GLOB '*[^a-z0-9._-]*'
    ),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    PRIMARY KEY (life_id, capability_id),
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);

CREATE TABLE life_capability_authorization_event (
    event_id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(event_id)) BETWEEN 1 AND 128),
    life_id TEXT NOT NULL CHECK (length(trim(life_id)) > 0),
    capability_id TEXT NOT NULL CHECK (
        length(capability_id) BETWEEN 1 AND 128
        AND capability_id NOT GLOB '*[^a-z0-9._-]*'
    ),
    old_enabled INTEGER NOT NULL CHECK (old_enabled IN (0, 1)),
    new_enabled INTEGER NOT NULL CHECK (new_enabled IN (0, 1)),
    old_revision INTEGER NOT NULL CHECK (old_revision >= 1 AND old_revision < 9223372036854775807),
    new_revision INTEGER NOT NULL CHECK (new_revision = old_revision + 1),
    changed_at TEXT NOT NULL CHECK (length(trim(changed_at)) > 0),
    actor_kind TEXT NOT NULL CHECK (actor_kind = 'user_explicit'),
    provenance_kind TEXT NOT NULL CHECK (provenance_kind = 'user_authorization_root'),
    evidence_version INTEGER NOT NULL CHECK (evidence_version = 1),
    CHECK (old_enabled <> new_enabled),
    UNIQUE (life_id, capability_id, new_revision),
    FOREIGN KEY (life_id, capability_id)
        REFERENCES life_capability_authorization(life_id, capability_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_life_capability_authorization_capability
    ON life_capability_authorization(capability_id);

CREATE TRIGGER life_capability_authorization_immutable_guard
BEFORE UPDATE ON life_capability_authorization
WHEN digital_life_writer_epoch() IS 1
 AND (
     NEW.life_id IS NOT OLD.life_id
     OR NEW.capability_id IS NOT OLD.capability_id
     OR NEW.created_at IS NOT OLD.created_at
 )
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_CAPABILITY_AUTHORIZATION_IMMUTABLE');
END;

CREATE TRIGGER life_capability_authorization_event_immutable_guard
BEFORE UPDATE ON life_capability_authorization_event
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_CAPABILITY_AUTHORIZATION_EVENT_IMMUTABLE');
END;
