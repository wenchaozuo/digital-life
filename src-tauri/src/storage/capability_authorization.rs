//! SQLite repository for the D28 Life-scoped capability authorization root.
//!
//! This module is the only writer for the durable authorization tables. It
//! contains no capability execution, tool broker, provider, prompt, model,
//! secret, filesystem, network, browser, or agent integration.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};

use super::{StorageError, StorageService};
use crate::capability::authorization::{
    validate_authorization_state, validate_create_request, validate_event_state,
    validate_update_request, CapabilityAuthorizationCreateOutcome, CapabilityAuthorizationError,
    CapabilityAuthorizationRepository, CapabilityAuthorizationUpdateOutcome,
    LifeCapabilityAuthorization, LifeCapabilityAuthorizationCreateRequest,
    LifeCapabilityAuthorizationEvent, LifeCapabilityAuthorizationUpdateRequest,
};
use crate::capability::descriptor::CapabilityId;

pub(super) const MIGRATION_030_SQL: &str =
    include_str!("migrations/030_capability_authorization_root.sql");

const CREATE_AUTHORIZATION_TABLE_SQL: &str = r#"CREATE TABLE life_capability_authorization (
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
)"#;
const CREATE_EVENT_TABLE_SQL: &str = r#"CREATE TABLE life_capability_authorization_event (
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
    CHECK (old_enabled <> new_enabled),
    UNIQUE (life_id, capability_id, new_revision),
    FOREIGN KEY (life_id, capability_id)
        REFERENCES life_capability_authorization(life_id, capability_id)
        ON DELETE CASCADE
)"#;
const CREATE_AUTHORIZATION_IMMUTABLE_TRIGGER_SQL: &str = r#"CREATE TRIGGER life_capability_authorization_immutable_guard
BEFORE UPDATE ON life_capability_authorization
WHEN digital_life_writer_epoch() IS 1
 AND (
     NEW.life_id IS NOT OLD.life_id
     OR NEW.capability_id IS NOT OLD.capability_id
     OR NEW.created_at IS NOT OLD.created_at
 )
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_CAPABILITY_AUTHORIZATION_IMMUTABLE');
END"#;
const CREATE_EVENT_IMMUTABLE_TRIGGER_SQL: &str = r#"CREATE TRIGGER life_capability_authorization_event_immutable_guard
BEFORE UPDATE ON life_capability_authorization_event
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_CAPABILITY_AUTHORIZATION_EVENT_IMMUTABLE');
END"#;

const AUTHORIZATION_COLUMNS: &str =
    "life_id, capability_id, enabled, revision, created_at, updated_at";
const EVENT_COLUMNS: &str =
    "event_id, life_id, capability_id, old_enabled, new_enabled, old_revision, new_revision, changed_at";

fn read_authorization(row: &Row<'_>) -> rusqlite::Result<LifeCapabilityAuthorization> {
    Ok(LifeCapabilityAuthorization {
        life_id: row.get(0)?,
        capability_id: CapabilityId::try_from(row.get::<_, String>(1)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        enabled: row.get::<_, bool>(2)?,
        revision: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

fn read_event(row: &Row<'_>) -> rusqlite::Result<LifeCapabilityAuthorizationEvent> {
    Ok(LifeCapabilityAuthorizationEvent {
        event_id: row.get(0)?,
        life_id: row.get(1)?,
        capability_id: CapabilityId::try_from(row.get::<_, String>(2)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        old_enabled: row.get::<_, bool>(3)?,
        new_enabled: row.get::<_, bool>(4)?,
        old_revision: row.get(5)?,
        new_revision: row.get(6)?,
        changed_at: row.get(7)?,
    })
}

fn validate_lookup_identity(name: &str, value: &str) -> Result<(), CapabilityAuthorizationError> {
    if value.is_empty()
        || value.chars().count() > 128
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(CapabilityAuthorizationError::invalid_argument(format!(
            "{name} must be non-empty and bounded."
        )));
    }
    Ok(())
}

fn sqlite_authority_now(connection: &Connection) -> Result<String, CapabilityAuthorizationError> {
    connection
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| CapabilityAuthorizationError::database())
}

fn next_revision(expected_revision: i64) -> Result<i64, CapabilityAuthorizationError> {
    expected_revision.checked_add(1).ok_or_else(|| {
        CapabilityAuthorizationError::invalid_argument(
            "the next capability authorization revision is unrepresentable.",
        )
    })
}

fn load_authorization(
    connection: &Connection,
    life_id: &str,
    capability_id: &CapabilityId,
) -> Result<Option<LifeCapabilityAuthorization>, CapabilityAuthorizationError> {
    connection
        .query_row(
            &format!(
                "SELECT {AUTHORIZATION_COLUMNS}
                 FROM life_capability_authorization
                 WHERE life_id = ?1 AND capability_id = ?2"
            ),
            params![life_id, capability_id.as_str()],
            read_authorization,
        )
        .optional()
        .map_err(|_| CapabilityAuthorizationError::database())
}

fn load_event_by_id(
    connection: &Connection,
    event_id: &str,
) -> Result<Option<LifeCapabilityAuthorizationEvent>, CapabilityAuthorizationError> {
    connection
        .query_row(
            &format!(
                "SELECT {EVENT_COLUMNS}
                 FROM life_capability_authorization_event
                 WHERE event_id = ?1"
            ),
            [event_id],
            read_event,
        )
        .optional()
        .map_err(|_| CapabilityAuthorizationError::database())
}

fn authorization_create_evidence_matches(
    authorization: &LifeCapabilityAuthorization,
    request: &LifeCapabilityAuthorizationCreateRequest,
) -> bool {
    authorization.life_id == request.life_id
        && authorization.capability_id == request.capability_id
        && !authorization.enabled
        && authorization.revision == 1
}

fn event_evidence_matches(
    event: &LifeCapabilityAuthorizationEvent,
    request: &LifeCapabilityAuthorizationUpdateRequest,
    applied_revision: i64,
) -> bool {
    event.event_id == request.event_id
        && event.life_id == request.life_id
        && event.capability_id == request.capability_id
        && event.old_enabled != request.enabled
        && event.new_enabled == request.enabled
        && event.old_revision == request.expected_revision
        && event.new_revision == applied_revision
}

fn require_life(
    transaction: &Transaction<'_>,
    life_id: &str,
) -> Result<(), CapabilityAuthorizationError> {
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
            [life_id],
            |row| row.get(0),
        )
        .map_err(|_| CapabilityAuthorizationError::database())?;
    if !exists {
        return Err(CapabilityAuthorizationError::life_not_found());
    }
    Ok(())
}

fn create_authorization_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeCapabilityAuthorizationCreateRequest,
) -> Result<CapabilityAuthorizationCreateOutcome, CapabilityAuthorizationError> {
    validate_create_request(&request)?;
    require_life(transaction, &request.life_id)?;
    if let Some(existing) =
        load_authorization(transaction, &request.life_id, &request.capability_id)?
    {
        if authorization_create_evidence_matches(&existing, &request) {
            validate_authorization_state(&existing)?;
            return Ok(CapabilityAuthorizationCreateOutcome::Replayed(existing));
        }
        return Err(CapabilityAuthorizationError::authorization_conflict());
    }

    let now = sqlite_authority_now(transaction)?;
    transaction
        .execute(
            "INSERT INTO life_capability_authorization
             (life_id, capability_id, enabled, revision, created_at, updated_at)
             VALUES (?1, ?2, 0, 1, ?3, ?3)",
            params![&request.life_id, request.capability_id.as_str(), &now],
        )
        .map_err(|_| CapabilityAuthorizationError::database())?;
    let created = load_authorization(transaction, &request.life_id, &request.capability_id)?
        .ok_or_else(CapabilityAuthorizationError::database)?;
    validate_authorization_state(&created)?;
    Ok(CapabilityAuthorizationCreateOutcome::Applied(created))
}

fn update_authorization_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeCapabilityAuthorizationUpdateRequest,
) -> Result<CapabilityAuthorizationUpdateOutcome, CapabilityAuthorizationError> {
    validate_update_request(&request)?;
    let applied_revision = next_revision(request.expected_revision)?;
    require_life(transaction, &request.life_id)?;

    // Event identity is checked before the current revision so an already
    // committed exact event remains replayable after later updates.
    if let Some(existing_event) = load_event_by_id(transaction, &request.event_id)? {
        validate_event_state(&existing_event)?;
        if event_evidence_matches(&existing_event, &request, applied_revision) {
            let current =
                load_authorization(transaction, &request.life_id, &request.capability_id)?
                    .ok_or_else(CapabilityAuthorizationError::authorization_not_found)?;
            validate_authorization_state(&current)?;
            return Ok(CapabilityAuthorizationUpdateOutcome::Replayed {
                event: existing_event,
                current,
            });
        }
        return Err(CapabilityAuthorizationError::event_conflict());
    }

    let current = load_authorization(transaction, &request.life_id, &request.capability_id)?
        .ok_or_else(CapabilityAuthorizationError::authorization_not_found)?;
    validate_authorization_state(&current)?;
    if current.revision != request.expected_revision {
        return Err(CapabilityAuthorizationError::revision_conflict());
    }
    if current.enabled == request.enabled {
        return Err(CapabilityAuthorizationError::invalid_transition());
    }

    let now = sqlite_authority_now(transaction)?;
    let changed = transaction
        .execute(
            "UPDATE life_capability_authorization
             SET enabled = ?1, revision = ?2, updated_at = ?3
             WHERE life_id = ?4 AND capability_id = ?5
               AND revision = ?6 AND enabled = ?7",
            params![
                request.enabled,
                applied_revision,
                &now,
                &request.life_id,
                request.capability_id.as_str(),
                request.expected_revision,
                current.enabled,
            ],
        )
        .map_err(|_| CapabilityAuthorizationError::database())?;
    if changed != 1 {
        return Err(CapabilityAuthorizationError::revision_conflict());
    }

    let event = LifeCapabilityAuthorizationEvent {
        event_id: request.event_id,
        life_id: request.life_id,
        capability_id: request.capability_id,
        old_enabled: current.enabled,
        new_enabled: request.enabled,
        old_revision: current.revision,
        new_revision: applied_revision,
        changed_at: now,
    };
    validate_event_state(&event)?;
    transaction
        .execute(
            &format!(
                "INSERT INTO life_capability_authorization_event ({EVENT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
            ),
            params![
                &event.event_id,
                &event.life_id,
                event.capability_id.as_str(),
                event.old_enabled,
                event.new_enabled,
                event.old_revision,
                event.new_revision,
                &event.changed_at,
            ],
        )
        .map_err(|_| CapabilityAuthorizationError::database())?;

    let persisted_event = load_event_by_id(transaction, &event.event_id)?
        .ok_or_else(CapabilityAuthorizationError::database)?;
    let persisted_authorization =
        load_authorization(transaction, &event.life_id, &event.capability_id)?
            .ok_or_else(CapabilityAuthorizationError::authorization_not_found)?;
    validate_event_state(&persisted_event)?;
    validate_authorization_state(&persisted_authorization)?;
    Ok(CapabilityAuthorizationUpdateOutcome::Applied {
        event: persisted_event,
        authorization: persisted_authorization,
    })
}

impl CapabilityAuthorizationRepository for StorageService {
    fn create_capability_authorization(
        &self,
        request: LifeCapabilityAuthorizationCreateRequest,
    ) -> Result<CapabilityAuthorizationCreateOutcome, CapabilityAuthorizationError> {
        let mut state = self
            .state()
            .map_err(|_| CapabilityAuthorizationError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CapabilityAuthorizationError::database())?;
        let outcome = create_authorization_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| CapabilityAuthorizationError::database())?;
        Ok(outcome)
    }

    fn find_capability_authorization(
        &self,
        life_id: &str,
        capability_id: &CapabilityId,
    ) -> Result<Option<LifeCapabilityAuthorization>, CapabilityAuthorizationError> {
        validate_lookup_identity("life identity", life_id)?;
        let state = self
            .state()
            .map_err(|_| CapabilityAuthorizationError::database())?;
        let authorization = load_authorization(&state.connection, life_id, capability_id)?;
        if let Some(authorization) = &authorization {
            validate_authorization_state(authorization)?;
        }
        Ok(authorization)
    }

    fn update_capability_authorization(
        &self,
        request: LifeCapabilityAuthorizationUpdateRequest,
    ) -> Result<CapabilityAuthorizationUpdateOutcome, CapabilityAuthorizationError> {
        let mut state = self
            .state()
            .map_err(|_| CapabilityAuthorizationError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CapabilityAuthorizationError::database())?;
        let outcome = update_authorization_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| CapabilityAuthorizationError::database())?;
        Ok(outcome)
    }

    fn find_capability_authorization_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeCapabilityAuthorizationEvent>, CapabilityAuthorizationError> {
        validate_lookup_identity("life identity", life_id)?;
        validate_lookup_identity("authorization event identity", event_id)?;
        let state = self
            .state()
            .map_err(|_| CapabilityAuthorizationError::database())?;
        let event = state
            .connection
            .query_row(
                &format!(
                    "SELECT {EVENT_COLUMNS}
                     FROM life_capability_authorization_event
                     WHERE life_id = ?1 AND event_id = ?2"
                ),
                params![life_id, event_id],
                read_event,
            )
            .optional()
            .map_err(|_| CapabilityAuthorizationError::database())?;
        if let Some(event) = &event {
            validate_event_state(event)?;
        }
        Ok(event)
    }
}

/// Exact normalized validation of the Schema-30 D28 objects. Validation is
/// read-only and never repairs malformed database state.
pub(super) fn validate_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    for (object_kind, object_name, expected_sql) in [
        (
            "table",
            "life_capability_authorization",
            CREATE_AUTHORIZATION_TABLE_SQL,
        ),
        (
            "table",
            "life_capability_authorization_event",
            CREATE_EVENT_TABLE_SQL,
        ),
        (
            "trigger",
            "life_capability_authorization_immutable_guard",
            CREATE_AUTHORIZATION_IMMUTABLE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "life_capability_authorization_event_immutable_guard",
            CREATE_EVENT_IMMUTABLE_TRIGGER_SQL,
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![object_kind, object_name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StorageError::migration_transaction_failed())?;
        let Some(actual) = actual else {
            return Err(StorageError::migration_transaction_failed());
        };
        if normalize_schema_sql(&actual) != normalize_schema_sql(expected_sql) {
            return Err(StorageError::migration_transaction_failed());
        }
    }

    let authorization_columns = read_columns(connection, "life_capability_authorization")?;
    if authorization_columns
        .iter()
        .map(|column| column.as_str())
        .collect::<Vec<_>>()
        != [
            "life_id",
            "capability_id",
            "enabled",
            "revision",
            "created_at",
            "updated_at",
        ]
    {
        return Err(StorageError::migration_transaction_failed());
    }
    let event_columns = read_columns(connection, "life_capability_authorization_event")?;
    if event_columns
        .iter()
        .map(|column| column.as_str())
        .collect::<Vec<_>>()
        != [
            "event_id",
            "life_id",
            "capability_id",
            "old_enabled",
            "new_enabled",
            "old_revision",
            "new_revision",
            "changed_at",
        ]
    {
        return Err(StorageError::migration_transaction_failed());
    }

    for (child, parent, from, to) in [
        (
            "life_capability_authorization",
            "life_identity",
            "life_id",
            "id",
        ),
        (
            "life_capability_authorization_event",
            "life_capability_authorization",
            "life_id",
            "life_id",
        ),
    ] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)
                 WHERE \"table\" = ?2 AND \"from\" = ?3 AND \"to\" = ?4
                   AND on_delete = 'CASCADE'",
                params![child, parent, from, to],
                |row| row.get(0),
            )
            .map_err(|_| StorageError::migration_transaction_failed())?;
        if count != 1 {
            return Err(StorageError::migration_transaction_failed());
        }
    }

    let index_meta: Option<(bool, String)> = connection
        .query_row(
            "SELECT \"unique\", origin FROM pragma_index_list('life_capability_authorization')
             WHERE name='idx_life_capability_authorization_capability'",
            [],
            |row| Ok((row.get::<_, i64>(0)? == 1, row.get(1)?)),
        )
        .optional()
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if index_meta != Some((false, "c".to_string())) {
        return Err(StorageError::migration_transaction_failed());
    }
    let index_columns: Vec<String> = connection
        .prepare("PRAGMA index_info(idx_life_capability_authorization_capability)")
        .map_err(|_| StorageError::migration_transaction_failed())?
        .query_map([], |row| row.get(2))
        .map_err(|_| StorageError::migration_transaction_failed())?
        .collect::<Result<_, _>>()
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if index_columns != ["capability_id"] {
        return Err(StorageError::migration_transaction_failed());
    }
    Ok(())
}

fn read_columns(connection: &Connection, table: &str) -> Result<Vec<String>, StorageError> {
    connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|_| StorageError::migration_transaction_failed())?
        .query_map([], |row| row.get(1))
        .map_err(|_| StorageError::migration_transaction_failed())?
        .collect::<Result<_, _>>()
        .map_err(|_| StorageError::migration_transaction_failed())
}

fn normalize_schema_sql(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(';')
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase())
        .map(char::from)
        .collect()
}

const _: fn(&Connection) -> Result<(), StorageError> = validate_schema_objects;

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::{
        capability::{
            authorization::{
                evaluate_capability_authorization, CapabilityAuthorizationDecisionCode,
                CapabilityAuthorizationDecisionKind, CapabilityAuthorizationErrorCode,
                CapabilityAuthorizationRepository, CapabilityAuthorizationUpdateOutcome,
                LifeCapabilityAuthorizationCreateRequest, LifeCapabilityAuthorizationUpdateRequest,
                RequestedCapabilityScope,
            },
            descriptor::{
                ApprovalFloor, CapabilityDescriptor, CapabilityId, CapabilityRegistry, RiskClass,
                ScopeRequirement,
            },
        },
        storage::{LifeIdentityRecord, PersonaTemplateRecord},
    };

    struct Fixture {
        _root: TempDir,
        storage: StorageService,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let storage =
                StorageService::initialize_with_roots(root.path().to_path_buf(), None).unwrap();
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "d28-persona".into(),
                    name: "D28 Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            storage
                .save_life(LifeIdentityRecord {
                    id: "d28-life".into(),
                    name: "D28 Life".into(),
                    created_at: "2026-09-01T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "d28-body".into(),
                    persona_id: "d28-persona".into(),
                    persona_version: 1,
                })
                .unwrap();
            Self {
                _root: root,
                storage,
            }
        }

        fn capability_id(&self) -> CapabilityId {
            CapabilityId::try_from("test.one").unwrap()
        }

        fn create(&self) {
            let outcome = self
                .storage
                .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                    life_id: "d28-life".into(),
                    capability_id: self.capability_id(),
                })
                .unwrap();
            match outcome {
                CapabilityAuthorizationCreateOutcome::Applied(row) => {
                    assert!(!row.enabled);
                    assert_eq!(row.revision, 1);
                }
                CapabilityAuthorizationCreateOutcome::Replayed(_) => {
                    panic!("the first D28 root creation must apply")
                }
            }
        }

        fn update(
            &self,
            event_id: &str,
            enabled: bool,
            expected_revision: i64,
        ) -> Result<CapabilityAuthorizationUpdateOutcome, CapabilityAuthorizationError> {
            self.storage
                .update_capability_authorization(LifeCapabilityAuthorizationUpdateRequest {
                    event_id: event_id.into(),
                    life_id: "d28-life".into(),
                    capability_id: self.capability_id(),
                    enabled,
                    expected_revision,
                })
        }
    }

    #[test]
    fn root_is_missing_by_default_and_creation_is_disabled_revision_one_and_replayable() {
        let fixture = Fixture::new();
        assert!(fixture
            .storage
            .find_capability_authorization("d28-life", &fixture.capability_id())
            .unwrap()
            .is_none());
        fixture.create();
        let replay = fixture
            .storage
            .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                life_id: "d28-life".into(),
                capability_id: fixture.capability_id(),
            })
            .unwrap();
        assert!(matches!(
            replay,
            CapabilityAuthorizationCreateOutcome::Replayed(_)
        ));
    }

    #[test]
    fn explicit_cas_update_records_immutable_event_and_exact_replay() {
        let fixture = Fixture::new();
        fixture.create();
        let applied = fixture.update("d28-event-enable", true, 1).unwrap();
        let event = match &applied {
            CapabilityAuthorizationUpdateOutcome::Applied {
                event,
                authorization,
            } => {
                assert_eq!(authorization.revision, 2);
                assert!(authorization.enabled);
                event.clone()
            }
            CapabilityAuthorizationUpdateOutcome::Replayed { .. } => {
                panic!("the first D28 update must apply")
            }
        };
        assert!(!event.old_enabled);
        assert!(event.new_enabled);
        assert_eq!((event.old_revision, event.new_revision), (1, 2));
        assert_eq!(
            fixture
                .storage
                .find_capability_authorization_event("d28-life", "d28-event-enable")
                .unwrap()
                .unwrap(),
            event
        );
        let replay = fixture.update("d28-event-enable", true, 1).unwrap();
        match replay {
            CapabilityAuthorizationUpdateOutcome::Replayed {
                event: replayed,
                current,
            } => {
                assert_eq!(replayed, event);
                assert!(current.enabled);
                assert_eq!(current.revision, 2);
            }
            CapabilityAuthorizationUpdateOutcome::Applied { .. } => {
                panic!("exact D28 event evidence must replay")
            }
        }
        let disabled = fixture.update("d28-event-disable", false, 2).unwrap();
        match disabled {
            CapabilityAuthorizationUpdateOutcome::Applied {
                event,
                authorization,
            } => {
                assert!(event.old_enabled);
                assert!(!event.new_enabled);
                assert_eq!((event.old_revision, event.new_revision), (2, 3));
                assert!(!authorization.enabled);
                assert_eq!(authorization.revision, 3);
            }
            CapabilityAuthorizationUpdateOutcome::Replayed { .. } => {
                panic!("the D28 disable transition must apply")
            }
        }
        let conflict = fixture.update("d28-event-enable", false, 1).unwrap_err();
        assert_eq!(
            conflict.code,
            CapabilityAuthorizationErrorCode::EventConflict
        );
        let state = fixture.storage.state().unwrap();
        let immutable_error = state
            .connection
            .execute(
                "UPDATE life_capability_authorization_event
                 SET new_enabled = old_enabled
                 WHERE event_id='d28-event-enable'",
                [],
            )
            .unwrap_err();
        assert!(immutable_error
            .to_string()
            .contains("LIFE_CAPABILITY_AUTHORIZATION_EVENT_IMMUTABLE"));
    }

    #[test]
    fn no_op_and_stale_revision_updates_are_rejected_without_extra_events() {
        let fixture = Fixture::new();
        fixture.create();
        assert_eq!(
            fixture
                .update("d28-event-no-op", false, 1)
                .unwrap_err()
                .code,
            CapabilityAuthorizationErrorCode::InvalidTransition
        );
        fixture.update("d28-event-enable", true, 1).unwrap();
        assert_eq!(
            fixture
                .update("d28-event-stale", false, 1)
                .unwrap_err()
                .code,
            CapabilityAuthorizationErrorCode::RevisionConflict
        );
        let state = fixture.storage.state().unwrap();
        let event_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM life_capability_authorization_event",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 1);
    }

    #[test]
    fn evaluator_reads_fresh_sqlite_state_and_returns_current_revision_evidence() {
        let fixture = Fixture::new();
        fixture.create();
        let descriptor = CapabilityDescriptor::new(
            fixture.capability_id(),
            "Synthetic capability",
            RiskClass::Low,
            ApprovalFloor::RootEnabled,
            ScopeRequirement::None,
        )
        .unwrap();
        let registry = CapabilityRegistry::from_trusted_descriptors([descriptor.clone()]).unwrap();

        let disabled = evaluate_capability_authorization(
            &fixture.storage,
            &registry,
            "d28-life",
            &descriptor,
            RequestedCapabilityScope::None,
        )
        .unwrap();
        assert_eq!(
            disabled.outcome,
            CapabilityAuthorizationDecisionKind::RootDisabled
        );
        assert_eq!(disabled.authorization_revision, Some(1));

        fixture.update("d28-event-enable", true, 1).unwrap();
        let enabled = evaluate_capability_authorization(
            &fixture.storage,
            &registry,
            "d28-life",
            &descriptor,
            RequestedCapabilityScope::None,
        )
        .unwrap();
        assert_eq!(
            enabled.outcome,
            CapabilityAuthorizationDecisionKind::Eligible
        );
        assert_eq!(
            enabled.decision_code,
            CapabilityAuthorizationDecisionCode::Eligible
        );
        assert_eq!(enabled.authorization_revision, Some(2));

        fixture.update("d28-event-disable", false, 2).unwrap();
        let disabled_again = evaluate_capability_authorization(
            &fixture.storage,
            &registry,
            "d28-life",
            &descriptor,
            RequestedCapabilityScope::None,
        )
        .unwrap();
        assert_eq!(
            disabled_again.outcome,
            CapabilityAuthorizationDecisionKind::RootDisabled
        );
        assert_eq!(disabled_again.authorization_revision, Some(3));
    }

    #[test]
    fn unknown_life_and_orphan_event_are_rejected_by_sqlite_ownership() {
        let fixture = Fixture::new();
        let error = fixture
            .storage
            .create_capability_authorization(LifeCapabilityAuthorizationCreateRequest {
                life_id: "missing-life".into(),
                capability_id: fixture.capability_id(),
            })
            .unwrap_err();
        assert_eq!(error.code, CapabilityAuthorizationErrorCode::LifeNotFound);
        let state = fixture.storage.state().unwrap();
        assert!(state
            .connection
            .execute(
                "INSERT INTO life_capability_authorization_event
                 (event_id, life_id, capability_id, old_enabled, new_enabled,
                  old_revision, new_revision, changed_at)
                 VALUES ('orphan', 'missing-life', 'test.one', 0, 1, 1, 2, 'now')",
                [],
            )
            .is_err());
    }

    #[test]
    fn schema_validator_is_exact_and_audit_rows_have_no_prompt_or_model_fields() {
        let fixture = Fixture::new();
        let state = fixture.storage.state().unwrap();
        validate_schema_objects(&state.connection).unwrap();
        for forbidden in [
            "prompt",
            "reasoning",
            "credential",
            "tool_args",
            "raw_command",
            "secret",
            "json",
        ] {
            let count: i64 = state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('life_capability_authorization_event')
                     WHERE lower(name) LIKE ?1",
                    [format!("%{forbidden}%")],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "event schema must not contain {forbidden}");
        }
    }
}
