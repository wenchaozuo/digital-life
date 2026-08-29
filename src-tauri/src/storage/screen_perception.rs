//! SQLite-authoritative persistence for the D23-B1 screen-perception consent
//! policy.
//!
//! The repository stores consent evidence only.  It does not observe or
//! capture a screen, persist observations or capture targets, or expose a
//! generic capability grant.  Policy state and its immutable event are changed
//! in one IMMEDIATE transaction under the existing storage writer capability.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};

use super::StorageService;
use crate::perception::screen_policy::{
    validate_screen_perception_policy_create_request,
    validate_screen_perception_policy_event_state, validate_screen_perception_policy_state,
    validate_screen_perception_policy_update_request, LifeScreenPerceptionPolicy,
    LifeScreenPerceptionPolicyCreateRequest, LifeScreenPerceptionPolicyEvent,
    LifeScreenPerceptionPolicyUpdateOutcome, LifeScreenPerceptionPolicyUpdateRequest,
    ScreenPerceptionCreateOutcome, ScreenPerceptionError, ScreenPerceptionRepository,
    SCREEN_PERCEPTION_POLICY_ACTOR_KIND_USER_EXPLICIT, SCREEN_PERCEPTION_POLICY_EVENT_VERSION,
    SCREEN_PERCEPTION_POLICY_VERSION,
};

pub(super) const CREATE_LIFE_SCREEN_PERCEPTION_POLICY_TABLE_SQL: &str =
    include_str!("migrations/027_screen_perception_authority.life_screen_perception_policy.sql");
pub(super) const CREATE_LIFE_SCREEN_PERCEPTION_POLICY_EVENT_TABLE_SQL: &str = include_str!(
    "migrations/027_screen_perception_authority.life_screen_perception_policy_event.sql"
);
pub(super) const CREATE_LIFE_SCREEN_PERCEPTION_POLICY_IMMUTABLE_TRIGGER_SQL: &str = include_str!(
    "migrations/027_screen_perception_authority.life_screen_perception_policy_immutable_trigger.sql"
);
pub(super) const CREATE_LIFE_SCREEN_PERCEPTION_POLICY_EVENT_IMMUTABLE_TRIGGER_SQL: &str =
    include_str!(
        "migrations/027_screen_perception_authority.life_screen_perception_policy_event_immutable_trigger.sql"
    );

pub(super) const MIGRATION_027_TABLE_SQLS: &[&str] = &[
    CREATE_LIFE_SCREEN_PERCEPTION_POLICY_TABLE_SQL,
    CREATE_LIFE_SCREEN_PERCEPTION_POLICY_EVENT_TABLE_SQL,
];

pub(super) const MIGRATION_027_TRIGGER_SQLS: &[&str] = &[
    CREATE_LIFE_SCREEN_PERCEPTION_POLICY_IMMUTABLE_TRIGGER_SQL,
    CREATE_LIFE_SCREEN_PERCEPTION_POLICY_EVENT_IMMUTABLE_TRIGGER_SQL,
];

const POLICY_COLUMNS: &str =
    "life_id, screen_perception_enabled, revision, created_at, updated_at, policy_version";
const POLICY_EVENT_COLUMNS: &str = "event_id, life_id, old_screen_perception_enabled, new_screen_perception_enabled, expected_revision, applied_revision, actor_kind, occurred_at, event_version";

fn read_policy(row: &Row<'_>) -> rusqlite::Result<LifeScreenPerceptionPolicy> {
    Ok(LifeScreenPerceptionPolicy {
        life_id: row.get(0)?,
        screen_perception_enabled: row.get::<_, bool>(1)?,
        revision: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        policy_version: row.get(5)?,
    })
}

fn read_policy_event(row: &Row<'_>) -> rusqlite::Result<LifeScreenPerceptionPolicyEvent> {
    Ok(LifeScreenPerceptionPolicyEvent {
        event_id: row.get(0)?,
        life_id: row.get(1)?,
        old_screen_perception_enabled: row.get::<_, bool>(2)?,
        new_screen_perception_enabled: row.get::<_, bool>(3)?,
        expected_revision: row.get(4)?,
        applied_revision: row.get(5)?,
        actor_kind: row.get(6)?,
        occurred_at: row.get(7)?,
        event_version: row.get(8)?,
    })
}

fn validate_lookup_argument(name: &str, value: &str) -> Result<(), ScreenPerceptionError> {
    if value.trim().is_empty() {
        return Err(ScreenPerceptionError::invalid_argument(format!(
            "{name} must not be empty."
        )));
    }
    Ok(())
}

fn validate_lookup_arguments(
    life_id: &str,
    entity_name: &str,
    entity_id: &str,
) -> Result<(), ScreenPerceptionError> {
    validate_lookup_argument("life identity", life_id)?;
    validate_lookup_argument(entity_name, entity_id)
}

fn sqlite_authority_now(connection: &Connection) -> Result<String, ScreenPerceptionError> {
    connection
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| ScreenPerceptionError::database())
}

fn next_revision(expected_revision: i64) -> Result<i64, ScreenPerceptionError> {
    expected_revision.checked_add(1).ok_or_else(|| {
        ScreenPerceptionError::invalid_argument("the target revision is unrepresentable.")
    })
}

fn load_policy(
    connection: &Connection,
    life_id: &str,
) -> Result<Option<LifeScreenPerceptionPolicy>, ScreenPerceptionError> {
    connection
        .query_row(
            &format!(
                "SELECT {POLICY_COLUMNS} FROM life_screen_perception_policy WHERE life_id = ?1"
            ),
            [life_id],
            read_policy,
        )
        .optional()
        .map_err(|_| ScreenPerceptionError::database())
}

fn load_policy_event_by_id(
    connection: &Connection,
    event_id: &str,
) -> Result<Option<LifeScreenPerceptionPolicyEvent>, ScreenPerceptionError> {
    connection
        .query_row(
            &format!(
                "SELECT {POLICY_EVENT_COLUMNS} FROM life_screen_perception_policy_event
                 WHERE event_id = ?1"
            ),
            [event_id],
            read_policy_event,
        )
        .optional()
        .map_err(|_| ScreenPerceptionError::database())
}

fn policy_create_evidence_matches(
    policy: &LifeScreenPerceptionPolicy,
    request: &LifeScreenPerceptionPolicyCreateRequest,
) -> bool {
    policy.life_id == request.life_id
        && policy.screen_perception_enabled == request.screen_perception_enabled
}

fn policy_event_evidence_matches(
    event: &LifeScreenPerceptionPolicyEvent,
    request: &LifeScreenPerceptionPolicyUpdateRequest,
    applied_revision: i64,
) -> bool {
    event.event_id == request.event_id
        && event.life_id == request.life_id
        && event.new_screen_perception_enabled == request.screen_perception_enabled
        && event.expected_revision == request.expected_revision
        && event.applied_revision == applied_revision
        && event.actor_kind == SCREEN_PERCEPTION_POLICY_ACTOR_KIND_USER_EXPLICIT
        && event.event_version == SCREEN_PERCEPTION_POLICY_EVENT_VERSION
}

fn require_life(transaction: &Transaction<'_>, life_id: &str) -> Result<(), ScreenPerceptionError> {
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
            [life_id],
            |row| row.get(0),
        )
        .map_err(|_| ScreenPerceptionError::database())?;
    if !exists {
        return Err(ScreenPerceptionError::life_not_found());
    }
    Ok(())
}

fn create_policy_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeScreenPerceptionPolicyCreateRequest,
) -> Result<ScreenPerceptionCreateOutcome<LifeScreenPerceptionPolicy>, ScreenPerceptionError> {
    validate_screen_perception_policy_create_request(&request)?;

    // The policy identity is resolved before checking whether the referenced
    // Life exists, preserving create replay/conflict precedence.
    if let Some(existing) = transaction
        .query_row(
            &format!(
                "SELECT {POLICY_COLUMNS} FROM life_screen_perception_policy WHERE life_id = ?1"
            ),
            [&request.life_id],
            read_policy,
        )
        .optional()
        .map_err(|_| ScreenPerceptionError::database())?
    {
        if policy_create_evidence_matches(&existing, &request) {
            validate_screen_perception_policy_state(&existing)?;
            return Ok(ScreenPerceptionCreateOutcome::Replayed(existing));
        }
        return Err(ScreenPerceptionError::policy_conflict());
    }

    require_life(transaction, &request.life_id)?;
    let now = sqlite_authority_now(transaction)?;
    transaction
        .execute(
            "INSERT INTO life_screen_perception_policy
             (life_id, screen_perception_enabled, revision, created_at, updated_at, policy_version)
             VALUES (?1, ?2, 1, ?3, ?3, ?4)",
            params![
                &request.life_id,
                request.screen_perception_enabled,
                &now,
                SCREEN_PERCEPTION_POLICY_VERSION,
            ],
        )
        .map_err(map_database_error)?;

    let created = transaction
        .query_row(
            &format!(
                "SELECT {POLICY_COLUMNS} FROM life_screen_perception_policy WHERE life_id = ?1"
            ),
            [&request.life_id],
            read_policy,
        )
        .map_err(|_| ScreenPerceptionError::database())?;
    validate_screen_perception_policy_state(&created)?;
    Ok(ScreenPerceptionCreateOutcome::Applied(created))
}

fn update_policy_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeScreenPerceptionPolicyUpdateRequest,
) -> Result<LifeScreenPerceptionPolicyUpdateOutcome, ScreenPerceptionError> {
    validate_screen_perception_policy_update_request(&request)?;
    let applied_revision = next_revision(request.expected_revision)?;

    // Event identity is authoritative replay evidence and is intentionally
    // checked before the current policy revision.
    if let Some(existing_event) = load_policy_event_by_id(transaction, &request.event_id)? {
        if policy_event_evidence_matches(&existing_event, &request, applied_revision) {
            let current = load_policy(transaction, &request.life_id)?
                .ok_or_else(ScreenPerceptionError::policy_not_found)?;
            validate_screen_perception_policy_event_state(&existing_event)?;
            validate_screen_perception_policy_state(&current)?;
            return Ok(LifeScreenPerceptionPolicyUpdateOutcome::Replayed {
                event: existing_event,
                current,
            });
        }
        return Err(ScreenPerceptionError::policy_event_conflict());
    }

    let current = load_policy(transaction, &request.life_id)?
        .ok_or_else(ScreenPerceptionError::policy_not_found)?;
    validate_screen_perception_policy_state(&current)?;
    if current.revision != request.expected_revision {
        return Err(ScreenPerceptionError::revision_conflict());
    }
    if current.screen_perception_enabled == request.screen_perception_enabled {
        return Err(ScreenPerceptionError::invalid_transition());
    }

    let now = sqlite_authority_now(transaction)?;
    let changed = transaction
        .execute(
            "UPDATE life_screen_perception_policy
             SET screen_perception_enabled = ?1,
                 revision = ?2,
                 updated_at = ?3
             WHERE life_id = ?4
               AND revision = ?5
               AND screen_perception_enabled = ?6",
            params![
                request.screen_perception_enabled,
                applied_revision,
                &now,
                &request.life_id,
                request.expected_revision,
                current.screen_perception_enabled,
            ],
        )
        .map_err(map_database_error)?;
    if changed != 1 {
        return Err(ScreenPerceptionError::revision_conflict());
    }

    let event = LifeScreenPerceptionPolicyEvent {
        event_id: request.event_id,
        life_id: request.life_id,
        old_screen_perception_enabled: current.screen_perception_enabled,
        new_screen_perception_enabled: request.screen_perception_enabled,
        expected_revision: request.expected_revision,
        applied_revision,
        actor_kind: SCREEN_PERCEPTION_POLICY_ACTOR_KIND_USER_EXPLICIT.to_string(),
        occurred_at: now,
        event_version: SCREEN_PERCEPTION_POLICY_EVENT_VERSION,
    };
    validate_screen_perception_policy_event_state(&event)?;
    transaction
        .execute(
            &format!(
                "INSERT INTO life_screen_perception_policy_event ({POLICY_EVENT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
            ),
            params![
                &event.event_id,
                &event.life_id,
                event.old_screen_perception_enabled,
                event.new_screen_perception_enabled,
                event.expected_revision,
                event.applied_revision,
                &event.actor_kind,
                &event.occurred_at,
                event.event_version,
            ],
        )
        .map_err(map_database_error)?;

    let persisted_event = load_policy_event_by_id(transaction, &event.event_id)?
        .ok_or_else(ScreenPerceptionError::database)?;
    let persisted_policy = load_policy(transaction, &event.life_id)?
        .ok_or_else(ScreenPerceptionError::policy_not_found)?;
    validate_screen_perception_policy_event_state(&persisted_event)?;
    validate_screen_perception_policy_state(&persisted_policy)?;
    Ok(LifeScreenPerceptionPolicyUpdateOutcome::Applied {
        event: persisted_event,
        policy: persisted_policy,
    })
}

impl ScreenPerceptionRepository for StorageService {
    fn create_screen_perception_policy(
        &self,
        request: LifeScreenPerceptionPolicyCreateRequest,
    ) -> Result<ScreenPerceptionCreateOutcome<LifeScreenPerceptionPolicy>, ScreenPerceptionError>
    {
        let mut state = self
            .state()
            .map_err(|_| ScreenPerceptionError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ScreenPerceptionError::database())?;
        let outcome = create_policy_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| ScreenPerceptionError::database())?;
        Ok(outcome)
    }

    fn find_screen_perception_policy(
        &self,
        life_id: &str,
    ) -> Result<Option<LifeScreenPerceptionPolicy>, ScreenPerceptionError> {
        validate_lookup_argument("life identity", life_id)?;
        let state = self
            .state()
            .map_err(|_| ScreenPerceptionError::database())?;
        let policy = load_policy(&state.connection, life_id)?;
        if let Some(policy) = &policy {
            validate_screen_perception_policy_state(policy)?;
        }
        Ok(policy)
    }

    fn update_screen_perception_policy(
        &self,
        request: LifeScreenPerceptionPolicyUpdateRequest,
    ) -> Result<LifeScreenPerceptionPolicyUpdateOutcome, ScreenPerceptionError> {
        let mut state = self
            .state()
            .map_err(|_| ScreenPerceptionError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ScreenPerceptionError::database())?;
        let outcome = update_policy_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| ScreenPerceptionError::database())?;
        Ok(outcome)
    }

    fn find_screen_perception_policy_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeScreenPerceptionPolicyEvent>, ScreenPerceptionError> {
        validate_lookup_arguments(life_id, "policy event identity", event_id)?;
        let state = self
            .state()
            .map_err(|_| ScreenPerceptionError::database())?;
        let event = state
            .connection
            .query_row(
                &format!(
                    "SELECT {POLICY_EVENT_COLUMNS} FROM life_screen_perception_policy_event
                     WHERE life_id = ?1 AND event_id = ?2"
                ),
                params![life_id, event_id],
                read_policy_event,
            )
            .optional()
            .map_err(|_| ScreenPerceptionError::database())?;
        if let Some(event) = &event {
            validate_screen_perception_policy_event_state(event)?;
        }
        Ok(event)
    }
}

const _: for<'a> fn(
    &'a StorageService,
    LifeScreenPerceptionPolicyCreateRequest,
) -> Result<
    ScreenPerceptionCreateOutcome<LifeScreenPerceptionPolicy>,
    ScreenPerceptionError,
> = <StorageService as ScreenPerceptionRepository>::create_screen_perception_policy;
const _: for<'a> fn(
    &'a StorageService,
    LifeScreenPerceptionPolicyUpdateRequest,
) -> Result<LifeScreenPerceptionPolicyUpdateOutcome, ScreenPerceptionError> =
    <StorageService as ScreenPerceptionRepository>::update_screen_perception_policy;

/// Exact normalized validation of the Schema27 D23-B1 objects.  The validator
/// keeps the migration fail-closed without installing or repairing anything.
pub(super) fn validate_schema_objects(connection: &Connection) -> Result<(), super::StorageError> {
    for (object_kind, object_name, expected_sql) in [
        (
            "table",
            "life_screen_perception_policy",
            CREATE_LIFE_SCREEN_PERCEPTION_POLICY_TABLE_SQL,
        ),
        (
            "table",
            "life_screen_perception_policy_event",
            CREATE_LIFE_SCREEN_PERCEPTION_POLICY_EVENT_TABLE_SQL,
        ),
        (
            "trigger",
            "life_screen_perception_policy_immutable_guard",
            CREATE_LIFE_SCREEN_PERCEPTION_POLICY_IMMUTABLE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "life_screen_perception_policy_event_immutable_guard",
            CREATE_LIFE_SCREEN_PERCEPTION_POLICY_EVENT_IMMUTABLE_TRIGGER_SQL,
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![object_kind, object_name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| super::StorageError::migration_transaction_failed())?;
        let Some(actual) = actual else {
            return Err(super::StorageError::migration_transaction_failed());
        };
        if normalize_schema_sql(&actual) != normalize_schema_sql(expected_sql) {
            return Err(super::StorageError::migration_transaction_failed());
        }
    }

    for (child_table, parent_table, from_column, to_column) in [
        (
            "life_screen_perception_policy",
            "life_identity",
            "life_id",
            "id",
        ),
        (
            "life_screen_perception_policy_event",
            "life_screen_perception_policy",
            "life_id",
            "life_id",
        ),
    ] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)
                 WHERE \"table\" = ?2 AND \"from\" = ?3 AND \"to\" = ?4
                   AND on_delete = 'CASCADE'",
                params![child_table, parent_table, from_column, to_column],
                |row| row.get(0),
            )
            .map_err(|_| super::StorageError::migration_transaction_failed())?;
        if count != 1 {
            return Err(super::StorageError::migration_transaction_failed());
        }
    }
    Ok(())
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

fn map_database_error(_error: rusqlite::Error) -> ScreenPerceptionError {
    ScreenPerceptionError::database()
}

const _: fn(&Connection) -> Result<(), super::StorageError> = validate_schema_objects;

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use tempfile::TempDir;

    use super::*;
    use crate::{
        perception::screen_policy::{
            LifeScreenPerceptionPolicyCreateRequest, LifeScreenPerceptionPolicyUpdateRequest,
            ScreenPerceptionErrorCode,
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
                    id: "screen-persona".into(),
                    name: "Screen Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            for (id, name, body_id, created_at) in [
                (
                    "screen-life-a",
                    "Screen Life A",
                    "screen-body-a",
                    "2026-08-27T00:00:00.000Z",
                ),
                (
                    "screen-life-b",
                    "Screen Life B",
                    "screen-body-b",
                    "2026-08-27T00:00:01.000Z",
                ),
            ] {
                storage
                    .save_life(LifeIdentityRecord {
                        id: id.into(),
                        name: name.into(),
                        created_at: created_at.into(),
                        version: 1,
                        body_id: body_id.into(),
                        persona_id: "screen-persona".into(),
                        persona_version: 1,
                    })
                    .unwrap();
            }
            Self {
                _root: root,
                storage,
            }
        }

        fn create(&self, life_id: &str, enabled: bool) -> LifeScreenPerceptionPolicy {
            match self
                .storage
                .create_screen_perception_policy(LifeScreenPerceptionPolicyCreateRequest {
                    life_id: life_id.into(),
                    screen_perception_enabled: enabled,
                })
                .unwrap()
            {
                ScreenPerceptionCreateOutcome::Applied(policy) => policy,
                ScreenPerceptionCreateOutcome::Replayed(_) => {
                    panic!("the first screen policy create must apply")
                }
            }
        }

        fn update(
            &self,
            event_id: &str,
            life_id: &str,
            enabled: bool,
            expected_revision: i64,
        ) -> Result<LifeScreenPerceptionPolicyUpdateOutcome, ScreenPerceptionError> {
            self.storage
                .update_screen_perception_policy(LifeScreenPerceptionPolicyUpdateRequest {
                    event_id: event_id.into(),
                    life_id: life_id.into(),
                    screen_perception_enabled: enabled,
                    expected_revision,
                })
        }
    }

    #[test]
    fn create_supports_enabled_disabled_no_row_replay_conflict_and_missing_life() {
        let fixture = Fixture::new();
        assert!(fixture
            .storage
            .find_screen_perception_policy("screen-life-a")
            .unwrap()
            .is_none());

        let enabled = fixture.create("screen-life-a", true);
        assert!(enabled.is_screen_perception_enabled());
        assert_eq!(enabled.revision, 1);
        assert_eq!(enabled.created_at, enabled.updated_at);
        assert_eq!(enabled.policy_version, SCREEN_PERCEPTION_POLICY_VERSION);

        let disabled = fixture.create("screen-life-b", false);
        assert!(!disabled.is_screen_perception_enabled());
        assert_eq!(disabled.revision, 1);

        let replay = fixture
            .storage
            .create_screen_perception_policy(LifeScreenPerceptionPolicyCreateRequest {
                life_id: "screen-life-a".into(),
                screen_perception_enabled: true,
            })
            .unwrap();
        assert_eq!(
            replay,
            ScreenPerceptionCreateOutcome::Replayed(enabled.clone())
        );

        let conflict = fixture
            .storage
            .create_screen_perception_policy(LifeScreenPerceptionPolicyCreateRequest {
                life_id: "screen-life-a".into(),
                screen_perception_enabled: false,
            })
            .unwrap_err();
        assert_eq!(
            conflict.code,
            ScreenPerceptionErrorCode::ScreenPerceptionPolicyConflict
        );

        let missing_life = fixture
            .storage
            .create_screen_perception_policy(LifeScreenPerceptionPolicyCreateRequest {
                life_id: "screen-life-missing".into(),
                screen_perception_enabled: true,
            })
            .unwrap_err();
        assert_eq!(missing_life.code, ScreenPerceptionErrorCode::LifeNotFound);
    }

    #[test]
    fn updates_cover_both_directions_timestamp_authority_replay_conflict_and_cas() {
        let fixture = Fixture::new();
        fixture.create("screen-life-a", false);

        let applied = fixture
            .update("screen-event-1", "screen-life-a", true, 1)
            .unwrap();
        let (event, policy) = match applied {
            LifeScreenPerceptionPolicyUpdateOutcome::Applied { event, policy } => (event, policy),
            LifeScreenPerceptionPolicyUpdateOutcome::Replayed { .. } => {
                panic!("the first screen update must apply")
            }
        };
        assert!(!event.old_screen_perception_enabled);
        assert!(event.new_screen_perception_enabled);
        assert_eq!(event.expected_revision, 1);
        assert_eq!(event.applied_revision, 2);
        assert_eq!(policy.revision, 2);
        assert_eq!(policy.updated_at, event.occurred_at);

        let replay = fixture
            .update("screen-event-1", "screen-life-a", true, 1)
            .unwrap();
        match replay {
            LifeScreenPerceptionPolicyUpdateOutcome::Replayed {
                event: replayed,
                current,
            } => {
                assert_eq!(replayed, event);
                assert_eq!(current.revision, 2);
                assert!(current.screen_perception_enabled);
            }
            LifeScreenPerceptionPolicyUpdateOutcome::Applied { .. } => {
                panic!("the same screen event evidence must replay")
            }
        }

        let event_conflict = fixture
            .update("screen-event-1", "screen-life-a", false, 1)
            .unwrap_err();
        assert_eq!(
            event_conflict.code,
            ScreenPerceptionErrorCode::ScreenPerceptionPolicyEventConflict
        );

        let stale = fixture
            .update("screen-event-stale", "screen-life-a", false, 1)
            .unwrap_err();
        assert_eq!(stale.code, ScreenPerceptionErrorCode::RevisionConflict);

        let no_op = fixture
            .update("screen-event-no-op", "screen-life-a", true, 2)
            .unwrap_err();
        assert_eq!(no_op.code, ScreenPerceptionErrorCode::InvalidTransition);

        let reverse = fixture
            .update("screen-event-2", "screen-life-a", false, 2)
            .unwrap();
        match reverse {
            LifeScreenPerceptionPolicyUpdateOutcome::Applied { event, policy } => {
                assert!(event.old_screen_perception_enabled);
                assert!(!event.new_screen_perception_enabled);
                assert_eq!(policy.revision, 3);
            }
            LifeScreenPerceptionPolicyUpdateOutcome::Replayed { .. } => {
                panic!("the reverse screen update must apply")
            }
        }

        let found = fixture
            .storage
            .find_screen_perception_policy_event("screen-life-a", "screen-event-2")
            .unwrap()
            .unwrap();
        assert_eq!(found.applied_revision, 3);
    }

    #[test]
    fn policy_and_event_immutability_leave_governed_update_open() {
        let fixture = Fixture::new();
        fixture.create("screen-life-a", false);
        fixture
            .update("screen-event-immutable", "screen-life-a", true, 1)
            .unwrap();
        let state = fixture.storage.state().unwrap();

        for sql in [
            "UPDATE life_screen_perception_policy SET life_id='screen-life-b' WHERE life_id='screen-life-a'",
            "UPDATE life_screen_perception_policy SET created_at='changed' WHERE life_id='screen-life-a'",
            "UPDATE life_screen_perception_policy SET policy_version=2 WHERE life_id='screen-life-a'",
        ] {
            let error = state.connection.execute(sql, []).unwrap_err();
            assert!(error
                .to_string()
                .contains("LIFE_SCREEN_PERCEPTION_POLICY_IMMUTABLE"));
        }
        let event_error = state
            .connection
            .execute(
                "UPDATE life_screen_perception_policy_event
                 SET new_screen_perception_enabled=0
                 WHERE event_id='screen-event-immutable'",
                [],
            )
            .unwrap_err();
        assert!(event_error
            .to_string()
            .contains("LIFE_SCREEN_PERCEPTION_POLICY_EVENT_IMMUTABLE"));
        drop(state);

        let governed = fixture
            .update("screen-event-governed", "screen-life-a", false, 2)
            .unwrap();
        assert!(matches!(
            governed,
            LifeScreenPerceptionPolicyUpdateOutcome::Applied { .. }
        ));
    }

    #[test]
    fn schema_shape_contains_only_consent_columns_and_no_observation_payload() {
        let fixture = Fixture::new();
        let state = fixture.storage.state().unwrap();
        let tables: Vec<String> = state
            .connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type='table' AND name LIKE 'life_screen_perception_%'
                 ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            tables,
            vec![
                "life_screen_perception_policy".to_string(),
                "life_screen_perception_policy_event".to_string()
            ]
        );

        let expected_columns = [
            (
                "life_screen_perception_policy",
                vec![
                    "life_id",
                    "screen_perception_enabled",
                    "revision",
                    "created_at",
                    "updated_at",
                    "policy_version",
                ],
            ),
            (
                "life_screen_perception_policy_event",
                vec![
                    "event_id",
                    "life_id",
                    "old_screen_perception_enabled",
                    "new_screen_perception_enabled",
                    "expected_revision",
                    "applied_revision",
                    "actor_kind",
                    "occurred_at",
                    "event_version",
                ],
            ),
        ];
        for (table, expected) in expected_columns {
            let mut statement = state
                .connection
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap();
            let columns: Vec<String> = statement
                .query_map([], |row| row.get(1))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(columns, expected);
        }

        let forbidden = [
            "pixel",
            "screenshot",
            "ocr",
            "window",
            "process",
            "pid",
            "hwnd",
            "clipboard",
            "camera",
            "microphone",
            "observation",
            "json",
            "focus_state",
            "target",
        ];
        for value in tables.iter().flat_map(|table| {
            let mut values = vec![table.clone()];
            let mut statement = state
                .connection
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap();
            values.extend(
                statement
                    .query_map([], |row| row.get::<_, String>(1))
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
            );
            values
        }) {
            let lower = value.to_ascii_lowercase();
            assert!(
                !forbidden.iter().any(|word| lower.contains(word)),
                "{value}"
            );
        }
    }

    #[test]
    fn concurrent_services_apply_one_revision_and_one_event() {
        let fixture = Fixture::new();
        fixture.create("screen-life-a", false);
        let root = fixture._root.path().to_path_buf();
        let Fixture { _root, storage } = fixture;
        let first = Arc::new(storage);
        let second = Arc::new(StorageService::initialize_with_roots(root, None).unwrap());
        let barrier = Arc::new(Barrier::new(3));

        let first_barrier = Arc::clone(&barrier);
        let first_service = Arc::clone(&first);
        let first_thread = thread::spawn(move || {
            first_barrier.wait();
            first_service.update_screen_perception_policy(LifeScreenPerceptionPolicyUpdateRequest {
                event_id: "screen-concurrent-a".into(),
                life_id: "screen-life-a".into(),
                screen_perception_enabled: true,
                expected_revision: 1,
            })
        });

        let second_barrier = Arc::clone(&barrier);
        let second_service = Arc::clone(&second);
        let second_thread = thread::spawn(move || {
            second_barrier.wait();
            second_service.update_screen_perception_policy(
                LifeScreenPerceptionPolicyUpdateRequest {
                    event_id: "screen-concurrent-b".into(),
                    life_id: "screen-life-a".into(),
                    screen_perception_enabled: true,
                    expected_revision: 1,
                },
            )
        });

        barrier.wait();
        let first_result = first_thread.join().unwrap();
        let second_result = second_thread.join().unwrap();
        let mut applied = 0;
        let mut conflicts = 0;
        for result in [first_result, second_result] {
            match result {
                Ok(LifeScreenPerceptionPolicyUpdateOutcome::Applied { .. }) => applied += 1,
                Err(error) if error.code == ScreenPerceptionErrorCode::RevisionConflict => {
                    conflicts += 1
                }
                other => panic!("unexpected concurrent result: {other:?}"),
            }
        }
        assert_eq!(applied, 1);
        assert_eq!(conflicts, 1);

        let policy = first
            .find_screen_perception_policy("screen-life-a")
            .unwrap()
            .unwrap();
        assert_eq!(policy.revision, 2);
        assert!(policy.screen_perception_enabled);
        let state = first.state().unwrap();
        let event_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM life_screen_perception_policy_event
                 WHERE life_id='screen-life-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 1);
        drop(state);
        drop(second);
        drop(_root);
    }

    #[test]
    fn event_insert_failure_rolls_back_policy_update_and_event() {
        let fixture = Fixture::new();
        fixture.create("screen-life-a", false);
        {
            let state = fixture.storage.state().unwrap();
            state
                .connection
                .execute_batch(
                    "CREATE TEMP TRIGGER screen_test_event_insert_failure
                     BEFORE INSERT ON life_screen_perception_policy_event
                     BEGIN
                         SELECT RAISE(ROLLBACK, 'D23_B1_TEST_EVENT_INSERT_FAILURE');
                     END;",
                )
                .unwrap();
        }

        let error = fixture
            .update("screen-event-failure", "screen-life-a", true, 1)
            .unwrap_err();
        assert_eq!(error.code, ScreenPerceptionErrorCode::DatabaseUnavailable);
        let policy = fixture
            .storage
            .find_screen_perception_policy("screen-life-a")
            .unwrap()
            .unwrap();
        assert!(!policy.screen_perception_enabled);
        assert_eq!(policy.revision, 1);
        let state = fixture.storage.state().unwrap();
        let event_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM life_screen_perception_policy_event
                 WHERE event_id='screen-event-failure'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 0);
    }

    #[test]
    fn deleting_life_cascades_policy_and_policy_events() {
        let fixture = Fixture::new();
        fixture.create("screen-life-a", false);
        fixture
            .update("screen-event-delete", "screen-life-a", true, 1)
            .unwrap();
        {
            let state = fixture.storage.state().unwrap();
            state
                .connection
                .execute("DELETE FROM life_identity WHERE id='screen-life-a'", [])
                .unwrap();
            let counts: (i64, i64) = state
                .connection
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM life_screen_perception_policy
                                  WHERE life_id='screen-life-a'),
                            (SELECT COUNT(*) FROM life_screen_perception_policy_event
                                  WHERE life_id='screen-life-a')",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(counts, (0, 0));
        }
        assert!(fixture
            .storage
            .find_screen_perception_policy("screen-life-a")
            .unwrap()
            .is_none());
        assert!(fixture
            .storage
            .find_screen_perception_policy_event("screen-life-a", "screen-event-delete")
            .unwrap()
            .is_none());
    }

    #[test]
    fn restart_simulation_new_session_gate_is_disarmed_and_authorization_is_denied() {
        use crate::perception::screen_policy::{
            authorize_screen_perception, ScreenPerceptionSessionGate,
        };

        let root = tempfile::tempdir().unwrap();
        // "Process A": create a fresh DB and an enabled durable policy.
        let storage_a =
            StorageService::initialize_with_roots(root.path().to_path_buf(), None).unwrap();
        storage_a
            .save_persona(PersonaTemplateRecord {
                id: "restart-persona".into(),
                name: "Restart Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        storage_a
            .save_life(LifeIdentityRecord {
                id: "restart-life".into(),
                name: "Restart Life".into(),
                created_at: "2026-08-27T00:00:00.000Z".into(),
                version: 1,
                body_id: "restart-body".into(),
                persona_id: "restart-persona".into(),
                persona_version: 1,
            })
            .unwrap();
        storage_a
            .create_screen_perception_policy(LifeScreenPerceptionPolicyCreateRequest {
                life_id: "restart-life".into(),
                screen_perception_enabled: true,
            })
            .unwrap();
        let gate_a = ScreenPerceptionSessionGate::new();
        gate_a.arm_for_life("restart-life");
        authorize_screen_perception(&storage_a, &gate_a, "restart-life").unwrap();
        drop(storage_a);
        drop(gate_a);

        // "Process B": a brand-new service and a brand-new gate over the same
        // persisted SQLite database.  The durable policy remains enabled, but
        // the new gate starts disarmed, so authorization must be denied.
        let storage_b =
            StorageService::initialize_with_roots(root.path().to_path_buf(), None).unwrap();
        let policy = storage_b
            .find_screen_perception_policy("restart-life")
            .unwrap()
            .unwrap();
        assert!(
            policy.is_screen_perception_enabled(),
            "the durable policy must survive the restart"
        );
        let gate_b = ScreenPerceptionSessionGate::new();
        assert!(
            gate_b.is_disarmed(),
            "a new session gate must start disarmed"
        );

        let error = authorize_screen_perception(&storage_b, &gate_b, "restart-life").unwrap_err();
        assert_eq!(error.code, ScreenPerceptionErrorCode::SessionNotArmed);

        // Even if some future code tried to re-arm from persisted state (which
        // B1 never does), a restored backup cannot auto-activate: the gate is
        // process-local and a fresh instance is always disarmed.
        assert!(storage_b
            .find_screen_perception_policy("restart-life")
            .unwrap()
            .is_some());
    }
}
