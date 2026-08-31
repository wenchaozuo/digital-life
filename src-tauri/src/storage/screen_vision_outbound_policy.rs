//! SQLite repository for the D25-A Life-scoped screen-vision outbound policy.
//!
//! The repository owns only durable policy state and immutable explicit-user
//! event evidence.  It has no capture, image, provider, or delivery path.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};

use super::{StorageError, StorageService};
use crate::perception::screen_vision_outbound_policy::{
    validate_screen_vision_outbound_policy_create_request,
    validate_screen_vision_outbound_policy_event_state,
    validate_screen_vision_outbound_policy_state,
    validate_screen_vision_outbound_policy_update_request, LifeScreenVisionOutboundPolicy,
    LifeScreenVisionOutboundPolicyCreateRequest, LifeScreenVisionOutboundPolicyEvent,
    LifeScreenVisionOutboundPolicyUpdateOutcome, LifeScreenVisionOutboundPolicyUpdateRequest,
    ScreenVisionOutboundPolicyCreateOutcome, ScreenVisionOutboundPolicyError,
    ScreenVisionOutboundPolicyRepository, SCREEN_VISION_OUTBOUND_POLICY_ACTOR_KIND_USER_EXPLICIT,
    SCREEN_VISION_OUTBOUND_POLICY_EVENT_VERSION, SCREEN_VISION_OUTBOUND_POLICY_VERSION,
};

pub(super) const CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_TABLE_SQL: &str = include_str!(
    "migrations/028_screen_vision_outbound_policy.life_screen_vision_outbound_policy.sql"
);
pub(super) const CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_EVENT_TABLE_SQL: &str = include_str!(
    "migrations/028_screen_vision_outbound_policy.life_screen_vision_outbound_policy_event.sql"
);
pub(super) const CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_IMMUTABLE_TRIGGER_SQL: &str =
    include_str!(
        "migrations/028_screen_vision_outbound_policy.life_screen_vision_outbound_policy_immutable_trigger.sql"
    );
pub(super) const CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_EVENT_IMMUTABLE_TRIGGER_SQL: &str =
    include_str!(
        "migrations/028_screen_vision_outbound_policy.life_screen_vision_outbound_policy_event_immutable_trigger.sql"
    );

pub(super) const MIGRATION_028_TABLE_SQLS: &[&str] = &[
    CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_TABLE_SQL,
    CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_EVENT_TABLE_SQL,
];

pub(super) const MIGRATION_028_TRIGGER_SQLS: &[&str] = &[
    CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_IMMUTABLE_TRIGGER_SQL,
    CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_EVENT_IMMUTABLE_TRIGGER_SQL,
];

const POLICY_COLUMNS: &str =
    "life_id, screen_vision_outbound_enabled, revision, created_at, updated_at, policy_version";
const POLICY_EVENT_COLUMNS: &str = "event_id, life_id, old_screen_vision_outbound_enabled, new_screen_vision_outbound_enabled, expected_revision, applied_revision, actor_kind, occurred_at, event_version";

fn read_policy(row: &Row<'_>) -> rusqlite::Result<LifeScreenVisionOutboundPolicy> {
    Ok(LifeScreenVisionOutboundPolicy {
        life_id: row.get(0)?,
        screen_vision_outbound_enabled: row.get::<_, bool>(1)?,
        revision: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        policy_version: row.get(5)?,
    })
}

fn read_policy_event(row: &Row<'_>) -> rusqlite::Result<LifeScreenVisionOutboundPolicyEvent> {
    Ok(LifeScreenVisionOutboundPolicyEvent {
        event_id: row.get(0)?,
        life_id: row.get(1)?,
        old_screen_vision_outbound_enabled: row.get::<_, bool>(2)?,
        new_screen_vision_outbound_enabled: row.get::<_, bool>(3)?,
        expected_revision: row.get(4)?,
        applied_revision: row.get(5)?,
        actor_kind: row.get(6)?,
        occurred_at: row.get(7)?,
        event_version: row.get(8)?,
    })
}

fn validate_lookup_argument(
    name: &str,
    value: &str,
) -> Result<(), ScreenVisionOutboundPolicyError> {
    if value.trim().is_empty() {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(format!(
            "{name} must not be empty."
        )));
    }
    Ok(())
}

fn validate_lookup_arguments(
    life_id: &str,
    entity_name: &str,
    entity_id: &str,
) -> Result<(), ScreenVisionOutboundPolicyError> {
    validate_lookup_argument("life identity", life_id)?;
    validate_lookup_argument(entity_name, entity_id)
}

fn sqlite_authority_now(
    connection: &Connection,
) -> Result<String, ScreenVisionOutboundPolicyError> {
    connection
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| ScreenVisionOutboundPolicyError::database())
}

fn next_revision(expected_revision: i64) -> Result<i64, ScreenVisionOutboundPolicyError> {
    expected_revision.checked_add(1).ok_or_else(|| {
        ScreenVisionOutboundPolicyError::invalid_argument("the target revision is unrepresentable.")
    })
}

fn load_policy(
    connection: &Connection,
    life_id: &str,
) -> Result<Option<LifeScreenVisionOutboundPolicy>, ScreenVisionOutboundPolicyError> {
    connection
        .query_row(
            &format!(
                "SELECT {POLICY_COLUMNS} FROM life_screen_vision_outbound_policy WHERE life_id = ?1"
            ),
            [life_id],
            read_policy,
        )
        .optional()
        .map_err(|_| ScreenVisionOutboundPolicyError::database())
}

fn load_policy_event_by_id(
    connection: &Connection,
    event_id: &str,
) -> Result<Option<LifeScreenVisionOutboundPolicyEvent>, ScreenVisionOutboundPolicyError> {
    connection
        .query_row(
            &format!(
                "SELECT {POLICY_EVENT_COLUMNS}
                 FROM life_screen_vision_outbound_policy_event
                 WHERE event_id = ?1"
            ),
            [event_id],
            read_policy_event,
        )
        .optional()
        .map_err(|_| ScreenVisionOutboundPolicyError::database())
}

fn policy_create_evidence_matches(
    policy: &LifeScreenVisionOutboundPolicy,
    request: &LifeScreenVisionOutboundPolicyCreateRequest,
) -> bool {
    policy.life_id == request.life_id
        && !policy.screen_vision_outbound_enabled
        && policy.revision == 1
        && policy.policy_version == SCREEN_VISION_OUTBOUND_POLICY_VERSION
}

fn policy_event_evidence_matches(
    event: &LifeScreenVisionOutboundPolicyEvent,
    request: &LifeScreenVisionOutboundPolicyUpdateRequest,
    applied_revision: i64,
) -> bool {
    event.event_id == request.event_id
        && event.life_id == request.life_id
        && event.new_screen_vision_outbound_enabled == request.screen_vision_outbound_enabled
        && event.expected_revision == request.expected_revision
        && event.applied_revision == applied_revision
        && event.actor_kind == SCREEN_VISION_OUTBOUND_POLICY_ACTOR_KIND_USER_EXPLICIT
        && event.event_version == SCREEN_VISION_OUTBOUND_POLICY_EVENT_VERSION
}

fn require_life(
    transaction: &Transaction<'_>,
    life_id: &str,
) -> Result<(), ScreenVisionOutboundPolicyError> {
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
            [life_id],
            |row| row.get(0),
        )
        .map_err(|_| ScreenVisionOutboundPolicyError::database())?;
    if !exists {
        return Err(ScreenVisionOutboundPolicyError::life_not_found());
    }
    Ok(())
}

fn create_policy_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeScreenVisionOutboundPolicyCreateRequest,
) -> Result<
    ScreenVisionOutboundPolicyCreateOutcome<LifeScreenVisionOutboundPolicy>,
    ScreenVisionOutboundPolicyError,
> {
    validate_screen_vision_outbound_policy_create_request(&request)?;

    // Identity is checked before Life existence so duplicate creation has a
    // stable replay/conflict result even when the Life was later removed.
    if let Some(existing) = transaction
        .query_row(
            &format!(
                "SELECT {POLICY_COLUMNS}
                 FROM life_screen_vision_outbound_policy
                 WHERE life_id = ?1"
            ),
            [&request.life_id],
            read_policy,
        )
        .optional()
        .map_err(|_| ScreenVisionOutboundPolicyError::database())?
    {
        if policy_create_evidence_matches(&existing, &request) {
            validate_screen_vision_outbound_policy_state(&existing)?;
            return Ok(ScreenVisionOutboundPolicyCreateOutcome::Replayed(existing));
        }
        return Err(ScreenVisionOutboundPolicyError::policy_conflict());
    }

    require_life(transaction, &request.life_id)?;
    let now = sqlite_authority_now(transaction)?;
    transaction
        .execute(
            "INSERT INTO life_screen_vision_outbound_policy
             (life_id, screen_vision_outbound_enabled, revision, created_at, updated_at, policy_version)
             VALUES (?1, 0, 1, ?2, ?2, ?3)",
            params![
                &request.life_id,
                &now,
                SCREEN_VISION_OUTBOUND_POLICY_VERSION,
            ],
        )
        .map_err(map_database_error)?;

    let created = transaction
        .query_row(
            &format!(
                "SELECT {POLICY_COLUMNS}
                 FROM life_screen_vision_outbound_policy
                 WHERE life_id = ?1"
            ),
            [&request.life_id],
            read_policy,
        )
        .map_err(|_| ScreenVisionOutboundPolicyError::database())?;
    validate_screen_vision_outbound_policy_state(&created)?;
    Ok(ScreenVisionOutboundPolicyCreateOutcome::Applied(created))
}

fn update_policy_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeScreenVisionOutboundPolicyUpdateRequest,
) -> Result<LifeScreenVisionOutboundPolicyUpdateOutcome, ScreenVisionOutboundPolicyError> {
    validate_screen_vision_outbound_policy_update_request(&request)?;
    let applied_revision = next_revision(request.expected_revision)?;

    // Event identity is checked before the current revision.  This makes a
    // retried committed event replayable even after the policy has advanced.
    if let Some(existing_event) = load_policy_event_by_id(transaction, &request.event_id)? {
        if policy_event_evidence_matches(&existing_event, &request, applied_revision) {
            let current = load_policy(transaction, &request.life_id)?
                .ok_or_else(ScreenVisionOutboundPolicyError::policy_not_found)?;
            validate_screen_vision_outbound_policy_event_state(&existing_event)?;
            validate_screen_vision_outbound_policy_state(&current)?;
            return Ok(LifeScreenVisionOutboundPolicyUpdateOutcome::Replayed {
                event: existing_event,
                current,
            });
        }
        return Err(ScreenVisionOutboundPolicyError::policy_event_conflict());
    }

    let current = load_policy(transaction, &request.life_id)?
        .ok_or_else(ScreenVisionOutboundPolicyError::policy_not_found)?;
    validate_screen_vision_outbound_policy_state(&current)?;
    if current.revision != request.expected_revision {
        return Err(ScreenVisionOutboundPolicyError::revision_conflict());
    }
    if current.screen_vision_outbound_enabled == request.screen_vision_outbound_enabled {
        return Err(ScreenVisionOutboundPolicyError::invalid_transition());
    }

    let now = sqlite_authority_now(transaction)?;
    let changed = transaction
        .execute(
            "UPDATE life_screen_vision_outbound_policy
             SET screen_vision_outbound_enabled = ?1,
                 revision = ?2,
                 updated_at = ?3
             WHERE life_id = ?4
               AND revision = ?5
               AND screen_vision_outbound_enabled = ?6",
            params![
                request.screen_vision_outbound_enabled,
                applied_revision,
                &now,
                &request.life_id,
                request.expected_revision,
                current.screen_vision_outbound_enabled,
            ],
        )
        .map_err(map_database_error)?;
    if changed != 1 {
        return Err(ScreenVisionOutboundPolicyError::revision_conflict());
    }

    let event = LifeScreenVisionOutboundPolicyEvent {
        event_id: request.event_id,
        life_id: request.life_id,
        old_screen_vision_outbound_enabled: current.screen_vision_outbound_enabled,
        new_screen_vision_outbound_enabled: request.screen_vision_outbound_enabled,
        expected_revision: request.expected_revision,
        applied_revision,
        actor_kind: SCREEN_VISION_OUTBOUND_POLICY_ACTOR_KIND_USER_EXPLICIT.to_string(),
        occurred_at: now,
        event_version: SCREEN_VISION_OUTBOUND_POLICY_EVENT_VERSION,
    };
    validate_screen_vision_outbound_policy_event_state(&event)?;
    transaction
        .execute(
            &format!(
                "INSERT INTO life_screen_vision_outbound_policy_event ({POLICY_EVENT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
            ),
            params![
                &event.event_id,
                &event.life_id,
                event.old_screen_vision_outbound_enabled,
                event.new_screen_vision_outbound_enabled,
                event.expected_revision,
                event.applied_revision,
                &event.actor_kind,
                &event.occurred_at,
                event.event_version,
            ],
        )
        .map_err(map_database_error)?;

    let persisted_event = load_policy_event_by_id(transaction, &event.event_id)?
        .ok_or_else(ScreenVisionOutboundPolicyError::database)?;
    let persisted_policy = load_policy(transaction, &event.life_id)?
        .ok_or_else(ScreenVisionOutboundPolicyError::policy_not_found)?;
    validate_screen_vision_outbound_policy_event_state(&persisted_event)?;
    validate_screen_vision_outbound_policy_state(&persisted_policy)?;
    Ok(LifeScreenVisionOutboundPolicyUpdateOutcome::Applied {
        event: persisted_event,
        policy: persisted_policy,
    })
}

impl ScreenVisionOutboundPolicyRepository for StorageService {
    fn create_screen_vision_outbound_policy(
        &self,
        request: LifeScreenVisionOutboundPolicyCreateRequest,
    ) -> Result<
        ScreenVisionOutboundPolicyCreateOutcome<LifeScreenVisionOutboundPolicy>,
        ScreenVisionOutboundPolicyError,
    > {
        let mut state = self
            .state()
            .map_err(|_| ScreenVisionOutboundPolicyError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ScreenVisionOutboundPolicyError::database())?;
        let outcome = create_policy_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| ScreenVisionOutboundPolicyError::database())?;
        Ok(outcome)
    }

    fn find_screen_vision_outbound_policy(
        &self,
        life_id: &str,
    ) -> Result<Option<LifeScreenVisionOutboundPolicy>, ScreenVisionOutboundPolicyError> {
        validate_lookup_argument("life identity", life_id)?;
        let state = self
            .state()
            .map_err(|_| ScreenVisionOutboundPolicyError::database())?;
        let policy = load_policy(&state.connection, life_id)?;
        if let Some(policy) = &policy {
            validate_screen_vision_outbound_policy_state(policy)?;
        }
        Ok(policy)
    }

    fn update_screen_vision_outbound_policy(
        &self,
        request: LifeScreenVisionOutboundPolicyUpdateRequest,
    ) -> Result<LifeScreenVisionOutboundPolicyUpdateOutcome, ScreenVisionOutboundPolicyError> {
        let mut state = self
            .state()
            .map_err(|_| ScreenVisionOutboundPolicyError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ScreenVisionOutboundPolicyError::database())?;
        let outcome = update_policy_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| ScreenVisionOutboundPolicyError::database())?;
        Ok(outcome)
    }

    fn find_screen_vision_outbound_policy_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeScreenVisionOutboundPolicyEvent>, ScreenVisionOutboundPolicyError> {
        validate_lookup_arguments(life_id, "policy event identity", event_id)?;
        let state = self
            .state()
            .map_err(|_| ScreenVisionOutboundPolicyError::database())?;
        let event = state
            .connection
            .query_row(
                &format!(
                    "SELECT {POLICY_EVENT_COLUMNS}
                     FROM life_screen_vision_outbound_policy_event
                     WHERE life_id = ?1 AND event_id = ?2"
                ),
                params![life_id, event_id],
                read_policy_event,
            )
            .optional()
            .map_err(|_| ScreenVisionOutboundPolicyError::database())?;
        if let Some(event) = &event {
            validate_screen_vision_outbound_policy_event_state(event)?;
        }
        Ok(event)
    }
}

const _: for<'a> fn(
    &'a StorageService,
    LifeScreenVisionOutboundPolicyCreateRequest,
) -> Result<
    ScreenVisionOutboundPolicyCreateOutcome<LifeScreenVisionOutboundPolicy>,
    ScreenVisionOutboundPolicyError,
> = <StorageService as ScreenVisionOutboundPolicyRepository>::create_screen_vision_outbound_policy;
const _: for<'a> fn(
    &'a StorageService,
    LifeScreenVisionOutboundPolicyUpdateRequest,
) -> Result<
    LifeScreenVisionOutboundPolicyUpdateOutcome,
    ScreenVisionOutboundPolicyError,
> = <StorageService as ScreenVisionOutboundPolicyRepository>::update_screen_vision_outbound_policy;

/// Exact normalized validation of the Schema28 D25-A objects.  This validator
/// is fail-closed and never installs or repairs schema objects.
pub(super) fn validate_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    for (object_kind, object_name, expected_sql) in [
        (
            "table",
            "life_screen_vision_outbound_policy",
            CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_TABLE_SQL,
        ),
        (
            "table",
            "life_screen_vision_outbound_policy_event",
            CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_EVENT_TABLE_SQL,
        ),
        (
            "trigger",
            "life_screen_vision_outbound_policy_immutable_guard",
            CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_IMMUTABLE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "life_screen_vision_outbound_policy_event_immutable_guard",
            CREATE_LIFE_SCREEN_VISION_OUTBOUND_POLICY_EVENT_IMMUTABLE_TRIGGER_SQL,
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

    for (child_table, parent_table, from_column, to_column) in [
        (
            "life_screen_vision_outbound_policy",
            "life_identity",
            "life_id",
            "id",
        ),
        (
            "life_screen_vision_outbound_policy_event",
            "life_screen_vision_outbound_policy",
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
            .map_err(|_| StorageError::migration_transaction_failed())?;
        if count != 1 {
            return Err(StorageError::migration_transaction_failed());
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

fn map_database_error(_error: rusqlite::Error) -> ScreenVisionOutboundPolicyError {
    ScreenVisionOutboundPolicyError::database()
}

const _: fn(&Connection) -> Result<(), StorageError> = validate_schema_objects;

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::{
        perception::screen_vision_outbound_policy::{
            authorize_screen_vision_outbound, LifeScreenVisionOutboundPolicyCreateRequest,
            LifeScreenVisionOutboundPolicyUpdateRequest, ScreenVisionOutboundPolicyErrorCode,
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
                    id: "vision-persona".into(),
                    name: "Vision Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            storage
                .save_life(LifeIdentityRecord {
                    id: "vision-life-a".into(),
                    name: "Vision Life A".into(),
                    created_at: "2026-08-31T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "vision-body-a".into(),
                    persona_id: "vision-persona".into(),
                    persona_version: 1,
                })
                .unwrap();
            Self {
                _root: root,
                storage,
            }
        }

        fn create(&self) -> LifeScreenVisionOutboundPolicy {
            match self
                .storage
                .create_screen_vision_outbound_policy(LifeScreenVisionOutboundPolicyCreateRequest {
                    life_id: "vision-life-a".into(),
                })
                .unwrap()
            {
                ScreenVisionOutboundPolicyCreateOutcome::Applied(policy) => policy,
                ScreenVisionOutboundPolicyCreateOutcome::Replayed(_) => {
                    panic!("the first D25-A policy create must apply")
                }
            }
        }

        fn update(
            &self,
            event_id: &str,
            enabled: bool,
            expected_revision: i64,
        ) -> Result<LifeScreenVisionOutboundPolicyUpdateOutcome, ScreenVisionOutboundPolicyError>
        {
            self.storage.update_screen_vision_outbound_policy(
                LifeScreenVisionOutboundPolicyUpdateRequest {
                    event_id: event_id.into(),
                    life_id: "vision-life-a".into(),
                    screen_vision_outbound_enabled: enabled,
                    expected_revision,
                },
            )
        }
    }

    #[test]
    fn create_is_default_deny_replay_aware_and_refuses_conflicting_existing_state() {
        let fixture = Fixture::new();
        assert!(fixture
            .storage
            .find_screen_vision_outbound_policy("vision-life-a")
            .unwrap()
            .is_none());

        let created = fixture.create();
        assert!(!created.screen_vision_outbound_enabled);
        assert_eq!(created.revision, 1);
        assert_eq!(created.created_at, created.updated_at);
        assert_eq!(
            created.policy_version,
            SCREEN_VISION_OUTBOUND_POLICY_VERSION
        );

        let replay = fixture
            .storage
            .create_screen_vision_outbound_policy(LifeScreenVisionOutboundPolicyCreateRequest {
                life_id: "vision-life-a".into(),
            })
            .unwrap();
        assert_eq!(
            replay,
            ScreenVisionOutboundPolicyCreateOutcome::Replayed(created.clone())
        );

        fixture.update("vision-event-enable", true, 1).unwrap();
        let conflict = fixture
            .storage
            .create_screen_vision_outbound_policy(LifeScreenVisionOutboundPolicyCreateRequest {
                life_id: "vision-life-a".into(),
            })
            .unwrap_err();
        assert_eq!(
            conflict.code,
            ScreenVisionOutboundPolicyErrorCode::PolicyConflict
        );
    }

    #[test]
    fn explicit_update_records_exact_event_cas_and_replay_before_revision_check() {
        let fixture = Fixture::new();
        fixture.create();
        let applied = fixture.update("vision-event-enable", true, 1).unwrap();
        let (event, policy) = match applied {
            LifeScreenVisionOutboundPolicyUpdateOutcome::Applied { event, policy } => {
                (event, policy)
            }
            LifeScreenVisionOutboundPolicyUpdateOutcome::Replayed { .. } => {
                panic!("the first D25-A update must apply")
            }
        };
        assert!(!event.old_screen_vision_outbound_enabled);
        assert!(event.new_screen_vision_outbound_enabled);
        assert_eq!(event.actor_kind, "user_explicit");
        assert_eq!(event.expected_revision, 1);
        assert_eq!(event.applied_revision, 2);
        assert_eq!(policy.revision, 2);
        assert_eq!(policy.updated_at, event.occurred_at);

        let replay = fixture.update("vision-event-enable", true, 1).unwrap();
        match replay {
            LifeScreenVisionOutboundPolicyUpdateOutcome::Replayed {
                event: replayed,
                current,
            } => {
                assert_eq!(replayed, event);
                assert_eq!(current.revision, 2);
                assert!(current.screen_vision_outbound_enabled);
            }
            LifeScreenVisionOutboundPolicyUpdateOutcome::Applied { .. } => {
                panic!("the same D25-A event evidence must replay")
            }
        }

        let event_conflict = fixture.update("vision-event-enable", false, 1).unwrap_err();
        assert_eq!(
            event_conflict.code,
            ScreenVisionOutboundPolicyErrorCode::PolicyEventConflict
        );
        let stale = fixture.update("vision-event-stale", false, 1).unwrap_err();
        assert_eq!(
            stale.code,
            ScreenVisionOutboundPolicyErrorCode::RevisionConflict
        );
        let no_op = fixture.update("vision-event-no-op", true, 2).unwrap_err();
        assert_eq!(
            no_op.code,
            ScreenVisionOutboundPolicyErrorCode::InvalidTransition
        );
        let found = fixture
            .storage
            .find_screen_vision_outbound_policy_event("vision-life-a", "vision-event-enable")
            .unwrap()
            .unwrap();
        assert_eq!(found, event);
    }

    #[test]
    fn durable_authorization_is_missing_disabled_then_enabled_only_after_explicit_update() {
        let fixture = Fixture::new();
        let missing =
            authorize_screen_vision_outbound(&fixture.storage, "vision-life-a").unwrap_err();
        assert_eq!(
            missing.code,
            ScreenVisionOutboundPolicyErrorCode::PolicyNotFound
        );
        fixture.create();
        let disabled =
            authorize_screen_vision_outbound(&fixture.storage, "vision-life-a").unwrap_err();
        assert_eq!(
            disabled.code,
            ScreenVisionOutboundPolicyErrorCode::PolicyDisabled
        );
        fixture.update("vision-event-enable", true, 1).unwrap();
        authorize_screen_vision_outbound(&fixture.storage, "vision-life-a").unwrap();
    }

    #[test]
    fn immutable_fields_are_guarded_but_governed_fields_remain_updatable() {
        let fixture = Fixture::new();
        fixture.create();
        fixture.update("vision-event-immutable", true, 1).unwrap();
        let state = fixture.storage.state().unwrap();
        for sql in [
            "UPDATE life_screen_vision_outbound_policy SET life_id='other' WHERE life_id='vision-life-a'",
            "UPDATE life_screen_vision_outbound_policy SET created_at='changed' WHERE life_id='vision-life-a'",
            "UPDATE life_screen_vision_outbound_policy SET policy_version=2 WHERE life_id='vision-life-a'",
        ] {
            let error = state.connection.execute(sql, []).unwrap_err();
            assert!(error
                .to_string()
                .contains("LIFE_SCREEN_VISION_OUTBOUND_POLICY_IMMUTABLE"));
        }
        let event_error = state
            .connection
            .execute(
                "UPDATE life_screen_vision_outbound_policy_event
                 SET new_screen_vision_outbound_enabled=0
                 WHERE event_id='vision-event-immutable'",
                [],
            )
            .unwrap_err();
        assert!(event_error
            .to_string()
            .contains("LIFE_SCREEN_VISION_OUTBOUND_POLICY_EVENT_IMMUTABLE"));
        drop(state);

        let governed = fixture.update("vision-event-disable", false, 2).unwrap();
        assert!(matches!(
            governed,
            LifeScreenVisionOutboundPolicyUpdateOutcome::Applied { .. }
        ));
    }

    #[test]
    fn failed_event_insert_rolls_back_the_policy_update() {
        let fixture = Fixture::new();
        fixture.create();
        {
            let state = fixture.storage.state().unwrap();
            state
                .connection
                .execute_batch(
                    "CREATE TRIGGER d25_test_reject_event_insert
                     BEFORE INSERT ON life_screen_vision_outbound_policy_event
                     BEGIN
                         SELECT RAISE(ROLLBACK, 'D25_TEST_EVENT_INSERT_REJECTED');
                     END;",
                )
                .unwrap();
        }

        let error = fixture
            .update("vision-event-rollback", true, 1)
            .unwrap_err();
        assert_eq!(
            error.code,
            ScreenVisionOutboundPolicyErrorCode::DatabaseUnavailable
        );
        {
            let state = fixture.storage.state().unwrap();
            let policy: (bool, i64) = state
                .connection
                .query_row(
                    "SELECT screen_vision_outbound_enabled, revision
                     FROM life_screen_vision_outbound_policy
                     WHERE life_id='vision-life-a'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(policy, (false, 1));
            let events: i64 = state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM life_screen_vision_outbound_policy_event",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(events, 0);
            state
                .connection
                .execute_batch("DROP TRIGGER d25_test_reject_event_insert")
                .unwrap();
        }
        fixture
            .update("vision-event-after-rollback", true, 1)
            .unwrap();
    }

    #[test]
    fn schema_shape_contains_only_policy_and_event_fields() {
        let fixture = Fixture::new();
        let state = fixture.storage.state().unwrap();
        let tables: Vec<String> = state
            .connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type='table' AND name LIKE 'life_screen_vision_outbound_%'
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
                "life_screen_vision_outbound_policy".to_string(),
                "life_screen_vision_outbound_policy_event".to_string()
            ]
        );

        let forbidden = [
            "image",
            "pixel",
            "screenshot",
            "ocr",
            "capture",
            "window",
            "process",
            "pid",
            "hwnd",
            "provider",
            "url",
            "base64",
            "multipart",
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
}
