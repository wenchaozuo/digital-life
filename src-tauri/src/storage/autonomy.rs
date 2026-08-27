//! SQLite-authoritative persistence for D15-B1 autonomy policy and
//! proactive-intent evidence.
//!
//! This module is deliberately a foundation only. It persists explicit policy
//! configuration and bounded `goal_check_in` evidence. It does not score
//! initiative, create or mutate D14 goals, transition intents, schedule work,
//! deliver messages, or invoke an Agent or Tool.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};

use super::StorageService;
use crate::{
    autonomy::{
        validate_intent_create_request, validate_intent_state, validate_policy_create_request,
        validate_policy_event_state, validate_policy_state, validate_policy_update_request,
        AutonomyCreateOutcome, AutonomyError, LifeAutonomyPolicy, LifeAutonomyPolicyCreateRequest,
        LifeAutonomyPolicyEvent, LifeAutonomyPolicyUpdateOutcome, LifeAutonomyPolicyUpdateRequest,
        LifeProactiveIntent, LifeProactiveIntentCreateRequest, LifeProactiveIntentEvent,
        INTENT_CREATED_BY_KIND_AUTONOMY_POLICY, INTENT_STATUS_PENDING, INTENT_VERSION,
        POLICY_ACTOR_KIND_USER_EXPLICIT, POLICY_EVENT_VERSION,
    },
    life_intent::GOAL_STATUS_ACTIVE,
};

pub(super) const CREATE_LIFE_AUTONOMY_POLICY_TABLE_SQL: &str = include_str!(
    "migrations/023_autonomous_life_proactive_intent_authority.life_autonomy_policy.sql"
);
pub(super) const CREATE_LIFE_AUTONOMY_POLICY_EVENT_TABLE_SQL: &str = include_str!(
    "migrations/023_autonomous_life_proactive_intent_authority.life_autonomy_policy_event.sql"
);
pub(super) const CREATE_LIFE_PROACTIVE_INTENT_TABLE_SQL: &str = include_str!(
    "migrations/023_autonomous_life_proactive_intent_authority.life_proactive_intent.sql"
);
pub(super) const CREATE_LIFE_PROACTIVE_INTENT_EVENT_TABLE_SQL: &str = include_str!(
    "migrations/023_autonomous_life_proactive_intent_authority.life_proactive_intent_event.sql"
);
pub(super) const CREATE_LIFE_AUTONOMY_POLICY_IMMUTABLE_TRIGGER_SQL: &str = include_str!(
    "migrations/023_autonomous_life_proactive_intent_authority.life_autonomy_policy_immutable_trigger.sql"
);
pub(super) const CREATE_LIFE_AUTONOMY_POLICY_EVENT_IMMUTABLE_TRIGGER_SQL: &str = include_str!(
    "migrations/023_autonomous_life_proactive_intent_authority.life_autonomy_policy_event_immutable_trigger.sql"
);
pub(super) const CREATE_LIFE_PROACTIVE_INTENT_IMMUTABLE_TRIGGER_SQL: &str = include_str!(
    "migrations/023_autonomous_life_proactive_intent_authority.life_proactive_intent_immutable_trigger.sql"
);
pub(super) const CREATE_LIFE_PROACTIVE_INTENT_EVENT_IMMUTABLE_TRIGGER_SQL: &str = include_str!(
    "migrations/023_autonomous_life_proactive_intent_authority.life_proactive_intent_event_immutable_trigger.sql"
);

pub(super) const MIGRATION_023_TABLE_SQLS: &[&str] = &[
    CREATE_LIFE_AUTONOMY_POLICY_TABLE_SQL,
    CREATE_LIFE_AUTONOMY_POLICY_EVENT_TABLE_SQL,
    CREATE_LIFE_PROACTIVE_INTENT_TABLE_SQL,
    CREATE_LIFE_PROACTIVE_INTENT_EVENT_TABLE_SQL,
];

pub(super) const MIGRATION_023_TRIGGER_SQLS: &[&str] = &[
    CREATE_LIFE_AUTONOMY_POLICY_IMMUTABLE_TRIGGER_SQL,
    CREATE_LIFE_AUTONOMY_POLICY_EVENT_IMMUTABLE_TRIGGER_SQL,
    CREATE_LIFE_PROACTIVE_INTENT_IMMUTABLE_TRIGGER_SQL,
    CREATE_LIFE_PROACTIVE_INTENT_EVENT_IMMUTABLE_TRIGGER_SQL,
];

const POLICY_COLUMNS: &str = "life_id, enabled, dnd, max_ready_per_window, window_seconds, min_gap_seconds, revision, created_at, updated_at, policy_version";
const POLICY_EVENT_COLUMNS: &str = "event_id, life_id, old_enabled, new_enabled, old_dnd, new_dnd, old_max_ready_per_window, new_max_ready_per_window, old_window_seconds, new_window_seconds, old_min_gap_seconds, new_min_gap_seconds, expected_revision, applied_revision, actor_kind, occurred_at, event_version";
const INTENT_COLUMNS: &str = "intent_id, life_id, goal_id, intent_kind, importance, user_relevance, self_desire, interruption_cost, focus_state, acceptance_score, recent_interaction_seconds, status, revision, created_by_kind, created_at, updated_at, not_before, expires_at, closed_at, intent_version";
const INTENT_EVENT_COLUMNS: &str = "event_id, life_id, intent_id, from_status, to_status, expected_revision, applied_revision, not_before_after, actor_kind, occurred_at, event_version";

fn read_policy(row: &Row<'_>) -> rusqlite::Result<LifeAutonomyPolicy> {
    Ok(LifeAutonomyPolicy {
        life_id: row.get(0)?,
        enabled: row.get::<_, bool>(1)?,
        dnd: row.get::<_, bool>(2)?,
        max_ready_per_window: row.get(3)?,
        window_seconds: row.get(4)?,
        min_gap_seconds: row.get(5)?,
        revision: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
        policy_version: row.get(9)?,
    })
}

fn read_policy_event(row: &Row<'_>) -> rusqlite::Result<LifeAutonomyPolicyEvent> {
    Ok(LifeAutonomyPolicyEvent {
        event_id: row.get(0)?,
        life_id: row.get(1)?,
        old_enabled: row.get::<_, bool>(2)?,
        new_enabled: row.get::<_, bool>(3)?,
        old_dnd: row.get::<_, bool>(4)?,
        new_dnd: row.get::<_, bool>(5)?,
        old_max_ready_per_window: row.get(6)?,
        new_max_ready_per_window: row.get(7)?,
        old_window_seconds: row.get(8)?,
        new_window_seconds: row.get(9)?,
        old_min_gap_seconds: row.get(10)?,
        new_min_gap_seconds: row.get(11)?,
        expected_revision: row.get(12)?,
        applied_revision: row.get(13)?,
        actor_kind: row.get(14)?,
        occurred_at: row.get(15)?,
        event_version: row.get(16)?,
    })
}

fn read_intent(row: &Row<'_>) -> rusqlite::Result<LifeProactiveIntent> {
    Ok(LifeProactiveIntent {
        intent_id: row.get(0)?,
        life_id: row.get(1)?,
        goal_id: row.get(2)?,
        intent_kind: row.get(3)?,
        importance: row.get(4)?,
        user_relevance: row.get(5)?,
        self_desire: row.get(6)?,
        interruption_cost: row.get(7)?,
        focus_state: row.get(8)?,
        acceptance_score: row.get(9)?,
        recent_interaction_seconds: row.get(10)?,
        status: row.get(11)?,
        revision: row.get(12)?,
        created_by_kind: row.get(13)?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
        not_before: row.get(16)?,
        expires_at: row.get(17)?,
        closed_at: row.get(18)?,
        intent_version: row.get(19)?,
    })
}

fn read_intent_event(row: &Row<'_>) -> rusqlite::Result<LifeProactiveIntentEvent> {
    Ok(LifeProactiveIntentEvent {
        event_id: row.get(0)?,
        life_id: row.get(1)?,
        intent_id: row.get(2)?,
        from_status: row.get(3)?,
        to_status: row.get(4)?,
        expected_revision: row.get(5)?,
        applied_revision: row.get(6)?,
        not_before_after: row.get(7)?,
        actor_kind: row.get(8)?,
        occurred_at: row.get(9)?,
        event_version: row.get(10)?,
    })
}

fn validate_lookup_argument(name: &str, value: &str) -> Result<(), AutonomyError> {
    if value.trim().is_empty() {
        return Err(AutonomyError::invalid_argument(format!(
            "{name} must not be empty."
        )));
    }
    Ok(())
}

fn validate_lookup_arguments(
    life_id: &str,
    entity_name: &str,
    entity_id: &str,
) -> Result<(), AutonomyError> {
    validate_lookup_argument("life identity", life_id)?;
    validate_lookup_argument(entity_name, entity_id)
}

fn sqlite_authority_now(connection: &Connection) -> Result<String, AutonomyError> {
    connection
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| AutonomyError::database())
}

fn map_database_error(_error: rusqlite::Error) -> AutonomyError {
    AutonomyError::database()
}

fn next_revision(expected_revision: i64) -> Result<i64, AutonomyError> {
    expected_revision
        .checked_add(1)
        .ok_or_else(|| AutonomyError::invalid_argument("the target revision is unrepresentable."))
}

fn load_policy(
    connection: &Connection,
    life_id: &str,
) -> Result<Option<LifeAutonomyPolicy>, AutonomyError> {
    connection
        .query_row(
            &format!("SELECT {POLICY_COLUMNS} FROM life_autonomy_policy WHERE life_id = ?1"),
            [life_id],
            read_policy,
        )
        .optional()
        .map_err(|_| AutonomyError::database())
}

fn load_policy_event_by_id(
    connection: &Connection,
    event_id: &str,
) -> Result<Option<LifeAutonomyPolicyEvent>, AutonomyError> {
    connection
        .query_row(
            &format!(
                "SELECT {POLICY_EVENT_COLUMNS} FROM life_autonomy_policy_event
                 WHERE event_id = ?1"
            ),
            [event_id],
            read_policy_event,
        )
        .optional()
        .map_err(|_| AutonomyError::database())
}

fn load_intent_by_id(
    connection: &Connection,
    intent_id: &str,
) -> Result<Option<LifeProactiveIntent>, AutonomyError> {
    connection
        .query_row(
            &format!("SELECT {INTENT_COLUMNS} FROM life_proactive_intent WHERE intent_id = ?1"),
            [intent_id],
            read_intent,
        )
        .optional()
        .map_err(|_| AutonomyError::database())
}

fn load_intent(
    connection: &Connection,
    life_id: &str,
    intent_id: &str,
) -> Result<Option<LifeProactiveIntent>, AutonomyError> {
    connection
        .query_row(
            &format!(
                "SELECT {INTENT_COLUMNS} FROM life_proactive_intent
                 WHERE life_id = ?1 AND intent_id = ?2"
            ),
            params![life_id, intent_id],
            read_intent,
        )
        .optional()
        .map_err(|_| AutonomyError::database())
}

fn policy_create_evidence_matches(
    policy: &LifeAutonomyPolicy,
    request: &LifeAutonomyPolicyCreateRequest,
) -> bool {
    policy.life_id == request.life_id
        && policy.enabled == request.enabled
        && policy.dnd == request.dnd
        && policy.max_ready_per_window == request.max_ready_per_window
        && policy.window_seconds == request.window_seconds
        && policy.min_gap_seconds == request.min_gap_seconds
}

fn policy_event_evidence_matches(
    event: &LifeAutonomyPolicyEvent,
    request: &LifeAutonomyPolicyUpdateRequest,
    applied_revision: i64,
) -> bool {
    event.event_id == request.event_id
        && event.life_id == request.life_id
        && event.new_enabled == request.enabled
        && event.new_dnd == request.dnd
        && event.new_max_ready_per_window == request.max_ready_per_window
        && event.new_window_seconds == request.window_seconds
        && event.new_min_gap_seconds == request.min_gap_seconds
        && event.expected_revision == request.expected_revision
        && event.applied_revision == applied_revision
        && event.actor_kind == POLICY_ACTOR_KIND_USER_EXPLICIT
        && event.event_version == POLICY_EVENT_VERSION
}

fn intent_create_evidence_matches(
    intent: &LifeProactiveIntent,
    request: &LifeProactiveIntentCreateRequest,
) -> bool {
    intent.intent_id == request.intent_id
        && intent.life_id == request.life_id
        && intent.goal_id == request.goal_id
        && intent.intent_kind == request.intent_kind
        && intent.importance == request.importance
        && intent.user_relevance == request.user_relevance
        && intent.self_desire == request.self_desire
        && intent.interruption_cost == request.interruption_cost
        && intent.focus_state == request.focus_state
        && intent.acceptance_score == request.acceptance_score
        && intent.recent_interaction_seconds == request.recent_interaction_seconds
        && intent.expires_at == request.expires_at
}

fn require_life(transaction: &Transaction<'_>, life_id: &str) -> Result<(), AutonomyError> {
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
            [life_id],
            |row| row.get(0),
        )
        .map_err(|_| AutonomyError::database())?;
    if !exists {
        return Err(AutonomyError::life_not_found());
    }
    Ok(())
}

fn require_active_goal(
    transaction: &Transaction<'_>,
    life_id: &str,
    goal_id: &str,
) -> Result<(), AutonomyError> {
    let goal: Option<(String, String)> = transaction
        .query_row(
            "SELECT life_id, status FROM life_goal WHERE goal_id = ?1",
            [goal_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| AutonomyError::database())?;
    let Some((goal_life_id, status)) = goal else {
        return Err(AutonomyError::goal_not_found());
    };
    if goal_life_id != life_id {
        return Err(AutonomyError::goal_life_mismatch());
    }
    if status != GOAL_STATUS_ACTIVE {
        return Err(AutonomyError::goal_not_active());
    }
    Ok(())
}

fn create_policy_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeAutonomyPolicyCreateRequest,
) -> Result<AutonomyCreateOutcome<LifeAutonomyPolicy>, AutonomyError> {
    validate_policy_create_request(&request)?;

    if let Some(existing) = transaction
        .query_row(
            &format!("SELECT {POLICY_COLUMNS} FROM life_autonomy_policy WHERE life_id = ?1"),
            [&request.life_id],
            read_policy,
        )
        .optional()
        .map_err(|_| AutonomyError::database())?
    {
        if policy_create_evidence_matches(&existing, &request) {
            validate_policy_state(&existing)?;
            return Ok(AutonomyCreateOutcome::Replayed(existing));
        }
        return Err(AutonomyError::policy_conflict());
    }

    require_life(transaction, &request.life_id)?;
    let now = sqlite_authority_now(transaction)?;
    transaction
        .execute(
            "INSERT INTO life_autonomy_policy
             (life_id, enabled, dnd, max_ready_per_window, window_seconds,
              min_gap_seconds, revision, created_at, updated_at, policy_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7, 1)",
            params![
                &request.life_id,
                request.enabled,
                request.dnd,
                request.max_ready_per_window,
                request.window_seconds,
                request.min_gap_seconds,
                &now,
            ],
        )
        .map_err(map_database_error)?;

    let created = transaction
        .query_row(
            &format!("SELECT {POLICY_COLUMNS} FROM life_autonomy_policy WHERE life_id = ?1"),
            [&request.life_id],
            read_policy,
        )
        .map_err(|_| AutonomyError::database())?;
    validate_policy_state(&created)?;
    Ok(AutonomyCreateOutcome::Applied(created))
}

fn update_policy_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeAutonomyPolicyUpdateRequest,
) -> Result<LifeAutonomyPolicyUpdateOutcome, AutonomyError> {
    validate_policy_update_request(&request)?;
    let applied_revision = next_revision(request.expected_revision)?;

    // Event identity is authoritative replay evidence and is intentionally
    // checked before loading the current policy revision.
    if let Some(existing_event) = load_policy_event_by_id(transaction, &request.event_id)? {
        if policy_event_evidence_matches(&existing_event, &request, applied_revision) {
            let current = load_policy(transaction, &request.life_id)?
                .ok_or_else(AutonomyError::policy_not_found)?;
            validate_policy_event_state(&existing_event)?;
            validate_policy_state(&current)?;
            return Ok(LifeAutonomyPolicyUpdateOutcome::Replayed {
                event: existing_event,
                current,
            });
        }
        return Err(AutonomyError::autonomy_policy_event_conflict());
    }

    let current =
        load_policy(transaction, &request.life_id)?.ok_or_else(AutonomyError::policy_not_found)?;
    validate_policy_state(&current)?;
    if current.revision != request.expected_revision {
        return Err(AutonomyError::revision_conflict());
    }

    let now = sqlite_authority_now(transaction)?;
    let changed = transaction
        .execute(
            "UPDATE life_autonomy_policy
             SET enabled = ?1,
                 dnd = ?2,
                 max_ready_per_window = ?3,
                 window_seconds = ?4,
                 min_gap_seconds = ?5,
                 revision = ?6,
                 updated_at = ?7
             WHERE life_id = ?8 AND revision = ?9",
            params![
                request.enabled,
                request.dnd,
                request.max_ready_per_window,
                request.window_seconds,
                request.min_gap_seconds,
                applied_revision,
                &now,
                &request.life_id,
                request.expected_revision,
            ],
        )
        .map_err(map_database_error)?;
    if changed != 1 {
        return Err(AutonomyError::revision_conflict());
    }

    let event = LifeAutonomyPolicyEvent {
        event_id: request.event_id,
        life_id: request.life_id,
        old_enabled: current.enabled,
        new_enabled: request.enabled,
        old_dnd: current.dnd,
        new_dnd: request.dnd,
        old_max_ready_per_window: current.max_ready_per_window,
        new_max_ready_per_window: request.max_ready_per_window,
        old_window_seconds: current.window_seconds,
        new_window_seconds: request.window_seconds,
        old_min_gap_seconds: current.min_gap_seconds,
        new_min_gap_seconds: request.min_gap_seconds,
        expected_revision: request.expected_revision,
        applied_revision,
        actor_kind: POLICY_ACTOR_KIND_USER_EXPLICIT.to_string(),
        occurred_at: now,
        event_version: POLICY_EVENT_VERSION,
    };
    validate_policy_event_state(&event)?;
    transaction
        .execute(
            &format!(
                "INSERT INTO life_autonomy_policy_event ({POLICY_EVENT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                         ?11, ?12, ?13, ?14, ?15, ?16, ?17)"
            ),
            params![
                &event.event_id,
                &event.life_id,
                event.old_enabled,
                event.new_enabled,
                event.old_dnd,
                event.new_dnd,
                event.old_max_ready_per_window,
                event.new_max_ready_per_window,
                event.old_window_seconds,
                event.new_window_seconds,
                event.old_min_gap_seconds,
                event.new_min_gap_seconds,
                event.expected_revision,
                event.applied_revision,
                &event.actor_kind,
                &event.occurred_at,
                event.event_version,
            ],
        )
        .map_err(map_database_error)?;

    let persisted_event = load_policy_event_by_id(transaction, &event.event_id)?
        .ok_or_else(AutonomyError::database)?;
    let persisted_policy =
        load_policy(transaction, &event.life_id)?.ok_or_else(AutonomyError::policy_not_found)?;
    validate_policy_event_state(&persisted_event)?;
    validate_policy_state(&persisted_policy)?;
    Ok(LifeAutonomyPolicyUpdateOutcome::Applied {
        event: persisted_event,
        policy: persisted_policy,
    })
}

fn create_pending_intent_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeProactiveIntentCreateRequest,
) -> Result<AutonomyCreateOutcome<LifeProactiveIntent>, AutonomyError> {
    validate_intent_create_request(&request)?;

    // Identity precedence is intentional: an existing intent_id is resolved
    // before any goal existence, same-life, or active-status check.
    if let Some(existing) = load_intent_by_id(transaction, &request.intent_id)? {
        if intent_create_evidence_matches(&existing, &request) {
            validate_intent_state(&existing)?;
            return Ok(AutonomyCreateOutcome::Replayed(existing));
        }
        return Err(AutonomyError::proactive_intent_conflict());
    }

    let policy =
        load_policy(transaction, &request.life_id)?.ok_or_else(AutonomyError::policy_not_found)?;
    validate_policy_state(&policy)?;
    if !policy.enabled {
        return Err(AutonomyError::policy_disabled());
    }

    require_active_goal(transaction, &request.life_id, &request.goal_id)?;
    let now = sqlite_authority_now(transaction)?;
    transaction
        .execute(
            "INSERT INTO life_proactive_intent
             (intent_id, life_id, goal_id, intent_kind, importance, user_relevance,
              self_desire, interruption_cost, focus_state, acceptance_score,
              recent_interaction_seconds, status, revision, created_by_kind,
              created_at, updated_at, not_before, expires_at, closed_at, intent_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1,
                     ?13, ?14, ?14, NULL, ?15, NULL, ?16)",
            params![
                &request.intent_id,
                &request.life_id,
                &request.goal_id,
                &request.intent_kind,
                request.importance,
                request.user_relevance,
                request.self_desire,
                request.interruption_cost,
                &request.focus_state,
                request.acceptance_score,
                request.recent_interaction_seconds,
                INTENT_STATUS_PENDING,
                INTENT_CREATED_BY_KIND_AUTONOMY_POLICY,
                &now,
                &request.expires_at,
                INTENT_VERSION,
            ],
        )
        .map_err(map_database_error)?;

    let created =
        load_intent_by_id(transaction, &request.intent_id)?.ok_or_else(AutonomyError::database)?;
    validate_intent_state(&created)?;
    Ok(AutonomyCreateOutcome::Applied(created))
}

impl crate::autonomy::AutonomyRepository for StorageService {
    fn create_policy(
        &self,
        request: LifeAutonomyPolicyCreateRequest,
    ) -> Result<AutonomyCreateOutcome<LifeAutonomyPolicy>, AutonomyError> {
        let mut state = self.state().map_err(|_| AutonomyError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AutonomyError::database())?;
        let outcome = create_policy_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| AutonomyError::database())?;
        Ok(outcome)
    }

    fn find_policy(&self, life_id: &str) -> Result<Option<LifeAutonomyPolicy>, AutonomyError> {
        validate_lookup_argument("life identity", life_id)?;
        let state = self.state().map_err(|_| AutonomyError::database())?;
        let policy = load_policy(&state.connection, life_id)?;
        if let Some(policy) = &policy {
            validate_policy_state(policy)?;
        }
        Ok(policy)
    }

    fn update_policy(
        &self,
        request: LifeAutonomyPolicyUpdateRequest,
    ) -> Result<LifeAutonomyPolicyUpdateOutcome, AutonomyError> {
        let mut state = self.state().map_err(|_| AutonomyError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AutonomyError::database())?;
        let outcome = update_policy_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| AutonomyError::database())?;
        Ok(outcome)
    }

    fn create_pending_goal_check_in_intent(
        &self,
        request: LifeProactiveIntentCreateRequest,
    ) -> Result<AutonomyCreateOutcome<LifeProactiveIntent>, AutonomyError> {
        let mut state = self.state().map_err(|_| AutonomyError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AutonomyError::database())?;
        let outcome = create_pending_intent_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| AutonomyError::database())?;
        Ok(outcome)
    }

    fn find_intent(
        &self,
        life_id: &str,
        intent_id: &str,
    ) -> Result<Option<LifeProactiveIntent>, AutonomyError> {
        validate_lookup_arguments(life_id, "intent identity", intent_id)?;
        let state = self.state().map_err(|_| AutonomyError::database())?;
        let intent = load_intent(&state.connection, life_id, intent_id)?;
        if let Some(intent) = &intent {
            validate_intent_state(intent)?;
        }
        Ok(intent)
    }

    fn list_intents_for_life(
        &self,
        life_id: &str,
    ) -> Result<Vec<LifeProactiveIntent>, AutonomyError> {
        validate_lookup_argument("life identity", life_id)?;
        let state = self.state().map_err(|_| AutonomyError::database())?;
        let mut statement = state
            .connection
            .prepare(&format!(
                "SELECT {INTENT_COLUMNS} FROM life_proactive_intent
                 WHERE life_id = ?1 ORDER BY created_at, intent_id"
            ))
            .map_err(|_| AutonomyError::database())?;
        let rows = statement
            .query_map([life_id], read_intent)
            .map_err(|_| AutonomyError::database())?;
        let intents = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AutonomyError::database())?;
        for intent in &intents {
            validate_intent_state(intent)?;
        }
        Ok(intents)
    }

    fn list_intents_for_goal(
        &self,
        life_id: &str,
        goal_id: &str,
    ) -> Result<Vec<LifeProactiveIntent>, AutonomyError> {
        validate_lookup_arguments(life_id, "goal identity", goal_id)?;
        let state = self.state().map_err(|_| AutonomyError::database())?;
        let mut statement = state
            .connection
            .prepare(&format!(
                "SELECT {INTENT_COLUMNS} FROM life_proactive_intent
                 WHERE life_id = ?1 AND goal_id = ?2 ORDER BY created_at, intent_id"
            ))
            .map_err(|_| AutonomyError::database())?;
        let rows = statement
            .query_map(params![life_id, goal_id], read_intent)
            .map_err(|_| AutonomyError::database())?;
        let intents = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AutonomyError::database())?;
        for intent in &intents {
            validate_intent_state(intent)?;
        }
        Ok(intents)
    }

    fn find_policy_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeAutonomyPolicyEvent>, AutonomyError> {
        validate_lookup_arguments(life_id, "policy event identity", event_id)?;
        let state = self.state().map_err(|_| AutonomyError::database())?;
        let event = state
            .connection
            .query_row(
                &format!(
                    "SELECT {POLICY_EVENT_COLUMNS} FROM life_autonomy_policy_event
                     WHERE life_id = ?1 AND event_id = ?2"
                ),
                params![life_id, event_id],
                read_policy_event,
            )
            .optional()
            .map_err(|_| AutonomyError::database())?;
        if let Some(event) = &event {
            validate_policy_event_state(event)?;
        }
        Ok(event)
    }
}

const _: for<'a> fn(
    &'a StorageService,
    LifeAutonomyPolicyCreateRequest,
) -> Result<AutonomyCreateOutcome<LifeAutonomyPolicy>, AutonomyError> =
    <StorageService as crate::autonomy::AutonomyRepository>::create_policy;
const _: for<'a> fn(
    &'a StorageService,
    LifeAutonomyPolicyUpdateRequest,
) -> Result<LifeAutonomyPolicyUpdateOutcome, AutonomyError> =
    <StorageService as crate::autonomy::AutonomyRepository>::update_policy;
const _: for<'a> fn(
    &'a StorageService,
    LifeProactiveIntentCreateRequest,
) -> Result<AutonomyCreateOutcome<LifeProactiveIntent>, AutonomyError> =
    <StorageService as crate::autonomy::AutonomyRepository>::create_pending_goal_check_in_intent;

/// Exact normalized validation of every Schema23 D15 object. A matching name
/// is not sufficient: table and trigger DDL must retain all checks, foreign
/// keys, and selective immutability semantics.
pub(super) fn validate_schema_objects(connection: &Connection) -> Result<(), super::StorageError> {
    for (object_kind, object_name, expected_sql) in [
        (
            "table",
            "life_autonomy_policy",
            CREATE_LIFE_AUTONOMY_POLICY_TABLE_SQL,
        ),
        (
            "table",
            "life_autonomy_policy_event",
            CREATE_LIFE_AUTONOMY_POLICY_EVENT_TABLE_SQL,
        ),
        (
            "table",
            "life_proactive_intent",
            CREATE_LIFE_PROACTIVE_INTENT_TABLE_SQL,
        ),
        (
            "table",
            "life_proactive_intent_event",
            CREATE_LIFE_PROACTIVE_INTENT_EVENT_TABLE_SQL,
        ),
        (
            "trigger",
            "life_autonomy_policy_immutable_guard",
            CREATE_LIFE_AUTONOMY_POLICY_IMMUTABLE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "life_autonomy_policy_event_immutable_guard",
            CREATE_LIFE_AUTONOMY_POLICY_EVENT_IMMUTABLE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "life_proactive_intent_immutable_guard",
            CREATE_LIFE_PROACTIVE_INTENT_IMMUTABLE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "life_proactive_intent_event_immutable_guard",
            CREATE_LIFE_PROACTIVE_INTENT_EVENT_IMMUTABLE_TRIGGER_SQL,
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

    for (child_table, parent_table, column_pairs) in [
        (
            "life_autonomy_policy",
            "life_identity",
            &[("life_id", "id")][..],
        ),
        (
            "life_autonomy_policy_event",
            "life_autonomy_policy",
            &[("life_id", "life_id")][..],
        ),
        (
            "life_proactive_intent",
            "life_goal",
            &[("goal_id", "goal_id"), ("life_id", "life_id")][..],
        ),
        (
            "life_proactive_intent",
            "life_identity",
            &[("life_id", "id")][..],
        ),
        (
            "life_proactive_intent_event",
            "life_proactive_intent",
            &[("intent_id", "intent_id"), ("life_id", "life_id")][..],
        ),
    ] {
        for (from_column, to_column) in column_pairs {
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
    }

    connection
        .execute_batch(
            "CREATE TABLE _autonomy_fk_probe (
                 goal_id TEXT NOT NULL,
                 life_id TEXT NOT NULL,
                 intent_id TEXT NOT NULL,
                 FOREIGN KEY (goal_id, life_id)
                     REFERENCES life_goal(goal_id, life_id) ON DELETE CASCADE,
                 FOREIGN KEY (intent_id, life_id)
                     REFERENCES life_proactive_intent(intent_id, life_id) ON DELETE CASCADE
             );
             DROP TABLE _autonomy_fk_probe;",
        )
        .map_err(|_| super::StorageError::migration_transaction_failed())?;
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

const _: fn(&Connection) -> Result<(), super::StorageError> = validate_schema_objects;

#[cfg(test)]
mod tests {
    use rusqlite::params;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        autonomy::{
            validate_intent_event_state, AutonomyErrorCode, AutonomyRepository,
            LifeAutonomyPolicyUpdateOutcome, LifeProactiveIntentEvent,
            INTENT_EVENT_ACTOR_KIND_AUTONOMY_POLICY, INTENT_EVENT_VERSION,
            INTENT_FOCUS_STATE_AVAILABLE, INTENT_KIND_GOAL_CHECK_IN, INTENT_STATUS_PENDING,
            INTENT_STATUS_READY,
        },
        life_intent::{
            LifeGoalCreateRequest, LifeGoalTransitionKind, LifeGoalTransitionRequest,
            LifeIntentRepository,
        },
    };

    struct Fixture {
        _root: TempDir,
        storage: StorageService,
    }

    type BadSignalSetter = fn(&mut LifeProactiveIntentCreateRequest);

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let default_root = root.path().join("default");
            std::fs::create_dir_all(&default_root).unwrap();
            let storage = StorageService::initialize_with_roots(default_root, None).unwrap();
            storage
                .save_persona(crate::storage::PersonaTemplateRecord {
                    id: "autonomy-persona".into(),
                    name: "Autonomy Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            for (id, name, body_id, created_at) in [
                (
                    "autonomy-life-a",
                    "Autonomy Life A",
                    "autonomy-body-a",
                    "2026-08-27T00:00:00.000Z",
                ),
                (
                    "autonomy-life-b",
                    "Autonomy Life B",
                    "autonomy-body-b",
                    "2026-08-27T00:00:01.000Z",
                ),
            ] {
                storage
                    .save_life(crate::storage::LifeIdentityRecord {
                        id: id.into(),
                        name: name.into(),
                        created_at: created_at.into(),
                        version: 1,
                        body_id: body_id.into(),
                        persona_id: "autonomy-persona".into(),
                        persona_version: 1,
                    })
                    .unwrap();
            }
            Self {
                _root: root,
                storage,
            }
        }

        fn policy_request(&self, life_id: &str) -> LifeAutonomyPolicyCreateRequest {
            LifeAutonomyPolicyCreateRequest {
                life_id: life_id.into(),
                enabled: true,
                dnd: false,
                max_ready_per_window: 3,
                window_seconds: 900,
                min_gap_seconds: 60,
            }
        }

        fn create_policy(&self, life_id: &str, enabled: bool, dnd: bool) {
            let mut request = self.policy_request(life_id);
            request.enabled = enabled;
            request.dnd = dnd;
            self.storage.create_policy(request).unwrap();
        }

        fn intent_request(
            &self,
            intent_id: &str,
            life_id: &str,
            goal_id: &str,
        ) -> LifeProactiveIntentCreateRequest {
            LifeProactiveIntentCreateRequest {
                intent_id: intent_id.into(),
                life_id: life_id.into(),
                goal_id: goal_id.into(),
                intent_kind: INTENT_KIND_GOAL_CHECK_IN.into(),
                importance: 700,
                user_relevance: 800,
                self_desire: 200,
                interruption_cost: 100,
                focus_state: INTENT_FOCUS_STATE_AVAILABLE.into(),
                acceptance_score: Some(600),
                recent_interaction_seconds: Some(30),
                expires_at: Some("2026-08-28T00:00:00.000Z".into()),
            }
        }

        fn create_goal(&self, goal_id: &str, life_id: &str) {
            self.storage
                .create_goal(LifeGoalCreateRequest {
                    goal_id: goal_id.into(),
                    life_id: life_id.into(),
                    title: format!("Title {goal_id}"),
                    objective: format!("Objective {goal_id}"),
                })
                .unwrap();
        }
    }

    fn error_code(error: AutonomyError) -> AutonomyErrorCode {
        error.code
    }

    #[test]
    fn policy_create_replay_update_cas_and_dnd_are_authoritative() {
        let fixture = Fixture::new();
        assert!(fixture
            .storage
            .find_policy("autonomy-life-a")
            .unwrap()
            .is_none());

        let request = fixture.policy_request("autonomy-life-a");
        let applied = fixture.storage.create_policy(request.clone()).unwrap();
        let policy = match applied {
            AutonomyCreateOutcome::Applied(policy) => policy,
            AutonomyCreateOutcome::Replayed(_) => panic!("first policy create must apply"),
        };
        assert_eq!(policy.revision, 1);
        assert!(policy.is_effectively_enabled());

        let replay = fixture.storage.create_policy(request).unwrap();
        assert!(matches!(replay, AutonomyCreateOutcome::Replayed(_)));
        let mut conflicting = fixture.policy_request("autonomy-life-a");
        conflicting.max_ready_per_window = 4;
        assert_eq!(
            error_code(fixture.storage.create_policy(conflicting).unwrap_err()),
            AutonomyErrorCode::PolicyConflict
        );

        let update = LifeAutonomyPolicyUpdateRequest {
            event_id: "autonomy-policy-event-1".into(),
            life_id: "autonomy-life-a".into(),
            enabled: true,
            dnd: true,
            max_ready_per_window: 4,
            window_seconds: 1200,
            min_gap_seconds: 120,
            expected_revision: 1,
        };
        let updated = fixture.storage.update_policy(update.clone()).unwrap();
        let (event, policy) = match updated {
            LifeAutonomyPolicyUpdateOutcome::Applied { event, policy } => (event, policy),
            LifeAutonomyPolicyUpdateOutcome::Replayed { .. } => panic!("first update must apply"),
        };
        assert_eq!(event.applied_revision, 2);
        assert_eq!(policy.revision, 2);
        assert!(!policy.is_effectively_enabled());
        assert!(policy.dnd);
        assert_eq!(
            fixture
                .storage
                .find_policy_event("autonomy-life-a", "autonomy-policy-event-1")
                .unwrap()
                .unwrap(),
            event
        );

        let replay = fixture.storage.update_policy(update).unwrap();
        assert!(matches!(
            replay,
            LifeAutonomyPolicyUpdateOutcome::Replayed { .. }
        ));
        let conflicting_event = LifeAutonomyPolicyUpdateRequest {
            event_id: "autonomy-policy-event-1".into(),
            life_id: "autonomy-life-a".into(),
            enabled: false,
            dnd: true,
            max_ready_per_window: 4,
            window_seconds: 1200,
            min_gap_seconds: 120,
            expected_revision: 1,
        };
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .update_policy(conflicting_event)
                    .unwrap_err()
            ),
            AutonomyErrorCode::AutonomyPolicyEventConflict
        );
        let stale = LifeAutonomyPolicyUpdateRequest {
            event_id: "autonomy-policy-event-2".into(),
            life_id: "autonomy-life-a".into(),
            enabled: false,
            dnd: false,
            max_ready_per_window: 4,
            window_seconds: 1200,
            min_gap_seconds: 120,
            expected_revision: 1,
        };
        assert_eq!(
            error_code(fixture.storage.update_policy(stale).unwrap_err()),
            AutonomyErrorCode::RevisionConflict
        );
    }

    #[test]
    fn intent_create_replay_identity_precedence_goal_binding_and_lists() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-goal-a", "autonomy-life-a");
        fixture.create_goal("autonomy-goal-b", "autonomy-life-b");
        let request =
            fixture.intent_request("autonomy-intent-1", "autonomy-life-a", "autonomy-goal-a");
        let created = fixture
            .storage
            .create_pending_goal_check_in_intent(request.clone())
            .unwrap();
        let intent = match created {
            AutonomyCreateOutcome::Applied(intent) => intent,
            AutonomyCreateOutcome::Replayed(_) => panic!("first intent create must apply"),
        };
        assert_eq!(intent.status, INTENT_STATUS_PENDING);
        assert_eq!(intent.revision, 1);
        assert_eq!(
            intent.created_by_kind,
            INTENT_CREATED_BY_KIND_AUTONOMY_POLICY
        );
        assert_eq!(intent.closed_at, None);
        assert_eq!(intent.not_before, None);
        assert_eq!(intent.expires_at, request.expires_at);

        let replay = fixture
            .storage
            .create_pending_goal_check_in_intent(request.clone())
            .unwrap();
        assert!(matches!(replay, AutonomyCreateOutcome::Replayed(_)));
        let mut conflicting = request.clone();
        conflicting.goal_id = "missing-goal-for-precedence".into();
        conflicting.importance = 701;
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(conflicting)
                    .unwrap_err()
            ),
            AutonomyErrorCode::ProactiveIntentConflict
        );

        let missing_goal =
            fixture.intent_request("autonomy-intent-missing", "autonomy-life-a", "missing-goal");
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(missing_goal)
                    .unwrap_err()
            ),
            AutonomyErrorCode::GoalNotFound
        );
        let cross_life = fixture.intent_request(
            "autonomy-intent-cross-life",
            "autonomy-life-a",
            "autonomy-goal-b",
        );
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(cross_life)
                    .unwrap_err()
            ),
            AutonomyErrorCode::GoalLifeMismatch
        );

        fixture.create_goal("autonomy-goal-terminal", "autonomy-life-a");
        fixture
            .storage
            .transition_goal(LifeGoalTransitionRequest {
                goal_id: "autonomy-goal-terminal".into(),
                life_id: "autonomy-life-a".into(),
                kind: LifeGoalTransitionKind::Complete,
                event_id: "autonomy-goal-terminal-event".into(),
                expected_revision: 1,
            })
            .unwrap();
        let terminal = fixture.intent_request(
            "autonomy-intent-terminal-goal",
            "autonomy-life-a",
            "autonomy-goal-terminal",
        );
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(terminal)
                    .unwrap_err()
            ),
            AutonomyErrorCode::GoalNotActive
        );

        fixture.create_goal("autonomy-goal-cancelled", "autonomy-life-a");
        fixture
            .storage
            .transition_goal(LifeGoalTransitionRequest {
                goal_id: "autonomy-goal-cancelled".into(),
                life_id: "autonomy-life-a".into(),
                kind: LifeGoalTransitionKind::Cancel,
                event_id: "autonomy-goal-cancelled-event".into(),
                expected_revision: 1,
            })
            .unwrap();
        let cancelled = fixture.intent_request(
            "autonomy-intent-cancelled-goal",
            "autonomy-life-a",
            "autonomy-goal-cancelled",
        );
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(cancelled)
                    .unwrap_err()
            ),
            AutonomyErrorCode::GoalNotActive
        );

        assert_eq!(
            fixture
                .storage
                .find_intent("autonomy-life-a", "autonomy-intent-1")
                .unwrap()
                .unwrap(),
            intent
        );
        assert_eq!(
            fixture
                .storage
                .list_intents_for_life("autonomy-life-a")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            fixture
                .storage
                .list_intents_for_goal("autonomy-life-a", "autonomy-goal-a")
                .unwrap()
                .len(),
            1
        );

        let state = fixture.storage.state().unwrap();
        let columns: Vec<String> = state
            .connection
            .prepare("PRAGMA table_info(life_proactive_intent)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        for forbidden in [
            "message_body",
            "content_draft",
            "llm_output",
            "reasoning",
            "cot",
            "prompt",
            "raw_conversation",
            "raw_memory",
            "goal_title",
            "goal_objective",
        ] {
            assert!(!columns.iter().any(|column| column == forbidden));
        }
    }

    #[test]
    fn new_intent_requires_enabled_policy_and_preserves_identity_precedence() {
        let fixture = Fixture::new();
        fixture.create_goal("autonomy-goal-opt-in", "autonomy-life-a");
        let request = fixture.intent_request(
            "autonomy-intent-no-policy",
            "autonomy-life-a",
            "autonomy-goal-opt-in",
        );

        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(request)
                    .unwrap_err()
            ),
            AutonomyErrorCode::PolicyNotFound
        );
        let state = fixture.storage.state().unwrap();
        let intent_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM life_proactive_intent", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(intent_count, 0);
        drop(state);

        fixture.create_policy("autonomy-life-a", false, false);
        let disabled_request = fixture.intent_request(
            "autonomy-intent-disabled",
            "autonomy-life-a",
            "autonomy-goal-opt-in",
        );
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(disabled_request)
                    .unwrap_err()
            ),
            AutonomyErrorCode::PolicyDisabled
        );

        let missing_goal_request = fixture.intent_request(
            "autonomy-intent-disabled-missing-goal",
            "autonomy-life-a",
            "missing-goal-while-disabled",
        );
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(missing_goal_request)
                    .unwrap_err()
            ),
            AutonomyErrorCode::PolicyDisabled
        );

        fixture
            .storage
            .update_policy(LifeAutonomyPolicyUpdateRequest {
                event_id: "autonomy-policy-event-enable".into(),
                life_id: "autonomy-life-a".into(),
                enabled: true,
                dnd: false,
                max_ready_per_window: 3,
                window_seconds: 900,
                min_gap_seconds: 60,
                expected_revision: 1,
            })
            .unwrap();
        let request = fixture.intent_request(
            "autonomy-intent-after-enable",
            "autonomy-life-a",
            "autonomy-goal-opt-in",
        );
        let created = fixture
            .storage
            .create_pending_goal_check_in_intent(request.clone())
            .unwrap();
        assert!(matches!(created, AutonomyCreateOutcome::Applied(_)));

        fixture
            .storage
            .update_policy(LifeAutonomyPolicyUpdateRequest {
                event_id: "autonomy-policy-event-disable".into(),
                life_id: "autonomy-life-a".into(),
                enabled: false,
                dnd: false,
                max_ready_per_window: 3,
                window_seconds: 900,
                min_gap_seconds: 60,
                expected_revision: 2,
            })
            .unwrap();

        let replay = fixture
            .storage
            .create_pending_goal_check_in_intent(request.clone())
            .unwrap();
        assert!(matches!(replay, AutonomyCreateOutcome::Replayed(_)));

        let mut conflicting = request;
        conflicting.goal_id = "missing-goal-after-disable".into();
        conflicting.importance += 1;
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(conflicting)
                    .unwrap_err()
            ),
            AutonomyErrorCode::ProactiveIntentConflict
        );
        assert_eq!(
            fixture
                .storage
                .find_intent("autonomy-life-a", "autonomy-intent-after-enable")
                .unwrap()
                .unwrap()
                .importance,
            700
        );
        let state = fixture.storage.state().unwrap();
        let intent_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM life_proactive_intent", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(intent_count, 1);
    }

    #[test]
    fn enabled_dnd_policy_allows_pending_intent_creation() {
        let fixture = Fixture::new();
        fixture.create_goal("autonomy-goal-dnd", "autonomy-life-a");
        fixture.create_policy("autonomy-life-a", true, true);

        let request = fixture.intent_request(
            "autonomy-intent-dnd",
            "autonomy-life-a",
            "autonomy-goal-dnd",
        );
        let created = fixture
            .storage
            .create_pending_goal_check_in_intent(request)
            .unwrap();
        let intent = match created {
            AutonomyCreateOutcome::Applied(intent) => intent,
            AutonomyCreateOutcome::Replayed(_) => panic!("first intent create must apply"),
        };
        assert_eq!(intent.status, INTENT_STATUS_PENDING);
        assert_eq!(intent.revision, 1);
        assert_eq!(intent.focus_state, "available");
    }

    #[test]
    fn intent_bounds_focus_and_expiry_are_rejected_before_storage() {
        let fixture = Fixture::new();
        fixture.create_goal("autonomy-goal-bounds", "autonomy-life-a");
        let bad_signal_cases: [(&str, BadSignalSetter); 5] = [
            (
                "autonomy-intent-bad-importance",
                |request: &mut LifeProactiveIntentCreateRequest| request.importance = 1001,
            ),
            (
                "autonomy-intent-bad-relevance",
                |request: &mut LifeProactiveIntentCreateRequest| request.user_relevance = -1,
            ),
            (
                "autonomy-intent-bad-desire",
                |request: &mut LifeProactiveIntentCreateRequest| request.self_desire = 1001,
            ),
            (
                "autonomy-intent-bad-interruption",
                |request: &mut LifeProactiveIntentCreateRequest| request.interruption_cost = -1,
            ),
            (
                "autonomy-intent-bad-acceptance",
                |request: &mut LifeProactiveIntentCreateRequest| {
                    request.acceptance_score = Some(1001)
                },
            ),
        ];
        for (id, set_bad_signal) in bad_signal_cases {
            let mut request = fixture.intent_request(id, "autonomy-life-a", "autonomy-goal-bounds");
            set_bad_signal(&mut request);
            assert_eq!(
                error_code(
                    fixture
                        .storage
                        .create_pending_goal_check_in_intent(request)
                        .unwrap_err()
                ),
                AutonomyErrorCode::InvalidArgument
            );
        }
        let mut bad_recent = fixture.intent_request(
            "autonomy-intent-bad-recent",
            "autonomy-life-a",
            "autonomy-goal-bounds",
        );
        bad_recent.recent_interaction_seconds = Some(-1);
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(bad_recent)
                    .unwrap_err()
            ),
            AutonomyErrorCode::InvalidArgument
        );
        let mut bad_focus = fixture.intent_request(
            "autonomy-intent-bad-focus",
            "autonomy-life-a",
            "autonomy-goal-bounds",
        );
        bad_focus.focus_state = "away".into();
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(bad_focus)
                    .unwrap_err()
            ),
            AutonomyErrorCode::InvalidArgument
        );
        let mut bad_expiry = fixture.intent_request(
            "autonomy-intent-bad-expiry",
            "autonomy-life-a",
            "autonomy-goal-bounds",
        );
        bad_expiry.expires_at = Some("tomorrow".into());
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_pending_goal_check_in_intent(bad_expiry)
                    .unwrap_err()
            ),
            AutonomyErrorCode::InvalidArgument
        );
        let mut bad_policy = fixture.policy_request("autonomy-life-a");
        bad_policy.window_seconds = 59;
        assert_eq!(
            error_code(fixture.storage.create_policy(bad_policy).unwrap_err()),
            AutonomyErrorCode::InvalidArgument
        );
    }

    #[test]
    fn selective_immutability_event_ledger_and_cascades_are_enforced() {
        let fixture = Fixture::new();
        fixture.create_goal("autonomy-goal-cascade", "autonomy-life-a");
        fixture
            .storage
            .create_policy(fixture.policy_request("autonomy-life-a"))
            .unwrap();
        let intent = fixture
            .storage
            .create_pending_goal_check_in_intent(fixture.intent_request(
                "autonomy-intent-cascade",
                "autonomy-life-a",
                "autonomy-goal-cascade",
            ))
            .unwrap();
        let intent = match intent {
            AutonomyCreateOutcome::Applied(intent) => intent,
            AutonomyCreateOutcome::Replayed(_) => panic!("first intent create must apply"),
        };
        fixture
            .storage
            .update_policy(LifeAutonomyPolicyUpdateRequest {
                event_id: "autonomy-policy-event-cascade".into(),
                life_id: "autonomy-life-a".into(),
                enabled: false,
                dnd: false,
                max_ready_per_window: 3,
                window_seconds: 900,
                min_gap_seconds: 60,
                expected_revision: 1,
            })
            .unwrap();

        let state = fixture.storage.state().unwrap();
        let immutable_error = state
            .connection
            .execute(
                "UPDATE life_autonomy_policy SET created_at='2026-01-01T00:00:00.000Z'
                 WHERE life_id='autonomy-life-a'",
                [],
            )
            .unwrap_err();
        assert!(immutable_error
            .to_string()
            .contains("LIFE_AUTONOMY_POLICY_IMMUTABLE"));
        let event_immutable_error = state
            .connection
            .execute(
                "UPDATE life_autonomy_policy_event SET new_enabled=1
                 WHERE event_id='autonomy-policy-event-cascade'",
                [],
            )
            .unwrap_err();
        assert!(event_immutable_error
            .to_string()
            .contains("LIFE_AUTONOMY_POLICY_EVENT_IMMUTABLE"));

        state
            .connection
            .execute(
                "UPDATE life_proactive_intent
                 SET status='ready', revision=2, updated_at='2026-08-27T00:00:02.000Z'
                 WHERE intent_id=?1",
                params![intent.intent_id],
            )
            .unwrap();
        let lifecycle: LifeProactiveIntent = state
            .connection
            .query_row(
                &format!("SELECT {INTENT_COLUMNS} FROM life_proactive_intent WHERE intent_id=?1"),
                [&intent.intent_id],
                read_intent,
            )
            .unwrap();
        assert_eq!(lifecycle.status, INTENT_STATUS_READY);
        assert_eq!(lifecycle.revision, 2);

        state
            .connection
            .execute(
                &format!(
                    "INSERT INTO life_proactive_intent_event ({INTENT_EVENT_COLUMNS})
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, 2, NULL, ?6, ?7, ?8)"
                ),
                params![
                    "autonomy-intent-event-1",
                    intent.life_id,
                    intent.intent_id,
                    INTENT_STATUS_PENDING,
                    INTENT_STATUS_READY,
                    INTENT_EVENT_ACTOR_KIND_AUTONOMY_POLICY,
                    "2026-08-27T00:00:02.000Z",
                    INTENT_EVENT_VERSION,
                ],
            )
            .unwrap();
        let intent_event = state
            .connection
            .query_row(
                &format!(
                    "SELECT {INTENT_EVENT_COLUMNS} FROM life_proactive_intent_event
                     WHERE event_id='autonomy-intent-event-1'"
                ),
                [],
                read_intent_event,
            )
            .unwrap();
        validate_intent_event_state(&intent_event).unwrap();
        let constructed = LifeProactiveIntentEvent {
            event_id: "constructed-event".into(),
            life_id: intent.life_id.clone(),
            intent_id: intent.intent_id.clone(),
            from_status: INTENT_STATUS_PENDING.into(),
            to_status: INTENT_STATUS_READY.into(),
            expected_revision: 1,
            applied_revision: 2,
            not_before_after: None,
            actor_kind: INTENT_EVENT_ACTOR_KIND_AUTONOMY_POLICY.into(),
            occurred_at: "2026-08-27T00:00:02.000Z".into(),
            event_version: INTENT_EVENT_VERSION,
        };
        validate_intent_event_state(&constructed).unwrap();
        let intent_event_immutable_error = state
            .connection
            .execute(
                "UPDATE life_proactive_intent_event SET to_status='cancelled'
                 WHERE event_id='autonomy-intent-event-1'",
                [],
            )
            .unwrap_err();
        assert!(intent_event_immutable_error
            .to_string()
            .contains("LIFE_PROACTIVE_INTENT_EVENT_IMMUTABLE"));
        drop(state);

        fixture
            .storage
            .delete_goal("autonomy-life-a", "autonomy-goal-cascade")
            .unwrap();
        assert!(fixture
            .storage
            .find_intent("autonomy-life-a", "autonomy-intent-cascade")
            .unwrap()
            .is_none());
        let state = fixture.storage.state().unwrap();
        assert_eq!(
            state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM life_proactive_intent_event
                     WHERE intent_id='autonomy-intent-cascade'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        state
            .connection
            .execute("DELETE FROM life_identity WHERE id='autonomy-life-a'", [])
            .unwrap();
        assert_eq!(
            state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM life_autonomy_policy
                     WHERE life_id='autonomy-life-a'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM life_autonomy_policy_event
                     WHERE life_id='autonomy-life-a'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }
}
