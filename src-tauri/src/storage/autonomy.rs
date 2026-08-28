//! SQLite-authoritative persistence for D15-B2 autonomy policy and
//! proactive-intent evaluation evidence.
//!
//! It persists explicit policy and bounded `goal_check_in` evidence, evaluates
//! only pending intents, and records the resulting immutable lifecycle event.
//! It does not create intents automatically, mutate D14 goals, schedule work,
//! deliver messages, or invoke an Agent or Tool.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};

use super::StorageService;
use crate::{
    autonomy::{
        evaluate_initiative_policy, validate_intent_create_request,
        validate_intent_evaluation_request, validate_intent_event_state, validate_intent_state,
        validate_policy_create_request, validate_policy_event_state, validate_policy_state,
        validate_policy_update_request, AutonomyCreateOutcome, AutonomyError,
        InitiativePolicyDecision, InitiativePolicyTemporalContext, LifeAutonomyPolicy,
        LifeAutonomyPolicyCreateRequest, LifeAutonomyPolicyEvent, LifeAutonomyPolicyUpdateOutcome,
        LifeAutonomyPolicyUpdateRequest, LifeProactiveIntent, LifeProactiveIntentCreateRequest,
        LifeProactiveIntentEvaluationOutcome, LifeProactiveIntentEvaluationRequest,
        LifeProactiveIntentEvent, INTENT_CREATED_BY_KIND_AUTONOMY_POLICY,
        INTENT_EVENT_ACTOR_KIND_AUTONOMY_POLICY, INTENT_EVENT_VERSION,
        INTENT_FOCUS_STATE_AVAILABLE, INTENT_STATUS_CANCELLED, INTENT_STATUS_DEFERRED,
        INTENT_STATUS_EXPIRED, INTENT_STATUS_PENDING, INTENT_STATUS_READY,
        INTENT_STATUS_STORED_SILENTLY, INTENT_VERSION, MIN_RECHECK_SECONDS,
        POLICY_ACTOR_KIND_USER_EXPLICIT, POLICY_EVENT_VERSION, RECENT_INTERACTION_QUIET_SECONDS,
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

fn sqlite_add_seconds(
    connection: &Connection,
    base: &str,
    seconds: i64,
) -> Result<String, AutonomyError> {
    let modifier = if seconds >= 0 {
        format!("+{seconds} seconds")
    } else {
        format!("{seconds} seconds")
    };
    connection
        .query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1, ?2)",
            params![base, modifier],
            |row| row.get(0),
        )
        .map_err(|_| AutonomyError::database())
}

fn sqlite_elapsed_seconds(
    connection: &Connection,
    now: &str,
    earlier: &str,
) -> Result<i64, AutonomyError> {
    connection
        .query_row(
            "SELECT CAST(MAX(0.0, (julianday(?1) - julianday(?2)) * 86400.0) AS INTEGER)",
            params![now, earlier],
            |row| row.get(0),
        )
        .map_err(|_| AutonomyError::database())
}

impl StorageService {
    pub(crate) fn autonomy_tick_now(&self) -> Result<String, AutonomyError> {
        let state = self.state().map_err(|_| AutonomyError::database())?;
        sqlite_authority_now(&state.connection)
    }

    pub(crate) fn autonomy_tick_add_seconds(
        &self,
        base: &str,
        seconds: i64,
    ) -> Result<String, AutonomyError> {
        let state = self.state().map_err(|_| AutonomyError::database())?;
        sqlite_add_seconds(&state.connection, base, seconds)
    }

    pub(crate) fn autonomy_tick_elapsed_seconds(
        &self,
        now: &str,
        earlier: &str,
    ) -> Result<i64, AutonomyError> {
        let state = self.state().map_err(|_| AutonomyError::database())?;
        sqlite_elapsed_seconds(&state.connection, now, earlier)
    }

    pub(crate) fn autonomy_tick_active_goals(
        &self,
        life_id: &str,
        limit: i64,
    ) -> Result<Vec<crate::life_intent::LifeGoal>, crate::life_intent::LifeIntentError> {
        let state = self
            .state()
            .map_err(|_| crate::life_intent::LifeIntentError::database())?;
        super::life_intent::list_active_goals_for_autonomy_tick(&state.connection, life_id, limit)
    }
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

fn load_intent_event_by_id(
    connection: &Connection,
    event_id: &str,
) -> Result<Option<LifeProactiveIntentEvent>, AutonomyError> {
    connection
        .query_row(
            &format!(
                "SELECT {INTENT_EVENT_COLUMNS} FROM life_proactive_intent_event
                 WHERE event_id = ?1"
            ),
            [event_id],
            read_intent_event,
        )
        .optional()
        .map_err(|_| AutonomyError::database())
}

fn intent_event_evidence_matches(
    event: &LifeProactiveIntentEvent,
    request: &crate::autonomy::LifeProactiveIntentEvaluationRequest,
    applied_revision: i64,
) -> bool {
    event.event_id == request.event_id
        && event.life_id == request.life_id
        && event.intent_id == request.intent_id
        && event.from_status == INTENT_STATUS_PENDING
        && event.expected_revision == request.expected_revision
        && event.applied_revision == applied_revision
        && event.actor_kind == INTENT_EVENT_ACTOR_KIND_AUTONOMY_POLICY
        && event.event_version == INTENT_EVENT_VERSION
}

fn load_goal_is_active(
    connection: &Connection,
    life_id: &str,
    goal_id: &str,
) -> Result<bool, AutonomyError> {
    let status: Option<String> = connection
        .query_row(
            "SELECT status FROM life_goal WHERE goal_id = ?1 AND life_id = ?2",
            params![goal_id, life_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| AutonomyError::database())?;
    Ok(status.as_deref() == Some(GOAL_STATUS_ACTIVE))
}

#[derive(Debug, Default)]
struct ReadyEventHistory {
    count_in_window: i64,
    oldest_in_window: Option<String>,
    latest: Option<String>,
}

fn load_ready_event_history(
    connection: &Connection,
    life_id: &str,
    now: &str,
    window_seconds: i64,
) -> Result<ReadyEventHistory, AutonomyError> {
    let window_start = sqlite_add_seconds(connection, now, -window_seconds)?;
    let (count_in_window, oldest_in_window): (i64, Option<String>) = connection
        .query_row(
            "SELECT COUNT(*), MIN(occurred_at)
             FROM life_proactive_intent_event
             WHERE life_id = ?1
               AND to_status = 'ready'
               AND occurred_at >= ?2
               AND occurred_at <= ?3",
            params![life_id, window_start, now],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| AutonomyError::database())?;
    let latest: Option<String> = connection
        .query_row(
            "SELECT MAX(occurred_at)
             FROM life_proactive_intent_event
             WHERE life_id = ?1
               AND to_status = 'ready'
               AND occurred_at <= ?2",
            params![life_id, now],
            |row| row.get(0),
        )
        .map_err(|_| AutonomyError::database())?;
    Ok(ReadyEventHistory {
        count_in_window,
        oldest_in_window,
        latest,
    })
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
    // Storage compares only through the read-only evidence getters; it never
    // constructs or mutates a request it receives.
    intent.intent_id == request.intent_id()
        && intent.life_id == request.life_id()
        && intent.goal_id == request.goal_id()
        && intent.intent_kind == request.intent_kind()
        && intent.importance == request.importance()
        && intent.user_relevance == request.user_relevance()
        && intent.self_desire == request.self_desire()
        && intent.interruption_cost == request.interruption_cost()
        && intent.focus_state == request.focus_state()
        && intent.acceptance_score == request.acceptance_score()
        && intent.recent_interaction_seconds == request.recent_interaction_seconds()
        && intent.expires_at.as_deref() == request.expires_at()
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
    if let Some(existing) = load_intent_by_id(transaction, request.intent_id())? {
        if intent_create_evidence_matches(&existing, &request) {
            validate_intent_state(&existing)?;
            return Ok(AutonomyCreateOutcome::Replayed(existing));
        }
        return Err(AutonomyError::proactive_intent_conflict());
    }

    let policy =
        load_policy(transaction, request.life_id())?.ok_or_else(AutonomyError::policy_not_found)?;
    validate_policy_state(&policy)?;
    if !policy.enabled {
        return Err(AutonomyError::policy_disabled());
    }

    require_active_goal(transaction, request.life_id(), request.goal_id())?;
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
                request.intent_id(),
                request.life_id(),
                request.goal_id(),
                request.intent_kind(),
                request.importance(),
                request.user_relevance(),
                request.self_desire(),
                request.interruption_cost(),
                request.focus_state(),
                request.acceptance_score(),
                request.recent_interaction_seconds(),
                INTENT_STATUS_PENDING,
                INTENT_CREATED_BY_KIND_AUTONOMY_POLICY,
                &now,
                request.expires_at(),
                INTENT_VERSION,
            ],
        )
        .map_err(map_database_error)?;

    let created =
        load_intent_by_id(transaction, request.intent_id())?.ok_or_else(AutonomyError::database)?;
    validate_intent_state(&created)?;
    Ok(AutonomyCreateOutcome::Applied(created))
}

fn latest_defer_candidate(context: &InitiativePolicyTemporalContext) -> Option<String> {
    [
        context.recent_interaction_not_before.as_deref(),
        context.temporary_gate_not_before.as_deref(),
        context.frequency_not_before.as_deref(),
        context.min_gap_not_before.as_deref(),
    ]
    .into_iter()
    .flatten()
    .max()
    .map(str::to_owned)
}

fn evaluate_pending_intent_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeProactiveIntentEvaluationRequest,
) -> Result<LifeProactiveIntentEvaluationOutcome, AutonomyError> {
    validate_intent_evaluation_request(&request)?;

    // Event identity is checked before loading the target, policy, Goal, or
    // any current time. An exact replay returns the current authoritative
    // intent without recomputing the historical decision.
    if let Some(existing_event) = load_intent_event_by_id(transaction, &request.event_id)? {
        let applied_revision = next_revision(request.expected_revision)?;
        if intent_event_evidence_matches(&existing_event, &request, applied_revision) {
            let current = load_intent(transaction, &request.life_id, &request.intent_id)?
                .ok_or_else(AutonomyError::intent_not_found)?;
            validate_intent_event_state(&existing_event)?;
            validate_intent_state(&current)?;
            return Ok(LifeProactiveIntentEvaluationOutcome::Replayed {
                event: existing_event,
                current,
            });
        }
        return Err(AutonomyError::proactive_intent_event_conflict());
    }

    let current = load_intent_by_id(transaction, &request.intent_id)?
        .ok_or_else(AutonomyError::intent_not_found)?;
    if current.life_id != request.life_id {
        return Err(AutonomyError::intent_life_mismatch());
    }
    validate_intent_state(&current)?;
    if current.revision != request.expected_revision {
        return Err(AutonomyError::revision_conflict());
    }
    if current.status != INTENT_STATUS_PENDING {
        return Err(AutonomyError::invalid_intent_state());
    }

    let applied_revision = next_revision(request.expected_revision)?;
    let now = sqlite_authority_now(transaction)?;
    let expired = current
        .expires_at
        .as_deref()
        .is_some_and(|expires_at| expires_at <= now.as_str());

    let policy = if expired {
        None
    } else {
        let policy = load_policy(transaction, &request.life_id)?;
        if let Some(policy) = &policy {
            validate_policy_state(policy)?;
        }
        policy
    };
    let goal_is_active = if let Some(policy) = &policy {
        if policy.enabled {
            load_goal_is_active(transaction, &current.life_id, &current.goal_id)?
        } else {
            false
        }
    } else {
        false
    };

    let mut temporal = InitiativePolicyTemporalContext::default();
    if !expired && policy.as_ref().is_some_and(|policy| policy.enabled) && goal_is_active {
        temporal.recent_interaction_not_before = match current.recent_interaction_seconds {
            None => Some(sqlite_add_seconds(transaction, &now, MIN_RECHECK_SECONDS)?),
            Some(seconds) if seconds < RECENT_INTERACTION_QUIET_SECONDS => {
                Some(sqlite_add_seconds(
                    transaction,
                    &now,
                    RECENT_INTERACTION_QUIET_SECONDS - seconds,
                )?)
            }
            Some(_) => None,
        };

        let policy = policy.as_ref().expect("enabled policy was checked above");
        if policy.dnd || current.focus_state != INTENT_FOCUS_STATE_AVAILABLE {
            temporal.temporary_gate_not_before = Some(sqlite_add_seconds(
                transaction,
                &now,
                MIN_RECHECK_SECONDS.max(policy.min_gap_seconds),
            )?);
        }

        if policy.max_ready_per_window > 0 {
            let history = load_ready_event_history(
                transaction,
                &current.life_id,
                &now,
                policy.window_seconds,
            )?;
            if history.count_in_window >= policy.max_ready_per_window {
                let oldest = history
                    .oldest_in_window
                    .as_deref()
                    .ok_or_else(AutonomyError::database)?;
                temporal.frequency_not_before = Some(sqlite_add_seconds(
                    transaction,
                    oldest,
                    policy.window_seconds,
                )?);
            }
            if let Some(latest) = history.latest.as_deref() {
                let candidate = sqlite_add_seconds(transaction, latest, policy.min_gap_seconds)?;
                if candidate > now {
                    temporal.min_gap_not_before = Some(candidate);
                }
            }
        }
    }

    let decision =
        evaluate_initiative_policy(&current, policy.as_ref(), goal_is_active, &now, &temporal)?;
    let deferred_not_before = latest_defer_candidate(&temporal);
    let (to_status, not_before, closed_at) = match decision {
        InitiativePolicyDecision::Ready => (INTENT_STATUS_READY, None, None),
        InitiativePolicyDecision::Deferred => (
            INTENT_STATUS_DEFERRED,
            Some(deferred_not_before.ok_or_else(|| {
                AutonomyError::invalid_argument("deferred intent is missing not_before.")
            })?),
            None,
        ),
        InitiativePolicyDecision::StoredSilently => {
            (INTENT_STATUS_STORED_SILENTLY, None, Some(now.clone()))
        }
        InitiativePolicyDecision::Cancelled => (INTENT_STATUS_CANCELLED, None, Some(now.clone())),
        InitiativePolicyDecision::Expired => (INTENT_STATUS_EXPIRED, None, Some(now.clone())),
    };

    let changed = transaction
        .execute(
            "UPDATE life_proactive_intent
             SET status = ?1,
                 revision = ?2,
                 updated_at = ?3,
                 not_before = ?4,
                 closed_at = ?5
             WHERE intent_id = ?6
               AND life_id = ?7
               AND revision = ?8
               AND status = 'pending'",
            params![
                to_status,
                applied_revision,
                &now,
                &not_before,
                &closed_at,
                &request.intent_id,
                &request.life_id,
                request.expected_revision,
            ],
        )
        .map_err(map_database_error)?;
    if changed != 1 {
        return Err(AutonomyError::revision_conflict());
    }

    let event = LifeProactiveIntentEvent {
        event_id: request.event_id.clone(),
        life_id: request.life_id.clone(),
        intent_id: request.intent_id.clone(),
        from_status: INTENT_STATUS_PENDING.to_string(),
        to_status: to_status.to_string(),
        expected_revision: request.expected_revision,
        applied_revision,
        not_before_after: not_before.clone(),
        actor_kind: INTENT_EVENT_ACTOR_KIND_AUTONOMY_POLICY.to_string(),
        occurred_at: now.clone(),
        event_version: INTENT_EVENT_VERSION,
    };
    validate_intent_event_state(&event)?;
    transaction
        .execute(
            &format!(
                "INSERT INTO life_proactive_intent_event ({INTENT_EVENT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
            ),
            params![
                &event.event_id,
                &event.life_id,
                &event.intent_id,
                &event.from_status,
                &event.to_status,
                event.expected_revision,
                event.applied_revision,
                &event.not_before_after,
                &event.actor_kind,
                &event.occurred_at,
                event.event_version,
            ],
        )
        .map_err(map_database_error)?;

    let persisted_event = load_intent_event_by_id(transaction, &event.event_id)?
        .ok_or_else(AutonomyError::database)?;
    let persisted_intent = load_intent(transaction, &event.life_id, &event.intent_id)?
        .ok_or_else(AutonomyError::intent_not_found)?;
    validate_intent_event_state(&persisted_event)?;
    validate_intent_state(&persisted_intent)?;
    Ok(LifeProactiveIntentEvaluationOutcome::Applied {
        event: persisted_event,
        intent: persisted_intent,
    })
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

    fn evaluate_pending_intent(
        &self,
        request: LifeProactiveIntentEvaluationRequest,
    ) -> Result<LifeProactiveIntentEvaluationOutcome, AutonomyError> {
        let mut state = self.state().map_err(|_| AutonomyError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AutonomyError::database())?;
        let outcome = evaluate_pending_intent_in_transaction(&transaction, request)?;
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

    fn find_latest_intent_for_goal(
        &self,
        life_id: &str,
        goal_id: &str,
    ) -> Result<Option<LifeProactiveIntent>, AutonomyError> {
        validate_lookup_arguments(life_id, "goal identity", goal_id)?;
        let state = self.state().map_err(|_| AutonomyError::database())?;
        let intent = state
            .connection
            .query_row(
                &format!(
                    "SELECT {INTENT_COLUMNS} FROM life_proactive_intent
                     WHERE life_id = ?1 AND goal_id = ?2
                     ORDER BY created_at DESC, intent_id DESC LIMIT 1"
                ),
                params![life_id, goal_id],
                read_intent,
            )
            .optional()
            .map_err(|_| AutonomyError::database())?;
        if let Some(intent) = &intent {
            validate_intent_state(intent)?;
        }
        Ok(intent)
    }

    fn find_intent_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeProactiveIntentEvent>, AutonomyError> {
        validate_lookup_arguments(life_id, "intent event identity", event_id)?;
        let state = self.state().map_err(|_| AutonomyError::database())?;
        let event = state
            .connection
            .query_row(
                &format!(
                    "SELECT {INTENT_EVENT_COLUMNS} FROM life_proactive_intent_event
                     WHERE life_id = ?1 AND event_id = ?2"
                ),
                params![life_id, event_id],
                read_intent_event,
            )
            .optional()
            .map_err(|_| AutonomyError::database())?;
        if let Some(event) = &event {
            validate_intent_event_state(event)?;
        }
        Ok(event)
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
const _: for<'a> fn(
    &'a StorageService,
    LifeProactiveIntentEvaluationRequest,
) -> Result<LifeProactiveIntentEvaluationOutcome, AutonomyError> =
    <StorageService as crate::autonomy::AutonomyRepository>::evaluate_pending_intent;
const _: for<'a> fn(
    &'a StorageService,
    &'a str,
    &'a str,
) -> Result<Option<LifeProactiveIntent>, AutonomyError> =
    <StorageService as crate::autonomy::AutonomyRepository>::find_latest_intent_for_goal;
const _: for<'a> fn(
    &'a StorageService,
    &'a str,
    &'a str,
) -> Result<Option<LifeProactiveIntentEvent>, AutonomyError> =
    <StorageService as crate::autonomy::AutonomyRepository>::find_intent_event;

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
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use rusqlite::params;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        autonomy::runtime::{
            deterministic_evaluation_event_id, deterministic_intent_id, run_autonomy_tick,
            AutonomyTickError, AutonomyTickOutcome, AutonomyTickRequest, AutonomyTickWaitReason,
            MAX_GOALS_INSPECTED_PER_TICK,
        },
        autonomy::{
            validate_intent_event_state, AutonomyErrorCode, AutonomyRepository,
            LifeAutonomyPolicyUpdateOutcome, LifeProactiveIntentEvaluationOutcome,
            LifeProactiveIntentEvaluationRequest, LifeProactiveIntentEvent,
            INTENT_EVENT_ACTOR_KIND_AUTONOMY_POLICY, INTENT_EVENT_VERSION,
            INTENT_FOCUS_STATE_AVAILABLE, INTENT_FOCUS_STATE_DND, INTENT_FOCUS_STATE_FOCUSED,
            INTENT_FOCUS_STATE_UNKNOWN, INTENT_KIND_GOAL_CHECK_IN, INTENT_STATUS_CANCELLED,
            INTENT_STATUS_DEFERRED, INTENT_STATUS_EXPIRED, INTENT_STATUS_PENDING,
            INTENT_STATUS_READY, INTENT_STATUS_STORED_SILENTLY, MIN_RECHECK_SECONDS,
            RECENT_INTERACTION_QUIET_SECONDS,
        },
        experience::{
            ExperienceEpisode, ExperienceEpisodeRepository, EPISODE_KIND, EPISODE_VERSION,
            OUTCOME_KIND, SOURCE_KIND,
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
                expires_at: None,
            }
        }

        fn tick_intent_request(
            &self,
            intent_id: &str,
            life_id: &str,
            goal_id: &str,
            focus_state: &str,
            recent_interaction_seconds: Option<i64>,
        ) -> LifeProactiveIntentCreateRequest {
            LifeProactiveIntentCreateRequest {
                intent_id: intent_id.into(),
                life_id: life_id.into(),
                goal_id: goal_id.into(),
                intent_kind: INTENT_KIND_GOAL_CHECK_IN.into(),
                importance: crate::autonomy::runtime::GOAL_CHECK_IN_IMPORTANCE_V1,
                user_relevance: crate::autonomy::runtime::GOAL_CHECK_IN_USER_RELEVANCE_V1,
                self_desire: crate::autonomy::runtime::GOAL_CHECK_IN_SELF_DESIRE_V1,
                interruption_cost: crate::autonomy::runtime::GOAL_CHECK_IN_INTERRUPTION_COST_V1,
                focus_state: focus_state.into(),
                acceptance_score: None,
                recent_interaction_seconds,
                expires_at: None,
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

        fn create_intent(&self, request: LifeProactiveIntentCreateRequest) -> LifeProactiveIntent {
            match self
                .storage
                .create_pending_goal_check_in_intent(request)
                .unwrap()
            {
                AutonomyCreateOutcome::Applied(intent) => intent,
                AutonomyCreateOutcome::Replayed(_) => panic!("first intent create must apply"),
            }
        }

        fn evaluation_request(
            &self,
            event_id: &str,
            life_id: &str,
            intent_id: &str,
            expected_revision: i64,
        ) -> LifeProactiveIntentEvaluationRequest {
            LifeProactiveIntentEvaluationRequest {
                event_id: event_id.into(),
                life_id: life_id.into(),
                intent_id: intent_id.into(),
                expected_revision,
            }
        }

        fn intent_event_count(&self) -> i64 {
            let state = self.storage.state().unwrap();
            state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM life_proactive_intent_event",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        }

        fn intent_count(&self) -> i64 {
            let state = self.storage.state().unwrap();
            state
                .connection
                .query_row("SELECT COUNT(*) FROM life_proactive_intent", [], |row| {
                    row.get(0)
                })
                .unwrap()
        }

        fn tick(
            &self,
            tick_id: &str,
            focus_state: &str,
        ) -> Result<AutonomyTickOutcome, AutonomyTickError> {
            run_autonomy_tick(
                &self.storage,
                AutonomyTickRequest {
                    tick_id: tick_id.into(),
                    life_id: "autonomy-life-a".into(),
                    focus_state: focus_state.into(),
                },
            )
        }

        fn set_intent_times(&self, intent_id: &str, updated_at: &str, not_before: Option<&str>) {
            let state = self.storage.state().unwrap();
            state
                .connection
                .execute(
                    "UPDATE life_proactive_intent
                     SET updated_at = ?2, not_before = ?3
                     WHERE intent_id = ?1",
                    params![intent_id, updated_at, not_before],
                )
                .unwrap();
        }

        fn insert_episode_with_age(&self, life_id: &str, suffix: &str, age_seconds: i64) {
            let conversation_id = format!("autonomy-episode-conversation-{suffix}");
            let turn_id = format!("autonomy-episode-turn-{suffix}");
            let user_message_id = format!("autonomy-episode-user-{suffix}");
            let assistant_message_id = format!("autonomy-episode-assistant-{suffix}");
            let episode_id =
                format!("experience-conversation:{life_id}:{conversation_id}:{turn_id}");
            let source_ref = format!("{conversation_id}:{turn_id}");
            let state = self.storage.state().unwrap();
            let now = sqlite_authority_now(&state.connection).unwrap();
            let ended_at = sqlite_add_seconds(&state.connection, &now, -age_seconds).unwrap();
            let started_at = sqlite_add_seconds(&state.connection, &ended_at, -1).unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO conversation
                         (id, life_id, title, revision, created_at, updated_at, last_message_at)
                     VALUES (?1, ?2, ?3, 1, ?4, ?4, ?4)",
                    params![conversation_id, life_id, "Autonomy Episode", &started_at],
                )
                .unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO conversation_message
                         (id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at)
                     VALUES (?1, ?2, ?3, ?4, 'user', 'test user', 1, ?5),
                            (?6, ?2, ?3, ?4, 'assistant', 'test assistant', 2, ?7)",
                    params![
                        user_message_id,
                        conversation_id,
                        life_id,
                        turn_id,
                        &started_at,
                        assistant_message_id,
                        &ended_at,
                    ],
                )
                .unwrap();
            drop(state);
            self.storage
                .commit_episode(ExperienceEpisode {
                    episode_id,
                    life_id: life_id.into(),
                    episode_kind: EPISODE_KIND.into(),
                    source_kind: SOURCE_KIND.into(),
                    source_ref,
                    conversation_id,
                    turn_id,
                    counterpart_subject_id: "primary_user".into(),
                    user_message_id,
                    assistant_message_id,
                    outcome_kind: OUTCOME_KIND.into(),
                    started_at,
                    ended_at: ended_at.clone(),
                    episode_version: EPISODE_VERSION,
                    created_at: ended_at,
                })
                .unwrap();
        }

        fn add_seconds(&self, base: &str, seconds: i64) -> String {
            let state = self.storage.state().unwrap();
            sqlite_add_seconds(&state.connection, base, seconds).unwrap()
        }

        fn insert_ready_event(
            &self,
            event_id: &str,
            life_id: &str,
            intent_id: &str,
            occurred_at_modifier: &str,
        ) {
            let state = self.storage.state().unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO life_proactive_intent_event
                     (event_id, life_id, intent_id, from_status, to_status,
                      expected_revision, applied_revision, not_before_after,
                      actor_kind, occurred_at, event_version)
                     VALUES (?1, ?2, ?3, 'pending', 'ready', 1, 2, NULL,
                             'autonomy_policy',
                             strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?4), 1)",
                    params![event_id, life_id, intent_id, occurred_at_modifier],
                )
                .unwrap();
        }

        fn update_policy(&self, request: LifeAutonomyPolicyUpdateRequest) {
            self.storage.update_policy(request).unwrap();
        }

        fn evaluate(
            &self,
            event_id: &str,
            life_id: &str,
            intent_id: &str,
            expected_revision: i64,
        ) -> Result<LifeProactiveIntentEvaluationOutcome, AutonomyError> {
            self.storage
                .evaluate_pending_intent(self.evaluation_request(
                    event_id,
                    life_id,
                    intent_id,
                    expected_revision,
                ))
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
    fn pending_evaluation_event_identity_replay_and_revision_precedence() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-goal-evaluation", "autonomy-life-a");
        let mut request = fixture.intent_request(
            "autonomy-intent-evaluation",
            "autonomy-life-a",
            "autonomy-goal-evaluation",
        );
        request.recent_interaction_seconds = Some(120);
        fixture.create_intent(request);

        let first = fixture
            .evaluate(
                "autonomy-intent-event-1",
                "autonomy-life-a",
                "autonomy-intent-evaluation",
                1,
            )
            .unwrap();
        let event = match first {
            LifeProactiveIntentEvaluationOutcome::Applied { event, intent } => {
                assert_eq!(intent.status, INTENT_STATUS_READY);
                assert_eq!(intent.revision, 2);
                assert_eq!(intent.updated_at, event.occurred_at);
                assert!(intent.not_before.is_none());
                assert!(intent.closed_at.is_none());
                event
            }
            LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                panic!("first evaluation must apply")
            }
        };
        assert_eq!(event.from_status, INTENT_STATUS_PENDING);
        assert_eq!(event.to_status, INTENT_STATUS_READY);
        assert_eq!(event.expected_revision, 1);
        assert_eq!(event.applied_revision, 2);
        assert!(event.not_before_after.is_none());
        assert_eq!(fixture.intent_event_count(), 1);

        let replay = fixture
            .evaluate(
                "autonomy-intent-event-1",
                "autonomy-life-a",
                "autonomy-intent-evaluation",
                1,
            )
            .unwrap();
        match replay {
            LifeProactiveIntentEvaluationOutcome::Replayed {
                event: replayed,
                current,
            } => {
                assert_eq!(replayed, event);
                assert_eq!(current.revision, 2);
                assert_eq!(current.status, INTENT_STATUS_READY);
            }
            LifeProactiveIntentEvaluationOutcome::Applied { .. } => {
                panic!("exact evaluation must replay")
            }
        }
        assert_eq!(fixture.intent_event_count(), 1);

        fixture.update_policy(LifeAutonomyPolicyUpdateRequest {
            event_id: "autonomy-policy-event-after-evaluation".into(),
            life_id: "autonomy-life-a".into(),
            enabled: false,
            dnd: false,
            max_ready_per_window: 3,
            window_seconds: 900,
            min_gap_seconds: 60,
            expected_revision: 1,
        });
        let replay_after_policy_change = fixture
            .evaluate(
                "autonomy-intent-event-1",
                "autonomy-life-a",
                "autonomy-intent-evaluation",
                1,
            )
            .unwrap();
        assert!(matches!(
            replay_after_policy_change,
            LifeProactiveIntentEvaluationOutcome::Replayed { .. }
        ));

        let different_intent = fixture
            .storage
            .evaluate_pending_intent(fixture.evaluation_request(
                "autonomy-intent-event-1",
                "autonomy-life-a",
                "another-intent",
                1,
            ));
        assert_eq!(
            error_code(different_intent.unwrap_err()),
            AutonomyErrorCode::ProactiveIntentEventConflict
        );
        let different_revision =
            fixture
                .storage
                .evaluate_pending_intent(fixture.evaluation_request(
                    "autonomy-intent-event-1",
                    "autonomy-life-a",
                    "autonomy-intent-evaluation",
                    2,
                ));
        assert_eq!(
            error_code(different_revision.unwrap_err()),
            AutonomyErrorCode::ProactiveIntentEventConflict
        );
        assert_eq!(fixture.intent_event_count(), 1);
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
    fn pending_evaluation_expiry_policy_and_goal_governance_are_typed() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);

        fixture.create_goal("autonomy-goal-expired", "autonomy-life-a");
        let mut expired_request = fixture.intent_request(
            "autonomy-intent-expired",
            "autonomy-life-a",
            "autonomy-goal-expired",
        );
        expired_request.recent_interaction_seconds = Some(120);
        let state = fixture.storage.state().unwrap();
        let now = sqlite_authority_now(&state.connection).unwrap();
        expired_request.expires_at = Some(sqlite_add_seconds(&state.connection, &now, -1).unwrap());
        drop(state);
        fixture.create_intent(expired_request);
        let expired = fixture
            .evaluate(
                "autonomy-intent-event-expired",
                "autonomy-life-a",
                "autonomy-intent-expired",
                1,
            )
            .unwrap();
        match expired {
            LifeProactiveIntentEvaluationOutcome::Applied { event, intent } => {
                assert_eq!(event.to_status, INTENT_STATUS_EXPIRED);
                assert_eq!(intent.status, INTENT_STATUS_EXPIRED);
                assert_eq!(intent.revision, 2);
                assert!(intent.closed_at.is_some());
                assert!(event.not_before_after.is_none());
            }
            LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                panic!("first expiry evaluation must apply")
            }
        }

        fixture.create_goal("autonomy-goal-completed", "autonomy-life-a");
        let completed_intent = fixture.create_intent(fixture.intent_request(
            "autonomy-intent-completed-goal",
            "autonomy-life-a",
            "autonomy-goal-completed",
        ));
        fixture
            .storage
            .transition_goal(LifeGoalTransitionRequest {
                goal_id: "autonomy-goal-completed".into(),
                life_id: "autonomy-life-a".into(),
                kind: LifeGoalTransitionKind::Complete,
                event_id: "autonomy-goal-completed-event".into(),
                expected_revision: 1,
            })
            .unwrap();
        let completed = fixture
            .evaluate(
                "autonomy-intent-event-completed-goal",
                "autonomy-life-a",
                &completed_intent.intent_id,
                1,
            )
            .unwrap();
        match completed {
            LifeProactiveIntentEvaluationOutcome::Applied { event, intent } => {
                assert_eq!(event.to_status, INTENT_STATUS_CANCELLED);
                assert_eq!(intent.status, INTENT_STATUS_CANCELLED);
                assert!(intent.closed_at.is_some());
            }
            LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                panic!("first completed-goal evaluation must apply")
            }
        }

        fixture.create_goal("autonomy-goal-disabled", "autonomy-life-a");
        let disabled_intent = fixture.create_intent(fixture.intent_request(
            "autonomy-intent-disabled-evaluation",
            "autonomy-life-a",
            "autonomy-goal-disabled",
        ));

        fixture.create_policy("autonomy-life-b", true, false);
        fixture.create_goal("autonomy-goal-missing-policy", "autonomy-life-b");
        let missing_policy_intent = fixture.create_intent(fixture.intent_request(
            "autonomy-intent-missing-policy",
            "autonomy-life-b",
            "autonomy-goal-missing-policy",
        ));
        let state = fixture.storage.state().unwrap();
        state
            .connection
            .execute(
                "DELETE FROM life_autonomy_policy WHERE life_id='autonomy-life-b'",
                [],
            )
            .unwrap();
        drop(state);
        let missing_policy = fixture
            .evaluate(
                "autonomy-intent-event-missing-policy",
                "autonomy-life-b",
                &missing_policy_intent.intent_id,
                1,
            )
            .unwrap();
        match missing_policy {
            LifeProactiveIntentEvaluationOutcome::Applied { event, intent } => {
                assert_eq!(event.to_status, INTENT_STATUS_CANCELLED);
                assert_eq!(intent.status, INTENT_STATUS_CANCELLED);
            }
            LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                panic!("first missing-policy evaluation must apply")
            }
        }

        fixture.update_policy(LifeAutonomyPolicyUpdateRequest {
            event_id: "autonomy-policy-event-disable-evaluation".into(),
            life_id: "autonomy-life-a".into(),
            enabled: false,
            dnd: false,
            max_ready_per_window: 3,
            window_seconds: 900,
            min_gap_seconds: 60,
            expected_revision: 1,
        });
        let disabled = fixture
            .evaluate(
                "autonomy-intent-event-disabled-policy",
                "autonomy-life-a",
                &disabled_intent.intent_id,
                1,
            )
            .unwrap();
        match disabled {
            LifeProactiveIntentEvaluationOutcome::Applied { event, intent } => {
                assert_eq!(event.to_status, INTENT_STATUS_CANCELLED);
                assert_eq!(intent.status, INTENT_STATUS_CANCELLED);
                assert!(intent.closed_at.is_some());
            }
            LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                panic!("first disabled-policy evaluation must apply")
            }
        }
    }

    #[test]
    fn pending_evaluation_dnd_focus_and_recent_gates_are_deferred() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, true);
        fixture.create_goal("autonomy-goal-dnd-evaluation", "autonomy-life-a");
        let mut dnd_request = fixture.intent_request(
            "autonomy-intent-dnd-evaluation",
            "autonomy-life-a",
            "autonomy-goal-dnd-evaluation",
        );
        dnd_request.recent_interaction_seconds = Some(120);
        let dnd_intent = fixture.create_intent(dnd_request);
        let dnd_result = fixture
            .evaluate(
                "autonomy-intent-event-dnd-evaluation",
                "autonomy-life-a",
                &dnd_intent.intent_id,
                1,
            )
            .unwrap();
        let dnd_intent = match dnd_result {
            LifeProactiveIntentEvaluationOutcome::Applied { event, intent } => {
                assert_eq!(event.to_status, INTENT_STATUS_DEFERRED);
                assert!(event.not_before_after.is_some());
                assert_eq!(intent.status, INTENT_STATUS_DEFERRED);
                assert_eq!(intent.revision, 2);
                assert_eq!(intent.not_before, event.not_before_after);
                intent
            }
            LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                panic!("first DND evaluation must apply")
            }
        };
        assert_eq!(
            error_code(
                fixture
                    .evaluate(
                        "autonomy-intent-event-dnd-recheck",
                        "autonomy-life-a",
                        &dnd_intent.intent_id,
                        2,
                    )
                    .unwrap_err()
            ),
            AutonomyErrorCode::InvalidIntentState
        );
        assert_eq!(fixture.intent_event_count(), 1);

        let mut focus_policy = fixture.policy_request("autonomy-life-b");
        focus_policy.max_ready_per_window = 1;
        focus_policy.window_seconds = 60;
        focus_policy.min_gap_seconds = 0;
        fixture.storage.create_policy(focus_policy).unwrap();
        fixture.create_goal("autonomy-goal-focus-evaluation", "autonomy-life-b");
        for (intent_id, focus_state) in [
            ("autonomy-intent-focus-dnd", INTENT_FOCUS_STATE_DND),
            ("autonomy-intent-focus-focused", INTENT_FOCUS_STATE_FOCUSED),
            ("autonomy-intent-focus-unknown", INTENT_FOCUS_STATE_UNKNOWN),
        ] {
            let mut request = fixture.intent_request(
                intent_id,
                "autonomy-life-b",
                "autonomy-goal-focus-evaluation",
            );
            request.focus_state = focus_state.into();
            request.recent_interaction_seconds = Some(120);
            let intent = fixture.create_intent(request);
            let result = fixture
                .evaluate(
                    &format!("{intent_id}-event"),
                    "autonomy-life-b",
                    &intent.intent_id,
                    1,
                )
                .unwrap();
            match result {
                LifeProactiveIntentEvaluationOutcome::Applied { event, intent } => {
                    assert_eq!(event.to_status, INTENT_STATUS_DEFERRED);
                    assert_eq!(intent.status, INTENT_STATUS_DEFERRED);
                    assert_eq!(
                        intent.not_before,
                        Some(fixture.add_seconds(&event.occurred_at, MIN_RECHECK_SECONDS))
                    );
                    assert_eq!(intent.not_before, event.not_before_after);
                }
                LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                    panic!("first focus evaluation must apply")
                }
            }
        }

        for (intent_id, recent_interaction_seconds, expected_status) in [
            ("autonomy-intent-recent-null", None, INTENT_STATUS_DEFERRED),
            (
                "autonomy-intent-recent-zero",
                Some(0),
                INTENT_STATUS_DEFERRED,
            ),
            (
                "autonomy-intent-recent-119",
                Some(119),
                INTENT_STATUS_DEFERRED,
            ),
            ("autonomy-intent-recent-120", Some(120), INTENT_STATUS_READY),
        ] {
            let mut request = fixture.intent_request(
                intent_id,
                "autonomy-life-b",
                "autonomy-goal-focus-evaluation",
            );
            request.recent_interaction_seconds = recent_interaction_seconds;
            let intent = fixture.create_intent(request);
            let result = fixture
                .evaluate(
                    &format!("{intent_id}-event"),
                    "autonomy-life-b",
                    &intent.intent_id,
                    1,
                )
                .unwrap();
            let evaluated = match result {
                LifeProactiveIntentEvaluationOutcome::Applied { intent, event } => {
                    assert_eq!(intent.status, expected_status);
                    let expected_not_before = match recent_interaction_seconds {
                        None => Some(fixture.add_seconds(&event.occurred_at, MIN_RECHECK_SECONDS)),
                        Some(seconds) if seconds < RECENT_INTERACTION_QUIET_SECONDS => {
                            Some(fixture.add_seconds(
                                &event.occurred_at,
                                RECENT_INTERACTION_QUIET_SECONDS - seconds,
                            ))
                        }
                        Some(_) => None,
                    };
                    assert_eq!(intent.not_before, expected_not_before);
                    if expected_status == INTENT_STATUS_DEFERRED {
                        assert_eq!(intent.not_before, event.not_before_after);
                        assert!(intent.not_before.is_some());
                    } else {
                        assert!(intent.not_before.is_none());
                        assert!(event.not_before_after.is_none());
                    }
                    intent
                }
                LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                    panic!("first recent-interaction evaluation must apply")
                }
            };
            assert_eq!(evaluated.revision, 2);
        }
    }

    #[test]
    fn pending_evaluation_frequency_budget_and_min_gap_use_persisted_events() {
        let fixture = Fixture::new();
        let mut zero_budget = fixture.policy_request("autonomy-life-a");
        zero_budget.max_ready_per_window = 0;
        zero_budget.min_gap_seconds = 0;
        fixture.storage.create_policy(zero_budget).unwrap();
        fixture.create_goal("autonomy-goal-frequency-zero", "autonomy-life-a");
        let mut zero_request = fixture.intent_request(
            "autonomy-intent-frequency-zero",
            "autonomy-life-a",
            "autonomy-goal-frequency-zero",
        );
        zero_request.recent_interaction_seconds = Some(120);
        let zero_intent = fixture.create_intent(zero_request);
        let zero_result = fixture
            .evaluate(
                "autonomy-intent-event-frequency-zero",
                "autonomy-life-a",
                &zero_intent.intent_id,
                1,
            )
            .unwrap();
        match zero_result {
            LifeProactiveIntentEvaluationOutcome::Applied { event, intent } => {
                assert_eq!(event.to_status, INTENT_STATUS_STORED_SILENTLY);
                assert_eq!(intent.status, INTENT_STATUS_STORED_SILENTLY);
                assert_eq!(intent.revision, 2);
                assert_eq!(intent.updated_at, event.occurred_at);
                assert_eq!(
                    intent.closed_at.as_deref(),
                    Some(event.occurred_at.as_str())
                );
                assert!(intent.not_before.is_none());
                assert!(intent.closed_at.is_some());
                assert!(event.not_before_after.is_none());
            }
            LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                panic!("zero-budget evaluation must apply")
            }
        }
        assert_eq!(fixture.intent_event_count(), 1);

        fixture.update_policy(LifeAutonomyPolicyUpdateRequest {
            event_id: "autonomy-policy-event-frequency-ready".into(),
            life_id: "autonomy-life-a".into(),
            enabled: true,
            dnd: false,
            max_ready_per_window: 1,
            window_seconds: 60,
            min_gap_seconds: 0,
            expected_revision: 1,
        });
        fixture.create_goal("autonomy-goal-frequency-ready", "autonomy-life-a");
        let mut ready_request = fixture.intent_request(
            "autonomy-intent-frequency-ready",
            "autonomy-life-a",
            "autonomy-goal-frequency-ready",
        );
        ready_request.recent_interaction_seconds = Some(120);
        let ready_intent = fixture.create_intent(ready_request);
        let ready_result = fixture
            .evaluate(
                "autonomy-intent-event-frequency-ready",
                "autonomy-life-a",
                &ready_intent.intent_id,
                1,
            )
            .unwrap();
        let ready_occurred_at = match ready_result {
            LifeProactiveIntentEvaluationOutcome::Applied { event, intent } => {
                assert_eq!(intent.status, INTENT_STATUS_READY);
                event.occurred_at
            }
            LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                panic!("first frequency-ready evaluation must apply")
            }
        };
        let expected_frequency_not_before = fixture.add_seconds(&ready_occurred_at, 60);

        fixture.create_goal("autonomy-goal-frequency-exhausted", "autonomy-life-a");
        let mut exhausted_request = fixture.intent_request(
            "autonomy-intent-frequency-exhausted",
            "autonomy-life-a",
            "autonomy-goal-frequency-exhausted",
        );
        exhausted_request.recent_interaction_seconds = Some(120);
        let exhausted_intent = fixture.create_intent(exhausted_request);
        let exhausted = fixture
            .evaluate(
                "autonomy-intent-event-frequency-exhausted",
                "autonomy-life-a",
                &exhausted_intent.intent_id,
                1,
            )
            .unwrap();
        let exhausted_intent = match exhausted {
            LifeProactiveIntentEvaluationOutcome::Applied { event, intent } => {
                assert_eq!(event.to_status, INTENT_STATUS_DEFERRED);
                assert_eq!(intent.status, INTENT_STATUS_DEFERRED);
                assert_eq!(intent.not_before, event.not_before_after);
                intent
            }
            LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                panic!("frequency exhaustion must apply")
            }
        };
        assert_eq!(
            exhausted_intent.not_before.as_deref(),
            Some(expected_frequency_not_before.as_str())
        );

        fixture.update_policy(LifeAutonomyPolicyUpdateRequest {
            event_id: "autonomy-policy-event-frequency-gap".into(),
            life_id: "autonomy-life-a".into(),
            enabled: true,
            dnd: false,
            max_ready_per_window: 2,
            window_seconds: 60,
            min_gap_seconds: 60,
            expected_revision: 2,
        });
        fixture.create_goal("autonomy-goal-frequency-gap", "autonomy-life-a");
        let mut gap_request = fixture.intent_request(
            "autonomy-intent-frequency-gap",
            "autonomy-life-a",
            "autonomy-goal-frequency-gap",
        );
        gap_request.recent_interaction_seconds = Some(120);
        let gap_intent = fixture.create_intent(gap_request);
        let gap = fixture
            .evaluate(
                "autonomy-intent-event-frequency-gap",
                "autonomy-life-a",
                &gap_intent.intent_id,
                1,
            )
            .unwrap();
        match gap {
            LifeProactiveIntentEvaluationOutcome::Applied { event, intent } => {
                assert_eq!(event.to_status, INTENT_STATUS_DEFERRED);
                assert_eq!(intent.status, INTENT_STATUS_DEFERRED);
                assert_eq!(intent.not_before, event.not_before_after);
                assert_eq!(
                    intent.not_before.as_deref(),
                    Some(expected_frequency_not_before.as_str())
                );
            }
            LifeProactiveIntentEvaluationOutcome::Replayed { .. } => {
                panic!("minimum-gap evaluation must apply")
            }
        }

        let mut window_policy = fixture.policy_request("autonomy-life-b");
        window_policy.max_ready_per_window = 1;
        window_policy.window_seconds = 60;
        window_policy.min_gap_seconds = 0;
        fixture.storage.create_policy(window_policy).unwrap();
        fixture.create_goal("autonomy-goal-frequency-window", "autonomy-life-b");
        let mut old_event_parent_request = fixture.intent_request(
            "autonomy-intent-frequency-old-event-parent",
            "autonomy-life-b",
            "autonomy-goal-frequency-window",
        );
        old_event_parent_request.recent_interaction_seconds = Some(120);
        let old_event_parent = fixture.create_intent(old_event_parent_request);
        fixture.insert_ready_event(
            "autonomy-intent-event-frequency-old",
            "autonomy-life-b",
            &old_event_parent.intent_id,
            "-61 seconds",
        );
        let mut window_request = fixture.intent_request(
            "autonomy-intent-frequency-window",
            "autonomy-life-b",
            "autonomy-goal-frequency-window",
        );
        window_request.recent_interaction_seconds = Some(120);
        let window_intent = fixture.create_intent(window_request);
        let window = fixture
            .evaluate(
                "autonomy-intent-event-frequency-window",
                "autonomy-life-b",
                &window_intent.intent_id,
                1,
            )
            .unwrap();
        assert!(matches!(
            window,
            LifeProactiveIntentEvaluationOutcome::Applied { intent, .. }
                if intent.status == INTENT_STATUS_READY
        ));
    }

    #[test]
    fn pending_evaluation_target_and_status_errors_are_typed() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-goal-targets", "autonomy-life-a");
        let mut request = fixture.intent_request(
            "autonomy-intent-targets",
            "autonomy-life-a",
            "autonomy-goal-targets",
        );
        request.recent_interaction_seconds = Some(120);
        fixture.create_intent(request);

        let invalid_request =
            fixture
                .storage
                .evaluate_pending_intent(LifeProactiveIntentEvaluationRequest {
                    event_id: String::new(),
                    life_id: "autonomy-life-a".into(),
                    intent_id: "autonomy-intent-targets".into(),
                    expected_revision: 1,
                });
        assert_eq!(
            error_code(invalid_request.unwrap_err()),
            AutonomyErrorCode::InvalidArgument
        );
        let invalid_revision = fixture
            .storage
            .evaluate_pending_intent(fixture.evaluation_request(
                "autonomy-intent-event-invalid-revision",
                "autonomy-life-a",
                "autonomy-intent-targets",
                0,
            ));
        assert_eq!(
            error_code(invalid_revision.unwrap_err()),
            AutonomyErrorCode::InvalidArgument
        );

        let missing = fixture
            .evaluate(
                "autonomy-intent-event-missing",
                "autonomy-life-a",
                "missing-intent",
                1,
            )
            .unwrap_err();
        assert_eq!(error_code(missing), AutonomyErrorCode::IntentNotFound);

        let wrong_life = fixture
            .storage
            .evaluate_pending_intent(fixture.evaluation_request(
                "autonomy-intent-event-wrong-life",
                "autonomy-life-b",
                "autonomy-intent-targets",
                1,
            ));
        assert_eq!(
            error_code(wrong_life.unwrap_err()),
            AutonomyErrorCode::IntentLifeMismatch
        );

        let applied = fixture
            .evaluate(
                "autonomy-intent-event-targets",
                "autonomy-life-a",
                "autonomy-intent-targets",
                1,
            )
            .unwrap();
        assert!(matches!(
            applied,
            LifeProactiveIntentEvaluationOutcome::Applied { intent, .. }
                if intent.status == INTENT_STATUS_READY && intent.revision == 2
        ));
        let non_pending = fixture
            .evaluate(
                "autonomy-intent-event-non-pending",
                "autonomy-life-a",
                "autonomy-intent-targets",
                2,
            )
            .unwrap_err();
        assert_eq!(
            error_code(non_pending),
            AutonomyErrorCode::InvalidIntentState
        );
        assert_eq!(fixture.intent_event_count(), 1);
    }

    #[test]
    fn competing_sqlite_evaluations_allow_one_cas_winner() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-goal-race", "autonomy-life-a");
        let mut request = fixture.intent_request(
            "autonomy-intent-race",
            "autonomy-life-a",
            "autonomy-goal-race",
        );
        request.recent_interaction_seconds = Some(120);
        fixture.create_intent(request);

        let second_root = fixture._root.path().join("default");
        let second_service = StorageService::initialize_with_roots(second_root, None).unwrap();
        let first_service = Arc::new(fixture.storage);
        let second_service = Arc::new(second_service);
        let barrier = Arc::new(Barrier::new(3));

        let first_barrier = barrier.clone();
        let first = first_service.clone();
        let first_thread = thread::spawn(move || {
            first_barrier.wait();
            first.evaluate_pending_intent(LifeProactiveIntentEvaluationRequest {
                event_id: "autonomy-intent-event-race-a".into(),
                life_id: "autonomy-life-a".into(),
                intent_id: "autonomy-intent-race".into(),
                expected_revision: 1,
            })
        });

        let second_barrier = barrier.clone();
        let second = second_service.clone();
        let second_thread = thread::spawn(move || {
            second_barrier.wait();
            second.evaluate_pending_intent(LifeProactiveIntentEvaluationRequest {
                event_id: "autonomy-intent-event-race-b".into(),
                life_id: "autonomy-life-a".into(),
                intent_id: "autonomy-intent-race".into(),
                expected_revision: 1,
            })
        });

        barrier.wait();
        let first_result = first_thread.join().unwrap();
        let second_result = second_thread.join().unwrap();
        let results = [first_result, second_result];
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(
                        result,
                        Ok(LifeProactiveIntentEvaluationOutcome::Applied { .. })
                    )
                })
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(
                        result,
                        Err(error) if error.code == AutonomyErrorCode::RevisionConflict
                    )
                })
                .count(),
            1
        );
        let intent = first_service
            .find_intent("autonomy-life-a", "autonomy-intent-race")
            .unwrap()
            .unwrap();
        assert_eq!(intent.revision, 2);
        let state = first_service.state().unwrap();
        let event_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM life_proactive_intent_event",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 1);
    }

    #[test]
    fn pending_evaluation_rolls_back_intent_when_event_insert_fails() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-goal-atomic-evaluation", "autonomy-life-a");
        let mut request = fixture.intent_request(
            "autonomy-intent-atomic-evaluation",
            "autonomy-life-a",
            "autonomy-goal-atomic-evaluation",
        );
        request.recent_interaction_seconds = Some(120);
        fixture.create_intent(request);

        let state = fixture.storage.state().unwrap();
        state
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER d15_b2_test_event_insert_failure
                 BEFORE INSERT ON main.life_proactive_intent_event
                 BEGIN
                     SELECT RAISE(ABORT, 'D15_B2_TEST_EVENT_INSERT_FAILURE');
                 END;",
            )
            .unwrap();
        drop(state);

        let error = fixture
            .evaluate(
                "autonomy-intent-event-atomic-evaluation",
                "autonomy-life-a",
                "autonomy-intent-atomic-evaluation",
                1,
            )
            .unwrap_err();
        assert_eq!(error_code(error), AutonomyErrorCode::DatabaseUnavailable);
        let intent = fixture
            .storage
            .find_intent("autonomy-life-a", "autonomy-intent-atomic-evaluation")
            .unwrap()
            .unwrap();
        assert_eq!(intent.status, INTENT_STATUS_PENDING);
        assert_eq!(intent.revision, 1);
        assert!(intent.closed_at.is_none());
        assert_eq!(fixture.intent_event_count(), 0);
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

    #[test]
    fn autonomy_tick_disabled_has_no_intent_or_event_writes() {
        let fixture = Fixture::new();
        fixture.create_goal("autonomy-tick-disabled-goal", "autonomy-life-a");
        assert_eq!(
            fixture.tick("disabled-no-policy", INTENT_FOCUS_STATE_AVAILABLE),
            Ok(AutonomyTickOutcome::Disabled)
        );
        assert_eq!(fixture.intent_count(), 0);
        assert_eq!(fixture.intent_event_count(), 0);

        fixture.create_policy("autonomy-life-a", false, false);
        assert_eq!(
            fixture.tick("disabled-policy", INTENT_FOCUS_STATE_AVAILABLE),
            Ok(AutonomyTickOutcome::Disabled)
        );
        assert_eq!(fixture.intent_count(), 0);
        assert_eq!(fixture.intent_event_count(), 0);
    }

    #[test]
    fn autonomy_tick_ignores_completed_and_cancelled_goals() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-completed", "autonomy-life-a");
        fixture
            .storage
            .transition_goal(LifeGoalTransitionRequest {
                event_id: "autonomy-tick-completed-event".into(),
                life_id: "autonomy-life-a".into(),
                goal_id: "autonomy-tick-completed".into(),
                expected_revision: 1,
                kind: LifeGoalTransitionKind::Complete,
            })
            .unwrap();
        fixture.create_goal("autonomy-tick-cancelled", "autonomy-life-a");
        fixture
            .storage
            .transition_goal(LifeGoalTransitionRequest {
                event_id: "autonomy-tick-cancelled-event".into(),
                life_id: "autonomy-life-a".into(),
                goal_id: "autonomy-tick-cancelled".into(),
                expected_revision: 1,
                kind: LifeGoalTransitionKind::Cancel,
            })
            .unwrap();

        assert_eq!(
            fixture.tick("no-active-goal", INTENT_FOCUS_STATE_AVAILABLE),
            Ok(AutonomyTickOutcome::NoActiveGoal)
        );
        assert_eq!(fixture.intent_count(), 0);
        assert_eq!(fixture.intent_event_count(), 0);
    }

    #[test]
    fn autonomy_tick_inspects_eight_goals_and_produces_at_most_one_intent() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        for index in 0..9 {
            fixture.create_goal(&format!("autonomy-tick-bound-{index}"), "autonomy-life-a");
        }

        let outcome = fixture
            .tick("bounded-one", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(outcome, AutonomyTickOutcome::Applied { .. }));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
        assert_eq!(MAX_GOALS_INSPECTED_PER_TICK, 8);
        assert_eq!(crate::autonomy::runtime::MAX_INTENTS_PRODUCED_PER_TICK, 1);
    }

    #[test]
    fn autonomy_tick_replays_same_tick_without_duplicate_rows() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-replay-goal", "autonomy-life-a");

        let first = fixture
            .tick("same-tick", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        let expected_intent_id = deterministic_intent_id("autonomy-life-a", "same-tick");
        assert!(matches!(
            first,
            AutonomyTickOutcome::Applied { ref intent, .. }
                if intent.intent_id == expected_intent_id
        ));
        let second = fixture
            .tick("same-tick", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(
            second,
            AutonomyTickOutcome::Replayed {
                goal_id,
                intent,
                evaluation: LifeProactiveIntentEvaluationOutcome::Replayed { event, current },
            } if goal_id == "autonomy-tick-replay-goal"
                && intent.intent_id == expected_intent_id
                && current.intent_id == expected_intent_id
                && event.event_id == deterministic_evaluation_event_id(&expected_intent_id)
        ));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
        assert_eq!(
            deterministic_evaluation_event_id(&expected_intent_id),
            fixture
                .storage
                .find_intent_event(
                    "autonomy-life-a",
                    &deterministic_evaluation_event_id(&expected_intent_id),
                )
                .unwrap()
                .unwrap()
                .event_id
        );
    }

    #[test]
    fn autonomy_tick_same_tick_is_idempotent_across_multiple_goals() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-multi-a", "autonomy-life-a");
        fixture.create_goal("autonomy-tick-multi-b", "autonomy-life-a");

        let first = fixture
            .tick("same-multi-goal-tick", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        let first_intent_id = deterministic_intent_id("autonomy-life-a", "same-multi-goal-tick");
        assert!(matches!(
            first,
            AutonomyTickOutcome::Applied {
                goal_id,
                intent,
                evaluation: LifeProactiveIntentEvaluationOutcome::Applied { .. },
            } if goal_id == "autonomy-tick-multi-a"
                && intent.intent_id == first_intent_id
                && intent.status == INTENT_STATUS_DEFERRED
        ));

        let second = fixture
            .tick("same-multi-goal-tick", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(
            second,
            AutonomyTickOutcome::Replayed {
                goal_id,
                intent,
                evaluation: LifeProactiveIntentEvaluationOutcome::Replayed { event, current },
            } if goal_id == "autonomy-tick-multi-a"
                && intent.goal_id == "autonomy-tick-multi-a"
                && current.goal_id == "autonomy-tick-multi-a"
                && event.intent_id == first_intent_id
        ));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
        let intents = fixture
            .storage
            .list_intents_for_life("autonomy-life-a")
            .unwrap();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].goal_id, "autonomy-tick-multi-a");
    }

    #[test]
    fn autonomy_tick_ready_same_tick_replays_original_goal() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-ready-a", "autonomy-life-a");
        fixture.create_goal("autonomy-tick-ready-b", "autonomy-life-a");
        fixture.insert_episode_with_age("autonomy-life-a", "ready-same-tick", 121);

        let first = fixture
            .tick("ready-same-tick", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(
            first,
            AutonomyTickOutcome::Applied {
                goal_id,
                intent,
                ..
            } if goal_id == "autonomy-tick-ready-a" && intent.status == INTENT_STATUS_READY
        ));

        let second = fixture
            .tick("ready-same-tick", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(
            second,
            AutonomyTickOutcome::Replayed {
                goal_id,
                intent,
                evaluation: LifeProactiveIntentEvaluationOutcome::Replayed { current, .. },
            } if goal_id == "autonomy-tick-ready-a"
                && intent.status == INTENT_STATUS_READY
                && current.goal_id == "autonomy-tick-ready-a"
        ));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
    }

    #[test]
    fn autonomy_tick_same_tick_focus_conflict_has_no_mutation() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-focus-a", "autonomy-life-a");
        fixture.create_goal("autonomy-tick-focus-b", "autonomy-life-a");

        let first = fixture
            .tick("focus-conflict-tick", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(first, AutonomyTickOutcome::Applied { .. }));

        let conflict = fixture
            .tick("focus-conflict-tick", INTENT_FOCUS_STATE_FOCUSED)
            .unwrap_err();
        assert!(matches!(conflict, AutonomyTickError::TickConflict { .. }));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
        let intent_id = deterministic_intent_id("autonomy-life-a", "focus-conflict-tick");
        let intent = fixture
            .storage
            .find_intent("autonomy-life-a", &intent_id)
            .unwrap()
            .unwrap();
        assert_eq!(intent.focus_state, INTENT_FOCUS_STATE_AVAILABLE);
    }

    #[test]
    fn autonomy_tick_same_tick_replay_precedes_policy_change_and_zero_budget() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-policy-a", "autonomy-life-a");
        fixture.create_goal("autonomy-tick-policy-b", "autonomy-life-a");

        let first = fixture
            .tick("policy-replay-tick", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(first, AutonomyTickOutcome::Applied { .. }));

        let policy = fixture
            .storage
            .find_policy("autonomy-life-a")
            .unwrap()
            .unwrap();
        fixture.update_policy(LifeAutonomyPolicyUpdateRequest {
            event_id: "autonomy-tick-policy-change".into(),
            life_id: "autonomy-life-a".into(),
            enabled: true,
            dnd: false,
            max_ready_per_window: 0,
            window_seconds: policy.window_seconds,
            min_gap_seconds: policy.min_gap_seconds,
            expected_revision: policy.revision,
        });

        let replay = fixture
            .tick("policy-replay-tick", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(replay, AutonomyTickOutcome::Replayed { .. }));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
    }

    #[test]
    fn autonomy_tick_terminal_same_tick_replays_after_policy_change() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-terminal-a", "autonomy-life-a");
        fixture.create_goal("autonomy-tick-terminal-b", "autonomy-life-a");
        let tick_id = "terminal-replay-tick";
        let intent_id = deterministic_intent_id("autonomy-life-a", tick_id);
        fixture.create_intent(fixture.tick_intent_request(
            &intent_id,
            "autonomy-life-a",
            "autonomy-tick-terminal-a",
            INTENT_FOCUS_STATE_AVAILABLE,
            Some(120),
        ));

        let policy = fixture
            .storage
            .find_policy("autonomy-life-a")
            .unwrap()
            .unwrap();
        fixture.update_policy(LifeAutonomyPolicyUpdateRequest {
            event_id: "autonomy-tick-terminal-disable".into(),
            life_id: "autonomy-life-a".into(),
            enabled: false,
            dnd: policy.dnd,
            max_ready_per_window: policy.max_ready_per_window,
            window_seconds: policy.window_seconds,
            min_gap_seconds: policy.min_gap_seconds,
            expected_revision: policy.revision,
        });
        let first = fixture.tick(tick_id, INTENT_FOCUS_STATE_AVAILABLE).unwrap();
        assert!(matches!(
            first,
            AutonomyTickOutcome::Applied { intent, .. }
                if intent.status == INTENT_STATUS_CANCELLED
        ));

        let disabled_policy = fixture
            .storage
            .find_policy("autonomy-life-a")
            .unwrap()
            .unwrap();
        fixture.update_policy(LifeAutonomyPolicyUpdateRequest {
            event_id: "autonomy-tick-terminal-enable".into(),
            life_id: "autonomy-life-a".into(),
            enabled: true,
            dnd: disabled_policy.dnd,
            max_ready_per_window: disabled_policy.max_ready_per_window,
            window_seconds: disabled_policy.window_seconds,
            min_gap_seconds: disabled_policy.min_gap_seconds,
            expected_revision: disabled_policy.revision,
        });
        let second = fixture.tick(tick_id, INTENT_FOCUS_STATE_AVAILABLE).unwrap();
        assert!(matches!(
            second,
            AutonomyTickOutcome::Replayed { goal_id, intent, .. }
                if goal_id == "autonomy-tick-terminal-a"
                    && intent.intent_id == intent_id
                    && intent.status == INTENT_STATUS_CANCELLED
        ));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
    }

    #[test]
    fn autonomy_tick_same_tick_recovers_committed_pending_original_goal() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-pending-a", "autonomy-life-a");
        fixture.create_goal("autonomy-tick-pending-b", "autonomy-life-a");
        let tick_id = "pending-recovery-tick";
        let intent_id = deterministic_intent_id("autonomy-life-a", tick_id);
        let pending = fixture.create_intent(fixture.tick_intent_request(
            &intent_id,
            "autonomy-life-a",
            "autonomy-tick-pending-a",
            INTENT_FOCUS_STATE_AVAILABLE,
            None,
        ));
        assert_eq!(pending.status, INTENT_STATUS_PENDING);
        assert_eq!(fixture.intent_event_count(), 0);

        let recovered = fixture.tick(tick_id, INTENT_FOCUS_STATE_AVAILABLE).unwrap();
        assert!(matches!(
            recovered,
            AutonomyTickOutcome::Applied { goal_id, intent, .. }
                if goal_id == "autonomy-tick-pending-a"
                    && intent.intent_id == intent_id
                    && intent.status == INTENT_STATUS_DEFERRED
        ));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
    }

    #[test]
    fn autonomy_tick_exact_replay_survives_original_goal_completion() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-complete-a", "autonomy-life-a");
        fixture.create_goal("autonomy-tick-complete-b", "autonomy-life-a");
        fixture.insert_episode_with_age("autonomy-life-a", "complete-same-tick", 121);
        let tick_id = "complete-same-tick";

        let first = fixture.tick(tick_id, INTENT_FOCUS_STATE_AVAILABLE).unwrap();
        assert!(matches!(
            first,
            AutonomyTickOutcome::Applied { goal_id, intent, .. }
                if goal_id == "autonomy-tick-complete-a"
                    && intent.status == INTENT_STATUS_READY
        ));
        fixture
            .storage
            .transition_goal(LifeGoalTransitionRequest {
                event_id: "autonomy-tick-complete-event".into(),
                life_id: "autonomy-life-a".into(),
                goal_id: "autonomy-tick-complete-a".into(),
                expected_revision: 1,
                kind: LifeGoalTransitionKind::Complete,
            })
            .unwrap();

        let replay = fixture.tick(tick_id, INTENT_FOCUS_STATE_AVAILABLE).unwrap();
        assert!(matches!(
            replay,
            AutonomyTickOutcome::Replayed { goal_id, intent, .. }
                if goal_id == "autonomy-tick-complete-a"
                    && intent.goal_id == "autonomy-tick-complete-a"
                    && intent.status == INTENT_STATUS_READY
        ));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
    }

    #[test]
    fn autonomy_tick_concurrent_same_tick_has_one_intent_and_event() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-concurrent-a", "autonomy-life-a");
        fixture.create_goal("autonomy-tick-concurrent-b", "autonomy-life-a");

        let second_root = fixture._root.path().join("default");
        let second_service = StorageService::initialize_with_roots(second_root, None).unwrap();
        let first_service = Arc::new(fixture.storage);
        let second_service = Arc::new(second_service);
        let barrier = Arc::new(Barrier::new(3));

        let first_barrier = barrier.clone();
        let first = first_service.clone();
        let first_thread = thread::spawn(move || {
            first_barrier.wait();
            run_autonomy_tick(
                &first,
                AutonomyTickRequest {
                    tick_id: "concurrent-same-tick".into(),
                    life_id: "autonomy-life-a".into(),
                    focus_state: INTENT_FOCUS_STATE_AVAILABLE.into(),
                },
            )
        });

        let second_barrier = barrier.clone();
        let second = second_service.clone();
        let second_thread = thread::spawn(move || {
            second_barrier.wait();
            run_autonomy_tick(
                &second,
                AutonomyTickRequest {
                    tick_id: "concurrent-same-tick".into(),
                    life_id: "autonomy-life-a".into(),
                    focus_state: INTENT_FOCUS_STATE_AVAILABLE.into(),
                },
            )
        });

        barrier.wait();
        let first_result = first_thread.join().unwrap();
        let second_result = second_thread.join().unwrap();
        let results = [first_result, second_result];
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(AutonomyTickOutcome::Applied { .. })))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(AutonomyTickOutcome::Replayed { .. })))
                .count(),
            1
        );
        let intent_id = deterministic_intent_id("autonomy-life-a", "concurrent-same-tick");
        assert!(first_service
            .find_intent("autonomy-life-a", &intent_id)
            .unwrap()
            .is_some());
        let state = first_service.state().unwrap();
        let intent_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM life_proactive_intent WHERE life_id='autonomy-life-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let event_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM life_proactive_intent_event WHERE life_id='autonomy-life-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(intent_count, 1);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn autonomy_tick_recovers_pending_intent_through_b2_once() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-pending-goal", "autonomy-life-a");
        let mut request = fixture.intent_request(
            "autonomy-tick-pending-intent",
            "autonomy-life-a",
            "autonomy-tick-pending-goal",
        );
        request.recent_interaction_seconds = Some(120);
        request.expires_at = None;
        let pending = fixture.create_intent(request);

        let outcome = fixture
            .tick("recovery-tick", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(
            outcome,
            AutonomyTickOutcome::Applied {
                intent: ref evaluated,
                ..
            } if evaluated.intent_id == pending.intent_id && evaluated.revision == 2
        ));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
        let event_id = deterministic_evaluation_event_id(&pending.intent_id);
        let event = fixture
            .storage
            .find_intent_event("autonomy-life-a", &event_id)
            .unwrap()
            .unwrap();
        assert_eq!(event.event_id, event_id);
        assert_eq!(event.expected_revision, 1);
        assert_eq!(event.applied_revision, 2);
    }

    #[test]
    fn autonomy_tick_deferred_due_creates_fresh_evidence_without_mutating_old_row() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-deferred-goal", "autonomy-life-a");
        let first = fixture
            .tick("deferred-first", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        let old_intent_id = match first {
            AutonomyTickOutcome::Applied { intent, .. } => intent.intent_id,
            other => panic!("expected first tick to apply, got {other:?}"),
        };
        let state = fixture.storage.state().unwrap();
        let now = sqlite_authority_now(&state.connection).unwrap();
        let old = sqlite_add_seconds(&state.connection, &now, -1).unwrap();
        drop(state);
        fixture.set_intent_times(&old_intent_id, &old, Some(&old));

        let second = fixture
            .tick("deferred-due", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        let new_intent_id = match second {
            AutonomyTickOutcome::Applied { intent, .. } => intent.intent_id,
            other => panic!("expected due deferred tick to apply, got {other:?}"),
        };
        assert_ne!(new_intent_id, old_intent_id);
        assert_eq!(fixture.intent_count(), 2);
        let old_intent = fixture
            .storage
            .find_intent("autonomy-life-a", &old_intent_id)
            .unwrap()
            .unwrap();
        assert_eq!(old_intent.status, INTENT_STATUS_DEFERRED);
        assert_eq!(old_intent.not_before.as_deref(), Some(old.as_str()));
    }

    #[test]
    fn autonomy_tick_terminal_cooldown_is_sqlite_authoritative_and_bounded() {
        let fixture = Fixture::new();
        let mut policy = fixture.policy_request("autonomy-life-a");
        policy.max_ready_per_window = 0;
        fixture.storage.create_policy(policy).unwrap();
        fixture.create_goal("autonomy-tick-terminal-goal", "autonomy-life-a");
        let mut intent_request = fixture.intent_request(
            "autonomy-tick-terminal-intent",
            "autonomy-life-a",
            "autonomy-tick-terminal-goal",
        );
        intent_request.recent_interaction_seconds = Some(120);
        intent_request.expires_at = None;
        let intent = fixture.create_intent(intent_request);
        let evaluated = fixture
            .evaluate(
                "autonomy-tick-terminal-event",
                "autonomy-life-a",
                &intent.intent_id,
                1,
            )
            .unwrap();
        assert!(matches!(
            evaluated,
            LifeProactiveIntentEvaluationOutcome::Applied { intent, .. }
                if intent.status == INTENT_STATUS_STORED_SILENTLY
        ));

        let mut enabled_policy = fixture.policy_request("autonomy-life-a");
        enabled_policy.max_ready_per_window = 3;
        fixture.update_policy(LifeAutonomyPolicyUpdateRequest {
            event_id: "autonomy-tick-terminal-policy-event".into(),
            life_id: enabled_policy.life_id,
            enabled: enabled_policy.enabled,
            dnd: enabled_policy.dnd,
            max_ready_per_window: enabled_policy.max_ready_per_window,
            window_seconds: enabled_policy.window_seconds,
            min_gap_seconds: enabled_policy.min_gap_seconds,
            expected_revision: 1,
        });
        let waiting = fixture
            .tick("terminal-before-cooldown", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(
            waiting,
            AutonomyTickOutcome::Waiting {
                reason: AutonomyTickWaitReason::TerminalCooldown,
                ..
            }
        ));
        assert_eq!(fixture.intent_count(), 1);

        let state = fixture.storage.state().unwrap();
        let now = sqlite_authority_now(&state.connection).unwrap();
        let old = sqlite_add_seconds(&state.connection, &now, -61).unwrap();
        drop(state);
        fixture.set_intent_times(&intent.intent_id, &old, None);
        let after = fixture
            .tick("terminal-after-cooldown", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(after, AutonomyTickOutcome::Applied { .. }));
        assert_eq!(fixture.intent_count(), 2);
    }

    #[test]
    fn autonomy_tick_zero_ready_budget_suppresses_new_work_but_recovers_pending() {
        let fixture = Fixture::new();
        let mut policy = fixture.policy_request("autonomy-life-a");
        policy.max_ready_per_window = 0;
        fixture.storage.create_policy(policy).unwrap();
        fixture.create_goal("autonomy-tick-zero-budget-goal", "autonomy-life-a");

        assert_eq!(
            fixture.tick("zero-budget-new", INTENT_FOCUS_STATE_AVAILABLE),
            Ok(AutonomyTickOutcome::NoReadyBudget)
        );
        assert_eq!(fixture.intent_count(), 0);

        let mut pending_request = fixture.intent_request(
            "autonomy-tick-zero-budget-pending",
            "autonomy-life-a",
            "autonomy-tick-zero-budget-goal",
        );
        pending_request.expires_at = None;
        let pending = fixture.create_intent(pending_request);
        let recovered = fixture
            .tick("zero-budget-recovery", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(
            recovered,
            AutonomyTickOutcome::Applied { intent, .. }
                if intent.intent_id == pending.intent_id
                    && intent.status == INTENT_STATUS_STORED_SILENTLY
        ));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
        assert_eq!(
            fixture.tick("zero-budget-again", INTENT_FOCUS_STATE_AVAILABLE),
            Ok(AutonomyTickOutcome::NoReadyBudget)
        );
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
    }

    #[test]
    fn autonomy_tick_recent_episode_age_and_focus_are_fail_conservative() {
        for (suffix, age_seconds, expected_status) in [
            ("zero", 0, INTENT_STATUS_DEFERRED),
            ("recent", 119, INTENT_STATUS_DEFERRED),
            ("quiet", 121, INTENT_STATUS_READY),
        ] {
            let fixture = Fixture::new();
            fixture.create_policy("autonomy-life-a", true, false);
            let goal_id = format!("autonomy-tick-recent-goal-{suffix}");
            fixture.create_goal(&goal_id, "autonomy-life-a");
            fixture.insert_episode_with_age("autonomy-life-a", suffix, age_seconds);
            let outcome = fixture
                .tick(&format!("recent-{suffix}"), INTENT_FOCUS_STATE_AVAILABLE)
                .unwrap();
            let intent = match outcome {
                AutonomyTickOutcome::Applied { intent, .. } => intent,
                other => panic!("expected evaluated intent, got {other:?}"),
            };
            assert_eq!(intent.status, expected_status);
            assert!(intent.recent_interaction_seconds.is_some());
            let recent = intent.recent_interaction_seconds.unwrap();
            if age_seconds == 0 {
                assert!(recent <= 1);
            } else if age_seconds == 119 {
                assert!((119..120).contains(&recent));
            } else {
                assert!(recent >= 120);
            }
        }

        for focus_state in [
            INTENT_FOCUS_STATE_UNKNOWN,
            INTENT_FOCUS_STATE_FOCUSED,
            INTENT_FOCUS_STATE_DND,
        ] {
            let fixture = Fixture::new();
            fixture.create_policy("autonomy-life-a", true, false);
            fixture.create_goal("autonomy-tick-focus-goal", "autonomy-life-a");
            fixture.insert_episode_with_age("autonomy-life-a", focus_state, 121);
            let outcome = fixture.tick(focus_state, focus_state).unwrap();
            assert!(matches!(
                outcome,
                AutonomyTickOutcome::Applied { intent, .. }
                    if intent.status == INTENT_STATUS_DEFERRED
            ));
        }

        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-no-episode-goal", "autonomy-life-a");
        let outcome = fixture
            .tick("no-episode", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(
            outcome,
            AutonomyTickOutcome::Applied { intent, .. }
                if intent.status == INTENT_STATUS_DEFERRED
                    && intent.recent_interaction_seconds.is_none()
        ));
    }

    #[test]
    fn autonomy_tick_blocks_a_goal_with_latest_ready_intent() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-ready-goal", "autonomy-life-a");
        let mut request = fixture.intent_request(
            "autonomy-tick-ready-intent",
            "autonomy-life-a",
            "autonomy-tick-ready-goal",
        );
        request.recent_interaction_seconds = Some(120);
        request.expires_at = None;
        let intent = fixture.create_intent(request);
        let evaluated = fixture
            .evaluate(
                "autonomy-tick-ready-event",
                "autonomy-life-a",
                &intent.intent_id,
                1,
            )
            .unwrap();
        assert!(matches!(
            evaluated,
            LifeProactiveIntentEvaluationOutcome::Applied { intent, .. }
                if intent.status == INTENT_STATUS_READY
        ));

        let outcome = fixture
            .tick("ready-block", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        assert!(matches!(
            outcome,
            AutonomyTickOutcome::Waiting {
                goal_id,
                reason: AutonomyTickWaitReason::ReadyPendingDelivery,
                until: None,
            } if goal_id == "autonomy-tick-ready-goal"
        ));
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
    }

    #[test]
    fn autonomy_tick_reopens_and_applies_one_elapsed_resume_tick() {
        let fixture = Fixture::new();
        fixture.create_policy("autonomy-life-a", true, false);
        fixture.create_goal("autonomy-tick-resume-goal", "autonomy-life-a");
        let first = fixture
            .tick("offline-before-close", INTENT_FOCUS_STATE_AVAILABLE)
            .unwrap();
        let old_intent_id = match first {
            AutonomyTickOutcome::Applied { intent, .. } => intent.intent_id,
            other => panic!("expected persisted deferred evidence, got {other:?}"),
        };
        let state = fixture.storage.state().unwrap();
        let now = sqlite_authority_now(&state.connection).unwrap();
        let old = sqlite_add_seconds(&state.connection, &now, -61).unwrap();
        drop(state);
        fixture.set_intent_times(&old_intent_id, &old, Some(&old));
        let database_root = fixture._root.path().join("default");
        drop(fixture.storage);

        let reopened = StorageService::initialize_with_roots(database_root, None).unwrap();
        let resumed = run_autonomy_tick(
            &reopened,
            AutonomyTickRequest {
                tick_id: "offline-after-open".into(),
                life_id: "autonomy-life-a".into(),
                focus_state: INTENT_FOCUS_STATE_AVAILABLE.into(),
            },
        )
        .unwrap();
        assert!(matches!(resumed, AutonomyTickOutcome::Applied { .. }));
        let intents = reopened
            .list_intents_for_goal("autonomy-life-a", "autonomy-tick-resume-goal")
            .unwrap();
        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0].intent_id, old_intent_id);
        assert_eq!(intents[0].status, INTENT_STATUS_DEFERRED);
    }
}
