//! SQLite-authoritative persistence for D14-B1/B2 goal / plan / action-intent
//! authority.
//!
//! This module is a crate-internal storage boundary, never a Tauri command.
//! It implements the bounded B1 repository scope plus D14-B2's explicit,
//! CAS-protected lifecycle transitions and `life_intent_event` writes.
//!
//! SQLite is the sole authority for entity identity, same-life parent binding
//! (composite foreign keys), create replay, cascade deletion, and timestamps.
//! Callers never supply `created_at` / `updated_at` / `closed_at`; those come
//! from the canonical SQLite UTC seam `strftime('%Y-%m-%dT%H:%M:%fZ','now')`.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};

use super::StorageService;
use crate::life_intent::{
    validate_action_persisted_state, validate_action_request, validate_action_shape,
    validate_event_lookup_arguments, validate_goal_persisted_state, validate_goal_request,
    validate_goal_shape, validate_plan_persisted_state, validate_plan_request, validate_plan_shape,
    validate_step_persisted_state, validate_step_request, validate_step_shape, LifeActionIntent,
    LifeActionIntentCreateRequest, LifeActionTransitionRequest, LifeGoal, LifeGoalCreateRequest,
    LifeGoalTransitionRequest, LifeIntentCreateOutcome, LifeIntentError, LifeIntentEvent,
    LifeIntentRepository, LifeIntentTransitionOutcome, LifePlan, LifePlanCreateRequest,
    LifePlanStep, LifePlanStepCreateRequest, LifePlanTransitionKind, LifePlanTransitionRequest,
    LifeStepTransitionRequest, ACTION_ENTITY_KIND, ACTION_STATUS_PROPOSED,
    ACTOR_KIND_USER_EXPLICIT, CREATED_BY_KIND_USER_EXPLICIT, EVENT_VERSION, GOAL_ENTITY_KIND,
    GOAL_STATUS_ACTIVE, PLAN_ENTITY_KIND, PLAN_STATUS_DRAFT, STEP_ENTITY_KIND, STEP_STATUS_PENDING,
};

pub(super) const CREATE_LIFE_GOAL_TABLE_SQL: &str =
    include_str!("migrations/022_life_goal_plan_action_authority.life_goal.sql");
pub(super) const CREATE_LIFE_PLAN_TABLE_SQL: &str =
    include_str!("migrations/022_life_goal_plan_action_authority.life_plan.sql");
pub(super) const CREATE_LIFE_PLAN_STEP_TABLE_SQL: &str =
    include_str!("migrations/022_life_goal_plan_action_authority.life_plan_step.sql");
pub(super) const CREATE_LIFE_ACTION_INTENT_TABLE_SQL: &str =
    include_str!("migrations/022_life_goal_plan_action_authority.life_action_intent.sql");
pub(super) const CREATE_LIFE_INTENT_EVENT_TABLE_SQL: &str =
    include_str!("migrations/022_life_goal_plan_action_authority.life_intent_event.sql");
pub(super) const CREATE_LIFE_GOAL_IMMUTABLE_TRIGGER_SQL: &str =
    include_str!("migrations/022_life_goal_plan_action_authority.life_goal_immutable_trigger.sql");
pub(super) const CREATE_LIFE_PLAN_IMMUTABLE_TRIGGER_SQL: &str =
    include_str!("migrations/022_life_goal_plan_action_authority.life_plan_immutable_trigger.sql");
pub(super) const CREATE_LIFE_PLAN_STEP_IMMUTABLE_TRIGGER_SQL: &str = include_str!(
    "migrations/022_life_goal_plan_action_authority.life_plan_step_immutable_trigger.sql"
);
pub(super) const CREATE_LIFE_ACTION_INTENT_IMMUTABLE_TRIGGER_SQL: &str = include_str!(
    "migrations/022_life_goal_plan_action_authority.life_action_intent_immutable_trigger.sql"
);
pub(super) const CREATE_LIFE_INTENT_EVENT_IMMUTABLE_TRIGGER_SQL: &str = include_str!(
    "migrations/022_life_goal_plan_action_authority.life_intent_event_immutable_trigger.sql"
);

/// Complete Schema22 D14 table phase: the five authority tables, one
/// statement per file so each object keeps its exact-match validation source.
pub(super) const MIGRATION_022_TABLE_SQLS: &[&str] = &[
    CREATE_LIFE_GOAL_TABLE_SQL,
    CREATE_LIFE_PLAN_TABLE_SQL,
    CREATE_LIFE_PLAN_STEP_TABLE_SQL,
    CREATE_LIFE_ACTION_INTENT_TABLE_SQL,
    CREATE_LIFE_INTENT_EVENT_TABLE_SQL,
];

/// Complete Schema22 D14 semantic-guard phase: the five immutability triggers;
/// B1 guards immutable evidence while D14-B2 owns lifecycle transitions.
pub(super) const MIGRATION_022_TRIGGER_SQLS: &[&str] = &[
    CREATE_LIFE_GOAL_IMMUTABLE_TRIGGER_SQL,
    CREATE_LIFE_PLAN_IMMUTABLE_TRIGGER_SQL,
    CREATE_LIFE_PLAN_STEP_IMMUTABLE_TRIGGER_SQL,
    CREATE_LIFE_ACTION_INTENT_IMMUTABLE_TRIGGER_SQL,
    CREATE_LIFE_INTENT_EVENT_IMMUTABLE_TRIGGER_SQL,
];

const LIFE_GOAL_COLUMNS: &str = "goal_id, life_id, title, objective, status, revision, created_by_kind, created_at, updated_at, closed_at, goal_version";
const LIFE_PLAN_COLUMNS: &str = "plan_id, life_id, goal_id, title, status, revision, created_at, updated_at, closed_at, plan_version";
const LIFE_PLAN_STEP_COLUMNS: &str = "step_id, life_id, plan_id, ordinal, summary, status, revision, created_at, updated_at, closed_at, step_version";
const LIFE_ACTION_INTENT_COLUMNS: &str = "action_id, life_id, step_id, execution_class, summary, status, revision, created_at, updated_at, closed_at, action_version";
const LIFE_INTENT_EVENT_COLUMNS: &str = "event_id, life_id, entity_kind, goal_id, plan_id, step_id, action_id, from_status, to_status, expected_revision, applied_revision, actor_kind, occurred_at, event_version";

fn read_goal(row: &Row<'_>) -> rusqlite::Result<LifeGoal> {
    Ok(LifeGoal {
        goal_id: row.get(0)?,
        life_id: row.get(1)?,
        title: row.get(2)?,
        objective: row.get(3)?,
        status: row.get(4)?,
        revision: row.get(5)?,
        created_by_kind: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
        closed_at: row.get(9)?,
        goal_version: row.get(10)?,
    })
}

fn read_plan(row: &Row<'_>) -> rusqlite::Result<LifePlan> {
    Ok(LifePlan {
        plan_id: row.get(0)?,
        life_id: row.get(1)?,
        goal_id: row.get(2)?,
        title: row.get(3)?,
        status: row.get(4)?,
        revision: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        closed_at: row.get(8)?,
        plan_version: row.get(9)?,
    })
}

fn read_step(row: &Row<'_>) -> rusqlite::Result<LifePlanStep> {
    Ok(LifePlanStep {
        step_id: row.get(0)?,
        life_id: row.get(1)?,
        plan_id: row.get(2)?,
        ordinal: row.get(3)?,
        summary: row.get(4)?,
        status: row.get(5)?,
        revision: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
        closed_at: row.get(9)?,
        step_version: row.get(10)?,
    })
}

fn read_action(row: &Row<'_>) -> rusqlite::Result<LifeActionIntent> {
    Ok(LifeActionIntent {
        action_id: row.get(0)?,
        life_id: row.get(1)?,
        step_id: row.get(2)?,
        execution_class: row.get(3)?,
        summary: row.get(4)?,
        status: row.get(5)?,
        revision: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
        closed_at: row.get(9)?,
        action_version: row.get(10)?,
    })
}

fn read_event(row: &Row<'_>) -> rusqlite::Result<LifeIntentEvent> {
    Ok(LifeIntentEvent {
        event_id: row.get(0)?,
        life_id: row.get(1)?,
        entity_kind: row.get(2)?,
        goal_id: row.get(3)?,
        plan_id: row.get(4)?,
        step_id: row.get(5)?,
        action_id: row.get(6)?,
        from_status: row.get(7)?,
        to_status: row.get(8)?,
        expected_revision: row.get(9)?,
        applied_revision: row.get(10)?,
        actor_kind: row.get(11)?,
        occurred_at: row.get(12)?,
        event_version: row.get(13)?,
    })
}

fn invalid_lookup_argument(name: &str) -> LifeIntentError {
    LifeIntentError::invalid_argument(format!("{name} must not be empty."))
}

fn validate_lookup_arguments(life_id: &str, entity_id: &str) -> Result<(), LifeIntentError> {
    if life_id.trim().is_empty() {
        return Err(invalid_lookup_argument("life identity"));
    }
    if entity_id.trim().is_empty() {
        return Err(invalid_lookup_argument("entity identity"));
    }
    Ok(())
}

fn validate_list_arguments(life_id: &str, parent_id: Option<&str>) -> Result<(), LifeIntentError> {
    if life_id.trim().is_empty() {
        return Err(invalid_lookup_argument("life identity"));
    }
    if let Some(parent_id) = parent_id {
        if parent_id.trim().is_empty() {
            return Err(invalid_lookup_argument("parent identity"));
        }
    }
    Ok(())
}

fn require_life(transaction: &Transaction<'_>, life_id: &str) -> Result<(), LifeIntentError> {
    let life_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
            [life_id],
            |row| row.get(0),
        )
        .map_err(|_| LifeIntentError::database())?;
    if !life_exists {
        return Err(LifeIntentError::life_not_found());
    }
    Ok(())
}

/// Same-life parent authority check that distinguishes a missing parent from a
/// parent that exists under a different life. The caller's `life_id` is never
/// rewritten to match a parent.
fn require_parent(
    transaction: &Transaction<'_>,
    parent_table: &str,
    parent_id_column: &str,
    parent_id: &str,
    requested_life_id: &str,
) -> Result<(), LifeIntentError> {
    let parent_life: Option<String> = transaction
        .query_row(
            &format!("SELECT life_id FROM {parent_table} WHERE {parent_id_column} = ?1"),
            [parent_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| LifeIntentError::database())?;
    match parent_life {
        None => Err(LifeIntentError::parent_not_found()),
        Some(found_life) if found_life != requested_life_id => {
            Err(LifeIntentError::parent_life_mismatch())
        }
        Some(_) => Ok(()),
    }
}

/// SQLite's own UTC clock, consistent with the repository's canonical time
/// seam. Timestamps are authority-owned; callers never supply them.
fn sqlite_authority_now(connection: &Connection) -> Result<String, LifeIntentError> {
    connection
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| LifeIntentError::database())
}

/// Maps a residual INSERT failure after the explicit semantic prechecks.
///
/// Production classification NEVER inspects SQLite message text (English or
/// otherwise). Every typed category — replay, EntityConflict, LifeNotFound,
/// ParentNotFound, ParentLifeMismatch, duplicate step ordinal — is resolved by
/// explicit statements inside the same IMMEDIATE transaction before the
/// INSERT, so a failure reaching this point has no provable semantic category
/// from a structured code and is reported as database unavailability.
fn map_create_error(_error: rusqlite::Error) -> LifeIntentError {
    LifeIntentError::database()
}

fn map_transition_error(_error: rusqlite::Error) -> LifeIntentError {
    LifeIntentError::database()
}

fn next_revision(expected_revision: i64) -> Result<i64, LifeIntentError> {
    expected_revision
        .checked_add(1)
        .ok_or_else(|| LifeIntentError::invalid_argument("the target revision is unrepresentable."))
}

fn load_event_by_id(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<Option<LifeIntentEvent>, LifeIntentError> {
    transaction
        .query_row(
            &format!(
                "SELECT {LIFE_INTENT_EVENT_COLUMNS} FROM life_intent_event WHERE event_id = ?1"
            ),
            [event_id],
            read_event,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())
}

fn event_target_matches(event: &LifeIntentEvent, entity_kind: &str, entity_id: &str) -> bool {
    match entity_kind {
        GOAL_ENTITY_KIND => {
            event.goal_id.as_deref() == Some(entity_id)
                && event.plan_id.is_none()
                && event.step_id.is_none()
                && event.action_id.is_none()
        }
        PLAN_ENTITY_KIND => {
            event.goal_id.is_none()
                && event.plan_id.as_deref() == Some(entity_id)
                && event.step_id.is_none()
                && event.action_id.is_none()
        }
        STEP_ENTITY_KIND => {
            event.goal_id.is_none()
                && event.plan_id.is_none()
                && event.step_id.as_deref() == Some(entity_id)
                && event.action_id.is_none()
        }
        ACTION_ENTITY_KIND => {
            event.goal_id.is_none()
                && event.plan_id.is_none()
                && event.step_id.is_none()
                && event.action_id.as_deref() == Some(entity_id)
        }
        _ => false,
    }
}

fn event_evidence_matches(
    event: &LifeIntentEvent,
    life_id: &str,
    entity_kind: &str,
    entity_id: &str,
    to_status: &str,
    expected_revision: i64,
    applied_revision: i64,
) -> bool {
    event.life_id == life_id
        && event.entity_kind == entity_kind
        && event_target_matches(event, entity_kind, entity_id)
        && event.to_status == to_status
        && event.expected_revision == expected_revision
        && event.applied_revision == applied_revision
        && event.actor_kind == ACTOR_KIND_USER_EXPLICIT
        && event.event_version == EVENT_VERSION
}

fn insert_event(
    transaction: &Transaction<'_>,
    event: &LifeIntentEvent,
) -> Result<(), LifeIntentError> {
    transaction
        .execute(
            &format!(
                "INSERT INTO life_intent_event ({LIFE_INTENT_EVENT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"
            ),
            params![
                &event.event_id,
                &event.life_id,
                &event.entity_kind,
                event.goal_id.as_deref(),
                event.plan_id.as_deref(),
                event.step_id.as_deref(),
                event.action_id.as_deref(),
                &event.from_status,
                &event.to_status,
                event.expected_revision,
                event.applied_revision,
                &event.actor_kind,
                &event.occurred_at,
                event.event_version,
            ],
        )
        .map_err(map_transition_error)?;
    Ok(())
}

enum LifeIntentEventTarget<'a> {
    Goal(&'a str),
    Plan(&'a str),
    Step(&'a str),
    Action(&'a str),
}

struct LifeIntentEventBuild<'a> {
    event_id: &'a str,
    life_id: &'a str,
    target: LifeIntentEventTarget<'a>,
    from_status: &'a str,
    to_status: &'a str,
    expected_revision: i64,
    applied_revision: i64,
    occurred_at: &'a str,
}

fn build_event(input: LifeIntentEventBuild<'_>) -> LifeIntentEvent {
    let LifeIntentEventBuild {
        event_id,
        life_id,
        target,
        from_status,
        to_status,
        expected_revision,
        applied_revision,
        occurred_at,
    } = input;
    let (entity_kind, goal_id, plan_id, step_id, action_id) = match target {
        LifeIntentEventTarget::Goal(goal_id) => (
            GOAL_ENTITY_KIND,
            Some(goal_id.to_string()),
            None,
            None,
            None,
        ),
        LifeIntentEventTarget::Plan(plan_id) => (
            PLAN_ENTITY_KIND,
            None,
            Some(plan_id.to_string()),
            None,
            None,
        ),
        LifeIntentEventTarget::Step(step_id) => (
            STEP_ENTITY_KIND,
            None,
            None,
            Some(step_id.to_string()),
            None,
        ),
        LifeIntentEventTarget::Action(action_id) => (
            ACTION_ENTITY_KIND,
            None,
            None,
            None,
            Some(action_id.to_string()),
        ),
    };
    LifeIntentEvent {
        event_id: event_id.to_string(),
        life_id: life_id.to_string(),
        entity_kind: entity_kind.to_string(),
        goal_id,
        plan_id,
        step_id,
        action_id,
        from_status: from_status.to_string(),
        to_status: to_status.to_string(),
        expected_revision,
        applied_revision,
        actor_kind: ACTOR_KIND_USER_EXPLICIT.to_string(),
        occurred_at: occurred_at.to_string(),
        event_version: EVENT_VERSION,
    }
}

fn load_goal_by_id(
    transaction: &Transaction<'_>,
    goal_id: &str,
) -> Result<Option<LifeGoal>, LifeIntentError> {
    transaction
        .query_row(
            &format!("SELECT {LIFE_GOAL_COLUMNS} FROM life_goal WHERE goal_id = ?1"),
            [goal_id],
            read_goal,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())
}

fn load_plan_by_id(
    transaction: &Transaction<'_>,
    plan_id: &str,
) -> Result<Option<LifePlan>, LifeIntentError> {
    transaction
        .query_row(
            &format!("SELECT {LIFE_PLAN_COLUMNS} FROM life_plan WHERE plan_id = ?1"),
            [plan_id],
            read_plan,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())
}

fn load_step_by_id(
    transaction: &Transaction<'_>,
    step_id: &str,
) -> Result<Option<LifePlanStep>, LifeIntentError> {
    transaction
        .query_row(
            &format!("SELECT {LIFE_PLAN_STEP_COLUMNS} FROM life_plan_step WHERE step_id = ?1"),
            [step_id],
            read_step,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())
}

fn load_action_by_id(
    transaction: &Transaction<'_>,
    action_id: &str,
) -> Result<Option<LifeActionIntent>, LifeIntentError> {
    transaction
        .query_row(
            &format!(
                "SELECT {LIFE_ACTION_INTENT_COLUMNS} FROM life_action_intent WHERE action_id = ?1"
            ),
            [action_id],
            read_action,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())
}

fn load_goal_for_transition(
    transaction: &Transaction<'_>,
    life_id: &str,
    goal_id: &str,
) -> Result<LifeGoal, LifeIntentError> {
    let Some(goal) = load_goal_by_id(transaction, goal_id)? else {
        return Err(LifeIntentError::entity_not_found());
    };
    if goal.life_id != life_id {
        return Err(LifeIntentError::entity_life_mismatch());
    }
    validate_goal_persisted_state(&goal)?;
    Ok(goal)
}

fn load_plan_for_transition(
    transaction: &Transaction<'_>,
    life_id: &str,
    plan_id: &str,
) -> Result<LifePlan, LifeIntentError> {
    let Some(plan) = load_plan_by_id(transaction, plan_id)? else {
        return Err(LifeIntentError::entity_not_found());
    };
    if plan.life_id != life_id {
        return Err(LifeIntentError::entity_life_mismatch());
    }
    validate_plan_persisted_state(&plan)?;
    Ok(plan)
}

fn load_step_for_transition(
    transaction: &Transaction<'_>,
    life_id: &str,
    step_id: &str,
) -> Result<LifePlanStep, LifeIntentError> {
    let Some(step) = load_step_by_id(transaction, step_id)? else {
        return Err(LifeIntentError::entity_not_found());
    };
    if step.life_id != life_id {
        return Err(LifeIntentError::entity_life_mismatch());
    }
    validate_step_persisted_state(&step)?;
    Ok(step)
}

fn load_action_for_transition(
    transaction: &Transaction<'_>,
    life_id: &str,
    action_id: &str,
) -> Result<LifeActionIntent, LifeIntentError> {
    let Some(action) = load_action_by_id(transaction, action_id)? else {
        return Err(LifeIntentError::entity_not_found());
    };
    if action.life_id != life_id {
        return Err(LifeIntentError::entity_life_mismatch());
    }
    validate_action_persisted_state(&action)?;
    Ok(action)
}

/// Same-life validation of the requested step ordinal under one plan. Returns
/// true when the ordinal is already claimed by another, still-existing step.
fn ordinal_claimed_in_plan(
    transaction: &Transaction<'_>,
    plan_id: &str,
    ordinal: i64,
    except_step_id: &str,
) -> Result<bool, LifeIntentError> {
    let claimed: bool = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM life_plan_step
                 WHERE plan_id = ?1 AND ordinal = ?2 AND step_id <> ?3
             )",
            params![plan_id, ordinal, except_step_id],
            |row| row.get(0),
        )
        .map_err(|_| LifeIntentError::database())?;
    Ok(claimed)
}

pub(super) fn create_goal_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeGoalCreateRequest,
) -> Result<LifeIntentCreateOutcome<LifeGoal>, LifeIntentError> {
    validate_goal_request(&request)?;

    if let Some(existing) = transaction
        .query_row(
            &format!("SELECT {LIFE_GOAL_COLUMNS} FROM life_goal WHERE goal_id = ?1"),
            [&request.goal_id],
            read_goal,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())?
    {
        let evidence_matches = existing.life_id == request.life_id
            && existing.title == request.title
            && existing.objective == request.objective;
        if evidence_matches {
            return Ok(LifeIntentCreateOutcome::Replayed(existing));
        }
        return Err(LifeIntentError::entity_conflict());
    }

    require_life(transaction, &request.life_id)?;

    let now = sqlite_authority_now(transaction)?;
    transaction
        .execute(
            &format!(
                "INSERT INTO life_goal
                     (goal_id, life_id, title, objective, status, revision,
                      created_by_kind, created_at, updated_at, closed_at, goal_version)
                 VALUES (?1, ?2, ?3, ?4, {q}, 1, {k}, ?5, ?5, NULL, 1)",
                q = quote(GOAL_STATUS_ACTIVE),
                k = quote(CREATED_BY_KIND_USER_EXPLICIT)
            ),
            params![
                &request.goal_id,
                &request.life_id,
                &request.title,
                &request.objective,
                now
            ],
        )
        .map_err(map_create_error)?;

    let created = transaction
        .query_row(
            &format!("SELECT {LIFE_GOAL_COLUMNS} FROM life_goal WHERE goal_id = ?1"),
            [&request.goal_id],
            read_goal,
        )
        .map_err(|_| LifeIntentError::database())?;
    validate_goal_shape(&created)?;
    Ok(LifeIntentCreateOutcome::Applied(created))
}

pub(super) fn create_plan_in_transaction(
    transaction: &Transaction<'_>,
    request: LifePlanCreateRequest,
) -> Result<LifeIntentCreateOutcome<LifePlan>, LifeIntentError> {
    validate_plan_request(&request)?;

    if let Some(existing) = transaction
        .query_row(
            &format!("SELECT {LIFE_PLAN_COLUMNS} FROM life_plan WHERE plan_id = ?1"),
            [&request.plan_id],
            read_plan,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())?
    {
        let evidence_matches = existing.life_id == request.life_id
            && existing.goal_id == request.goal_id
            && existing.title == request.title;
        if evidence_matches {
            return Ok(LifeIntentCreateOutcome::Replayed(existing));
        }
        return Err(LifeIntentError::entity_conflict());
    }

    require_life(transaction, &request.life_id)?;
    require_parent(
        transaction,
        "life_goal",
        "goal_id",
        &request.goal_id,
        &request.life_id,
    )?;

    let now = sqlite_authority_now(transaction)?;
    transaction
        .execute(
            &format!(
                "INSERT INTO life_plan
                     (plan_id, life_id, goal_id, title, status, revision,
                      created_at, updated_at, closed_at, plan_version)
                 VALUES (?1, ?2, ?3, ?4, {q}, 1, ?5, ?5, NULL, 1)",
                q = quote(PLAN_STATUS_DRAFT)
            ),
            params![
                &request.plan_id,
                &request.life_id,
                &request.goal_id,
                &request.title,
                now
            ],
        )
        .map_err(map_create_error)?;

    let created = transaction
        .query_row(
            &format!("SELECT {LIFE_PLAN_COLUMNS} FROM life_plan WHERE plan_id = ?1"),
            [&request.plan_id],
            read_plan,
        )
        .map_err(|_| LifeIntentError::database())?;
    validate_plan_shape(&created)?;
    Ok(LifeIntentCreateOutcome::Applied(created))
}

pub(super) fn create_step_in_transaction(
    transaction: &Transaction<'_>,
    request: LifePlanStepCreateRequest,
) -> Result<LifeIntentCreateOutcome<LifePlanStep>, LifeIntentError> {
    validate_step_request(&request)?;

    if let Some(existing) = transaction
        .query_row(
            &format!("SELECT {LIFE_PLAN_STEP_COLUMNS} FROM life_plan_step WHERE step_id = ?1"),
            [&request.step_id],
            read_step,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())?
    {
        let evidence_matches = existing.life_id == request.life_id
            && existing.plan_id == request.plan_id
            && existing.ordinal == request.ordinal
            && existing.summary == request.summary;
        if evidence_matches {
            return Ok(LifeIntentCreateOutcome::Replayed(existing));
        }
        return Err(LifeIntentError::entity_conflict());
    }

    require_life(transaction, &request.life_id)?;
    require_parent(
        transaction,
        "life_plan",
        "plan_id",
        &request.plan_id,
        &request.life_id,
    )?;

    if ordinal_claimed_in_plan(
        transaction,
        &request.plan_id,
        request.ordinal,
        &request.step_id,
    )? {
        return Err(LifeIntentError::entity_conflict());
    }

    let now = sqlite_authority_now(transaction)?;
    transaction
        .execute(
            &format!(
                "INSERT INTO life_plan_step
                     (step_id, life_id, plan_id, ordinal, summary, status, revision,
                      created_at, updated_at, closed_at, step_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, {q}, 1, ?6, ?6, NULL, 1)",
                q = quote(STEP_STATUS_PENDING)
            ),
            params![
                &request.step_id,
                &request.life_id,
                &request.plan_id,
                request.ordinal,
                &request.summary,
                now
            ],
        )
        .map_err(map_create_error)?;

    let created = transaction
        .query_row(
            &format!("SELECT {LIFE_PLAN_STEP_COLUMNS} FROM life_plan_step WHERE step_id = ?1"),
            [&request.step_id],
            read_step,
        )
        .map_err(|_| LifeIntentError::database())?;
    validate_step_shape(&created)?;
    Ok(LifeIntentCreateOutcome::Applied(created))
}

pub(super) fn create_action_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeActionIntentCreateRequest,
) -> Result<LifeIntentCreateOutcome<LifeActionIntent>, LifeIntentError> {
    validate_action_request(&request)?;

    if let Some(existing) = transaction
        .query_row(
            &format!(
                "SELECT {LIFE_ACTION_INTENT_COLUMNS} FROM life_action_intent WHERE action_id = ?1"
            ),
            [&request.action_id],
            read_action,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())?
    {
        let evidence_matches = existing.life_id == request.life_id
            && existing.step_id == request.step_id
            && existing.execution_class == request.execution_class
            && existing.summary == request.summary;
        if evidence_matches {
            return Ok(LifeIntentCreateOutcome::Replayed(existing));
        }
        return Err(LifeIntentError::entity_conflict());
    }

    require_life(transaction, &request.life_id)?;
    require_parent(
        transaction,
        "life_plan_step",
        "step_id",
        &request.step_id,
        &request.life_id,
    )?;

    let now = sqlite_authority_now(transaction)?;
    transaction
        .execute(
            &format!(
                "INSERT INTO life_action_intent
                     (action_id, life_id, step_id, execution_class, summary, status, revision,
                      created_at, updated_at, closed_at, action_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, {q}, 1, ?6, ?6, NULL, 1)",
                q = quote(ACTION_STATUS_PROPOSED)
            ),
            params![
                &request.action_id,
                &request.life_id,
                &request.step_id,
                &request.execution_class,
                &request.summary,
                now
            ],
        )
        .map_err(map_create_error)?;

    let created = transaction
        .query_row(
            &format!(
                "SELECT {LIFE_ACTION_INTENT_COLUMNS} FROM life_action_intent WHERE action_id = ?1"
            ),
            [&request.action_id],
            read_action,
        )
        .map_err(|_| LifeIntentError::database())?;
    validate_action_shape(&created)?;
    Ok(LifeIntentCreateOutcome::Applied(created))
}

/// Performs one goal lifecycle transition inside a caller-owned transaction.
/// This helper never begins, commits, or rolls back the transaction.
pub(super) fn transition_goal_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeGoalTransitionRequest,
) -> Result<LifeIntentTransitionOutcome<LifeGoal>, LifeIntentError> {
    request.validate()?;
    let applied_revision = next_revision(request.expected_revision)?;
    let requested_to_status = request.kind.to_status();

    if let Some(event) = load_event_by_id(transaction, &request.event_id)? {
        if event_evidence_matches(
            &event,
            &request.life_id,
            GOAL_ENTITY_KIND,
            &request.goal_id,
            requested_to_status,
            request.expected_revision,
            applied_revision,
        ) {
            let current =
                load_goal_for_transition(transaction, &request.life_id, &request.goal_id)?;
            return Ok(LifeIntentTransitionOutcome::Replayed { event, current });
        }
        return Err(LifeIntentError::life_intent_event_conflict());
    }

    let current = load_goal_for_transition(transaction, &request.life_id, &request.goal_id)?;
    if current.revision != request.expected_revision {
        return Err(LifeIntentError::revision_conflict());
    }
    let to_status = request
        .kind
        .target_status(&current.status)
        .ok_or_else(LifeIntentError::invalid_transition)?;
    let now = sqlite_authority_now(transaction)?;
    let closed_at = Some(now.clone());
    let event = build_event(LifeIntentEventBuild {
        event_id: &request.event_id,
        life_id: &request.life_id,
        target: LifeIntentEventTarget::Goal(&request.goal_id),
        from_status: &current.status,
        to_status,
        expected_revision: request.expected_revision,
        applied_revision,
        occurred_at: &now,
    });

    let changed = transaction
        .execute(
            "UPDATE life_goal
             SET status = ?1, revision = ?2, updated_at = ?3, closed_at = ?4
             WHERE goal_id = ?5 AND life_id = ?6 AND revision = ?7 AND status = ?8",
            params![
                to_status,
                applied_revision,
                &now,
                &closed_at,
                &request.goal_id,
                &request.life_id,
                request.expected_revision,
                &current.status,
            ],
        )
        .map_err(map_transition_error)?;
    if changed != 1 {
        return Err(LifeIntentError::revision_conflict());
    }
    insert_event(transaction, &event)?;

    let committed_event =
        load_event_by_id(transaction, &request.event_id)?.ok_or_else(LifeIntentError::database)?;
    let committed_goal = load_goal_for_transition(transaction, &request.life_id, &request.goal_id)?;
    Ok(LifeIntentTransitionOutcome::Applied {
        event: committed_event,
        entity: committed_goal,
    })
}

/// Performs one plan lifecycle transition inside a caller-owned transaction.
/// This helper never begins, commits, or rolls back the transaction.
pub(super) fn transition_plan_in_transaction(
    transaction: &Transaction<'_>,
    request: LifePlanTransitionRequest,
) -> Result<LifeIntentTransitionOutcome<LifePlan>, LifeIntentError> {
    request.validate()?;
    let applied_revision = next_revision(request.expected_revision)?;
    let requested_to_status = request.kind.to_status();

    if let Some(event) = load_event_by_id(transaction, &request.event_id)? {
        if event_evidence_matches(
            &event,
            &request.life_id,
            PLAN_ENTITY_KIND,
            &request.plan_id,
            requested_to_status,
            request.expected_revision,
            applied_revision,
        ) {
            let current =
                load_plan_for_transition(transaction, &request.life_id, &request.plan_id)?;
            return Ok(LifeIntentTransitionOutcome::Replayed { event, current });
        }
        return Err(LifeIntentError::life_intent_event_conflict());
    }

    let current = load_plan_for_transition(transaction, &request.life_id, &request.plan_id)?;
    if current.revision != request.expected_revision {
        return Err(LifeIntentError::revision_conflict());
    }
    let to_status = request
        .kind
        .target_status(&current.status)
        .ok_or_else(LifeIntentError::invalid_transition)?;
    let now = sqlite_authority_now(transaction)?;
    let closed_at = match request.kind {
        LifePlanTransitionKind::Activate => None,
        LifePlanTransitionKind::Complete | LifePlanTransitionKind::Cancel => Some(now.clone()),
    };
    let event = build_event(LifeIntentEventBuild {
        event_id: &request.event_id,
        life_id: &request.life_id,
        target: LifeIntentEventTarget::Plan(&request.plan_id),
        from_status: &current.status,
        to_status,
        expected_revision: request.expected_revision,
        applied_revision,
        occurred_at: &now,
    });

    let changed = transaction
        .execute(
            "UPDATE life_plan
             SET status = ?1, revision = ?2, updated_at = ?3, closed_at = ?4
             WHERE plan_id = ?5 AND life_id = ?6 AND revision = ?7 AND status = ?8",
            params![
                to_status,
                applied_revision,
                &now,
                &closed_at,
                &request.plan_id,
                &request.life_id,
                request.expected_revision,
                &current.status,
            ],
        )
        .map_err(map_transition_error)?;
    if changed != 1 {
        return Err(LifeIntentError::revision_conflict());
    }
    insert_event(transaction, &event)?;

    let committed_event =
        load_event_by_id(transaction, &request.event_id)?.ok_or_else(LifeIntentError::database)?;
    let committed_plan = load_plan_for_transition(transaction, &request.life_id, &request.plan_id)?;
    Ok(LifeIntentTransitionOutcome::Applied {
        event: committed_event,
        entity: committed_plan,
    })
}

/// Performs one plan-step lifecycle transition inside a caller-owned
/// transaction. This helper never begins, commits, or rolls back the
/// transaction.
pub(super) fn transition_step_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeStepTransitionRequest,
) -> Result<LifeIntentTransitionOutcome<LifePlanStep>, LifeIntentError> {
    request.validate()?;
    let applied_revision = next_revision(request.expected_revision)?;
    let requested_to_status = request.kind.to_status();

    if let Some(event) = load_event_by_id(transaction, &request.event_id)? {
        if event_evidence_matches(
            &event,
            &request.life_id,
            STEP_ENTITY_KIND,
            &request.step_id,
            requested_to_status,
            request.expected_revision,
            applied_revision,
        ) {
            let current =
                load_step_for_transition(transaction, &request.life_id, &request.step_id)?;
            return Ok(LifeIntentTransitionOutcome::Replayed { event, current });
        }
        return Err(LifeIntentError::life_intent_event_conflict());
    }

    let current = load_step_for_transition(transaction, &request.life_id, &request.step_id)?;
    if current.revision != request.expected_revision {
        return Err(LifeIntentError::revision_conflict());
    }
    let to_status = request
        .kind
        .target_status(&current.status)
        .ok_or_else(LifeIntentError::invalid_transition)?;
    let now = sqlite_authority_now(transaction)?;
    let closed_at = Some(now.clone());
    let event = build_event(LifeIntentEventBuild {
        event_id: &request.event_id,
        life_id: &request.life_id,
        target: LifeIntentEventTarget::Step(&request.step_id),
        from_status: &current.status,
        to_status,
        expected_revision: request.expected_revision,
        applied_revision,
        occurred_at: &now,
    });

    let changed = transaction
        .execute(
            "UPDATE life_plan_step
             SET status = ?1, revision = ?2, updated_at = ?3, closed_at = ?4
             WHERE step_id = ?5 AND life_id = ?6 AND revision = ?7 AND status = ?8",
            params![
                to_status,
                applied_revision,
                &now,
                &closed_at,
                &request.step_id,
                &request.life_id,
                request.expected_revision,
                &current.status,
            ],
        )
        .map_err(map_transition_error)?;
    if changed != 1 {
        return Err(LifeIntentError::revision_conflict());
    }
    insert_event(transaction, &event)?;

    let committed_event =
        load_event_by_id(transaction, &request.event_id)?.ok_or_else(LifeIntentError::database)?;
    let committed_step = load_step_for_transition(transaction, &request.life_id, &request.step_id)?;
    Ok(LifeIntentTransitionOutcome::Applied {
        event: committed_event,
        entity: committed_step,
    })
}

/// Performs one action-intent lifecycle transition inside a caller-owned
/// transaction. This helper never begins, commits, or rolls back the
/// transaction.
pub(super) fn transition_action_in_transaction(
    transaction: &Transaction<'_>,
    request: LifeActionTransitionRequest,
) -> Result<LifeIntentTransitionOutcome<LifeActionIntent>, LifeIntentError> {
    request.validate()?;
    let applied_revision = next_revision(request.expected_revision)?;
    let requested_to_status = request.kind.to_status();

    if let Some(event) = load_event_by_id(transaction, &request.event_id)? {
        if event_evidence_matches(
            &event,
            &request.life_id,
            ACTION_ENTITY_KIND,
            &request.action_id,
            requested_to_status,
            request.expected_revision,
            applied_revision,
        ) {
            let current =
                load_action_for_transition(transaction, &request.life_id, &request.action_id)?;
            return Ok(LifeIntentTransitionOutcome::Replayed { event, current });
        }
        return Err(LifeIntentError::life_intent_event_conflict());
    }

    let current = load_action_for_transition(transaction, &request.life_id, &request.action_id)?;
    if current.revision != request.expected_revision {
        return Err(LifeIntentError::revision_conflict());
    }
    let to_status = request
        .kind
        .target_status(&current.status)
        .ok_or_else(LifeIntentError::invalid_transition)?;
    let now = sqlite_authority_now(transaction)?;
    let closed_at = Some(now.clone());
    let event = build_event(LifeIntentEventBuild {
        event_id: &request.event_id,
        life_id: &request.life_id,
        target: LifeIntentEventTarget::Action(&request.action_id),
        from_status: &current.status,
        to_status,
        expected_revision: request.expected_revision,
        applied_revision,
        occurred_at: &now,
    });

    let changed = transaction
        .execute(
            "UPDATE life_action_intent
             SET status = ?1, revision = ?2, updated_at = ?3, closed_at = ?4
             WHERE action_id = ?5 AND life_id = ?6 AND revision = ?7 AND status = ?8",
            params![
                to_status,
                applied_revision,
                &now,
                &closed_at,
                &request.action_id,
                &request.life_id,
                request.expected_revision,
                &current.status,
            ],
        )
        .map_err(map_transition_error)?;
    if changed != 1 {
        return Err(LifeIntentError::revision_conflict());
    }
    insert_event(transaction, &event)?;

    let committed_event =
        load_event_by_id(transaction, &request.event_id)?.ok_or_else(LifeIntentError::database)?;
    let committed_action =
        load_action_for_transition(transaction, &request.life_id, &request.action_id)?;
    Ok(LifeIntentTransitionOutcome::Applied {
        event: committed_event,
        entity: committed_action,
    })
}

/// SQL literal quoting used only for fixed authority constants (status values
/// and creation kind), never for caller-controlled content.
fn quote(value: &str) -> String {
    format!("'{value}'")
}

fn load_goal(
    connection: &Connection,
    life_id: &str,
    goal_id: &str,
) -> Result<Option<LifeGoal>, LifeIntentError> {
    connection
        .query_row(
            &format!(
                "SELECT {LIFE_GOAL_COLUMNS} FROM life_goal WHERE goal_id = ?1 AND life_id = ?2"
            ),
            params![goal_id, life_id],
            read_goal,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())
}

fn load_plan(
    connection: &Connection,
    life_id: &str,
    plan_id: &str,
) -> Result<Option<LifePlan>, LifeIntentError> {
    connection
        .query_row(
            &format!(
                "SELECT {LIFE_PLAN_COLUMNS} FROM life_plan WHERE plan_id = ?1 AND life_id = ?2"
            ),
            params![plan_id, life_id],
            read_plan,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())
}

fn load_step(
    connection: &Connection,
    life_id: &str,
    step_id: &str,
) -> Result<Option<LifePlanStep>, LifeIntentError> {
    connection
        .query_row(
            &format!(
                "SELECT {LIFE_PLAN_STEP_COLUMNS} FROM life_plan_step WHERE step_id = ?1 AND life_id = ?2"
            ),
            params![step_id, life_id],
            read_step,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())
}

fn load_action(
    connection: &Connection,
    life_id: &str,
    action_id: &str,
) -> Result<Option<LifeActionIntent>, LifeIntentError> {
    connection
        .query_row(
            &format!(
                "SELECT {LIFE_ACTION_INTENT_COLUMNS} FROM life_action_intent WHERE action_id = ?1 AND life_id = ?2"
            ),
            params![action_id, life_id],
            read_action,
        )
        .optional()
        .map_err(|_| LifeIntentError::database())
}

fn list_goals_for_life(
    connection: &Connection,
    life_id: &str,
) -> Result<Vec<LifeGoal>, LifeIntentError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {LIFE_GOAL_COLUMNS} FROM life_goal
             WHERE life_id = ?1 ORDER BY created_at, goal_id"
        ))
        .map_err(|_| LifeIntentError::database())?;
    let rows = statement
        .query_map([life_id], read_goal)
        .map_err(|_| LifeIntentError::database())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| LifeIntentError::database())
}

fn list_plans_for_goal(
    connection: &Connection,
    life_id: &str,
    goal_id: &str,
) -> Result<Vec<LifePlan>, LifeIntentError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {LIFE_PLAN_COLUMNS} FROM life_plan
             WHERE life_id = ?1 AND goal_id = ?2 ORDER BY created_at, plan_id"
        ))
        .map_err(|_| LifeIntentError::database())?;
    let rows = statement
        .query_map(params![life_id, goal_id], read_plan)
        .map_err(|_| LifeIntentError::database())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| LifeIntentError::database())
}

fn list_steps_for_plan(
    connection: &Connection,
    life_id: &str,
    plan_id: &str,
) -> Result<Vec<LifePlanStep>, LifeIntentError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {LIFE_PLAN_STEP_COLUMNS} FROM life_plan_step
             WHERE life_id = ?1 AND plan_id = ?2 ORDER BY ordinal, step_id"
        ))
        .map_err(|_| LifeIntentError::database())?;
    let rows = statement
        .query_map(params![life_id, plan_id], read_step)
        .map_err(|_| LifeIntentError::database())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| LifeIntentError::database())
}

fn list_actions_for_step(
    connection: &Connection,
    life_id: &str,
    step_id: &str,
) -> Result<Vec<LifeActionIntent>, LifeIntentError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {LIFE_ACTION_INTENT_COLUMNS} FROM life_action_intent
             WHERE life_id = ?1 AND step_id = ?2 ORDER BY created_at, action_id"
        ))
        .map_err(|_| LifeIntentError::database())?;
    let rows = statement
        .query_map(params![life_id, step_id], read_action)
        .map_err(|_| LifeIntentError::database())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| LifeIntentError::database())
}

impl LifeIntentRepository for StorageService {
    fn create_goal(
        &self,
        request: LifeGoalCreateRequest,
    ) -> Result<LifeIntentCreateOutcome<LifeGoal>, LifeIntentError> {
        let mut state = self.state().map_err(|_| LifeIntentError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LifeIntentError::database())?;
        let outcome = create_goal_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| LifeIntentError::database())?;
        Ok(outcome)
    }

    fn find_goal(&self, life_id: &str, goal_id: &str) -> Result<Option<LifeGoal>, LifeIntentError> {
        validate_lookup_arguments(life_id, goal_id)?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        load_goal(&state.connection, life_id, goal_id)
    }

    fn list_goals(&self, life_id: &str) -> Result<Vec<LifeGoal>, LifeIntentError> {
        validate_list_arguments(life_id, None)?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        list_goals_for_life(&state.connection, life_id)
    }

    fn delete_goal(&self, life_id: &str, goal_id: &str) -> Result<bool, LifeIntentError> {
        validate_lookup_arguments(life_id, goal_id)?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        let deleted = state
            .connection
            .execute(
                "DELETE FROM life_goal WHERE goal_id = ?1 AND life_id = ?2",
                params![goal_id, life_id],
            )
            .map_err(|_| LifeIntentError::database())?;
        Ok(deleted > 0)
    }

    fn create_plan(
        &self,
        request: LifePlanCreateRequest,
    ) -> Result<LifeIntentCreateOutcome<LifePlan>, LifeIntentError> {
        let mut state = self.state().map_err(|_| LifeIntentError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LifeIntentError::database())?;
        let outcome = create_plan_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| LifeIntentError::database())?;
        Ok(outcome)
    }

    fn find_plan(&self, life_id: &str, plan_id: &str) -> Result<Option<LifePlan>, LifeIntentError> {
        validate_lookup_arguments(life_id, plan_id)?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        load_plan(&state.connection, life_id, plan_id)
    }

    fn list_plans(&self, life_id: &str, goal_id: &str) -> Result<Vec<LifePlan>, LifeIntentError> {
        validate_list_arguments(life_id, Some(goal_id))?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        list_plans_for_goal(&state.connection, life_id, goal_id)
    }

    fn delete_plan(&self, life_id: &str, plan_id: &str) -> Result<bool, LifeIntentError> {
        validate_lookup_arguments(life_id, plan_id)?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        let deleted = state
            .connection
            .execute(
                "DELETE FROM life_plan WHERE plan_id = ?1 AND life_id = ?2",
                params![plan_id, life_id],
            )
            .map_err(|_| LifeIntentError::database())?;
        Ok(deleted > 0)
    }

    fn create_step(
        &self,
        request: LifePlanStepCreateRequest,
    ) -> Result<LifeIntentCreateOutcome<LifePlanStep>, LifeIntentError> {
        let mut state = self.state().map_err(|_| LifeIntentError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LifeIntentError::database())?;
        let outcome = create_step_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| LifeIntentError::database())?;
        Ok(outcome)
    }

    fn find_step(
        &self,
        life_id: &str,
        step_id: &str,
    ) -> Result<Option<LifePlanStep>, LifeIntentError> {
        validate_lookup_arguments(life_id, step_id)?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        load_step(&state.connection, life_id, step_id)
    }

    fn list_steps(
        &self,
        life_id: &str,
        plan_id: &str,
    ) -> Result<Vec<LifePlanStep>, LifeIntentError> {
        validate_list_arguments(life_id, Some(plan_id))?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        list_steps_for_plan(&state.connection, life_id, plan_id)
    }

    fn delete_step(&self, life_id: &str, step_id: &str) -> Result<bool, LifeIntentError> {
        validate_lookup_arguments(life_id, step_id)?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        let deleted = state
            .connection
            .execute(
                "DELETE FROM life_plan_step WHERE step_id = ?1 AND life_id = ?2",
                params![step_id, life_id],
            )
            .map_err(|_| LifeIntentError::database())?;
        Ok(deleted > 0)
    }

    fn create_action(
        &self,
        request: LifeActionIntentCreateRequest,
    ) -> Result<LifeIntentCreateOutcome<LifeActionIntent>, LifeIntentError> {
        let mut state = self.state().map_err(|_| LifeIntentError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LifeIntentError::database())?;
        let outcome = create_action_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| LifeIntentError::database())?;
        Ok(outcome)
    }

    fn find_action(
        &self,
        life_id: &str,
        action_id: &str,
    ) -> Result<Option<LifeActionIntent>, LifeIntentError> {
        validate_lookup_arguments(life_id, action_id)?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        load_action(&state.connection, life_id, action_id)
    }

    fn list_actions(
        &self,
        life_id: &str,
        step_id: &str,
    ) -> Result<Vec<LifeActionIntent>, LifeIntentError> {
        validate_list_arguments(life_id, Some(step_id))?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        list_actions_for_step(&state.connection, life_id, step_id)
    }

    fn delete_action(&self, life_id: &str, action_id: &str) -> Result<bool, LifeIntentError> {
        validate_lookup_arguments(life_id, action_id)?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        let deleted = state
            .connection
            .execute(
                "DELETE FROM life_action_intent WHERE action_id = ?1 AND life_id = ?2",
                params![action_id, life_id],
            )
            .map_err(|_| LifeIntentError::database())?;
        Ok(deleted > 0)
    }

    fn transition_goal(
        &self,
        request: LifeGoalTransitionRequest,
    ) -> Result<LifeIntentTransitionOutcome<LifeGoal>, LifeIntentError> {
        let mut state = self.state().map_err(|_| LifeIntentError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LifeIntentError::database())?;
        let outcome = transition_goal_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| LifeIntentError::database())?;
        Ok(outcome)
    }

    fn transition_plan(
        &self,
        request: LifePlanTransitionRequest,
    ) -> Result<LifeIntentTransitionOutcome<LifePlan>, LifeIntentError> {
        let mut state = self.state().map_err(|_| LifeIntentError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LifeIntentError::database())?;
        let outcome = transition_plan_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| LifeIntentError::database())?;
        Ok(outcome)
    }

    fn transition_step(
        &self,
        request: LifeStepTransitionRequest,
    ) -> Result<LifeIntentTransitionOutcome<LifePlanStep>, LifeIntentError> {
        let mut state = self.state().map_err(|_| LifeIntentError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LifeIntentError::database())?;
        let outcome = transition_step_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| LifeIntentError::database())?;
        Ok(outcome)
    }

    fn transition_action(
        &self,
        request: LifeActionTransitionRequest,
    ) -> Result<LifeIntentTransitionOutcome<LifeActionIntent>, LifeIntentError> {
        let mut state = self.state().map_err(|_| LifeIntentError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| LifeIntentError::database())?;
        let outcome = transition_action_in_transaction(&transaction, request)?;
        transaction
            .commit()
            .map_err(|_| LifeIntentError::database())?;
        Ok(outcome)
    }

    fn find_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeIntentEvent>, LifeIntentError> {
        validate_event_lookup_arguments(life_id, event_id)?;
        let state = self.state().map_err(|_| LifeIntentError::database())?;
        state
            .connection
            .query_row(
                &format!(
                    "SELECT {LIFE_INTENT_EVENT_COLUMNS} FROM life_intent_event
                     WHERE life_id = ?1 AND event_id = ?2"
                ),
                params![life_id, event_id],
                read_event,
            )
            .optional()
            .map_err(|_| LifeIntentError::database())
    }
}

type GoalCreate = for<'a> fn(
    &'a StorageService,
    LifeGoalCreateRequest,
) -> Result<LifeIntentCreateOutcome<LifeGoal>, LifeIntentError>;
type GoalLookup =
    for<'a> fn(&'a StorageService, &'a str, &'a str) -> Result<Option<LifeGoal>, LifeIntentError>;
type GoalDelete = for<'a> fn(&'a StorageService, &'a str, &'a str) -> Result<bool, LifeIntentError>;
type GoalTransition = for<'a> fn(
    &'a StorageService,
    LifeGoalTransitionRequest,
) -> Result<LifeIntentTransitionOutcome<LifeGoal>, LifeIntentError>;
type PlanTransition = for<'a> fn(
    &'a StorageService,
    LifePlanTransitionRequest,
) -> Result<LifeIntentTransitionOutcome<LifePlan>, LifeIntentError>;
type StepTransition =
    for<'a> fn(
        &'a StorageService,
        LifeStepTransitionRequest,
    ) -> Result<LifeIntentTransitionOutcome<LifePlanStep>, LifeIntentError>;
type ActionTransition =
    for<'a> fn(
        &'a StorageService,
        LifeActionTransitionRequest,
    ) -> Result<LifeIntentTransitionOutcome<LifeActionIntent>, LifeIntentError>;
type EventLookup = for<'a> fn(
    &'a StorageService,
    &'a str,
    &'a str,
) -> Result<Option<LifeIntentEvent>, LifeIntentError>;

const _: GoalCreate = <StorageService as LifeIntentRepository>::create_goal;
const _: GoalLookup = <StorageService as LifeIntentRepository>::find_goal;
const _: GoalDelete = <StorageService as LifeIntentRepository>::delete_goal;
const _: GoalTransition = <StorageService as LifeIntentRepository>::transition_goal;
const _: PlanTransition = <StorageService as LifeIntentRepository>::transition_plan;
const _: StepTransition = <StorageService as LifeIntentRepository>::transition_step;
const _: ActionTransition = <StorageService as LifeIntentRepository>::transition_action;
const _: EventLookup = <StorageService as LifeIntentRepository>::find_event;

/// Exact normalized validation of every Schema22 D14 object. Only existence is
/// never enough: the stored DDL must match the migration SQL byte-for-byte
/// (whitespace/quote-insensitive), so a weakened CHECK, FK, or trigger body
/// fails closed without repair.
pub(super) fn validate_schema_objects(connection: &Connection) -> Result<(), super::StorageError> {
    for (object_kind, object_name, expected_sql) in [
        ("table", "life_goal", CREATE_LIFE_GOAL_TABLE_SQL),
        ("table", "life_plan", CREATE_LIFE_PLAN_TABLE_SQL),
        ("table", "life_plan_step", CREATE_LIFE_PLAN_STEP_TABLE_SQL),
        (
            "table",
            "life_action_intent",
            CREATE_LIFE_ACTION_INTENT_TABLE_SQL,
        ),
        (
            "table",
            "life_intent_event",
            CREATE_LIFE_INTENT_EVENT_TABLE_SQL,
        ),
        (
            "trigger",
            "life_goal_immutable_guard",
            CREATE_LIFE_GOAL_IMMUTABLE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "life_plan_immutable_guard",
            CREATE_LIFE_PLAN_IMMUTABLE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "life_plan_step_immutable_guard",
            CREATE_LIFE_PLAN_STEP_IMMUTABLE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "life_action_intent_immutable_guard",
            CREATE_LIFE_ACTION_INTENT_IMMUTABLE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "life_intent_event_immutable_guard",
            CREATE_LIFE_INTENT_EVENT_IMMUTABLE_TRIGGER_SQL,
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

    // Independent FK checks: every parent binding must reference the exact
    // (parent, from -> to) column pair and cascade on delete. The composite
    // same-life bindings appear as one FK row per column with a shared id.
    for (child_table, parent_table, column_pairs) in [
        ("life_goal", "life_identity", &[("life_id", "id")][..]),
        (
            "life_plan",
            "life_goal",
            &[("goal_id", "goal_id"), ("life_id", "life_id")][..],
        ),
        ("life_plan", "life_identity", &[("life_id", "id")][..]),
        (
            "life_plan_step",
            "life_plan",
            &[("plan_id", "plan_id"), ("life_id", "life_id")][..],
        ),
        ("life_plan_step", "life_identity", &[("life_id", "id")][..]),
        (
            "life_action_intent",
            "life_plan_step",
            &[("step_id", "step_id"), ("life_id", "life_id")][..],
        ),
        (
            "life_action_intent",
            "life_identity",
            &[("life_id", "id")][..],
        ),
        (
            "life_intent_event",
            "life_goal",
            &[("goal_id", "goal_id"), ("life_id", "life_id")][..],
        ),
        (
            "life_intent_event",
            "life_plan",
            &[("plan_id", "plan_id"), ("life_id", "life_id")][..],
        ),
        (
            "life_intent_event",
            "life_plan_step",
            &[("step_id", "step_id"), ("life_id", "life_id")][..],
        ),
        (
            "life_intent_event",
            "life_action_intent",
            &[("action_id", "action_id"), ("life_id", "life_id")][..],
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

    // The parent-side UNIQUE keys required by every same-life composite FK are
    // proven by the exact DDL comparison above (UNIQUE goal/life, plan/life,
    // step/life, plan/ordinal, action/life); an extra pragma-level probe of a
    // live foreign_key_check on a manufactured parent confirms the composite
    // bindings are enforceable by SQLite itself.
    connection
        .execute_batch(
            "CREATE TABLE _life_intent_fk_probe (
                 goal_id TEXT NOT NULL,
                 life_id TEXT NOT NULL,
                 plan_id TEXT NOT NULL,
                 step_id TEXT NOT NULL,
                 action_id TEXT NOT NULL,
                 FOREIGN KEY (goal_id, life_id)
                     REFERENCES life_goal(goal_id, life_id) ON DELETE CASCADE,
                 FOREIGN KEY (plan_id, life_id)
                     REFERENCES life_plan(plan_id, life_id) ON DELETE CASCADE,
                 FOREIGN KEY (step_id, life_id)
                     REFERENCES life_plan_step(step_id, life_id) ON DELETE CASCADE,
                 FOREIGN KEY (action_id, life_id)
                     REFERENCES life_action_intent(action_id, life_id) ON DELETE CASCADE
             );
             DROP TABLE _life_intent_fk_probe;",
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
const _: for<'a> fn(
    &'a Transaction<'a>,
    LifeGoalCreateRequest,
) -> Result<LifeIntentCreateOutcome<LifeGoal>, LifeIntentError> = create_goal_in_transaction;
const _: fn(&LifeGoalCreateRequest) -> Result<(), LifeIntentError> = validate_goal_request;
const _: fn(&LifePlanCreateRequest) -> Result<(), LifeIntentError> = validate_plan_request;
const _: fn(&LifePlanStepCreateRequest) -> Result<(), LifeIntentError> = validate_step_request;
const _: fn(&LifeActionIntentCreateRequest) -> Result<(), LifeIntentError> =
    validate_action_request;

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{Arc, Barrier},
        thread,
    };

    use rusqlite::params;
    use tempfile::TempDir;

    use super::*;
    use crate::life_intent::{
        LifeActionTransitionKind, LifeActionTransitionRequest, LifeGoalTransitionKind,
        LifeGoalTransitionRequest, LifeIntentErrorCode, LifeIntentTransitionOutcome,
        LifePlanTransitionKind, LifePlanTransitionRequest, LifeStepTransitionKind,
        LifeStepTransitionRequest, EXECUTION_CLASS_AGENT_TASK_PROPOSAL,
        EXECUTION_CLASS_INTERNAL_INTENT, EXECUTION_CLASS_TOOL_OPERATION_PROPOSAL,
    };

    struct Fixture {
        _root: TempDir,
        storage: StorageService,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let default_root = root.path().join("default");
            fs::create_dir_all(&default_root).unwrap();
            let storage = StorageService::initialize_with_roots(default_root, None).unwrap();
            storage
                .save_persona(crate::storage::PersonaTemplateRecord {
                    id: "intent-persona".into(),
                    name: "Intent Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            storage
                .save_life(crate::storage::LifeIdentityRecord {
                    id: "life-a".into(),
                    name: "Life A".into(),
                    created_at: "2026-08-27T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "body-a".into(),
                    persona_id: "intent-persona".into(),
                    persona_version: 1,
                })
                .unwrap();
            storage
                .save_life(crate::storage::LifeIdentityRecord {
                    id: "life-b".into(),
                    name: "Life B".into(),
                    created_at: "2026-08-27T00:00:01.000Z".into(),
                    version: 1,
                    body_id: "body-b".into(),
                    persona_id: "intent-persona".into(),
                    persona_version: 1,
                })
                .unwrap();
            Self {
                _root: root,
                storage,
            }
        }

        fn goal_request(&self, goal_id: &str) -> LifeGoalCreateRequest {
            LifeGoalCreateRequest {
                goal_id: goal_id.into(),
                life_id: "life-a".into(),
                title: "Become fluent in Mandarin".into(),
                objective: "Hold a natural 30-minute conversation by year end.".into(),
            }
        }

        fn plan_request(&self, plan_id: &str, goal_id: &str) -> LifePlanCreateRequest {
            LifePlanCreateRequest {
                plan_id: plan_id.into(),
                life_id: "life-a".into(),
                goal_id: goal_id.into(),
                title: "Three-month Mandarin study plan".into(),
            }
        }

        fn step_request(
            &self,
            step_id: &str,
            plan_id: &str,
            ordinal: i64,
        ) -> LifePlanStepCreateRequest {
            LifePlanStepCreateRequest {
                step_id: step_id.into(),
                life_id: "life-a".into(),
                plan_id: plan_id.into(),
                ordinal,
                summary: "Study HSK1 vocabulary for thirty minutes each day.".into(),
            }
        }

        fn action_request(
            &self,
            action_id: &str,
            step_id: &str,
            execution_class: &str,
        ) -> LifeActionIntentCreateRequest {
            LifeActionIntentCreateRequest {
                action_id: action_id.into(),
                life_id: "life-a".into(),
                step_id: step_id.into(),
                execution_class: execution_class.into(),
                summary: "Proposal to review today's vocabulary list.".into(),
            }
        }
    }

    fn goal_transition(
        event_id: &str,
        life_id: &str,
        goal_id: &str,
        expected_revision: i64,
        kind: LifeGoalTransitionKind,
    ) -> LifeGoalTransitionRequest {
        LifeGoalTransitionRequest {
            event_id: event_id.into(),
            life_id: life_id.into(),
            goal_id: goal_id.into(),
            expected_revision,
            kind,
        }
    }

    fn plan_transition(
        event_id: &str,
        life_id: &str,
        plan_id: &str,
        expected_revision: i64,
        kind: LifePlanTransitionKind,
    ) -> LifePlanTransitionRequest {
        LifePlanTransitionRequest {
            event_id: event_id.into(),
            life_id: life_id.into(),
            plan_id: plan_id.into(),
            expected_revision,
            kind,
        }
    }

    fn step_transition(
        event_id: &str,
        life_id: &str,
        step_id: &str,
        expected_revision: i64,
        kind: LifeStepTransitionKind,
    ) -> LifeStepTransitionRequest {
        LifeStepTransitionRequest {
            event_id: event_id.into(),
            life_id: life_id.into(),
            step_id: step_id.into(),
            expected_revision,
            kind,
        }
    }

    fn action_transition(
        event_id: &str,
        life_id: &str,
        action_id: &str,
        expected_revision: i64,
        kind: LifeActionTransitionKind,
    ) -> LifeActionTransitionRequest {
        LifeActionTransitionRequest {
            event_id: event_id.into(),
            life_id: life_id.into(),
            action_id: action_id.into(),
            expected_revision,
            kind,
        }
    }

    struct D14RowCounts {
        goals: i64,
        plans: i64,
        steps: i64,
        actions: i64,
        events: i64,
    }

    fn count_rows(connection: &Connection) -> D14RowCounts {
        fn single(connection: &Connection, table: &str) -> i64 {
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        }
        D14RowCounts {
            goals: single(connection, "life_goal"),
            plans: single(connection, "life_plan"),
            steps: single(connection, "life_plan_step"),
            actions: single(connection, "life_action_intent"),
            events: single(connection, "life_intent_event"),
        }
    }

    fn error_code(error: LifeIntentError) -> LifeIntentErrorCode {
        error.code
    }

    /// Direct authorized INSERT of one lifecycle-event fixture row (B1 never
    /// writes these itself; D14-B2 owns transition mutation).
    fn insert_event_fixture(
        connection: &Connection,
        event_id: &str,
        life_id: &str,
        entity_kind: &str,
        entity_id: &str,
        from_status: &str,
        to_status: &str,
    ) {
        let (goal_id, plan_id, step_id, action_id) = match entity_kind {
            "goal" => (Some(entity_id), None, None, None),
            "plan" => (None, Some(entity_id), None, None),
            "step" => (None, None, Some(entity_id), None),
            "action" => (None, None, None, Some(entity_id)),
            other => panic!("unexpected entity kind {other}"),
        };
        connection
            .execute(
                "INSERT INTO life_intent_event
                     (event_id, life_id, entity_kind, goal_id, plan_id, step_id, action_id,
                      from_status, to_status, expected_revision, applied_revision,
                      actor_kind, occurred_at, event_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, 2, 'user_explicit',
                         '2026-08-27T00:00:00.000Z', 1)",
                params![
                    event_id,
                    life_id,
                    entity_kind,
                    goal_id,
                    plan_id,
                    step_id,
                    action_id,
                    from_status,
                    to_status
                ],
            )
            .unwrap();
    }

    #[test]
    fn frozen_v1_vocabulary_and_authority_versions_are_pinned() {
        use crate::life_intent as authority;
        assert_eq!(authority::CREATED_BY_KIND_USER_EXPLICIT, "user_explicit");
        assert_eq!(authority::ACTOR_KIND_USER_EXPLICIT, "user_explicit");
        assert_eq!(authority::GOAL_VERSION, 1);
        assert_eq!(authority::PLAN_VERSION, 1);
        assert_eq!(authority::STEP_VERSION, 1);
        assert_eq!(authority::ACTION_VERSION, 1);
        assert_eq!(authority::EVENT_VERSION, 1);
        assert_eq!(authority::GOAL_STATUS_ACTIVE, "active");
        assert_eq!(authority::GOAL_STATUS_COMPLETED, "completed");
        assert_eq!(authority::GOAL_STATUS_CANCELLED, "cancelled");
        assert_eq!(authority::PLAN_STATUS_DRAFT, "draft");
        assert_eq!(authority::PLAN_STATUS_ACTIVE, "active");
        assert_eq!(authority::PLAN_STATUS_COMPLETED, "completed");
        assert_eq!(authority::PLAN_STATUS_CANCELLED, "cancelled");
        assert_eq!(authority::STEP_STATUS_PENDING, "pending");
        assert_eq!(authority::STEP_STATUS_COMPLETED, "completed");
        assert_eq!(authority::STEP_STATUS_SKIPPED, "skipped");
        assert_eq!(authority::STEP_STATUS_CANCELLED, "cancelled");
        assert_eq!(authority::ACTION_STATUS_PROPOSED, "proposed");
        assert_eq!(authority::ACTION_STATUS_DISMISSED, "dismissed");
        assert_eq!(
            authority::EXECUTION_CLASS_INTERNAL_INTENT,
            "internal_intent"
        );
        assert_eq!(
            authority::EXECUTION_CLASS_AGENT_TASK_PROPOSAL,
            "agent_task_proposal"
        );
        assert_eq!(
            authority::EXECUTION_CLASS_TOOL_OPERATION_PROPOSAL,
            "tool_operation_proposal"
        );
        assert_eq!(authority::GOAL_ENTITY_KIND, "goal");
        assert_eq!(authority::PLAN_ENTITY_KIND, "plan");
        assert_eq!(authority::STEP_ENTITY_KIND, "step");
        assert_eq!(authority::ACTION_ENTITY_KIND, "action");
    }

    #[test]
    fn goal_create_and_find_round_trip_is_applied_with_authority_fields() {
        let fixture = Fixture::new();
        let outcome = fixture
            .storage
            .create_goal(fixture.goal_request("goal-1"))
            .unwrap();
        let LifeIntentCreateOutcome::Applied(goal) = outcome else {
            panic!("expected Applied");
        };
        assert_eq!(goal.goal_id, "goal-1");
        assert_eq!(goal.life_id, "life-a");
        assert_eq!(goal.status, "active");
        assert_eq!(goal.revision, 1);
        assert_eq!(goal.created_by_kind, "user_explicit");
        assert_eq!(goal.goal_version, 1);
        assert!(goal.closed_at.is_none());
        assert!(!goal.created_at.is_empty());
        assert_eq!(goal.created_at, goal.updated_at);
        let found = fixture
            .storage
            .find_goal("life-a", "goal-1")
            .unwrap()
            .expect("goal must be readable");
        assert_eq!(found, goal);
        let listed = fixture.storage.list_goals("life-a").unwrap();
        assert_eq!(listed, vec![goal.clone()]);
        assert!(fixture.storage.list_goals("life-b").unwrap().is_empty());
        // The authority timestamp is a full-fidelity SQLite UTC string.
        assert!(goal.created_at.starts_with("20"));
        assert!(goal.created_at.ends_with('Z'));
    }

    #[test]
    fn goal_exact_create_replay_is_replayed_without_duplicate() {
        let fixture = Fixture::new();
        let request = fixture.goal_request("goal-replay");
        let first = fixture.storage.create_goal(request.clone()).unwrap();
        let second = fixture.storage.create_goal(request).unwrap();
        assert!(matches!(first, LifeIntentCreateOutcome::Applied(_)));
        assert!(matches!(second, LifeIntentCreateOutcome::Replayed(_)));
        let state = fixture.storage.state().unwrap();
        assert_eq!(count_rows(&state.connection).goals, 1);
    }

    #[test]
    fn goal_same_id_with_different_evidence_is_an_entity_conflict() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-conflict"))
            .unwrap();
        let mut conflicting = fixture.goal_request("goal-conflict");
        conflicting.title = "A different title".into();
        let error = fixture.storage.create_goal(conflicting).unwrap_err();
        assert_eq!(error_code(error), LifeIntentErrorCode::EntityConflict);
        let state = fixture.storage.state().unwrap();
        assert_eq!(count_rows(&state.connection).goals, 1);
    }

    #[test]
    fn goal_replay_does_not_compare_authority_timestamps() {
        let fixture = Fixture::new();
        let request = fixture.goal_request("goal-time");
        let state = fixture.storage.state().unwrap();
        // A row inserted directly with a fabricated, stale SQLite timestamp
        // must still replay against the same caller-controlled evidence.
        state
            .connection
            .execute(
                "INSERT INTO life_goal
                     (goal_id, life_id, title, objective, status, revision,
                      created_by_kind, created_at, updated_at, closed_at, goal_version)
                 VALUES (?1, 'life-a', ?2, ?3, 'active', 1, 'user_explicit',
                         '2020-01-01T00:00:00.000Z', '2020-01-01T00:00:00.000Z', NULL, 1)",
                params![&request.goal_id, &request.title, &request.objective],
            )
            .unwrap();
        drop(state);
        // Replay equality compares only caller-controlled evidence, never the
        // SQLite authority timestamps.
        let outcome = fixture.storage.create_goal(request).unwrap();
        let LifeIntentCreateOutcome::Replayed(goal) = outcome else {
            panic!("expected Replayed");
        };
        assert_eq!(goal.created_at, "2020-01-01T00:00:00.000Z");
    }

    #[test]
    fn missing_life_is_rejected_for_every_create() {
        let fixture = Fixture::new();
        let mut goal = fixture.goal_request("goal-nolife");
        goal.life_id = "no-such-life".into();
        assert_eq!(
            error_code(fixture.storage.create_goal(goal).unwrap_err()),
            LifeIntentErrorCode::LifeNotFound
        );
        let mut plan = fixture.plan_request("plan-nolife", "goal-x");
        plan.life_id = "no-such-life".into();
        assert_eq!(
            error_code(fixture.storage.create_plan(plan).unwrap_err()),
            LifeIntentErrorCode::LifeNotFound
        );
        let mut step = fixture.step_request("step-nolife", "plan-x", 1);
        step.life_id = "no-such-life".into();
        assert_eq!(
            error_code(fixture.storage.create_step(step).unwrap_err()),
            LifeIntentErrorCode::LifeNotFound
        );
        let mut action =
            fixture.action_request("action-nolife", "step-x", EXECUTION_CLASS_INTERNAL_INTENT);
        action.life_id = "no-such-life".into();
        assert_eq!(
            error_code(fixture.storage.create_action(action).unwrap_err()),
            LifeIntentErrorCode::LifeNotFound
        );
    }

    #[test]
    fn plan_binds_to_the_same_goal_with_valid_parent() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-p1"))
            .unwrap();
        let outcome = fixture
            .storage
            .create_plan(fixture.plan_request("plan-p1", "goal-p1"))
            .unwrap();
        let LifeIntentCreateOutcome::Applied(plan) = outcome else {
            panic!("expected Applied");
        };
        assert_eq!(plan.plan_id, "plan-p1");
        assert_eq!(plan.life_id, "life-a");
        assert_eq!(plan.goal_id, "goal-p1");
        assert_eq!(plan.status, "draft");
        assert_eq!(plan.revision, 1);
        assert_eq!(plan.plan_version, 1);
        assert!(plan.closed_at.is_none());
        assert_eq!(
            fixture.storage.find_plan("life-a", "plan-p1").unwrap(),
            Some(plan.clone())
        );
        assert_eq!(
            fixture.storage.list_plans("life-a", "goal-p1").unwrap(),
            vec![plan]
        );
        assert!(fixture
            .storage
            .list_plans("life-a", "missing-goal")
            .unwrap()
            .is_empty());
        // No plan may exist without the goal: the parent is mandatory.
        let error = fixture
            .storage
            .create_plan(fixture.plan_request("plan-nogoal", "missing-goal"))
            .unwrap_err();
        assert_eq!(error_code(error), LifeIntentErrorCode::ParentNotFound);
    }

    #[test]
    fn cross_life_goal_plan_binding_is_rejected_without_repair() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-cross"))
            .unwrap();
        // Same goal_id exists under life-a; the proposed plan names life-b.
        let mut request = fixture.plan_request("plan-cross", "goal-cross");
        request.life_id = "life-b".into();
        let error = fixture.storage.create_plan(request).unwrap_err();
        assert_eq!(error_code(error), LifeIntentErrorCode::ParentLifeMismatch);
        // The caller's life_id is never rewritten to match the goal.
        let state = fixture.storage.state().unwrap();
        let plan_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM life_plan", [], |row| row.get(0))
            .unwrap();
        assert_eq!(plan_count, 0);
    }

    #[test]
    fn step_create_and_ordinal_uniqueness_within_one_plan() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-s1"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-s1", "goal-s1"))
            .unwrap();
        let first = fixture
            .storage
            .create_step(fixture.step_request("step-s1", "plan-s1", 1))
            .unwrap();
        let LifeIntentCreateOutcome::Applied(step) = first else {
            panic!("expected Applied");
        };
        assert_eq!(step.status, "pending");
        assert_eq!(step.revision, 1);
        assert_eq!(step.step_version, 1);
        assert_eq!(step.ordinal, 1);
        assert!(step.closed_at.is_none());
        let second = fixture
            .storage
            .create_step(fixture.step_request("step-s2", "plan-s1", 2))
            .unwrap();
        assert!(matches!(second, LifeIntentCreateOutcome::Applied(_)));
        assert_eq!(
            fixture
                .storage
                .list_steps("life-a", "plan-s1")
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            fixture
                .storage
                .find_step("life-a", "step-s1")
                .unwrap()
                .expect("step must be readable")
                .ordinal,
            1
        );
        assert!(fixture
            .storage
            .find_step("life-b", "step-s1")
            .unwrap()
            .is_none());
        // Duplicate ordinal under the SAME plan is rejected fail-closed.
        let duplicate = fixture
            .storage
            .create_step(fixture.step_request("step-s3", "plan-s1", 1));
        assert_eq!(
            error_code(duplicate.unwrap_err()),
            LifeIntentErrorCode::EntityConflict
        );
    }

    #[test]
    fn same_ordinal_under_different_plans_is_allowed() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-s4"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-s4a", "goal-s4"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-s4b", "goal-s4"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-s4a", "plan-s4a", 1))
            .unwrap();
        let result = fixture
            .storage
            .create_step(fixture.step_request("step-s4b", "plan-s4b", 1))
            .unwrap();
        assert!(matches!(result, LifeIntentCreateOutcome::Applied(_)));
    }

    #[test]
    fn step_parent_binding_is_same_life_and_missing_parent_is_rejected() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-s5"))
            .unwrap();
        // Plan exists under life-a; the step names life-b.
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-s5", "goal-s5"))
            .unwrap();
        let mut request = fixture.step_request("step-s5", "plan-s5", 1);
        request.life_id = "life-b".into();
        let error = fixture.storage.create_step(request).unwrap_err();
        assert_eq!(error_code(error), LifeIntentErrorCode::ParentLifeMismatch);
        let error = fixture
            .storage
            .create_step(fixture.step_request("step-s6", "missing-plan", 1))
            .unwrap_err();
        assert_eq!(error_code(error), LifeIntentErrorCode::ParentNotFound);
    }

    #[test]
    fn action_intent_supports_all_three_execution_classes() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-a1"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-a1", "goal-a1"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-a1", "plan-a1", 1))
            .unwrap();
        for (action_id, execution_class) in [
            ("action-internal", EXECUTION_CLASS_INTERNAL_INTENT),
            ("action-agent", EXECUTION_CLASS_AGENT_TASK_PROPOSAL),
            ("action-tool", EXECUTION_CLASS_TOOL_OPERATION_PROPOSAL),
        ] {
            let outcome = fixture
                .storage
                .create_action(fixture.action_request(action_id, "step-a1", execution_class))
                .unwrap();
            let LifeIntentCreateOutcome::Applied(action) = outcome else {
                panic!("expected Applied for {action_id}");
            };
            assert_eq!(action.execution_class, execution_class);
            assert_eq!(action.status, "proposed");
            assert_eq!(action.revision, 1);
            assert_eq!(action.action_version, 1);
            assert!(action.closed_at.is_none());
        }
        assert_eq!(
            fixture
                .storage
                .list_actions("life-a", "step-a1")
                .unwrap()
                .len(),
            3
        );
        // Unsupported production execution classes are rejected.
        let bad = fixture.storage.create_action(fixture.action_request(
            "action-bad",
            "step-a1",
            "shell_execute",
        ));
        assert_eq!(
            error_code(bad.unwrap_err()),
            LifeIntentErrorCode::InvalidArgument
        );
    }

    #[test]
    fn action_parent_binding_is_same_life_and_missing_parent_is_rejected() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-a2"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-a2", "goal-a2"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-a2", "plan-a2", 1))
            .unwrap();
        let mut request =
            fixture.action_request("action-a2", "step-a2", EXECUTION_CLASS_INTERNAL_INTENT);
        request.life_id = "life-b".into();
        let error = fixture.storage.create_action(request).unwrap_err();
        assert_eq!(error_code(error), LifeIntentErrorCode::ParentLifeMismatch);
        let error = fixture
            .storage
            .create_action(fixture.action_request(
                "action-a3",
                "missing-step",
                EXECUTION_CLASS_INTERNAL_INTENT,
            ))
            .unwrap_err();
        assert_eq!(error_code(error), LifeIntentErrorCode::ParentNotFound);
    }

    #[test]
    fn action_schema_carries_no_executable_payload_or_permission_fields() {
        let fixture = Fixture::new();
        let state = fixture.storage.state().unwrap();
        let connection = &state.connection;
        let columns: Vec<String> = connection
            .prepare("SELECT name FROM pragma_table_info('life_action_intent')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        let forbidden_columns = [
            "command",
            "shell",
            "argv",
            "executable",
            "url",
            "credential",
            "secret",
            "api_key",
            "capability",
            "token",
            "permission",
            "grant",
            "payload",
            "json",
            "codex",
            "tool_payload",
        ];
        for column in &columns {
            assert!(
                !forbidden_columns.contains(&column.as_str()),
                "schema must not carry executable/permission field {column}"
            );
        }
        let table_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='life_action_intent'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
            .to_ascii_lowercase();
        for token in forbidden_columns {
            assert!(
                !table_sql.contains(token),
                "life_action_intent DDL must not mention {token}"
            );
        }
        drop(state);
        // The domain record deliberately derives no Serialize, so no serde
        // escape hatch can ever carry it as an arbitrary JSON payload.
    }

    #[test]
    fn text_and_id_bounds_fail_closed() {
        let fixture = Fixture::new();
        let mut id_too_long = fixture.goal_request(&"x".repeat(129));
        id_too_long.life_id = "life-a".into();
        assert_eq!(
            error_code(fixture.storage.create_goal(id_too_long).unwrap_err()),
            LifeIntentErrorCode::InvalidArgument
        );
        let mut empty_title = fixture.goal_request("goal-bounds");
        empty_title.title = "   ".into();
        assert_eq!(
            error_code(fixture.storage.create_goal(empty_title).unwrap_err()),
            LifeIntentErrorCode::InvalidArgument
        );
        let mut long_objective = fixture.goal_request("goal-bounds2");
        long_objective.objective = "y".repeat(4097);
        assert_eq!(
            error_code(fixture.storage.create_goal(long_objective).unwrap_err()),
            LifeIntentErrorCode::InvalidArgument
        );
        let mut long_title = fixture.plan_request("plan-bounds", "goal-x");
        long_title.title = "z".repeat(257);
        assert_eq!(
            error_code(fixture.storage.create_plan(long_title).unwrap_err()),
            LifeIntentErrorCode::InvalidArgument
        );
        let mut zero_ordinal = fixture.step_request("step-bounds", "plan-x", 0);
        zero_ordinal.ordinal = 0;
        assert_eq!(
            error_code(fixture.storage.create_step(zero_ordinal).unwrap_err()),
            LifeIntentErrorCode::InvalidArgument
        );
        let mut empty_summary =
            fixture.action_request("action-bounds", "step-x", EXECUTION_CLASS_INTERNAL_INTENT);
        empty_summary.summary = "  ".into();
        assert_eq!(
            error_code(fixture.storage.create_action(empty_summary).unwrap_err()),
            LifeIntentErrorCode::InvalidArgument
        );
    }

    #[test]
    fn unicode_character_bounds_follow_sqlite_character_counts() {
        // Frozen D14 bounds are CHARACTER limits. Each CJK scalar below is 3
        // UTF-8 bytes, so a byte-counting validator would reject the max-bounds
        // rows this test proves are accepted by both Rust and SQLite.
        let fixture = Fixture::new();
        let boundary_character = "目";

        // Entity ID: 128 characters accepted (real SQLite create), 129 rejected.
        let max_id = boundary_character.repeat(128);
        assert_eq!(
            max_id.len(),
            384,
            "the 128-character ID must be 384 UTF-8 bytes"
        );
        let outcome = fixture
            .storage
            .create_goal(LifeGoalCreateRequest {
                goal_id: max_id.clone(),
                life_id: "life-a".into(),
                title: boundary_character.repeat(8),
                objective: boundary_character.repeat(16),
            })
            .unwrap();
        assert!(matches!(outcome, LifeIntentCreateOutcome::Applied(_)));
        assert_eq!(
            fixture
                .storage
                .find_goal("life-a", &max_id)
                .unwrap()
                .expect("the 128-character goal must be readable")
                .goal_id,
            max_id
        );
        let over_id = boundary_character.repeat(129);
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_goal(LifeGoalCreateRequest {
                        goal_id: over_id,
                        life_id: "life-a".into(),
                        title: "t".into(),
                        objective: "o".into(),
                    })
                    .unwrap_err()
            ),
            LifeIntentErrorCode::InvalidArgument
        );

        // Title: 256 characters accepted, 257 rejected (real SQLite create at
        // the maximum so Rust and SQLite agree on the boundary).
        let max_title = boundary_character.repeat(256);
        assert_eq!(
            max_title.len(),
            768,
            "the 256-character title must be 768 UTF-8 bytes"
        );
        let title_outcome = fixture
            .storage
            .create_goal(LifeGoalCreateRequest {
                goal_id: "goal-unicode-title".into(),
                life_id: "life-a".into(),
                title: max_title.clone(),
                objective: "unicode title boundary".into(),
            })
            .unwrap();
        assert!(matches!(title_outcome, LifeIntentCreateOutcome::Applied(_)));
        assert_eq!(
            fixture
                .storage
                .find_goal("life-a", "goal-unicode-title")
                .unwrap()
                .unwrap()
                .title,
            max_title
        );
        let over_title = boundary_character.repeat(257);
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_goal(LifeGoalCreateRequest {
                        goal_id: "goal-unicode-title-over".into(),
                        life_id: "life-a".into(),
                        title: over_title,
                        objective: "o".into(),
                    })
                    .unwrap_err()
            ),
            LifeIntentErrorCode::InvalidArgument
        );

        // Long content: 4096 characters accepted with a real SQLite create,
        // 4097 rejected.
        let max_content = boundary_character.repeat(4096);
        assert_eq!(
            max_content.len(),
            12_288,
            "the 4096-character content must be 12288 UTF-8 bytes"
        );
        let content_outcome = fixture
            .storage
            .create_goal(LifeGoalCreateRequest {
                goal_id: "goal-unicode-content".into(),
                life_id: "life-a".into(),
                title: "unicode content boundary".into(),
                objective: max_content.clone(),
            })
            .unwrap();
        assert!(matches!(
            content_outcome,
            LifeIntentCreateOutcome::Applied(_)
        ));
        assert_eq!(
            fixture
                .storage
                .find_goal("life-a", "goal-unicode-content")
                .unwrap()
                .unwrap()
                .objective,
            max_content
        );
        let over_content = boundary_character.repeat(4097);
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_goal(LifeGoalCreateRequest {
                        goal_id: "goal-unicode-content-over".into(),
                        life_id: "life-a".into(),
                        title: "t".into(),
                        objective: over_content,
                    })
                    .unwrap_err()
            ),
            LifeIntentErrorCode::InvalidArgument
        );

        // Summary boundary: 4096 characters accepted with a real SQLite create,
        // 4097 rejected.
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-unicode-summary"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-unicode-summary", "goal-unicode-summary"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-unicode-summary", "plan-unicode-summary", 1))
            .unwrap();
        let max_summary = boundary_character.repeat(4096);
        assert_eq!(
            max_summary.len(),
            12_288,
            "the 4096-character summary must be 12288 UTF-8 bytes"
        );
        let summary_outcome = fixture
            .storage
            .create_action(LifeActionIntentCreateRequest {
                action_id: "action-unicode-summary".into(),
                life_id: "life-a".into(),
                step_id: "step-unicode-summary".into(),
                execution_class: EXECUTION_CLASS_INTERNAL_INTENT.into(),
                summary: max_summary.clone(),
            })
            .unwrap();
        assert!(matches!(
            summary_outcome,
            LifeIntentCreateOutcome::Applied(_)
        ));
        assert_eq!(
            fixture
                .storage
                .find_action("life-a", "action-unicode-summary")
                .unwrap()
                .unwrap()
                .summary,
            max_summary
        );
        let over_summary = boundary_character.repeat(4097);
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_action(LifeActionIntentCreateRequest {
                        action_id: "action-unicode-summary-over".into(),
                        life_id: "life-a".into(),
                        step_id: "step-unicode-summary".into(),
                        execution_class: EXECUTION_CLASS_INTERNAL_INTENT.into(),
                        summary: over_summary,
                    })
                    .unwrap_err()
            ),
            LifeIntentErrorCode::InvalidArgument
        );
    }

    #[test]
    fn direct_updates_of_frozen_goal_content_are_rejected() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-frozen"))
            .unwrap();
        let state = fixture.storage.state().unwrap();
        for sql in [
            "UPDATE life_goal SET title = 'rewritten' WHERE goal_id = 'goal-frozen'",
            "UPDATE life_goal SET objective = 'rewritten' WHERE goal_id = 'goal-frozen'",
            "UPDATE life_goal SET goal_id = 'goal-frozen-2' WHERE goal_id = 'goal-frozen'",
            "UPDATE life_goal SET life_id = 'life-b' WHERE goal_id = 'goal-frozen'",
            "UPDATE life_goal SET created_by_kind = 'agent' WHERE goal_id = 'goal-frozen'",
            "UPDATE life_goal SET created_at = '2026-01-01T00:00:00.000Z' WHERE goal_id = 'goal-frozen'",
            "UPDATE life_goal SET goal_version = 2 WHERE goal_id = 'goal-frozen'",
        ] {
            let error = state.connection.execute(sql, []).unwrap_err();
            assert!(
                error.to_string().contains("LIFE_GOAL_IMMUTABLE"),
                "{sql} must fail closed, got {error}"
            );
        }
    }

    #[test]
    fn direct_updates_of_frozen_plan_identity_are_rejected() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-frozen-p"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-frozen", "goal-frozen-p"))
            .unwrap();
        let state = fixture.storage.state().unwrap();
        for sql in [
            "UPDATE life_plan SET title = 'rewritten' WHERE plan_id = 'plan-frozen'",
            "UPDATE life_plan SET goal_id = 'other-goal' WHERE plan_id = 'plan-frozen'",
            "UPDATE life_plan SET life_id = 'life-b' WHERE plan_id = 'plan-frozen'",
            "UPDATE life_plan SET plan_id = 'plan-frozen-2' WHERE plan_id = 'plan-frozen'",
            "UPDATE life_plan SET created_at = '2026-01-01T00:00:00.000Z' WHERE plan_id = 'plan-frozen'",
            "UPDATE life_plan SET plan_version = 2 WHERE plan_id = 'plan-frozen'",
        ] {
            let error = state.connection.execute(sql, []).unwrap_err();
            assert!(
                error.to_string().contains("LIFE_PLAN_IMMUTABLE"),
                "{sql} must fail closed, got {error}"
            );
        }
    }

    #[test]
    fn direct_updates_of_step_ordinal_or_summary_are_rejected() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-frozen-s"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-frozen-s", "goal-frozen-s"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-frozen", "plan-frozen-s", 1))
            .unwrap();
        let state = fixture.storage.state().unwrap();
        for sql in [
            "UPDATE life_plan_step SET ordinal = 9 WHERE step_id = 'step-frozen'",
            "UPDATE life_plan_step SET summary = 'rewritten' WHERE step_id = 'step-frozen'",
            "UPDATE life_plan_step SET plan_id = 'other-plan' WHERE step_id = 'step-frozen'",
            "UPDATE life_plan_step SET step_id = 'step-frozen-2' WHERE step_id = 'step-frozen'",
            "UPDATE life_plan_step SET life_id = 'life-b' WHERE step_id = 'step-frozen'",
            "UPDATE life_plan_step SET created_at = '2026-01-01T00:00:00.000Z' WHERE step_id = 'step-frozen'",
            "UPDATE life_plan_step SET step_version = 2 WHERE step_id = 'step-frozen'",
        ] {
            let error = state.connection.execute(sql, []).unwrap_err();
            assert!(
                error.to_string().contains("LIFE_PLAN_STEP_IMMUTABLE"),
                "{sql} must fail closed, got {error}"
            );
        }
    }

    #[test]
    fn direct_updates_of_action_execution_class_or_summary_are_rejected() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-frozen-a"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-frozen-a", "goal-frozen-a"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-frozen-a", "plan-frozen-a", 1))
            .unwrap();
        fixture
            .storage
            .create_action(fixture.action_request(
                "action-frozen",
                "step-frozen-a",
                EXECUTION_CLASS_INTERNAL_INTENT,
            ))
            .unwrap();
        let state = fixture.storage.state().unwrap();
        for sql in [
            "UPDATE life_action_intent SET execution_class = 'tool_operation_proposal' WHERE action_id = 'action-frozen'",
            "UPDATE life_action_intent SET summary = 'rewritten' WHERE action_id = 'action-frozen'",
            "UPDATE life_action_intent SET step_id = 'other-step' WHERE action_id = 'action-frozen'",
            "UPDATE life_action_intent SET action_id = 'action-frozen-2' WHERE action_id = 'action-frozen'",
            "UPDATE life_action_intent SET life_id = 'life-b' WHERE action_id = 'action-frozen'",
            "UPDATE life_action_intent SET created_at = '2026-01-01T00:00:00.000Z' WHERE action_id = 'action-frozen'",
            "UPDATE life_action_intent SET action_version = 2 WHERE action_id = 'action-frozen'",
        ] {
            let error = state.connection.execute(sql, []).unwrap_err();
            assert!(
                error.to_string().contains("LIFE_ACTION_INTENT_IMMUTABLE"),
                "{sql} must fail closed, got {error}"
            );
        }
    }

    #[test]
    fn lifecycle_columns_are_structurally_mutable_for_all_four_entities() {
        // Schema22 compatibility proof only: the frozen B1 guards must not
        // make D14-B2 lifecycle mutation impossible. No production B2
        // transition API exists in B1/F1; these direct authorized UPDATEs
        // exercise valid table CHECK combinations exclusively on the
        // lifecycle-mutable columns (status, revision, updated_at, closed_at).
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-lc"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-lc", "goal-lc"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-lc", "plan-lc", 1))
            .unwrap();
        fixture
            .storage
            .create_action(fixture.action_request(
                "action-lc",
                "step-lc",
                EXECUTION_CLASS_INTERNAL_INTENT,
            ))
            .unwrap();

        let state = fixture.storage.state().unwrap();
        let connection = &state.connection;
        assert_eq!(
            connection
                .execute(
                    "UPDATE life_goal SET status = 'completed', revision = 2,
                         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                         closed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                     WHERE goal_id = 'goal-lc'",
                    [],
                )
                .unwrap(),
            1,
            "active/revision1/open must be able to move to completed/revision2/closed"
        );
        assert_eq!(
            connection
                .execute(
                    "UPDATE life_plan SET status = 'active', revision = 2,
                         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                     WHERE plan_id = 'plan-lc'",
                    [],
                )
                .unwrap(),
            1,
            "draft/revision1/open must be able to move to active/revision2/open"
        );
        assert_eq!(
            connection
                .execute(
                    "UPDATE life_plan_step SET status = 'completed', revision = 2,
                         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                         closed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                     WHERE step_id = 'step-lc'",
                    [],
                )
                .unwrap(),
            1,
            "pending/revision1/open must be able to move to completed/revision2/closed"
        );
        assert_eq!(
            connection
                .execute(
                    "UPDATE life_action_intent SET status = 'dismissed', revision = 2,
                         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                         closed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                     WHERE action_id = 'action-lc'",
                    [],
                )
                .unwrap(),
            1,
            "proposed/revision1/open must be able to move to dismissed/revision2/closed"
        );

        let (goal_status, goal_revision, goal_closed): (String, i64, Option<String>) = connection
            .query_row(
                "SELECT status, revision, closed_at FROM life_goal WHERE goal_id = 'goal-lc'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((goal_status.as_str(), goal_revision), ("completed", 2));
        assert!(goal_closed.is_some());
        let (plan_status, plan_revision, plan_closed): (String, i64, Option<String>) = connection
            .query_row(
                "SELECT status, revision, closed_at FROM life_plan WHERE plan_id = 'plan-lc'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((plan_status.as_str(), plan_revision), ("active", 2));
        assert!(plan_closed.is_none());
        let (step_status, step_revision): (String, i64) = connection
            .query_row(
                "SELECT status, revision FROM life_plan_step WHERE step_id = 'step-lc'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((step_status.as_str(), step_revision), ("completed", 2));
        let (action_status, action_revision): (String, i64) = connection
            .query_row(
                "SELECT status, revision FROM life_action_intent WHERE action_id = 'action-lc'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((action_status.as_str(), action_revision), ("dismissed", 2));

        // The frozen identity/content evidence is still intact after the
        // lifecycle-column writes.
        let error = connection
            .execute(
                "UPDATE life_goal SET title = 'rewritten' WHERE goal_id = 'goal-lc'",
                [],
            )
            .unwrap_err();
        assert!(error.to_string().contains("LIFE_GOAL_IMMUTABLE"));
    }

    #[test]
    fn life_intent_event_rows_are_immutable() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-e1"))
            .unwrap();
        let state = fixture.storage.state().unwrap();
        insert_event_fixture(
            &state.connection,
            "event-frozen",
            "life-a",
            "goal",
            "goal-e1",
            "active",
            "completed",
        );
        let error = state
            .connection
            .execute(
                "UPDATE life_intent_event SET to_status = 'cancelled' WHERE event_id = 'event-frozen'",
                [],
            )
            .unwrap_err();
        assert!(error.to_string().contains("LIFE_INTENT_EVENT_IMMUTABLE"));
    }

    #[test]
    fn deleting_life_cascades_to_every_d14_row() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-cascade"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-cascade", "goal-cascade"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-cascade", "plan-cascade", 1))
            .unwrap();
        fixture
            .storage
            .create_action(fixture.action_request(
                "action-cascade",
                "step-cascade",
                EXECUTION_CLASS_INTERNAL_INTENT,
            ))
            .unwrap();
        let state = fixture.storage.state().unwrap();
        insert_event_fixture(
            &state.connection,
            "event-cascade-g",
            "life-a",
            "goal",
            "goal-cascade",
            "active",
            "completed",
        );
        insert_event_fixture(
            &state.connection,
            "event-cascade-p",
            "life-a",
            "plan",
            "plan-cascade",
            "draft",
            "active",
        );
        insert_event_fixture(
            &state.connection,
            "event-cascade-s",
            "life-a",
            "step",
            "step-cascade",
            "pending",
            "completed",
        );
        insert_event_fixture(
            &state.connection,
            "event-cascade-a",
            "life-a",
            "action",
            "action-cascade",
            "proposed",
            "dismissed",
        );
        assert_eq!(count_rows(&state.connection).events, 4);
        state
            .connection
            .execute(
                "UPDATE app_state SET current_life_id = NULL WHERE singleton = 1",
                [],
            )
            .unwrap();
        state
            .connection
            .execute("DELETE FROM life_identity WHERE id = 'life-a'", [])
            .unwrap();
        let counts = count_rows(&state.connection);
        assert_eq!(counts.goals, 0);
        assert_eq!(counts.plans, 0);
        assert_eq!(counts.steps, 0);
        assert_eq!(counts.actions, 0);
        assert_eq!(counts.events, 0);
    }

    #[test]
    fn deleting_goal_cascades_to_plans_steps_actions_and_events() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-cg"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-cg", "goal-cg"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-cg", "plan-cg", 1))
            .unwrap();
        fixture
            .storage
            .create_action(fixture.action_request(
                "action-cg",
                "step-cg",
                EXECUTION_CLASS_INTERNAL_INTENT,
            ))
            .unwrap();
        let state = fixture.storage.state().unwrap();
        insert_event_fixture(
            &state.connection,
            "event-cg",
            "life-a",
            "goal",
            "goal-cg",
            "active",
            "completed",
        );
        drop(state);
        assert!(fixture.storage.delete_goal("life-a", "goal-cg").unwrap());
        let state = fixture.storage.state().unwrap();
        let counts = count_rows(&state.connection);
        assert_eq!(counts.goals, 0);
        assert_eq!(counts.plans, 0);
        assert_eq!(counts.steps, 0);
        assert_eq!(counts.actions, 0);
        assert_eq!(counts.events, 0);
    }

    #[test]
    fn deleting_plan_cascades_to_steps_actions_and_events() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-cp"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-cp", "goal-cp"))
            .unwrap();
        for (step_id, ordinal) in [("step-cp1", 1), ("step-cp2", 2)] {
            fixture
                .storage
                .create_step(fixture.step_request(step_id, "plan-cp", ordinal))
                .unwrap();
        }
        fixture
            .storage
            .create_action(fixture.action_request(
                "action-cp",
                "step-cp1",
                EXECUTION_CLASS_INTERNAL_INTENT,
            ))
            .unwrap();
        let state = fixture.storage.state().unwrap();
        insert_event_fixture(
            &state.connection,
            "event-cp-p",
            "life-a",
            "plan",
            "plan-cp",
            "draft",
            "active",
        );
        insert_event_fixture(
            &state.connection,
            "event-cp-s",
            "life-a",
            "step",
            "step-cp1",
            "pending",
            "completed",
        );
        insert_event_fixture(
            &state.connection,
            "event-cp-a",
            "life-a",
            "action",
            "action-cp",
            "proposed",
            "dismissed",
        );
        drop(state);
        assert!(fixture.storage.delete_plan("life-a", "plan-cp").unwrap());
        let state = fixture.storage.state().unwrap();
        let counts = count_rows(&state.connection);
        assert_eq!(counts.goals, 1, "the goal survives plan deletion");
        assert_eq!(counts.plans, 0);
        assert_eq!(counts.steps, 0);
        assert_eq!(counts.actions, 0);
        assert_eq!(counts.events, 0);
    }

    #[test]
    fn deleting_step_cascades_to_actions_and_events() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-cs"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-cs", "goal-cs"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-cs", "plan-cs", 1))
            .unwrap();
        fixture
            .storage
            .create_action(fixture.action_request(
                "action-cs",
                "step-cs",
                EXECUTION_CLASS_INTERNAL_INTENT,
            ))
            .unwrap();
        let state = fixture.storage.state().unwrap();
        insert_event_fixture(
            &state.connection,
            "event-cs-s",
            "life-a",
            "step",
            "step-cs",
            "pending",
            "completed",
        );
        insert_event_fixture(
            &state.connection,
            "event-cs-a",
            "life-a",
            "action",
            "action-cs",
            "proposed",
            "dismissed",
        );
        drop(state);
        assert!(fixture.storage.delete_step("life-a", "step-cs").unwrap());
        let state = fixture.storage.state().unwrap();
        let counts = count_rows(&state.connection);
        assert_eq!(counts.plans, 1, "the plan survives step deletion");
        assert_eq!(counts.steps, 0);
        assert_eq!(counts.actions, 0);
        assert_eq!(counts.events, 0);
    }

    #[test]
    fn deleting_action_cascades_to_its_events_only() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-ca"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-ca", "goal-ca"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-ca", "plan-ca", 1))
            .unwrap();
        fixture
            .storage
            .create_action(fixture.action_request(
                "action-ca1",
                "step-ca",
                EXECUTION_CLASS_INTERNAL_INTENT,
            ))
            .unwrap();
        fixture
            .storage
            .create_action(fixture.action_request(
                "action-ca2",
                "step-ca",
                EXECUTION_CLASS_AGENT_TASK_PROPOSAL,
            ))
            .unwrap();
        let state = fixture.storage.state().unwrap();
        insert_event_fixture(
            &state.connection,
            "event-ca1",
            "life-a",
            "action",
            "action-ca1",
            "proposed",
            "dismissed",
        );
        insert_event_fixture(
            &state.connection,
            "event-ca2",
            "life-a",
            "action",
            "action-ca2",
            "proposed",
            "dismissed",
        );
        drop(state);
        assert!(fixture
            .storage
            .delete_action("life-a", "action-ca1")
            .unwrap());
        let state = fixture.storage.state().unwrap();
        let counts = count_rows(&state.connection);
        assert_eq!(counts.actions, 1);
        assert_eq!(counts.events, 1);
        drop(state);
        assert_eq!(
            fixture
                .storage
                .find_action("life-a", "action-ca2")
                .unwrap()
                .unwrap()
                .action_id,
            "action-ca2"
        );
        // Missing targets delete nothing.
        assert!(!fixture
            .storage
            .delete_goal("life-a", "missing-goal")
            .unwrap());
        assert!(!fixture
            .storage
            .delete_action("life-b", "action-ca2")
            .unwrap());
    }

    #[test]
    fn goal_id_reused_under_a_different_life_is_an_entity_conflict() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-global"))
            .unwrap();
        let mut request = fixture.goal_request("goal-global");
        request.life_id = "life-b".into();
        let error = fixture.storage.create_goal(request).unwrap_err();
        assert_eq!(error_code(error), LifeIntentErrorCode::EntityConflict);
    }

    #[test]
    fn existing_id_conflicts_take_precedence_over_life_parent_and_ordinal_checks() {
        let fixture = Fixture::new();

        fixture
            .storage
            .create_goal(fixture.goal_request("goal-precedence"))
            .unwrap();
        let mut changed_goal = fixture.goal_request("goal-precedence");
        changed_goal.title = "Changed evidence".into();
        assert_eq!(
            error_code(fixture.storage.create_goal(changed_goal).unwrap_err()),
            LifeIntentErrorCode::EntityConflict
        );
        let mut missing_life_goal = fixture.goal_request("goal-precedence");
        missing_life_goal.life_id = "missing-life".into();
        assert_eq!(
            error_code(fixture.storage.create_goal(missing_life_goal).unwrap_err()),
            LifeIntentErrorCode::EntityConflict
        );

        fixture
            .storage
            .create_plan(fixture.plan_request("plan-precedence", "goal-precedence"))
            .unwrap();
        let mut missing_goal_plan = fixture.plan_request("plan-precedence", "goal-precedence");
        missing_goal_plan.goal_id = "missing-goal".into();
        assert_eq!(
            error_code(fixture.storage.create_plan(missing_goal_plan).unwrap_err()),
            LifeIntentErrorCode::EntityConflict
        );
        let mut cross_life_plan = fixture.plan_request("plan-precedence", "goal-precedence");
        cross_life_plan.life_id = "life-b".into();
        assert_eq!(
            error_code(fixture.storage.create_plan(cross_life_plan).unwrap_err()),
            LifeIntentErrorCode::EntityConflict
        );

        fixture
            .storage
            .create_step(fixture.step_request("step-precedence", "plan-precedence", 1))
            .unwrap();
        let mut missing_plan_step = fixture.step_request("step-precedence", "plan-precedence", 1);
        missing_plan_step.plan_id = "missing-plan".into();
        assert_eq!(
            error_code(fixture.storage.create_step(missing_plan_step).unwrap_err()),
            LifeIntentErrorCode::EntityConflict
        );
        let mut cross_life_step = fixture.step_request("step-precedence", "plan-precedence", 1);
        cross_life_step.life_id = "life-b".into();
        assert_eq!(
            error_code(fixture.storage.create_step(cross_life_step).unwrap_err()),
            LifeIntentErrorCode::EntityConflict
        );
        fixture
            .storage
            .create_step(fixture.step_request("step-precedence-other", "plan-precedence", 2))
            .unwrap();
        let ordinal_conflict = fixture.step_request("step-precedence", "plan-precedence", 2);
        assert_eq!(
            error_code(fixture.storage.create_step(ordinal_conflict).unwrap_err()),
            LifeIntentErrorCode::EntityConflict
        );
        assert_eq!(
            fixture
                .storage
                .find_step("life-a", "step-precedence")
                .unwrap()
                .expect("existing step must remain unchanged")
                .ordinal,
            1
        );

        fixture
            .storage
            .create_action(fixture.action_request(
                "action-precedence",
                "step-precedence",
                EXECUTION_CLASS_INTERNAL_INTENT,
            ))
            .unwrap();
        let mut missing_step_action = fixture.action_request(
            "action-precedence",
            "step-precedence",
            EXECUTION_CLASS_INTERNAL_INTENT,
        );
        missing_step_action.step_id = "missing-step".into();
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_action(missing_step_action)
                    .unwrap_err()
            ),
            LifeIntentErrorCode::EntityConflict
        );
        let mut cross_life_action = fixture.action_request(
            "action-precedence",
            "step-precedence",
            EXECUTION_CLASS_INTERNAL_INTENT,
        );
        cross_life_action.life_id = "life-b".into();
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .create_action(cross_life_action)
                    .unwrap_err()
            ),
            LifeIntentErrorCode::EntityConflict
        );
    }

    #[test]
    fn create_replays_for_plan_step_and_action_are_exact() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-replay-all"))
            .unwrap();
        let plan_request = fixture.plan_request("plan-replay-all", "goal-replay-all");
        let step_request = fixture.step_request("step-replay-all", "plan-replay-all", 1);
        let action_request = fixture.action_request(
            "action-replay-all",
            "step-replay-all",
            EXECUTION_CLASS_TOOL_OPERATION_PROPOSAL,
        );
        fixture.storage.create_plan(plan_request.clone()).unwrap();
        fixture.storage.create_step(step_request.clone()).unwrap();
        fixture
            .storage
            .create_action(action_request.clone())
            .unwrap();
        assert!(matches!(
            fixture.storage.create_plan(plan_request).unwrap(),
            LifeIntentCreateOutcome::Replayed(_)
        ));
        assert!(matches!(
            fixture.storage.create_step(step_request).unwrap(),
            LifeIntentCreateOutcome::Replayed(_)
        ));
        assert!(matches!(
            fixture.storage.create_action(action_request).unwrap(),
            LifeIntentCreateOutcome::Replayed(_)
        ));
        let mut conflicting_step = fixture.step_request("step-replay-all", "plan-replay-all", 1);
        conflicting_step.summary = "different evidence".into();
        assert_eq!(
            error_code(fixture.storage.create_step(conflicting_step).unwrap_err()),
            LifeIntentErrorCode::EntityConflict
        );
    }

    #[test]
    fn goal_lifecycle_records_authoritative_event_and_replays_after_terminal_state() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-lifecycle"))
            .unwrap();

        let request = goal_transition(
            "event-goal-complete",
            "life-a",
            "goal-lifecycle",
            1,
            LifeGoalTransitionKind::Complete,
        );
        let outcome = fixture.storage.transition_goal(request.clone()).unwrap();
        let LifeIntentTransitionOutcome::Applied { event, entity } = outcome else {
            panic!("the first goal transition must apply");
        };
        assert_eq!(entity.status, "completed");
        assert_eq!(entity.revision, 2);
        assert_eq!(
            entity.closed_at.as_deref(),
            Some(event.occurred_at.as_str())
        );
        assert_eq!(entity.updated_at, event.occurred_at);
        assert_eq!(event.event_id, "event-goal-complete");
        assert_eq!(event.life_id, "life-a");
        assert_eq!(event.entity_kind, "goal");
        assert_eq!(event.goal_id.as_deref(), Some("goal-lifecycle"));
        assert!(event.plan_id.is_none());
        assert!(event.step_id.is_none());
        assert!(event.action_id.is_none());
        assert_eq!(event.from_status, "active");
        assert_eq!(event.to_status, "completed");
        assert_eq!(event.expected_revision, 1);
        assert_eq!(event.applied_revision, 2);
        assert_eq!(event.actor_kind, "user_explicit");
        assert_eq!(event.event_version, 1);
        assert!(!event.occurred_at.is_empty());

        assert_eq!(
            fixture
                .storage
                .find_event("life-a", "event-goal-complete")
                .unwrap(),
            Some(event.clone())
        );
        assert!(fixture
            .storage
            .find_event("life-b", "event-goal-complete")
            .unwrap()
            .is_none());

        let replay = fixture.storage.transition_goal(request).unwrap();
        let LifeIntentTransitionOutcome::Replayed {
            event: replayed_event,
            current,
        } = replay
        else {
            panic!("the exact goal transition must replay");
        };
        assert_eq!(replayed_event, event);
        assert_eq!(current.status, "completed");
        assert_eq!(current.revision, 2);
        assert_eq!(
            count_rows(&fixture.storage.state().unwrap().connection).events,
            1
        );

        let stale = fixture.storage.transition_goal(goal_transition(
            "event-goal-stale",
            "life-a",
            "goal-lifecycle",
            1,
            LifeGoalTransitionKind::Complete,
        ));
        assert_eq!(
            error_code(stale.unwrap_err()),
            LifeIntentErrorCode::RevisionConflict
        );

        let terminal = fixture.storage.transition_goal(goal_transition(
            "event-goal-terminal",
            "life-a",
            "goal-lifecycle",
            2,
            LifeGoalTransitionKind::Cancel,
        ));
        assert_eq!(
            error_code(terminal.unwrap_err()),
            LifeIntentErrorCode::InvalidTransition
        );

        let event_conflict = fixture.storage.transition_goal(goal_transition(
            "event-goal-complete",
            "life-a",
            "goal-lifecycle",
            1,
            LifeGoalTransitionKind::Cancel,
        ));
        assert_eq!(
            error_code(event_conflict.unwrap_err()),
            LifeIntentErrorCode::LifeIntentEventConflict
        );

        fixture
            .storage
            .create_goal(fixture.goal_request("goal-cancel"))
            .unwrap();
        let cancelled = fixture
            .storage
            .transition_goal(goal_transition(
                "event-goal-cancel",
                "life-a",
                "goal-cancel",
                1,
                LifeGoalTransitionKind::Cancel,
            ))
            .unwrap();
        let LifeIntentTransitionOutcome::Applied { entity, .. } = cancelled else {
            panic!("goal cancellation must apply");
        };
        assert_eq!(entity.status, "cancelled");
        assert_eq!(entity.revision, 2);
    }

    #[test]
    fn plan_lifecycle_obeys_graph_and_replays_activation_after_completion() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-plan-lifecycle"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-lifecycle", "goal-plan-lifecycle"))
            .unwrap();

        let activate_request = plan_transition(
            "event-plan-activate",
            "life-a",
            "plan-lifecycle",
            1,
            LifePlanTransitionKind::Activate,
        );
        let activated = fixture
            .storage
            .transition_plan(activate_request.clone())
            .unwrap();
        let LifeIntentTransitionOutcome::Applied { event, entity } = activated else {
            panic!("plan activation must apply");
        };
        assert_eq!(entity.status, "active");
        assert_eq!(entity.revision, 2);
        assert!(entity.closed_at.is_none());
        assert_eq!(entity.updated_at, event.occurred_at);
        assert_eq!(event.from_status, "draft");
        assert_eq!(event.to_status, "active");
        assert_eq!(event.plan_id.as_deref(), Some("plan-lifecycle"));
        assert!(event.goal_id.is_none());
        assert!(event.step_id.is_none());
        assert!(event.action_id.is_none());

        let completed = fixture
            .storage
            .transition_plan(plan_transition(
                "event-plan-complete",
                "life-a",
                "plan-lifecycle",
                2,
                LifePlanTransitionKind::Complete,
            ))
            .unwrap();
        let LifeIntentTransitionOutcome::Applied { entity, .. } = completed else {
            panic!("plan completion must apply");
        };
        assert_eq!(entity.status, "completed");
        assert_eq!(entity.revision, 3);
        assert!(entity.closed_at.is_some());

        let replayed = fixture.storage.transition_plan(activate_request).unwrap();
        let LifeIntentTransitionOutcome::Replayed { event, current } = replayed else {
            panic!("activation must replay after later completion");
        };
        assert_eq!(event.event_id, "event-plan-activate");
        assert_eq!(event.expected_revision, 1);
        assert_eq!(event.applied_revision, 2);
        assert_eq!(current.status, "completed");
        assert_eq!(current.revision, 3);

        for conflicting in [
            plan_transition(
                "event-plan-activate",
                "life-a",
                "plan-lifecycle",
                1,
                LifePlanTransitionKind::Cancel,
            ),
            plan_transition(
                "event-plan-activate",
                "life-a",
                "other-plan",
                1,
                LifePlanTransitionKind::Activate,
            ),
            plan_transition(
                "event-plan-activate",
                "life-a",
                "plan-lifecycle",
                2,
                LifePlanTransitionKind::Activate,
            ),
        ] {
            assert_eq!(
                error_code(fixture.storage.transition_plan(conflicting).unwrap_err()),
                LifeIntentErrorCode::LifeIntentEventConflict
            );
        }

        let terminal_reopen = fixture.storage.transition_plan(plan_transition(
            "event-plan-reopen",
            "life-a",
            "plan-lifecycle",
            3,
            LifePlanTransitionKind::Activate,
        ));
        assert_eq!(
            error_code(terminal_reopen.unwrap_err()),
            LifeIntentErrorCode::InvalidTransition
        );

        fixture
            .storage
            .create_plan(fixture.plan_request("plan-draft-complete", "goal-plan-lifecycle"))
            .unwrap();
        assert_eq!(
            error_code(
                fixture
                    .storage
                    .transition_plan(plan_transition(
                        "event-plan-illegal",
                        "life-a",
                        "plan-draft-complete",
                        1,
                        LifePlanTransitionKind::Complete,
                    ))
                    .unwrap_err()
            ),
            LifeIntentErrorCode::InvalidTransition
        );

        fixture
            .storage
            .create_plan(fixture.plan_request("plan-draft-cancel", "goal-plan-lifecycle"))
            .unwrap();
        let draft_cancel = fixture
            .storage
            .transition_plan(plan_transition(
                "event-plan-draft-cancel",
                "life-a",
                "plan-draft-cancel",
                1,
                LifePlanTransitionKind::Cancel,
            ))
            .unwrap();
        let LifeIntentTransitionOutcome::Applied { entity, .. } = draft_cancel else {
            panic!("draft cancellation must apply");
        };
        assert_eq!(entity.status, "cancelled");
        assert_eq!(entity.revision, 2);
        assert!(entity.closed_at.is_some());

        fixture
            .storage
            .create_plan(fixture.plan_request("plan-active-cancel", "goal-plan-lifecycle"))
            .unwrap();
        fixture
            .storage
            .transition_plan(plan_transition(
                "event-plan-activate-2",
                "life-a",
                "plan-active-cancel",
                1,
                LifePlanTransitionKind::Activate,
            ))
            .unwrap();
        let active_cancel = fixture
            .storage
            .transition_plan(plan_transition(
                "event-plan-cancel-2",
                "life-a",
                "plan-active-cancel",
                2,
                LifePlanTransitionKind::Cancel,
            ))
            .unwrap();
        let LifeIntentTransitionOutcome::Applied { entity, .. } = active_cancel else {
            panic!("active plan cancellation must apply");
        };
        assert_eq!(entity.status, "cancelled");
        assert_eq!(entity.revision, 3);
    }

    #[test]
    fn step_lifecycle_supports_all_terminals_without_parent_auto_progression() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-step-lifecycle"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-step-lifecycle", "goal-step-lifecycle"))
            .unwrap();
        for step_id in ["step-complete", "step-skip", "step-cancel"] {
            let ordinal = match step_id {
                "step-complete" => 1,
                "step-skip" => 2,
                "step-cancel" => 3,
                _ => unreachable!(),
            };
            fixture
                .storage
                .create_step(fixture.step_request(step_id, "plan-step-lifecycle", ordinal))
                .unwrap();
        }

        for (step_id, event_id, kind, expected_status) in [
            (
                "step-complete",
                "event-step-complete",
                LifeStepTransitionKind::Complete,
                "completed",
            ),
            (
                "step-skip",
                "event-step-skip",
                LifeStepTransitionKind::Skip,
                "skipped",
            ),
            (
                "step-cancel",
                "event-step-cancel",
                LifeStepTransitionKind::Cancel,
                "cancelled",
            ),
        ] {
            let outcome = fixture
                .storage
                .transition_step(step_transition(event_id, "life-a", step_id, 1, kind))
                .unwrap();
            let LifeIntentTransitionOutcome::Applied { event, entity } = outcome else {
                panic!("step transition must apply");
            };
            assert_eq!(entity.status, expected_status);
            assert_eq!(entity.revision, 2);
            assert_eq!(
                entity.closed_at.as_deref(),
                Some(event.occurred_at.as_str())
            );
            assert_eq!(entity.updated_at, event.occurred_at);
            assert_eq!(event.entity_kind, "step");
            assert_eq!(event.step_id.as_deref(), Some(step_id));
            assert_eq!(event.from_status, "pending");
            assert_eq!(event.to_status, expected_status);
        }

        let plan = fixture
            .storage
            .find_plan("life-a", "plan-step-lifecycle")
            .unwrap()
            .unwrap();
        let goal = fixture
            .storage
            .find_goal("life-a", "goal-step-lifecycle")
            .unwrap()
            .unwrap();
        assert_eq!((plan.status.as_str(), plan.revision), ("draft", 1));
        assert_eq!((goal.status.as_str(), goal.revision), ("active", 1));

        let terminal_again = fixture.storage.transition_step(step_transition(
            "event-step-terminal-again",
            "life-a",
            "step-complete",
            2,
            LifeStepTransitionKind::Cancel,
        ));
        assert_eq!(
            error_code(terminal_again.unwrap_err()),
            LifeIntentErrorCode::InvalidTransition
        );
    }

    #[test]
    fn action_lifecycle_dismisses_all_proposal_classes_without_execution() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-action-lifecycle"))
            .unwrap();
        fixture
            .storage
            .create_plan(fixture.plan_request("plan-action-lifecycle", "goal-action-lifecycle"))
            .unwrap();
        fixture
            .storage
            .create_step(fixture.step_request("step-action-lifecycle", "plan-action-lifecycle", 1))
            .unwrap();
        for (action_id, execution_class) in [
            ("action-dismiss-internal", EXECUTION_CLASS_INTERNAL_INTENT),
            ("action-dismiss-agent", EXECUTION_CLASS_AGENT_TASK_PROPOSAL),
            (
                "action-dismiss-tool",
                EXECUTION_CLASS_TOOL_OPERATION_PROPOSAL,
            ),
        ] {
            fixture
                .storage
                .create_action(fixture.action_request(
                    action_id,
                    "step-action-lifecycle",
                    execution_class,
                ))
                .unwrap();
            let outcome = fixture
                .storage
                .transition_action(action_transition(
                    &format!("event-{action_id}"),
                    "life-a",
                    action_id,
                    1,
                    LifeActionTransitionKind::Dismiss,
                ))
                .unwrap();
            let LifeIntentTransitionOutcome::Applied { event, entity } = outcome else {
                panic!("action dismissal must apply");
            };
            assert_eq!(entity.execution_class, execution_class);
            assert_eq!(entity.status, "dismissed");
            assert_eq!(entity.revision, 2);
            assert_eq!(
                entity.closed_at.as_deref(),
                Some(event.occurred_at.as_str())
            );
            assert_eq!(entity.updated_at, event.occurred_at);
            assert_eq!(event.entity_kind, "action");
            assert_eq!(event.action_id.as_deref(), Some(action_id));
            assert_eq!(event.from_status, "proposed");
            assert_eq!(event.to_status, "dismissed");
        }

        let dismissed_again = fixture.storage.transition_action(action_transition(
            "event-action-dismissed-again",
            "life-a",
            "action-dismiss-internal",
            2,
            LifeActionTransitionKind::Dismiss,
        ));
        assert_eq!(
            error_code(dismissed_again.unwrap_err()),
            LifeIntentErrorCode::InvalidTransition
        );
    }

    #[test]
    fn transition_target_binding_and_request_validation_are_fail_closed() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-target"))
            .unwrap();

        let missing = fixture.storage.transition_goal(goal_transition(
            "event-missing-target",
            "life-a",
            "missing-goal",
            1,
            LifeGoalTransitionKind::Complete,
        ));
        assert_eq!(
            error_code(missing.unwrap_err()),
            LifeIntentErrorCode::EntityNotFound
        );

        let cross_life = fixture.storage.transition_goal(goal_transition(
            "event-cross-life-target",
            "life-b",
            "goal-target",
            1,
            LifeGoalTransitionKind::Complete,
        ));
        assert_eq!(
            error_code(cross_life.unwrap_err()),
            LifeIntentErrorCode::EntityLifeMismatch
        );
        assert_eq!(
            fixture
                .storage
                .find_goal("life-a", "goal-target")
                .unwrap()
                .unwrap()
                .status,
            "active"
        );

        let invalid_event = fixture.storage.transition_goal(LifeGoalTransitionRequest {
            event_id: String::new(),
            life_id: "life-a".into(),
            goal_id: "goal-target".into(),
            expected_revision: 1,
            kind: LifeGoalTransitionKind::Complete,
        });
        assert_eq!(
            error_code(invalid_event.unwrap_err()),
            LifeIntentErrorCode::InvalidArgument
        );
        let invalid_revision = fixture.storage.transition_goal(goal_transition(
            "event-invalid-revision",
            "life-a",
            "goal-target",
            0,
            LifeGoalTransitionKind::Complete,
        ));
        assert_eq!(
            error_code(invalid_revision.unwrap_err()),
            LifeIntentErrorCode::InvalidArgument
        );
    }

    #[test]
    fn caller_owned_transition_helper_commits_only_when_caller_commits() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-caller-owned"))
            .unwrap();
        let mut state = fixture.storage.state().unwrap();
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let outcome = transition_goal_in_transaction(
            &transaction,
            goal_transition(
                "event-caller-owned",
                "life-a",
                "goal-caller-owned",
                1,
                LifeGoalTransitionKind::Complete,
            ),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            LifeIntentTransitionOutcome::Applied { .. }
        ));
        let event_count: i64 = transaction
            .query_row("SELECT COUNT(*) FROM life_intent_event", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(event_count, 1);
        transaction.commit().unwrap();
        drop(state);

        assert_eq!(
            fixture
                .storage
                .find_goal("life-a", "goal-caller-owned")
                .unwrap()
                .unwrap()
                .status,
            "completed"
        );
    }

    #[test]
    fn transition_rolls_back_entity_when_event_insert_fails() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-atomic"))
            .unwrap();
        let state = fixture.storage.state().unwrap();
        state
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER d14_b2_test_event_insert_failure
                 BEFORE INSERT ON main.life_intent_event
                 BEGIN
                     SELECT RAISE(ABORT, 'D14_B2_TEST_EVENT_INSERT_FAILURE');
                 END;",
            )
            .unwrap();
        drop(state);

        let error = fixture
            .storage
            .transition_goal(goal_transition(
                "event-atomic",
                "life-a",
                "goal-atomic",
                1,
                LifeGoalTransitionKind::Complete,
            ))
            .unwrap_err();
        assert_eq!(error_code(error), LifeIntentErrorCode::DatabaseUnavailable);
        let goal = fixture
            .storage
            .find_goal("life-a", "goal-atomic")
            .unwrap()
            .unwrap();
        assert_eq!(goal.status, "active");
        assert_eq!(goal.revision, 1);
        assert!(goal.closed_at.is_none());
        assert!(fixture
            .storage
            .find_event("life-a", "event-atomic")
            .unwrap()
            .is_none());
        assert_eq!(
            count_rows(&fixture.storage.state().unwrap().connection).events,
            0
        );
    }

    #[test]
    fn competing_sqlite_connections_allow_one_cas_transition() {
        let fixture = Fixture::new();
        fixture
            .storage
            .create_goal(fixture.goal_request("goal-race"))
            .unwrap();
        let second_root = fixture._root.path().join("default");
        let second_service = StorageService::initialize_with_roots(second_root, None).unwrap();
        let first_service = Arc::new(fixture.storage);
        let second_service = Arc::new(second_service);
        let barrier = Arc::new(Barrier::new(3));

        let first_barrier = barrier.clone();
        let first = first_service.clone();
        let first_thread = thread::spawn(move || {
            first_barrier.wait();
            first.transition_goal(goal_transition(
                "event-race-complete",
                "life-a",
                "goal-race",
                1,
                LifeGoalTransitionKind::Complete,
            ))
        });

        let second_barrier = barrier.clone();
        let second = second_service.clone();
        let second_thread = thread::spawn(move || {
            second_barrier.wait();
            second.transition_goal(goal_transition(
                "event-race-cancel",
                "life-a",
                "goal-race",
                1,
                LifeGoalTransitionKind::Cancel,
            ))
        });

        barrier.wait();
        let first_result = first_thread.join().unwrap();
        let second_result = second_thread.join().unwrap();
        let results = [first_result, second_result];
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(LifeIntentTransitionOutcome::Applied { .. })))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(
                        result,
                        Err(error) if error.code == LifeIntentErrorCode::RevisionConflict
                    )
                })
                .count(),
            1
        );

        let goal = first_service
            .find_goal("life-a", "goal-race")
            .unwrap()
            .unwrap();
        assert!(matches!(goal.status.as_str(), "completed" | "cancelled"));
        assert_eq!(goal.revision, 2);
        let state = first_service.state().unwrap();
        assert_eq!(count_rows(&state.connection).events, 1);
    }
}
