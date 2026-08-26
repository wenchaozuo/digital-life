//! D14-B1 goal / plan / action-intent authority domain.
//!
//! This module defines bounded, crate-internal records and create requests for
//! explicit, user-governed Life intention authority: LifeGoal, LifePlan,
//! LifePlanStep, and LifeActionIntent.
//!
//! D14 deliberately implements NO autonomous life: nothing here executes an
//! Agent or Tool, advances an Episode, scores initiative, or reads Prompt or
//! conversation content. LifeActionIntent is a persisted PROPOSAL only; it
//! carries descriptive text and an execution class, and never an executable
//! payload, command, URL, credential, capability token, or permission grant.
//!
//! All authority timestamps (created_at / updated_at / closed_at) are owned by
//! SQLite UTC and are never supplied by a caller. Status transitions and
//! lifecycle events belong to D14-B2; B1 persists only the frozen initial
//! states.

/// Fixed V1 authority constants. Only `user_explicit` creation exists in B1.
pub(crate) const CREATED_BY_KIND_USER_EXPLICIT: &str = "user_explicit";
pub(crate) const ACTOR_KIND_USER_EXPLICIT: &str = "user_explicit";
pub(crate) const GOAL_VERSION: i64 = 1;
pub(crate) const PLAN_VERSION: i64 = 1;
pub(crate) const STEP_VERSION: i64 = 1;
pub(crate) const ACTION_VERSION: i64 = 1;
pub(crate) const EVENT_VERSION: i64 = 1;

pub(crate) const GOAL_STATUS_ACTIVE: &str = "active";
pub(crate) const GOAL_STATUS_COMPLETED: &str = "completed";
pub(crate) const GOAL_STATUS_CANCELLED: &str = "cancelled";

pub(crate) const PLAN_STATUS_DRAFT: &str = "draft";
pub(crate) const PLAN_STATUS_ACTIVE: &str = "active";
pub(crate) const PLAN_STATUS_COMPLETED: &str = "completed";
pub(crate) const PLAN_STATUS_CANCELLED: &str = "cancelled";

pub(crate) const STEP_STATUS_PENDING: &str = "pending";
pub(crate) const STEP_STATUS_COMPLETED: &str = "completed";
pub(crate) const STEP_STATUS_SKIPPED: &str = "skipped";
pub(crate) const STEP_STATUS_CANCELLED: &str = "cancelled";

pub(crate) const ACTION_STATUS_PROPOSED: &str = "proposed";
pub(crate) const ACTION_STATUS_DISMISSED: &str = "dismissed";

/// The only production execution classes in V1. Both proposal classes are
/// descriptive only: B1 never invokes an Agent or Tool.
pub(crate) const EXECUTION_CLASS_INTERNAL_INTENT: &str = "internal_intent";
pub(crate) const EXECUTION_CLASS_AGENT_TASK_PROPOSAL: &str = "agent_task_proposal";
pub(crate) const EXECUTION_CLASS_TOOL_OPERATION_PROPOSAL: &str = "tool_operation_proposal";

pub(crate) const GOAL_ENTITY_KIND: &str = "goal";
pub(crate) const PLAN_ENTITY_KIND: &str = "plan";
pub(crate) const STEP_ENTITY_KIND: &str = "step";
pub(crate) const ACTION_ENTITY_KIND: &str = "action";

pub(crate) const MAX_ID_LENGTH: usize = 128;
pub(crate) const MAX_TITLE_LENGTH: usize = 256;
pub(crate) const MAX_OBJECTIVE_LENGTH: usize = 4096;
pub(crate) const MAX_SUMMARY_LENGTH: usize = 4096;

/// One authoritative user-governed LifeGoal, backed by SQLite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeGoal {
    pub(crate) goal_id: String,
    pub(crate) life_id: String,
    pub(crate) title: String,
    pub(crate) objective: String,
    pub(crate) status: String,
    pub(crate) revision: i64,
    pub(crate) created_by_kind: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) closed_at: Option<String>,
    pub(crate) goal_version: i64,
}

/// The caller-controlled creation evidence for a LifeGoal. Status, revision,
/// creation kind, timestamps, and version are never caller-controlled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeGoalCreateRequest {
    pub(crate) goal_id: String,
    pub(crate) life_id: String,
    pub(crate) title: String,
    pub(crate) objective: String,
}

/// One authoritative user-governed LifePlan bound to the SAME LifeGoal and
/// Life identity it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifePlan {
    pub(crate) plan_id: String,
    pub(crate) life_id: String,
    pub(crate) goal_id: String,
    pub(crate) title: String,
    pub(crate) status: String,
    pub(crate) revision: i64,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) closed_at: Option<String>,
    pub(crate) plan_version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifePlanCreateRequest {
    pub(crate) plan_id: String,
    pub(crate) life_id: String,
    pub(crate) goal_id: String,
    pub(crate) title: String,
}

/// One authoritative user-governed LifePlanStep under the SAME LifePlan and
/// Life identity it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifePlanStep {
    pub(crate) step_id: String,
    pub(crate) life_id: String,
    pub(crate) plan_id: String,
    pub(crate) ordinal: i64,
    pub(crate) summary: String,
    pub(crate) status: String,
    pub(crate) revision: i64,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) closed_at: Option<String>,
    pub(crate) step_version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifePlanStepCreateRequest {
    pub(crate) step_id: String,
    pub(crate) life_id: String,
    pub(crate) plan_id: String,
    pub(crate) ordinal: i64,
    pub(crate) summary: String,
}

/// One authoritative user-governed LifeActionIntent PROPOSAL bound to the SAME
/// LifePlanStep and Life identity it names. It never carries executable
/// payload, shell/command text, credentials, capability tokens, or permission
/// grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeActionIntent {
    pub(crate) action_id: String,
    pub(crate) life_id: String,
    pub(crate) step_id: String,
    pub(crate) execution_class: String,
    pub(crate) summary: String,
    pub(crate) status: String,
    pub(crate) revision: i64,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) closed_at: Option<String>,
    pub(crate) action_version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeActionIntentCreateRequest {
    pub(crate) action_id: String,
    pub(crate) life_id: String,
    pub(crate) step_id: String,
    pub(crate) execution_class: String,
    pub(crate) summary: String,
}

/// Typed create outcome. `Replayed` is returned when the exact same
/// caller-controlled creation evidence already exists for the same entity id;
/// it never overwrites the existing row and never compares SQLite authority
/// timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LifeIntentCreateOutcome<T> {
    Applied(T),
    Replayed(T),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifeIntentErrorCode {
    InvalidArgument,
    LifeNotFound,
    ParentNotFound,
    ParentLifeMismatch,
    EntityConflict,
    DatabaseUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeIntentError {
    pub(crate) code: LifeIntentErrorCode,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl LifeIntentError {
    pub(crate) fn new(code: LifeIntentErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: matches!(
                code,
                LifeIntentErrorCode::LifeNotFound
                    | LifeIntentErrorCode::ParentNotFound
                    | LifeIntentErrorCode::DatabaseUnavailable
            ),
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(LifeIntentErrorCode::InvalidArgument, message)
    }

    pub(crate) fn life_not_found() -> Self {
        Self::new(
            LifeIntentErrorCode::LifeNotFound,
            "The specified life was not found.",
        )
    }

    pub(crate) fn parent_not_found() -> Self {
        Self::new(
            LifeIntentErrorCode::ParentNotFound,
            "The persisted parent authority was not found.",
        )
    }

    pub(crate) fn parent_life_mismatch() -> Self {
        Self::new(
            LifeIntentErrorCode::ParentLifeMismatch,
            "The parent authority exists under a different life.",
        )
    }

    pub(crate) fn entity_conflict() -> Self {
        Self::new(
            LifeIntentErrorCode::EntityConflict,
            "An entity with the same identity exists with conflicting creation evidence.",
        )
    }

    pub(crate) fn database() -> Self {
        Self::new(
            LifeIntentErrorCode::DatabaseUnavailable,
            "The life intent storage operation failed.",
        )
    }
}

/// Crate-internal persistence boundary. Implementations must keep SQLite as
/// the sole authority for entity identity, same-life parent binding, create
/// replay, and governed hard deletion. B1 deliberately exposes no status
/// transition API and never writes lifecycle events.
pub(crate) trait LifeIntentRepository: Send + Sync {
    fn create_goal(
        &self,
        request: LifeGoalCreateRequest,
    ) -> Result<LifeIntentCreateOutcome<LifeGoal>, LifeIntentError>;

    fn find_goal(&self, life_id: &str, goal_id: &str) -> Result<Option<LifeGoal>, LifeIntentError>;

    fn list_goals(&self, life_id: &str) -> Result<Vec<LifeGoal>, LifeIntentError>;

    fn delete_goal(&self, life_id: &str, goal_id: &str) -> Result<bool, LifeIntentError>;

    fn create_plan(
        &self,
        request: LifePlanCreateRequest,
    ) -> Result<LifeIntentCreateOutcome<LifePlan>, LifeIntentError>;

    fn find_plan(&self, life_id: &str, plan_id: &str) -> Result<Option<LifePlan>, LifeIntentError>;

    fn list_plans(&self, life_id: &str, goal_id: &str) -> Result<Vec<LifePlan>, LifeIntentError>;

    fn delete_plan(&self, life_id: &str, plan_id: &str) -> Result<bool, LifeIntentError>;

    fn create_step(
        &self,
        request: LifePlanStepCreateRequest,
    ) -> Result<LifeIntentCreateOutcome<LifePlanStep>, LifeIntentError>;

    fn find_step(
        &self,
        life_id: &str,
        step_id: &str,
    ) -> Result<Option<LifePlanStep>, LifeIntentError>;

    fn list_steps(
        &self,
        life_id: &str,
        plan_id: &str,
    ) -> Result<Vec<LifePlanStep>, LifeIntentError>;

    fn delete_step(&self, life_id: &str, step_id: &str) -> Result<bool, LifeIntentError>;

    fn create_action(
        &self,
        request: LifeActionIntentCreateRequest,
    ) -> Result<LifeIntentCreateOutcome<LifeActionIntent>, LifeIntentError>;

    fn find_action(
        &self,
        life_id: &str,
        action_id: &str,
    ) -> Result<Option<LifeActionIntent>, LifeIntentError>;

    fn list_actions(
        &self,
        life_id: &str,
        step_id: &str,
    ) -> Result<Vec<LifeActionIntent>, LifeIntentError>;

    fn delete_action(&self, life_id: &str, action_id: &str) -> Result<bool, LifeIntentError>;
}

const _: fn(&LifeGoal) -> Result<(), LifeIntentError> = validate_goal_shape;
const _: fn(&LifePlan) -> Result<(), LifeIntentError> = validate_plan_shape;
const _: fn(&LifePlanStep) -> Result<(), LifeIntentError> = validate_step_shape;
const _: fn(&LifeActionIntent) -> Result<(), LifeIntentError> = validate_action_shape;

pub(crate) fn validate_goal_shape(goal: &LifeGoal) -> Result<(), LifeIntentError> {
    validate_id("goal identity", &goal.goal_id)?;
    validate_nonempty("life identity", &goal.life_id)?;
    validate_title("goal title", &goal.title)?;
    validate_objective("goal objective", &goal.objective)?;
    if goal.status != GOAL_STATUS_ACTIVE {
        return Err(LifeIntentError::invalid_argument(
            "goal status must be active.",
        ));
    }
    if goal.revision != 1 {
        return Err(LifeIntentError::invalid_argument(
            "goal revision must be 1.",
        ));
    }
    if goal.created_by_kind != CREATED_BY_KIND_USER_EXPLICIT {
        return Err(LifeIntentError::invalid_argument(
            "goal creation kind must be user_explicit.",
        ));
    }
    if goal.goal_version != GOAL_VERSION {
        return Err(LifeIntentError::invalid_argument("goal version must be 1."));
    }
    validate_authority_timestamps("goal", &goal.created_at, &goal.updated_at, &goal.closed_at)?;
    Ok(())
}

pub(crate) fn validate_plan_shape(plan: &LifePlan) -> Result<(), LifeIntentError> {
    validate_id("plan identity", &plan.plan_id)?;
    validate_nonempty("life identity", &plan.life_id)?;
    validate_nonempty("goal identity", &plan.goal_id)?;
    validate_title("plan title", &plan.title)?;
    if plan.status != PLAN_STATUS_DRAFT {
        return Err(LifeIntentError::invalid_argument(
            "plan status must be draft.",
        ));
    }
    if plan.revision != 1 {
        return Err(LifeIntentError::invalid_argument(
            "plan revision must be 1.",
        ));
    }
    if plan.plan_version != PLAN_VERSION {
        return Err(LifeIntentError::invalid_argument("plan version must be 1."));
    }
    validate_authority_timestamps("plan", &plan.created_at, &plan.updated_at, &plan.closed_at)?;
    Ok(())
}

pub(crate) fn validate_step_shape(step: &LifePlanStep) -> Result<(), LifeIntentError> {
    validate_id("step identity", &step.step_id)?;
    validate_nonempty("life identity", &step.life_id)?;
    validate_nonempty("plan identity", &step.plan_id)?;
    if step.ordinal < 1 {
        return Err(LifeIntentError::invalid_argument(
            "step ordinal must be positive.",
        ));
    }
    validate_summary("step summary", &step.summary)?;
    if step.status != STEP_STATUS_PENDING {
        return Err(LifeIntentError::invalid_argument(
            "step status must be pending.",
        ));
    }
    if step.revision != 1 {
        return Err(LifeIntentError::invalid_argument(
            "step revision must be 1.",
        ));
    }
    if step.step_version != STEP_VERSION {
        return Err(LifeIntentError::invalid_argument("step version must be 1."));
    }
    validate_authority_timestamps("step", &step.created_at, &step.updated_at, &step.closed_at)?;
    Ok(())
}

pub(crate) fn validate_action_shape(action: &LifeActionIntent) -> Result<(), LifeIntentError> {
    validate_id("action identity", &action.action_id)?;
    validate_nonempty("life identity", &action.life_id)?;
    validate_nonempty("step identity", &action.step_id)?;
    if !matches!(
        action.execution_class.as_str(),
        EXECUTION_CLASS_INTERNAL_INTENT
            | EXECUTION_CLASS_AGENT_TASK_PROPOSAL
            | EXECUTION_CLASS_TOOL_OPERATION_PROPOSAL
    ) {
        return Err(LifeIntentError::invalid_argument(
            "execution class is not a supported V1 class.",
        ));
    }
    validate_summary("action summary", &action.summary)?;
    if action.status != ACTION_STATUS_PROPOSED {
        return Err(LifeIntentError::invalid_argument(
            "action status must be proposed.",
        ));
    }
    if action.revision != 1 {
        return Err(LifeIntentError::invalid_argument(
            "action revision must be 1.",
        ));
    }
    if action.action_version != ACTION_VERSION {
        return Err(LifeIntentError::invalid_argument(
            "action version must be 1.",
        ));
    }
    validate_authority_timestamps(
        "action",
        &action.created_at,
        &action.updated_at,
        &action.closed_at,
    )?;
    Ok(())
}

pub(crate) fn validate_goal_request(
    request: &LifeGoalCreateRequest,
) -> Result<(), LifeIntentError> {
    validate_id("goal identity", &request.goal_id)?;
    validate_nonempty("life identity", &request.life_id)?;
    validate_title("goal title", &request.title)?;
    validate_objective("goal objective", &request.objective)
}

pub(crate) fn validate_plan_request(
    request: &LifePlanCreateRequest,
) -> Result<(), LifeIntentError> {
    validate_id("plan identity", &request.plan_id)?;
    validate_nonempty("life identity", &request.life_id)?;
    validate_nonempty("goal identity", &request.goal_id)?;
    validate_title("plan title", &request.title)
}

pub(crate) fn validate_step_request(
    request: &LifePlanStepCreateRequest,
) -> Result<(), LifeIntentError> {
    validate_id("step identity", &request.step_id)?;
    validate_nonempty("life identity", &request.life_id)?;
    validate_nonempty("plan identity", &request.plan_id)?;
    if request.ordinal < 1 {
        return Err(LifeIntentError::invalid_argument(
            "step ordinal must be positive.",
        ));
    }
    validate_summary("step summary", &request.summary)
}

pub(crate) fn validate_action_request(
    request: &LifeActionIntentCreateRequest,
) -> Result<(), LifeIntentError> {
    validate_id("action identity", &request.action_id)?;
    validate_nonempty("life identity", &request.life_id)?;
    validate_nonempty("step identity", &request.step_id)?;
    if !matches!(
        request.execution_class.as_str(),
        EXECUTION_CLASS_INTERNAL_INTENT
            | EXECUTION_CLASS_AGENT_TASK_PROPOSAL
            | EXECUTION_CLASS_TOOL_OPERATION_PROPOSAL
    ) {
        return Err(LifeIntentError::invalid_argument(
            "execution class is not a supported V1 class.",
        ));
    }
    validate_summary("action summary", &request.summary)
}

fn validate_id(name: &str, value: &str) -> Result<(), LifeIntentError> {
    let trimmed = value.trim();
    // The frozen D14 ID limit is in Unicode scalar characters (matching
    // SQLite `length()`), never UTF-8 bytes.
    if trimmed.is_empty() || trimmed.chars().count() > MAX_ID_LENGTH {
        return Err(LifeIntentError::invalid_argument(format!(
            "{name} must be non-empty and at most {MAX_ID_LENGTH} characters."
        )));
    }
    Ok(())
}

fn validate_nonempty(name: &str, value: &str) -> Result<(), LifeIntentError> {
    if value.trim().is_empty() {
        return Err(LifeIntentError::invalid_argument(format!(
            "{name} must not be empty."
        )));
    }
    Ok(())
}

fn validate_title(name: &str, value: &str) -> Result<(), LifeIntentError> {
    let trimmed = value.trim();
    // Frozen D14 content limits are Unicode scalar character counts, matching
    // SQLite `length()`; a multibyte title must not be rejected by byte count.
    if trimmed.is_empty() || trimmed.chars().count() > MAX_TITLE_LENGTH {
        return Err(LifeIntentError::invalid_argument(format!(
            "{name} must be between 1 and {MAX_TITLE_LENGTH} characters after trimming."
        )));
    }
    Ok(())
}

fn validate_objective(name: &str, value: &str) -> Result<(), LifeIntentError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_OBJECTIVE_LENGTH {
        return Err(LifeIntentError::invalid_argument(format!(
            "{name} must be between 1 and {MAX_OBJECTIVE_LENGTH} characters after trimming."
        )));
    }
    Ok(())
}

fn validate_summary(name: &str, value: &str) -> Result<(), LifeIntentError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_SUMMARY_LENGTH {
        return Err(LifeIntentError::invalid_argument(format!(
            "{name} must be between 1 and {MAX_SUMMARY_LENGTH} characters after trimming."
        )));
    }
    Ok(())
}

fn validate_authority_timestamps(
    entity: &str,
    created_at: &str,
    updated_at: &str,
    closed_at: &Option<String>,
) -> Result<(), LifeIntentError> {
    if created_at.trim().is_empty() || updated_at.trim().is_empty() {
        return Err(LifeIntentError::invalid_argument(format!(
            "{entity} authority timestamps must not be empty."
        )));
    }
    if let Some(closed) = closed_at {
        if closed.trim().is_empty() {
            return Err(LifeIntentError::invalid_argument(format!(
                "{entity} closed timestamp must not be empty."
            )));
        }
    }
    Ok(())
}
