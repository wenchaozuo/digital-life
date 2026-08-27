//! D15-B2 autonomous-policy and proactive-intent authority.
//!
//! This module defines bounded, persisted authority records, the deterministic
//! InitiativePolicyV1 decision, and their crate-internal repository contract.
//! It evaluates only caller-selected pending intent evidence; it does not
//! create intents automatically, mutate D14 goals, deliver an intent, or
//! execute an Agent or Tool.

pub(crate) mod runtime;

pub(crate) const POLICY_VERSION: i64 = 1;
pub(crate) const POLICY_EVENT_VERSION: i64 = 1;
pub(crate) const INTENT_VERSION: i64 = 1;
pub(crate) const INTENT_EVENT_VERSION: i64 = 1;
pub(crate) const INITIATIVE_POLICY_VERSION: i64 = 1;

pub(crate) const POLICY_ACTOR_KIND_USER_EXPLICIT: &str = "user_explicit";
pub(crate) const INTENT_CREATED_BY_KIND_AUTONOMY_POLICY: &str = "autonomy_policy";
pub(crate) const INTENT_EVENT_ACTOR_KIND_AUTONOMY_POLICY: &str = "autonomy_policy";

pub(crate) const INTENT_KIND_GOAL_CHECK_IN: &str = "goal_check_in";

pub(crate) const INTENT_FOCUS_STATE_UNKNOWN: &str = "unknown";
pub(crate) const INTENT_FOCUS_STATE_AVAILABLE: &str = "available";
pub(crate) const INTENT_FOCUS_STATE_FOCUSED: &str = "focused";
pub(crate) const INTENT_FOCUS_STATE_DND: &str = "dnd";

pub(crate) const INTENT_STATUS_PENDING: &str = "pending";
pub(crate) const INTENT_STATUS_READY: &str = "ready";
pub(crate) const INTENT_STATUS_DEFERRED: &str = "deferred";
pub(crate) const INTENT_STATUS_STORED_SILENTLY: &str = "stored_silently";
pub(crate) const INTENT_STATUS_CANCELLED: &str = "cancelled";
pub(crate) const INTENT_STATUS_EXPIRED: &str = "expired";
pub(crate) const INTENT_STATUS_CONSUMED: &str = "consumed";

pub(crate) const MAX_ID_LENGTH: usize = 128;
pub(crate) const SIGNAL_MIN: i64 = 0;
pub(crate) const SIGNAL_MAX: i64 = 1000;
pub(crate) const MAX_READY_PER_WINDOW_MIN: i64 = 0;
pub(crate) const MAX_READY_PER_WINDOW_MAX: i64 = 32;
pub(crate) const WINDOW_SECONDS_MIN: i64 = 60;
pub(crate) const WINDOW_SECONDS_MAX: i64 = 86_400;
pub(crate) const MIN_GAP_SECONDS_MIN: i64 = 0;
pub(crate) const MIN_GAP_SECONDS_MAX: i64 = 86_400;

pub(crate) const MIN_RECHECK_SECONDS: i64 = 60;
pub(crate) const RECENT_INTERACTION_QUIET_SECONDS: i64 = 120;
pub(crate) const NEUTRAL_ACCEPTANCE_SCORE: i64 = 500;
pub(crate) const MIN_USER_RELEVANCE_FOR_INTERRUPT: i64 = 500;
pub(crate) const MAX_INTERRUPTION_COST_FOR_INTERRUPT: i64 = 600;
pub(crate) const MIN_ACCEPTANCE_FOR_INTERRUPT: i64 = 400;
pub(crate) const READINESS_SCORE_THRESHOLD: i64 = 2500;
pub(crate) const SELF_DESIRE_CONTRIBUTION_CAP: i64 = 500;

/// One explicit opt-in policy row.  No row is also a meaningful state: it
/// means autonomy is disabled for that Life.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeAutonomyPolicy {
    pub(crate) life_id: String,
    pub(crate) enabled: bool,
    pub(crate) dnd: bool,
    pub(crate) max_ready_per_window: i64,
    pub(crate) window_seconds: i64,
    pub(crate) min_gap_seconds: i64,
    pub(crate) revision: i64,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) policy_version: i64,
}

impl LifeAutonomyPolicy {
    /// Effective opt-in state.  DND is an authority flag that suppresses
    /// proactive behavior even when the policy remains enabled.
    pub(crate) fn is_effectively_enabled(&self) -> bool {
        self.enabled && !self.dnd
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeAutonomyPolicyCreateRequest {
    pub(crate) life_id: String,
    pub(crate) enabled: bool,
    pub(crate) dnd: bool,
    pub(crate) max_ready_per_window: i64,
    pub(crate) window_seconds: i64,
    pub(crate) min_gap_seconds: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeAutonomyPolicyUpdateRequest {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) enabled: bool,
    pub(crate) dnd: bool,
    pub(crate) max_ready_per_window: i64,
    pub(crate) window_seconds: i64,
    pub(crate) min_gap_seconds: i64,
    pub(crate) expected_revision: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeAutonomyPolicyEvent {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) old_enabled: bool,
    pub(crate) new_enabled: bool,
    pub(crate) old_dnd: bool,
    pub(crate) new_dnd: bool,
    pub(crate) old_max_ready_per_window: i64,
    pub(crate) new_max_ready_per_window: i64,
    pub(crate) old_window_seconds: i64,
    pub(crate) new_window_seconds: i64,
    pub(crate) old_min_gap_seconds: i64,
    pub(crate) new_min_gap_seconds: i64,
    pub(crate) expected_revision: i64,
    pub(crate) applied_revision: i64,
    pub(crate) actor_kind: String,
    pub(crate) occurred_at: String,
    pub(crate) event_version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AutonomyCreateOutcome<T> {
    Applied(T),
    Replayed(T),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LifeAutonomyPolicyUpdateOutcome {
    Applied {
        event: LifeAutonomyPolicyEvent,
        policy: LifeAutonomyPolicy,
    },
    Replayed {
        event: LifeAutonomyPolicyEvent,
        current: LifeAutonomyPolicy,
    },
}

/// One persisted proactive intent.  B1 creates only `pending` rows for the
/// single `goal_check_in` kind; the remaining statuses and lifecycle columns
/// are represented now for the governed B2 state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeProactiveIntent {
    pub(crate) intent_id: String,
    pub(crate) life_id: String,
    pub(crate) goal_id: String,
    pub(crate) intent_kind: String,
    pub(crate) importance: i64,
    pub(crate) user_relevance: i64,
    pub(crate) self_desire: i64,
    pub(crate) interruption_cost: i64,
    pub(crate) focus_state: String,
    pub(crate) acceptance_score: Option<i64>,
    pub(crate) recent_interaction_seconds: Option<i64>,
    pub(crate) status: String,
    pub(crate) revision: i64,
    pub(crate) created_by_kind: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) not_before: Option<String>,
    pub(crate) expires_at: Option<String>,
    pub(crate) closed_at: Option<String>,
    pub(crate) intent_version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeProactiveIntentCreateRequest {
    pub(crate) intent_id: String,
    pub(crate) life_id: String,
    pub(crate) goal_id: String,
    pub(crate) intent_kind: String,
    pub(crate) importance: i64,
    pub(crate) user_relevance: i64,
    pub(crate) self_desire: i64,
    pub(crate) interruption_cost: i64,
    pub(crate) focus_state: String,
    pub(crate) acceptance_score: Option<i64>,
    pub(crate) recent_interaction_seconds: Option<i64>,
    pub(crate) expires_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeProactiveIntentEvaluationRequest {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) intent_id: String,
    pub(crate) expected_revision: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifeProactiveIntentEvent {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) intent_id: String,
    pub(crate) from_status: String,
    pub(crate) to_status: String,
    pub(crate) expected_revision: i64,
    pub(crate) applied_revision: i64,
    pub(crate) not_before_after: Option<String>,
    pub(crate) actor_kind: String,
    pub(crate) occurred_at: String,
    pub(crate) event_version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LifeProactiveIntentEvaluationOutcome {
    Applied {
        event: LifeProactiveIntentEvent,
        intent: LifeProactiveIntent,
    },
    Replayed {
        event: LifeProactiveIntentEvent,
        current: LifeProactiveIntent,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InitiativePolicyDecision {
    Ready,
    Deferred,
    StoredSilently,
    Cancelled,
    Expired,
}

/// SQLite derives the temporal candidates; this value object keeps the
/// decision and value policy deterministic and independent of storage.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct InitiativePolicyTemporalContext {
    pub(crate) recent_interaction_not_before: Option<String>,
    pub(crate) temporary_gate_not_before: Option<String>,
    pub(crate) frequency_not_before: Option<String>,
    pub(crate) min_gap_not_before: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AutonomyErrorCode {
    InvalidArgument,
    LifeNotFound,
    PolicyNotFound,
    PolicyDisabled,
    PolicyConflict,
    AutonomyPolicyEventConflict,
    GoalNotFound,
    GoalLifeMismatch,
    GoalNotActive,
    ProactiveIntentConflict,
    IntentNotFound,
    IntentLifeMismatch,
    InvalidIntentState,
    ProactiveIntentEventConflict,
    DatabaseUnavailable,
    RevisionConflict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AutonomyError {
    pub(crate) code: AutonomyErrorCode,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl AutonomyError {
    pub(crate) fn new(code: AutonomyErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: matches!(
                code,
                AutonomyErrorCode::LifeNotFound
                    | AutonomyErrorCode::PolicyNotFound
                    | AutonomyErrorCode::PolicyDisabled
                    | AutonomyErrorCode::GoalNotFound
                    | AutonomyErrorCode::DatabaseUnavailable
            ),
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(AutonomyErrorCode::InvalidArgument, message)
    }

    pub(crate) fn life_not_found() -> Self {
        Self::new(
            AutonomyErrorCode::LifeNotFound,
            "The specified life was not found.",
        )
    }

    pub(crate) fn policy_not_found() -> Self {
        Self::new(
            AutonomyErrorCode::PolicyNotFound,
            "No autonomy policy exists for the specified life.",
        )
    }

    pub(crate) fn policy_disabled() -> Self {
        Self::new(
            AutonomyErrorCode::PolicyDisabled,
            "Autonomy is disabled for the specified life.",
        )
    }

    pub(crate) fn policy_conflict() -> Self {
        Self::new(
            AutonomyErrorCode::PolicyConflict,
            "An autonomy policy with conflicting evidence already exists.",
        )
    }

    pub(crate) fn autonomy_policy_event_conflict() -> Self {
        Self::new(
            AutonomyErrorCode::AutonomyPolicyEventConflict,
            "An autonomy policy event with conflicting evidence already exists.",
        )
    }

    pub(crate) fn goal_not_found() -> Self {
        Self::new(
            AutonomyErrorCode::GoalNotFound,
            "The specified LifeGoal was not found.",
        )
    }

    pub(crate) fn goal_life_mismatch() -> Self {
        Self::new(
            AutonomyErrorCode::GoalLifeMismatch,
            "The specified LifeGoal belongs to a different Life.",
        )
    }

    pub(crate) fn goal_not_active() -> Self {
        Self::new(
            AutonomyErrorCode::GoalNotActive,
            "The specified LifeGoal is not active.",
        )
    }

    pub(crate) fn proactive_intent_conflict() -> Self {
        Self::new(
            AutonomyErrorCode::ProactiveIntentConflict,
            "A proactive intent with conflicting evidence already exists.",
        )
    }

    pub(crate) fn intent_not_found() -> Self {
        Self::new(
            AutonomyErrorCode::IntentNotFound,
            "The specified proactive intent was not found.",
        )
    }

    pub(crate) fn intent_life_mismatch() -> Self {
        Self::new(
            AutonomyErrorCode::IntentLifeMismatch,
            "The specified proactive intent belongs to a different Life.",
        )
    }

    pub(crate) fn invalid_intent_state() -> Self {
        Self::new(
            AutonomyErrorCode::InvalidIntentState,
            "The proactive intent is not eligible for this lifecycle operation.",
        )
    }

    pub(crate) fn proactive_intent_event_conflict() -> Self {
        Self::new(
            AutonomyErrorCode::ProactiveIntentEventConflict,
            "A proactive intent event with conflicting evidence already exists.",
        )
    }

    pub(crate) fn database() -> Self {
        Self::new(
            AutonomyErrorCode::DatabaseUnavailable,
            "The autonomy authority storage operation failed.",
        )
    }

    pub(crate) fn revision_conflict() -> Self {
        Self::new(
            AutonomyErrorCode::RevisionConflict,
            "The autonomy policy changed after it was loaded. Refresh and try again.",
        )
    }
}

/// Crate-internal autonomy authority boundary. It exposes bounded policy and
/// intent persistence plus pending evaluation; it has no scheduler, delivery,
/// or execution operation.
pub(crate) trait AutonomyRepository: Send + Sync {
    fn create_policy(
        &self,
        request: LifeAutonomyPolicyCreateRequest,
    ) -> Result<AutonomyCreateOutcome<LifeAutonomyPolicy>, AutonomyError>;

    fn find_policy(&self, life_id: &str) -> Result<Option<LifeAutonomyPolicy>, AutonomyError>;

    fn update_policy(
        &self,
        request: LifeAutonomyPolicyUpdateRequest,
    ) -> Result<LifeAutonomyPolicyUpdateOutcome, AutonomyError>;

    fn create_pending_goal_check_in_intent(
        &self,
        request: LifeProactiveIntentCreateRequest,
    ) -> Result<AutonomyCreateOutcome<LifeProactiveIntent>, AutonomyError>;

    fn evaluate_pending_intent(
        &self,
        request: LifeProactiveIntentEvaluationRequest,
    ) -> Result<LifeProactiveIntentEvaluationOutcome, AutonomyError>;

    fn find_intent(
        &self,
        life_id: &str,
        intent_id: &str,
    ) -> Result<Option<LifeProactiveIntent>, AutonomyError>;

    fn list_intents_for_life(
        &self,
        life_id: &str,
    ) -> Result<Vec<LifeProactiveIntent>, AutonomyError>;

    fn list_intents_for_goal(
        &self,
        life_id: &str,
        goal_id: &str,
    ) -> Result<Vec<LifeProactiveIntent>, AutonomyError>;

    fn find_latest_intent_for_goal(
        &self,
        life_id: &str,
        goal_id: &str,
    ) -> Result<Option<LifeProactiveIntent>, AutonomyError>;

    fn find_intent_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeProactiveIntentEvent>, AutonomyError>;

    fn find_policy_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeAutonomyPolicyEvent>, AutonomyError>;
}

pub(crate) fn validate_policy_create_request(
    request: &LifeAutonomyPolicyCreateRequest,
) -> Result<(), AutonomyError> {
    validate_life_id(&request.life_id)?;
    validate_policy_values(
        request.max_ready_per_window,
        request.window_seconds,
        request.min_gap_seconds,
    )
}

pub(crate) fn validate_policy_update_request(
    request: &LifeAutonomyPolicyUpdateRequest,
) -> Result<(), AutonomyError> {
    validate_id("policy event identity", &request.event_id)?;
    validate_life_id(&request.life_id)?;
    validate_policy_values(
        request.max_ready_per_window,
        request.window_seconds,
        request.min_gap_seconds,
    )?;
    validate_expected_revision(request.expected_revision)
}

pub(crate) fn validate_intent_create_request(
    request: &LifeProactiveIntentCreateRequest,
) -> Result<(), AutonomyError> {
    validate_id("intent identity", &request.intent_id)?;
    validate_life_id(&request.life_id)?;
    validate_id("goal identity", &request.goal_id)?;
    if request.intent_kind != INTENT_KIND_GOAL_CHECK_IN {
        return Err(AutonomyError::invalid_argument(
            "intent kind must be goal_check_in.",
        ));
    }
    for (name, value) in [
        ("importance", request.importance),
        ("user relevance", request.user_relevance),
        ("self desire", request.self_desire),
        ("interruption cost", request.interruption_cost),
    ] {
        validate_signal(name, value)?;
    }
    if let Some(value) = request.acceptance_score {
        validate_signal("acceptance score", value)?;
    }
    if let Some(value) = request.recent_interaction_seconds {
        if value < 0 {
            return Err(AutonomyError::invalid_argument(
                "recent interaction seconds must not be negative.",
            ));
        }
    }
    validate_focus_state(&request.focus_state)?;
    validate_optional_canonical_timestamp("expires_at", &request.expires_at)
}

pub(crate) fn validate_intent_evaluation_request(
    request: &LifeProactiveIntentEvaluationRequest,
) -> Result<(), AutonomyError> {
    validate_id("intent event identity", &request.event_id)?;
    validate_life_id(&request.life_id)?;
    validate_id("intent identity", &request.intent_id)?;
    validate_expected_revision(request.expected_revision)
}

pub(crate) fn evaluate_initiative_policy(
    intent: &LifeProactiveIntent,
    policy: Option<&LifeAutonomyPolicy>,
    goal_is_active: bool,
    now: &str,
    temporal: &InitiativePolicyTemporalContext,
) -> Result<InitiativePolicyDecision, AutonomyError> {
    if intent
        .expires_at
        .as_deref()
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Ok(InitiativePolicyDecision::Expired);
    }

    let Some(policy) = policy else {
        return Ok(InitiativePolicyDecision::Cancelled);
    };
    if policy.policy_version != INITIATIVE_POLICY_VERSION {
        return Err(AutonomyError::invalid_argument(
            "initiative policy version must be 1.",
        ));
    }
    if !policy.enabled || !goal_is_active {
        return Ok(InitiativePolicyDecision::Cancelled);
    }
    if policy.max_ready_per_window == 0 {
        return Ok(InitiativePolicyDecision::StoredSilently);
    }

    let recent_gate_required = intent
        .recent_interaction_seconds
        .is_none_or(|seconds| seconds < RECENT_INTERACTION_QUIET_SECONDS);
    let temporary_gate_required = policy.dnd || intent.focus_state != INTENT_FOCUS_STATE_AVAILABLE;
    let mut defer_candidates = Vec::with_capacity(4);
    if recent_gate_required {
        defer_candidates.push(
            temporal
                .recent_interaction_not_before
                .as_deref()
                .ok_or_else(|| {
                    AutonomyError::invalid_argument(
                        "recent interaction gate is missing its authority timestamp.",
                    )
                })?,
        );
    }
    if temporary_gate_required {
        defer_candidates.push(
            temporal
                .temporary_gate_not_before
                .as_deref()
                .ok_or_else(|| {
                    AutonomyError::invalid_argument(
                        "temporary interruption gate is missing its authority timestamp.",
                    )
                })?,
        );
    }
    if let Some(candidate) = temporal.frequency_not_before.as_deref() {
        defer_candidates.push(candidate);
    }
    if let Some(candidate) = temporal.min_gap_not_before.as_deref() {
        defer_candidates.push(candidate);
    }
    if let Some(_latest) = defer_candidates.into_iter().max() {
        return Ok(InitiativePolicyDecision::Deferred);
    }

    if intent.user_relevance < MIN_USER_RELEVANCE_FOR_INTERRUPT
        || intent.interruption_cost > MAX_INTERRUPTION_COST_FOR_INTERRUPT
        || intent.acceptance_score.unwrap_or(NEUTRAL_ACCEPTANCE_SCORE)
            < MIN_ACCEPTANCE_FOR_INTERRUPT
    {
        return Ok(InitiativePolicyDecision::StoredSilently);
    }

    let acceptance = intent.acceptance_score.unwrap_or(NEUTRAL_ACCEPTANCE_SCORE);
    let support = intent
        .importance
        .checked_mul(2)
        .and_then(|value| value.checked_add(intent.user_relevance.checked_mul(3)?))
        .and_then(|value| value.checked_add(intent.self_desire.min(SELF_DESIRE_CONTRIBUTION_CAP)))
        .and_then(|value| value.checked_add(acceptance))
        .ok_or_else(|| AutonomyError::invalid_argument("initiative support is unrepresentable."))?;
    let cost = intent
        .interruption_cost
        .checked_mul(3)
        .ok_or_else(|| AutonomyError::invalid_argument("initiative cost is unrepresentable."))?;
    let readiness_score = support
        .checked_sub(cost)
        .ok_or_else(|| AutonomyError::invalid_argument("initiative score is unrepresentable."))?;
    if readiness_score >= READINESS_SCORE_THRESHOLD {
        Ok(InitiativePolicyDecision::Ready)
    } else {
        Ok(InitiativePolicyDecision::StoredSilently)
    }
}

pub(crate) fn validate_policy_state(policy: &LifeAutonomyPolicy) -> Result<(), AutonomyError> {
    validate_life_id(&policy.life_id)?;
    validate_policy_values(
        policy.max_ready_per_window,
        policy.window_seconds,
        policy.min_gap_seconds,
    )?;
    validate_persisted_revision(policy.revision)?;
    if policy.policy_version != POLICY_VERSION {
        return Err(AutonomyError::invalid_argument("policy version must be 1."));
    }
    validate_required_timestamp("policy created_at", &policy.created_at)?;
    validate_required_timestamp("policy updated_at", &policy.updated_at)
}

pub(crate) fn validate_intent_state(intent: &LifeProactiveIntent) -> Result<(), AutonomyError> {
    validate_id("intent identity", &intent.intent_id)?;
    validate_life_id(&intent.life_id)?;
    validate_id("goal identity", &intent.goal_id)?;
    if intent.intent_kind != INTENT_KIND_GOAL_CHECK_IN {
        return Err(AutonomyError::invalid_argument(
            "intent kind must be goal_check_in.",
        ));
    }
    for (name, value) in [
        ("importance", intent.importance),
        ("user relevance", intent.user_relevance),
        ("self desire", intent.self_desire),
        ("interruption cost", intent.interruption_cost),
    ] {
        validate_signal(name, value)?;
    }
    if let Some(value) = intent.acceptance_score {
        validate_signal("acceptance score", value)?;
    }
    if let Some(value) = intent.recent_interaction_seconds {
        if value < 0 {
            return Err(AutonomyError::invalid_argument(
                "recent interaction seconds must not be negative.",
            ));
        }
    }
    validate_focus_state(&intent.focus_state)?;
    if !matches!(
        intent.status.as_str(),
        INTENT_STATUS_PENDING
            | INTENT_STATUS_READY
            | INTENT_STATUS_DEFERRED
            | INTENT_STATUS_STORED_SILENTLY
            | INTENT_STATUS_CANCELLED
            | INTENT_STATUS_EXPIRED
            | INTENT_STATUS_CONSUMED
    ) {
        return Err(AutonomyError::invalid_argument(
            "intent status is not a supported V1 status.",
        ));
    }
    validate_persisted_revision(intent.revision)?;
    if intent.created_by_kind != INTENT_CREATED_BY_KIND_AUTONOMY_POLICY {
        return Err(AutonomyError::invalid_argument(
            "intent creation kind must be autonomy_policy.",
        ));
    }
    if intent.intent_version != INTENT_VERSION {
        return Err(AutonomyError::invalid_argument("intent version must be 1."));
    }
    validate_required_timestamp("intent created_at", &intent.created_at)?;
    validate_required_timestamp("intent updated_at", &intent.updated_at)?;
    validate_optional_canonical_timestamp("not_before", &intent.not_before)?;
    validate_optional_canonical_timestamp("expires_at", &intent.expires_at)?;
    validate_optional_canonical_timestamp("closed_at", &intent.closed_at)?;

    if intent.status == INTENT_STATUS_DEFERRED {
        if intent.not_before.is_none() {
            return Err(AutonomyError::invalid_argument(
                "deferred intent must have not_before.",
            ));
        }
    } else if intent.not_before.is_some() {
        return Err(AutonomyError::invalid_argument(
            "only deferred intent may have not_before.",
        ));
    }
    let is_open = matches!(
        intent.status.as_str(),
        INTENT_STATUS_PENDING | INTENT_STATUS_READY | INTENT_STATUS_DEFERRED
    );
    if is_open && intent.closed_at.is_some() {
        return Err(AutonomyError::invalid_argument(
            "open intent status must not have closed_at.",
        ));
    }
    if !is_open && intent.closed_at.is_none() {
        return Err(AutonomyError::invalid_argument(
            "terminal intent status must have closed_at.",
        ));
    }
    Ok(())
}

pub(crate) fn validate_policy_event_state(
    event: &LifeAutonomyPolicyEvent,
) -> Result<(), AutonomyError> {
    validate_id("policy event identity", &event.event_id)?;
    validate_life_id(&event.life_id)?;
    validate_policy_values(
        event.old_max_ready_per_window,
        event.old_window_seconds,
        event.old_min_gap_seconds,
    )?;
    validate_policy_values(
        event.new_max_ready_per_window,
        event.new_window_seconds,
        event.new_min_gap_seconds,
    )?;
    validate_expected_revision(event.expected_revision)?;
    if Some(event.applied_revision) != event.expected_revision.checked_add(1) {
        return Err(AutonomyError::invalid_argument(
            "policy event applied revision must equal expected revision plus one.",
        ));
    }
    if event.actor_kind != POLICY_ACTOR_KIND_USER_EXPLICIT {
        return Err(AutonomyError::invalid_argument(
            "policy event actor kind must be user_explicit.",
        ));
    }
    if event.event_version != POLICY_EVENT_VERSION {
        return Err(AutonomyError::invalid_argument(
            "policy event version must be 1.",
        ));
    }
    validate_required_timestamp("policy event occurred_at", &event.occurred_at)
}

pub(crate) fn validate_intent_event_state(
    event: &LifeProactiveIntentEvent,
) -> Result<(), AutonomyError> {
    validate_id("intent event identity", &event.event_id)?;
    validate_life_id(&event.life_id)?;
    validate_id("intent identity", &event.intent_id)?;
    if !is_intent_status(&event.from_status) || !is_intent_status(&event.to_status) {
        return Err(AutonomyError::invalid_argument(
            "intent event status is not supported.",
        ));
    }
    if event.from_status == event.to_status {
        return Err(AutonomyError::invalid_argument(
            "intent event must change status.",
        ));
    }
    validate_expected_revision(event.expected_revision)?;
    if Some(event.applied_revision) != event.expected_revision.checked_add(1) {
        return Err(AutonomyError::invalid_argument(
            "intent event applied revision must equal expected revision plus one.",
        ));
    }
    validate_optional_canonical_timestamp("not_before_after", &event.not_before_after)?;
    if event.actor_kind != INTENT_EVENT_ACTOR_KIND_AUTONOMY_POLICY {
        return Err(AutonomyError::invalid_argument(
            "intent event actor kind must be autonomy_policy.",
        ));
    }
    if event.event_version != INTENT_EVENT_VERSION {
        return Err(AutonomyError::invalid_argument(
            "intent event version must be 1.",
        ));
    }
    validate_required_timestamp("intent event occurred_at", &event.occurred_at)
}

fn validate_life_id(value: &str) -> Result<(), AutonomyError> {
    if value.trim().is_empty() {
        return Err(AutonomyError::invalid_argument(
            "life identity must not be empty.",
        ));
    }
    Ok(())
}

fn validate_id(name: &str, value: &str) -> Result<(), AutonomyError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_ID_LENGTH {
        return Err(AutonomyError::invalid_argument(format!(
            "{name} must be between 1 and {MAX_ID_LENGTH} characters after trimming."
        )));
    }
    Ok(())
}

fn validate_policy_values(
    max_ready_per_window: i64,
    window_seconds: i64,
    min_gap_seconds: i64,
) -> Result<(), AutonomyError> {
    if !(MAX_READY_PER_WINDOW_MIN..=MAX_READY_PER_WINDOW_MAX).contains(&max_ready_per_window) {
        return Err(AutonomyError::invalid_argument(
            "max ready per window must be between 0 and 32.",
        ));
    }
    if !(WINDOW_SECONDS_MIN..=WINDOW_SECONDS_MAX).contains(&window_seconds) {
        return Err(AutonomyError::invalid_argument(
            "window seconds must be between 60 and 86400.",
        ));
    }
    if !(MIN_GAP_SECONDS_MIN..=MIN_GAP_SECONDS_MAX).contains(&min_gap_seconds) {
        return Err(AutonomyError::invalid_argument(
            "minimum gap seconds must be between 0 and 86400.",
        ));
    }
    Ok(())
}

fn validate_signal(name: &str, value: i64) -> Result<(), AutonomyError> {
    if !(SIGNAL_MIN..=SIGNAL_MAX).contains(&value) {
        return Err(AutonomyError::invalid_argument(format!(
            "{name} must be between 0 and 1000."
        )));
    }
    Ok(())
}

fn validate_focus_state(value: &str) -> Result<(), AutonomyError> {
    if !matches!(
        value,
        INTENT_FOCUS_STATE_UNKNOWN
            | INTENT_FOCUS_STATE_AVAILABLE
            | INTENT_FOCUS_STATE_FOCUSED
            | INTENT_FOCUS_STATE_DND
    ) {
        return Err(AutonomyError::invalid_argument(
            "focus state must be unknown, available, focused, or dnd.",
        ));
    }
    Ok(())
}

fn is_intent_status(value: &str) -> bool {
    matches!(
        value,
        INTENT_STATUS_PENDING
            | INTENT_STATUS_READY
            | INTENT_STATUS_DEFERRED
            | INTENT_STATUS_STORED_SILENTLY
            | INTENT_STATUS_CANCELLED
            | INTENT_STATUS_EXPIRED
            | INTENT_STATUS_CONSUMED
    )
}

fn validate_persisted_revision(revision: i64) -> Result<(), AutonomyError> {
    if revision < 1 {
        return Err(AutonomyError::invalid_argument(
            "revision must be at least 1.",
        ));
    }
    Ok(())
}

fn validate_expected_revision(revision: i64) -> Result<(), AutonomyError> {
    if !(1..i64::MAX).contains(&revision) {
        return Err(AutonomyError::invalid_argument(
            "expected revision must be at least 1 and less than i64::MAX.",
        ));
    }
    Ok(())
}

fn validate_required_timestamp(name: &str, value: &str) -> Result<(), AutonomyError> {
    if value.trim().is_empty() {
        return Err(AutonomyError::invalid_argument(format!(
            "{name} must not be empty."
        )));
    }
    Ok(())
}

fn validate_optional_canonical_timestamp(
    name: &str,
    value: &Option<String>,
) -> Result<(), AutonomyError> {
    let Some(value) = value else {
        return Ok(());
    };
    let bytes = value.as_bytes();
    let canonical = bytes.len() == 24
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'.'
        && bytes[23] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 23) || byte.is_ascii_digit()
        });
    if !canonical {
        return Err(AutonomyError::invalid_argument(format!(
            "{name} must use canonical SQLite UTC timestamp form."
        )));
    }
    Ok(())
}

const _: fn(&LifeAutonomyPolicyCreateRequest) -> Result<(), AutonomyError> =
    validate_policy_create_request;
const _: fn(&LifeAutonomyPolicyUpdateRequest) -> Result<(), AutonomyError> =
    validate_policy_update_request;
const _: fn(&LifeProactiveIntentCreateRequest) -> Result<(), AutonomyError> =
    validate_intent_create_request;

#[cfg(test)]
mod initiative_policy_tests {
    use super::*;

    fn policy() -> LifeAutonomyPolicy {
        LifeAutonomyPolicy {
            life_id: "life-a".into(),
            enabled: true,
            dnd: false,
            max_ready_per_window: 1,
            window_seconds: 900,
            min_gap_seconds: 0,
            revision: 1,
            created_at: "2026-08-27T00:00:00.000Z".into(),
            updated_at: "2026-08-27T00:00:00.000Z".into(),
            policy_version: POLICY_VERSION,
        }
    }

    fn sample_intent() -> LifeProactiveIntent {
        LifeProactiveIntent {
            intent_id: "intent-a".into(),
            life_id: "life-a".into(),
            goal_id: "goal-a".into(),
            intent_kind: INTENT_KIND_GOAL_CHECK_IN.into(),
            importance: 700,
            user_relevance: 800,
            self_desire: 200,
            interruption_cost: 100,
            focus_state: INTENT_FOCUS_STATE_AVAILABLE.into(),
            acceptance_score: Some(600),
            recent_interaction_seconds: Some(120),
            status: INTENT_STATUS_PENDING.into(),
            revision: 1,
            created_by_kind: INTENT_CREATED_BY_KIND_AUTONOMY_POLICY.into(),
            created_at: "2026-08-27T00:00:00.000Z".into(),
            updated_at: "2026-08-27T00:00:00.000Z".into(),
            not_before: None,
            expires_at: None,
            closed_at: None,
            intent_version: INTENT_VERSION,
        }
    }

    fn evaluate(intent: &LifeProactiveIntent) -> InitiativePolicyDecision {
        evaluate_initiative_policy(
            intent,
            Some(&policy()),
            true,
            "2026-08-27T01:00:00.000Z",
            &InitiativePolicyTemporalContext::default(),
        )
        .unwrap()
    }

    #[test]
    fn value_policy_boundaries_are_deterministic() {
        let mut intent = sample_intent();
        intent.user_relevance = 499;
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::StoredSilently);
        intent.user_relevance = 500;
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::Ready);

        intent = sample_intent();
        intent.interruption_cost = 601;
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::StoredSilently);
        intent.interruption_cost = 600;
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::Ready);

        intent = sample_intent();
        intent.acceptance_score = Some(399);
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::StoredSilently);
        intent.acceptance_score = Some(400);
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::Ready);

        intent = sample_intent();
        intent.acceptance_score = None;
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::Ready);

        intent = sample_intent();
        intent.importance = 999;
        intent.user_relevance = 500;
        intent.self_desire = 99;
        intent.acceptance_score = Some(400);
        intent.interruption_cost = 600;
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::StoredSilently);
        intent.self_desire = 1000;
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::Ready);

        intent = sample_intent();
        intent.importance = 950;
        intent.user_relevance = 500;
        intent.self_desire = 499;
        intent.acceptance_score = Some(400);
        intent.interruption_cost = 600;
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::StoredSilently);
        intent.acceptance_score = Some(401);
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::Ready);
    }

    #[test]
    fn zero_ready_budget_precedes_temporal_and_value_gates() {
        let mut zero_budget = policy();
        zero_budget.max_ready_per_window = 0;
        zero_budget.dnd = true;

        for focus_state in [
            INTENT_FOCUS_STATE_AVAILABLE,
            INTENT_FOCUS_STATE_UNKNOWN,
            INTENT_FOCUS_STATE_FOCUSED,
            INTENT_FOCUS_STATE_DND,
        ] {
            let mut intent = sample_intent();
            intent.focus_state = focus_state.into();
            intent.recent_interaction_seconds = Some(120);
            assert_eq!(
                evaluate_initiative_policy(
                    &intent,
                    Some(&zero_budget),
                    true,
                    "2026-08-27T01:00:00.000Z",
                    &InitiativePolicyTemporalContext::default(),
                )
                .unwrap(),
                InitiativePolicyDecision::StoredSilently
            );
        }

        zero_budget.dnd = false;
        for recent_interaction_seconds in [None, Some(0), Some(119)] {
            let mut intent = sample_intent();
            intent.recent_interaction_seconds = recent_interaction_seconds;
            intent.importance = 0;
            intent.user_relevance = 0;
            intent.self_desire = 1000;
            intent.interruption_cost = 1000;
            intent.acceptance_score = Some(0);
            assert_eq!(
                evaluate_initiative_policy(
                    &intent,
                    Some(&zero_budget),
                    true,
                    "2026-08-27T01:00:00.000Z",
                    &InitiativePolicyTemporalContext::default(),
                )
                .unwrap(),
                InitiativePolicyDecision::StoredSilently
            );
        }
    }

    #[test]
    fn policy_outputs_handle_expiry_policy_goal_and_temporal_precedence() {
        let mut intent = sample_intent();
        intent.expires_at = Some("2026-08-27T00:59:59.999Z".into());
        assert_eq!(evaluate(&intent), InitiativePolicyDecision::Expired);

        let intent = sample_intent();
        assert_eq!(
            evaluate_initiative_policy(
                &intent,
                None,
                false,
                "2026-08-27T01:00:00.000Z",
                &InitiativePolicyTemporalContext::default(),
            )
            .unwrap(),
            InitiativePolicyDecision::Cancelled
        );
        let mut disabled = policy();
        disabled.enabled = false;
        assert_eq!(
            evaluate_initiative_policy(
                &intent,
                Some(&disabled),
                true,
                "2026-08-27T01:00:00.000Z",
                &InitiativePolicyTemporalContext::default(),
            )
            .unwrap(),
            InitiativePolicyDecision::Cancelled
        );
        assert_eq!(
            evaluate_initiative_policy(
                &intent,
                Some(&policy()),
                false,
                "2026-08-27T01:00:00.000Z",
                &InitiativePolicyTemporalContext::default(),
            )
            .unwrap(),
            InitiativePolicyDecision::Cancelled
        );

        let mut temporal = InitiativePolicyTemporalContext {
            recent_interaction_not_before: Some("2026-08-27T01:01:00.000Z".into()),
            temporary_gate_not_before: Some("2026-08-27T01:02:00.000Z".into()),
            frequency_not_before: Some("2026-08-27T01:03:00.000Z".into()),
            min_gap_not_before: Some("2026-08-27T01:04:00.000Z".into()),
        };
        assert_eq!(
            evaluate_initiative_policy(
                &intent,
                Some(&policy()),
                true,
                "2026-08-27T01:00:00.000Z",
                &temporal,
            )
            .unwrap(),
            InitiativePolicyDecision::Deferred
        );
        temporal = InitiativePolicyTemporalContext::default();
        let mut focus_blocked = intent;
        focus_blocked.focus_state = INTENT_FOCUS_STATE_FOCUSED.into();
        assert!(evaluate_initiative_policy(
            &focus_blocked,
            Some(&policy()),
            true,
            "2026-08-27T01:00:00.000Z",
            &temporal,
        )
        .is_err());
    }
}
