//! Explicit, bounded D15-C autonomy tick orchestration.
//!
//! This module is deliberately a synchronous operation. It reads the frozen
//! D14/D13 authority boundaries, creates at most one B1 pending intent, and
//! evaluates at most one pending intent through B2. It does not schedule work,
//! deliver an intent, mutate a Goal, or invoke an Agent or Tool.

use std::cmp::Ordering;

use sha2::{Digest, Sha256};

use crate::{
    experience::{ExperienceEpisodeError, ExperienceEpisodeRepository},
    life_intent::{LifeGoal, LifeIntentError},
    storage::StorageService,
};

use super::{
    AutonomyCreateOutcome, AutonomyError, AutonomyErrorCode, AutonomyRepository,
    LifeAutonomyPolicy, LifeProactiveIntent, LifeProactiveIntentCreateRequest,
    LifeProactiveIntentEvaluationOutcome, LifeProactiveIntentEvaluationRequest,
    INTENT_CREATED_BY_KIND_AUTONOMY_POLICY, INTENT_FOCUS_STATE_AVAILABLE, INTENT_FOCUS_STATE_DND,
    INTENT_FOCUS_STATE_FOCUSED, INTENT_FOCUS_STATE_UNKNOWN, INTENT_KIND_GOAL_CHECK_IN,
    INTENT_STATUS_CANCELLED, INTENT_STATUS_CONSUMED, INTENT_STATUS_DEFERRED, INTENT_STATUS_EXPIRED,
    INTENT_STATUS_PENDING, INTENT_STATUS_READY, INTENT_STATUS_STORED_SILENTLY, INTENT_VERSION,
    MIN_RECHECK_SECONDS,
};

pub(crate) const AUTONOMY_TICK_VERSION: i64 = 1;
pub(crate) const MAX_GOALS_INSPECTED_PER_TICK: i64 = 8;
pub(crate) const MAX_INTENTS_PRODUCED_PER_TICK: usize = 1;

// C has no Drive or Appraisal authority. The high relevance is justified by
// the fact that the selected Goal is an explicit user-created authority row;
// self desire remains zero until a separately governed authority exists.
pub(crate) const GOAL_CHECK_IN_IMPORTANCE_V1: i64 = 500;
pub(crate) const GOAL_CHECK_IN_USER_RELEVANCE_V1: i64 = 1000;
pub(crate) const GOAL_CHECK_IN_SELF_DESIRE_V1: i64 = 0;
pub(crate) const GOAL_CHECK_IN_INTERRUPTION_COST_V1: i64 = 500;

const INTENT_ID_PREFIX: &str = "d15c-intent-";
const EVALUATION_EVENT_ID_PREFIX: &str = "d15c-eval-";

#[cfg(not(test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AutonomyTickRequest {
    pub(super) tick_id: String,
    pub(super) life_id: String,
    pub(super) focus_state: String,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AutonomyTickRequest {
    pub(crate) tick_id: String,
    pub(crate) life_id: String,
    pub(crate) focus_state: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AutonomyTickWaitReason {
    ReadyPendingDelivery,
    DeferredNotDue,
    TerminalCooldown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AutonomyTickOutcome {
    Disabled,
    NoReadyBudget,
    NoActiveGoal,
    Waiting {
        goal_id: String,
        reason: AutonomyTickWaitReason,
        until: Option<String>,
    },
    Applied {
        goal_id: String,
        intent: LifeProactiveIntent,
        evaluation: LifeProactiveIntentEvaluationOutcome,
    },
    Replayed {
        goal_id: String,
        intent: LifeProactiveIntent,
        evaluation: LifeProactiveIntentEvaluationOutcome,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AutonomyTickError {
    InvalidArgument { message: String },
    TickConflict { message: String },
    Autonomy(AutonomyError),
    Experience(ExperienceEpisodeError),
    LifeIntent(LifeIntentError),
}

impl AutonomyTickError {
    fn invalid_argument(message: impl Into<String>) -> Self {
        Self::InvalidArgument {
            message: message.into(),
        }
    }

    fn tick_conflict(message: impl Into<String>) -> Self {
        Self::TickConflict {
            message: message.into(),
        }
    }
}

struct GoalCandidate {
    goal: LifeGoal,
    latest: Option<LifeProactiveIntent>,
}

enum Selection {
    Selected(usize),
    Waiting {
        goal_id: String,
        reason: AutonomyTickWaitReason,
        until: Option<String>,
    },
}

struct BlockedCandidate {
    index: usize,
    reason: AutonomyTickWaitReason,
    until: Option<String>,
}

/// Run one explicit, bounded goal check-in tick.
fn run_autonomy_tick_impl(
    storage: &StorageService,
    request: AutonomyTickRequest,
) -> Result<AutonomyTickOutcome, AutonomyTickError> {
    debug_assert_eq!(AUTONOMY_TICK_VERSION, 1);
    debug_assert_eq!(MAX_INTENTS_PRODUCED_PER_TICK, 1);
    validate_tick_request(&request)?;

    let tick_intent_id = deterministic_intent_id(&request.life_id, &request.tick_id);
    if let Some(intent) = storage
        .find_intent(&request.life_id, &tick_intent_id)
        .map_err(AutonomyTickError::Autonomy)?
    {
        return replay_existing_tick_intent(storage, &request, intent);
    }

    let policy = storage
        .find_policy(&request.life_id)
        .map_err(AutonomyTickError::Autonomy)?;
    let Some(policy) = policy else {
        return Ok(AutonomyTickOutcome::Disabled);
    };
    if !policy.enabled {
        return Ok(AutonomyTickOutcome::Disabled);
    }

    let active_goals = storage
        .autonomy_tick_active_goals(&request.life_id, MAX_GOALS_INSPECTED_PER_TICK)
        .map_err(AutonomyTickError::LifeIntent)?;
    if active_goals.is_empty() {
        return Ok(AutonomyTickOutcome::NoActiveGoal);
    }

    let mut candidates = Vec::with_capacity(active_goals.len());
    for goal in active_goals {
        let latest = storage
            .find_latest_intent_for_goal(&request.life_id, &goal.goal_id)
            .map_err(AutonomyTickError::Autonomy)?;
        candidates.push(GoalCandidate { goal, latest });
    }

    // Pending recovery has precedence even when the current policy has a zero
    // ready budget. B2 remains the sole authority for resolving that row.
    if let Some(index) = candidates.iter().position(|candidate| {
        candidate
            .latest
            .as_ref()
            .is_some_and(|intent| intent.status == INTENT_STATUS_PENDING)
    }) {
        let intent = candidates[index].latest.as_ref().ok_or_else(|| {
            AutonomyTickError::Autonomy(AutonomyError::invalid_argument(
                "pending candidate is missing its latest intent.",
            ))
        })?;
        return recover_pending_intent(storage, intent);
    }

    // A zero budget suppresses new production before any elapsed-time or
    // Episode calculation. Existing pending recovery above is still allowed.
    if policy.max_ready_per_window == 0 {
        return Ok(AutonomyTickOutcome::NoReadyBudget);
    }

    let now = storage
        .autonomy_tick_now()
        .map_err(AutonomyTickError::Autonomy)?;
    match select_candidate(storage, &policy, &candidates, &now)? {
        Selection::Selected(index) => create_and_evaluate_fresh_intent(
            storage,
            &request,
            &candidates[index],
            &now,
            &tick_intent_id,
        ),
        Selection::Waiting {
            goal_id,
            reason,
            until,
        } => Ok(AutonomyTickOutcome::Waiting {
            goal_id,
            reason,
            until,
        }),
    }
}

#[cfg(not(test))]
pub(super) fn run_autonomy_tick(
    storage: &StorageService,
    request: AutonomyTickRequest,
) -> Result<AutonomyTickOutcome, AutonomyTickError> {
    run_autonomy_tick_impl(storage, request)
}

#[cfg(test)]
pub(crate) fn run_autonomy_tick(
    storage: &StorageService,
    request: AutonomyTickRequest,
) -> Result<AutonomyTickOutcome, AutonomyTickError> {
    run_autonomy_tick_impl(storage, request)
}

fn recover_pending_intent(
    storage: &StorageService,
    intent: &LifeProactiveIntent,
) -> Result<AutonomyTickOutcome, AutonomyTickError> {
    let evaluation = storage
        .evaluate_pending_intent(LifeProactiveIntentEvaluationRequest {
            event_id: deterministic_evaluation_event_id(&intent.intent_id),
            life_id: intent.life_id.clone(),
            intent_id: intent.intent_id.clone(),
            expected_revision: intent.revision,
        })
        .map_err(AutonomyTickError::Autonomy)?;
    Ok(evaluation_outcome(intent.goal_id.clone(), evaluation))
}

fn replay_existing_tick_intent(
    storage: &StorageService,
    request: &AutonomyTickRequest,
    intent: LifeProactiveIntent,
) -> Result<AutonomyTickOutcome, AutonomyTickError> {
    let expected_intent_id = deterministic_intent_id(&request.life_id, &request.tick_id);
    validate_tick_intent_evidence(request, &expected_intent_id, &intent)?;

    if intent.status == INTENT_STATUS_PENDING {
        return recover_pending_intent(storage, &intent);
    }

    let event_id = deterministic_evaluation_event_id(&intent.intent_id);
    let event = storage
        .find_intent_event(&intent.life_id, &event_id)
        .map_err(AutonomyTickError::Autonomy)?
        .ok_or_else(|| {
            AutonomyTickError::tick_conflict(
                "the persisted tick intent has no deterministic evaluation event.",
            )
        })?;
    if event.event_id != event_id
        || event.life_id != intent.life_id
        || event.intent_id != intent.intent_id
        || event.from_status != INTENT_STATUS_PENDING
        || event.to_status != intent.status
        || event.applied_revision != intent.revision
        || event.not_before_after != intent.not_before
    {
        return Err(AutonomyTickError::tick_conflict(
            "the persisted tick intent has conflicting evaluation evidence.",
        ));
    }

    Ok(AutonomyTickOutcome::Replayed {
        goal_id: intent.goal_id.clone(),
        intent: intent.clone(),
        evaluation: LifeProactiveIntentEvaluationOutcome::Replayed {
            event,
            current: intent,
        },
    })
}

fn validate_tick_intent_evidence(
    request: &AutonomyTickRequest,
    expected_intent_id: &str,
    intent: &LifeProactiveIntent,
) -> Result<(), AutonomyTickError> {
    if intent.intent_id != expected_intent_id || intent.life_id != request.life_id {
        return Err(AutonomyTickError::tick_conflict(
            "the persisted tick intent identity does not match the request.",
        ));
    }
    if intent.focus_state != request.focus_state {
        return Err(AutonomyTickError::tick_conflict(
            "the tick was replayed with conflicting focus evidence.",
        ));
    }
    if intent.intent_kind != INTENT_KIND_GOAL_CHECK_IN
        || intent.importance != GOAL_CHECK_IN_IMPORTANCE_V1
        || intent.user_relevance != GOAL_CHECK_IN_USER_RELEVANCE_V1
        || intent.self_desire != GOAL_CHECK_IN_SELF_DESIRE_V1
        || intent.interruption_cost != GOAL_CHECK_IN_INTERRUPTION_COST_V1
        || intent.acceptance_score.is_some()
        || intent.expires_at.is_some()
        || intent.created_by_kind != INTENT_CREATED_BY_KIND_AUTONOMY_POLICY
        || intent.intent_version != INTENT_VERSION
    {
        return Err(AutonomyTickError::tick_conflict(
            "the persisted tick intent conflicts with D15-C creation evidence.",
        ));
    }
    Ok(())
}

fn select_candidate(
    storage: &StorageService,
    policy: &LifeAutonomyPolicy,
    candidates: &[GoalCandidate],
    now: &str,
) -> Result<Selection, AutonomyTickError> {
    let mut eligible = Vec::new();
    let mut blocked = Vec::new();

    for (index, candidate) in candidates.iter().enumerate() {
        let Some(intent) = candidate.latest.as_ref() else {
            eligible.push(index);
            continue;
        };

        if intent.status == INTENT_STATUS_PENDING {
            continue;
        }

        if let Some((reason, until)) = blocking_state(storage, policy, intent, now)? {
            blocked.push(BlockedCandidate {
                index,
                reason,
                until,
            });
        } else {
            eligible.push(index);
        }
    }

    eligible.sort_by(|left, right| compare_candidates(&candidates[*left], &candidates[*right]));
    if let Some(index) = eligible.into_iter().next() {
        return Ok(Selection::Selected(index));
    }

    blocked.sort_by(|left, right| {
        compare_candidates(&candidates[left.index], &candidates[right.index])
    });
    let Some(blocked) = blocked.into_iter().next() else {
        return Err(AutonomyTickError::Autonomy(
            AutonomyError::invalid_argument("active Goal selection produced no bounded candidate."),
        ));
    };
    Ok(Selection::Waiting {
        goal_id: candidates[blocked.index].goal.goal_id.clone(),
        reason: blocked.reason,
        until: blocked.until,
    })
}

fn blocking_state(
    storage: &StorageService,
    policy: &LifeAutonomyPolicy,
    intent: &LifeProactiveIntent,
    now: &str,
) -> Result<Option<(AutonomyTickWaitReason, Option<String>)>, AutonomyTickError> {
    match intent.status.as_str() {
        INTENT_STATUS_READY => Ok(Some((AutonomyTickWaitReason::ReadyPendingDelivery, None))),
        INTENT_STATUS_DEFERRED => {
            let not_before = intent.not_before.as_deref().ok_or_else(|| {
                AutonomyTickError::Autonomy(AutonomyError::invalid_argument(
                    "deferred intent is missing not_before.",
                ))
            })?;
            if not_before > now {
                Ok(Some((
                    AutonomyTickWaitReason::DeferredNotDue,
                    Some(not_before.to_string()),
                )))
            } else {
                Ok(None)
            }
        }
        INTENT_STATUS_STORED_SILENTLY
        | INTENT_STATUS_CANCELLED
        | INTENT_STATUS_EXPIRED
        | INTENT_STATUS_CONSUMED => {
            let cooldown_seconds = MIN_RECHECK_SECONDS.max(policy.min_gap_seconds);
            let until = storage
                .autonomy_tick_add_seconds(&intent.updated_at, cooldown_seconds)
                .map_err(AutonomyTickError::Autonomy)?;
            if now < until.as_str() {
                Ok(Some((
                    AutonomyTickWaitReason::TerminalCooldown,
                    Some(until),
                )))
            } else {
                Ok(None)
            }
        }
        INTENT_STATUS_PENDING => Ok(None),
        _ => Err(AutonomyTickError::Autonomy(
            AutonomyError::invalid_argument(
                "latest intent status is not supported by the bounded tick.",
            ),
        )),
    }
}

fn compare_candidates(left: &GoalCandidate, right: &GoalCandidate) -> Ordering {
    let left_without_history = left.latest.is_none();
    let right_without_history = right.latest.is_none();
    let history_order = right_without_history.cmp(&left_without_history);
    if history_order != Ordering::Equal {
        return history_order;
    }

    let left_updated_at = left
        .latest
        .as_ref()
        .map_or("", |intent| intent.updated_at.as_str());
    let right_updated_at = right
        .latest
        .as_ref()
        .map_or("", |intent| intent.updated_at.as_str());
    left_updated_at
        .cmp(right_updated_at)
        .then_with(|| left.goal.created_at.cmp(&right.goal.created_at))
        .then_with(|| left.goal.goal_id.cmp(&right.goal.goal_id))
}

fn create_and_evaluate_fresh_intent(
    storage: &StorageService,
    request: &AutonomyTickRequest,
    candidate: &GoalCandidate,
    now: &str,
    intent_id: &str,
) -> Result<AutonomyTickOutcome, AutonomyTickError> {
    let latest_episode = storage
        .find_latest_episode_for_life(&request.life_id)
        .map_err(AutonomyTickError::Experience)?;
    let recent_interaction_seconds = match latest_episode {
        Some(episode) => Some(
            storage
                .autonomy_tick_elapsed_seconds(now, &episode.ended_at)
                .map_err(AutonomyTickError::Autonomy)?,
        ),
        None => None,
    };

    let created =
        match storage.create_pending_goal_check_in_intent(LifeProactiveIntentCreateRequest {
            intent_id: intent_id.to_string(),
            life_id: request.life_id.clone(),
            goal_id: candidate.goal.goal_id.clone(),
            intent_kind: INTENT_KIND_GOAL_CHECK_IN.to_string(),
            importance: GOAL_CHECK_IN_IMPORTANCE_V1,
            user_relevance: GOAL_CHECK_IN_USER_RELEVANCE_V1,
            self_desire: GOAL_CHECK_IN_SELF_DESIRE_V1,
            interruption_cost: GOAL_CHECK_IN_INTERRUPTION_COST_V1,
            focus_state: request.focus_state.clone(),
            acceptance_score: None,
            recent_interaction_seconds,
            expires_at: None,
        }) {
            Ok(created) => created,
            Err(error) if error.code == AutonomyErrorCode::ProactiveIntentConflict => {
                if let Some(existing) = storage
                    .find_intent(&request.life_id, intent_id)
                    .map_err(AutonomyTickError::Autonomy)?
                {
                    return replay_existing_tick_intent(storage, request, existing);
                }
                return Err(AutonomyTickError::Autonomy(error));
            }
            Err(error) => return Err(AutonomyTickError::Autonomy(error)),
        };
    let intent = match created {
        AutonomyCreateOutcome::Applied(intent) => intent,
        AutonomyCreateOutcome::Replayed(intent) => {
            return replay_existing_tick_intent(storage, request, intent)
        }
    };

    if intent.status != INTENT_STATUS_PENDING {
        return Err(AutonomyTickError::Autonomy(
            AutonomyError::invalid_argument("a newly created tick intent was not pending."),
        ));
    }

    let evaluation = storage
        .evaluate_pending_intent(LifeProactiveIntentEvaluationRequest {
            event_id: deterministic_evaluation_event_id(&intent.intent_id),
            life_id: intent.life_id.clone(),
            intent_id: intent.intent_id.clone(),
            expected_revision: intent.revision,
        })
        .map_err(AutonomyTickError::Autonomy)?;
    Ok(evaluation_outcome(
        candidate.goal.goal_id.clone(),
        evaluation,
    ))
}

fn evaluation_outcome(
    goal_id: String,
    evaluation: LifeProactiveIntentEvaluationOutcome,
) -> AutonomyTickOutcome {
    let intent = match &evaluation {
        LifeProactiveIntentEvaluationOutcome::Applied { intent, .. } => intent.clone(),
        LifeProactiveIntentEvaluationOutcome::Replayed { current, .. } => current.clone(),
    };
    if matches!(
        &evaluation,
        LifeProactiveIntentEvaluationOutcome::Replayed { .. }
    ) {
        AutonomyTickOutcome::Replayed {
            goal_id,
            intent,
            evaluation,
        }
    } else {
        AutonomyTickOutcome::Applied {
            goal_id,
            intent,
            evaluation,
        }
    }
}

pub(super) fn validate_tick_identity(
    tick_id: &str,
    life_id: &str,
) -> Result<(), AutonomyTickError> {
    let tick_length = tick_id.chars().count();
    if !(1..=128).contains(&tick_length) {
        return Err(AutonomyTickError::invalid_argument(
            "tick identity must contain between 1 and 128 Unicode scalar characters.",
        ));
    }
    if life_id.trim().is_empty() {
        return Err(AutonomyTickError::invalid_argument(
            "life identity must not be empty.",
        ));
    }
    Ok(())
}

fn validate_tick_request(request: &AutonomyTickRequest) -> Result<(), AutonomyTickError> {
    validate_tick_identity(&request.tick_id, &request.life_id)?;
    if !matches!(
        request.focus_state.as_str(),
        INTENT_FOCUS_STATE_UNKNOWN
            | INTENT_FOCUS_STATE_AVAILABLE
            | INTENT_FOCUS_STATE_FOCUSED
            | INTENT_FOCUS_STATE_DND
    ) {
        return Err(AutonomyTickError::invalid_argument(
            "focus state must be unknown, available, focused, or dnd.",
        ));
    }
    Ok(())
}

pub(crate) fn deterministic_intent_id(life_id: &str, tick_id: &str) -> String {
    let canonical_input = format!("d15-c-goal-check-in-intent-v1\0{life_id}\0{tick_id}");
    format!(
        "{INTENT_ID_PREFIX}{:x}",
        Sha256::digest(canonical_input.as_bytes())
    )
}

pub(crate) fn deterministic_evaluation_event_id(intent_id: &str) -> String {
    let canonical_input = format!("d15-c-goal-check-in-eval-v1\0{intent_id}");
    format!(
        "{EVALUATION_EVENT_ID_PREFIX}{:x}",
        Sha256::digest(canonical_input.as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_ids_are_stable_and_bounded() {
        let intent_id = deterministic_intent_id("life", "tick");
        let event_id = deterministic_evaluation_event_id(&intent_id);
        assert_eq!(intent_id, deterministic_intent_id("life", "tick"));
        assert_ne!(intent_id, deterministic_intent_id("other-life", "tick"));
        assert_ne!(intent_id, deterministic_intent_id("life", "other-tick"));
        assert_eq!(event_id, deterministic_evaluation_event_id(&intent_id));
        assert!(intent_id.len() <= 128);
        assert!(event_id.len() <= 128);
        assert!(intent_id
            .strip_prefix(INTENT_ID_PREFIX)
            .is_some_and(|digest| digest.chars().all(|value| value.is_ascii_hexdigit())));
        assert!(event_id
            .strip_prefix(EVALUATION_EVENT_ID_PREFIX)
            .is_some_and(|digest| digest.chars().all(|value| value.is_ascii_hexdigit())));
    }

    #[test]
    fn tick_request_counts_unicode_scalars() {
        let valid = AutonomyTickRequest {
            tick_id: "界".repeat(128),
            life_id: "life".into(),
            focus_state: INTENT_FOCUS_STATE_AVAILABLE.into(),
        };
        assert!(validate_tick_request(&valid).is_ok());
        let invalid = AutonomyTickRequest {
            tick_id: "界".repeat(129),
            ..valid
        };
        assert!(validate_tick_request(&invalid).is_err());
    }
}
