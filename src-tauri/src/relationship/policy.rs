//! D12-B2 deterministic relationship evolution policy (RelationshipPolicyV1).
//!
//! A PURE function layer: current [`RelationshipState`] + bounded
//! [`RelationshipStimulusV1`] + event identity → an existing B1
//! [`RelationshipTransition`]. The policy never opens SQLite, never calls the
//! repository, never reads a clock, and has no external I/O. Orchestration and
//! persistence belong to the future D12-C transaction path.
//!
//! Determinism contract: identical inputs always produce identical transition
//! values. All arithmetic is integer-only with i64 intermediates.
//!
//! V1 recognizes exactly one stimulus: a successful interaction occurrence.
//! Only `familiarity` may move, by at most +1, capped at its frozen maximum.
//! There is deliberately NO passive decay, NO cross-dimension heuristic, and
//! NO semantic sentiment classification. At the familiarity cap the policy
//! still returns a valid zero-delta transition so event identity, replay
//! semantics, and one deterministic transition shape are preserved; whether a
//! transition is persisted belongs to D12-C.

use super::{
    validate_change_reason, RelationshipDimensions, RelationshipError, RelationshipEventSource,
    RelationshipState, RelationshipTransition, FAMILIARITY_MAX, INITIAL_POLICY_VERSION,
};

/// The closed V1 stimulus domain: only a successful interaction occurrence is
/// recognized. Richer stimuli (semantic sentiment, trust/boundary events,
/// appraisal) require future governed evidence work and MUST NOT be added here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelationshipStimulusV1 {
    SuccessfulConversationTurn,
}

/// One pure policy request. `life_id`/`subject_id` are deliberately absent:
/// they are derived from the current authoritative state, so a caller can
/// never mismatch policy evidence against another relationship pair. There is
/// no elapsed-time input because V1 has no passive decay.
#[derive(Clone, Debug)]
pub(crate) struct RelationshipPolicyRequest {
    pub(crate) event_id: String,
    pub(crate) source: RelationshipEventSource,
    pub(crate) change_reason: String,
    pub(crate) stimulus: RelationshipStimulusV1,
    pub(crate) event_time: String,
}

impl RelationshipPolicyRequest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        event_id: impl Into<String>,
        source: RelationshipEventSource,
        change_reason: impl Into<String>,
        stimulus: RelationshipStimulusV1,
        event_time: impl Into<String>,
    ) -> Result<Self, RelationshipError> {
        let request = Self {
            event_id: event_id.into(),
            source,
            change_reason: change_reason.into(),
            stimulus,
            event_time: event_time.into(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Reuses the SAME B1 validators for event identity, source, and change
    /// reason — there is no second, inconsistent validation rule set.
    pub(crate) fn validate(&self) -> Result<(), RelationshipError> {
        if self.event_id.trim().is_empty() {
            return Err(RelationshipError::invalid_argument(
                "event identity must not be empty.",
            ));
        }
        self.source.validate()?;
        validate_change_reason(&self.change_reason)?;
        if self.event_time.trim().is_empty() {
            return Err(RelationshipError::invalid_argument(
                "event time must not be empty.",
            ));
        }
        Ok(())
    }
}

fn validate_current_state(current: &RelationshipState) -> Result<(), RelationshipError> {
    if current.life_id.trim().is_empty() {
        return Err(RelationshipError::invalid_argument(
            "life identity must not be empty.",
        ));
    }
    if current.subject_id.trim().is_empty() {
        return Err(RelationshipError::invalid_argument(
            "subject identity must not be empty.",
        ));
    }
    current.values.validate_result()?;
    if current.revision < 0 {
        return Err(RelationshipError::invalid_argument(
            "state revision must not be negative.",
        ));
    }
    if current.policy_version != INITIAL_POLICY_VERSION {
        return Err(RelationshipError::invalid_argument(
            "the relationship state was written by a different policy version.",
        ));
    }
    // The pure mathematical policy does not require subject_id ==
    // PRIMARY_USER_SUBJECT_ID: the production primary-user restriction belongs
    // to the future D12-C orchestration path.
    Ok(())
}

/// RelationshipPolicyV1: derive the next atomic relationship transition.
///
/// For [`RelationshipStimulusV1::SuccessfulConversationTurn`] familiarity
/// advances by exactly +1 up to its frozen maximum (i64 intermediates keep the
/// arithmetic overflow-free); all seven other dimensions stay EXACTLY
/// unchanged. Each stored delta equals the exact next-minus-current result,
/// so a capped turn yields a 0 delta rather than a phantom +1.
pub(crate) fn evolve(
    current: &RelationshipState,
    request: RelationshipPolicyRequest,
) -> Result<RelationshipTransition, RelationshipError> {
    validate_current_state(current)?;
    request.validate()?;

    // V1 recognizes exactly one stimulus; matching (rather than ignoring) the
    // field makes the closed domain a compile-level fact — a future stimulus
    // variant cannot silently reuse the single-stimulus evolution.
    let RelationshipStimulusV1::SuccessfulConversationTurn = request.stimulus;

    let next_familiarity =
        (current.values.familiarity as i64 + 1).min(FAMILIARITY_MAX as i64) as i32;
    let familiarity_delta = next_familiarity as i64 - current.values.familiarity as i64;

    let deltas = RelationshipDimensions {
        familiarity: familiarity_delta as i32,
        ..RelationshipDimensions::neutral()
    };
    let mut next = current.values;
    next.familiarity = next_familiarity;

    let transition = RelationshipTransition::new(
        request.event_id,
        current.life_id.clone(),
        current.subject_id.clone(),
        request.source,
        request.change_reason,
        deltas,
        current.revision,
        next,
        current.policy_version,
        request.event_time,
    )?;
    // Fail closed before returning: a transition whose target revision cannot
    // exist must surface here as typed InvalidArgument, not at commit time.
    transition.target_revision()?;
    Ok(transition)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relationship::{RelationshipErrorCode, PRIMARY_USER_SUBJECT_ID};

    const EVENT_TIME: &str = "2026-08-25T00:00:00.000Z";

    fn state(life_id: &str, subject_id: &str, familiarity: i32) -> RelationshipState {
        RelationshipState {
            life_id: life_id.into(),
            subject_id: subject_id.into(),
            values: RelationshipDimensions {
                familiarity,
                ..RelationshipDimensions::neutral()
            },
            revision: 0,
            policy_version: INITIAL_POLICY_VERSION,
            last_applied_at: EVENT_TIME.into(),
            updated_at: EVENT_TIME.into(),
        }
    }

    fn request(event_id: &str) -> RelationshipPolicyRequest {
        RelationshipPolicyRequest::new(
            event_id,
            RelationshipEventSource::new("conversation", "turn-1"),
            "policy_successful_turn",
            RelationshipStimulusV1::SuccessfulConversationTurn,
            EVENT_TIME,
        )
        .unwrap()
    }

    fn evolved(current: &RelationshipState, event_id: &str) -> RelationshipTransition {
        evolve(current, request(event_id)).unwrap()
    }

    // ---------- A. V1 evolution ----------

    #[test]
    fn neutral_state_gains_exactly_one_familiarity_and_nothing_else() {
        let transition = evolved(&state("life-a", PRIMARY_USER_SUBJECT_ID, 0), "event-1");
        assert_eq!(transition.next.familiarity, 1);
        assert_eq!(transition.deltas.familiarity, 1);
        let unchanged = [
            transition.next.trust,
            transition.next.emotional_closeness,
            transition.next.collaboration,
            transition.next.safety,
            transition.next.dependency_tendency,
            transition.next.boundary_comfort,
            transition.next.tension,
        ];
        assert_eq!(unchanged, [0; 7]);
        assert_eq!(
            (
                transition.deltas.trust,
                transition.deltas.emotional_closeness,
                transition.deltas.collaboration,
                transition.deltas.safety,
                transition.deltas.dependency_tendency,
                transition.deltas.boundary_comfort,
                transition.deltas.tension
            ),
            (0, 0, 0, 0, 0, 0, 0)
        );
    }

    #[test]
    fn non_zero_current_state_changes_only_familiarity() {
        let mut current = state("life-a", PRIMARY_USER_SUBJECT_ID, 250);
        current.values.trust = -400;
        current.values.safety = 900;
        current.values.boundary_comfort = -120;
        current.values.tension = 77;
        current.revision = 9;
        let transition = evolved(&current, "event-2");
        assert_eq!(transition.next.familiarity, 251);
        assert_eq!(transition.deltas.familiarity, 1);
        // Every signed/non-negative dimension preserved EXACTLY.
        assert_eq!(transition.next.trust, -400);
        assert_eq!(transition.next.emotional_closeness, 0);
        assert_eq!(transition.next.collaboration, 0);
        assert_eq!(transition.next.safety, 900);
        assert_eq!(transition.next.dependency_tendency, 0);
        assert_eq!(transition.next.boundary_comfort, -120);
        assert_eq!(transition.next.tension, 77);
        assert_eq!(
            transition.deltas,
            RelationshipDimensions {
                familiarity: 1,
                ..RelationshipDimensions::neutral()
            }
        );
    }

    #[test]
    fn familiarity_999_advances_to_1000_with_delta_one() {
        let transition = evolved(&state("life-a", PRIMARY_USER_SUBJECT_ID, 999), "event-3");
        assert_eq!(transition.next.familiarity, 1000);
        assert_eq!(transition.deltas.familiarity, 1);
    }

    #[test]
    fn familiarity_at_cap_returns_valid_zero_delta_transition() {
        let transition = evolved(&state("life-a", PRIMARY_USER_SUBJECT_ID, 1000), "event-4");
        assert_eq!(transition.next.familiarity, 1000);
        assert_eq!(transition.deltas.familiarity, 0);
        assert_eq!(transition.deltas, RelationshipDimensions::neutral());
        // Still a fully valid transition shape with preserved identity.
        assert_eq!(transition.target_revision().unwrap(), 1);
    }

    #[test]
    fn delta_always_equals_next_minus_current_across_the_domain() {
        for familiarity in [0, 1, 500, 998, 999, 1000] {
            let current = state("life-a", PRIMARY_USER_SUBJECT_ID, familiarity);
            let transition = evolved(&current, "event-sweep");
            assert_eq!(
                transition.deltas.familiarity,
                transition.next.familiarity - current.values.familiarity
            );
            assert_eq!(transition.next.familiarity, (familiarity + 1).min(1000));
            assert!((0..=FAMILIARITY_MAX).contains(&transition.next.familiarity));
            assert!((0..=FAMILIARITY_MAX).contains(&transition.deltas.familiarity));
        }
    }

    // ---------- B. authority contract ----------

    #[test]
    fn returned_identity_comes_only_from_current_state() {
        let current = state("authoritative-life", "npc_wanderer_01", 5);
        let transition = evolved(&current, "event-6");
        assert_eq!(transition.life_id, "authoritative-life");
        assert_eq!(transition.subject_id, "npc_wanderer_01");
    }

    #[test]
    fn expected_revision_equals_current_revision_and_policy_version_is_one() {
        let mut current = state("life-a", PRIMARY_USER_SUBJECT_ID, 10);
        current.revision = 41;
        let transition = evolved(&current, "event-7");
        assert_eq!(transition.expected_revision, 41);
        assert_eq!(transition.target_revision().unwrap(), 42);
        assert_eq!(transition.policy_version, 1);
        assert_eq!(transition.policy_version, INITIAL_POLICY_VERSION);
    }

    #[test]
    fn event_identity_source_reason_and_time_are_preserved_exactly() {
        let source = RelationshipEventSource::new("memory", "mem-77");
        let request = RelationshipPolicyRequest::new(
            "event-abc",
            source.clone(),
            "policy_other_reason",
            RelationshipStimulusV1::SuccessfulConversationTurn,
            "2026-08-25T12:34:56.789Z",
        )
        .unwrap();
        let transition = evolve(&state("life-a", PRIMARY_USER_SUBJECT_ID, 3), request).unwrap();
        assert_eq!(transition.event_id, "event-abc");
        assert_eq!(transition.source, source);
        assert_eq!(transition.change_reason, "policy_other_reason");
        assert_eq!(transition.event_time, "2026-08-25T12:34:56.789Z");
    }

    // ---------- C. fail-closed validation ----------

    #[test]
    fn invalid_current_states_fail_closed() {
        let base = state("life-a", PRIMARY_USER_SUBJECT_ID, 10);

        let mut empty_life = base.clone();
        empty_life.life_id = "".into();
        assert_eq!(
            evolve(&empty_life, request("event-x")).unwrap_err().code,
            RelationshipErrorCode::InvalidArgument
        );

        let mut empty_subject = base.clone();
        empty_subject.subject_id = "".into();
        assert_eq!(
            evolve(&empty_subject, request("event-x")).unwrap_err().code,
            RelationshipErrorCode::InvalidArgument
        );

        let mut bad_dimension = base.clone();
        bad_dimension.values.trust = 1001;
        assert_eq!(
            evolve(&bad_dimension, request("event-x")).unwrap_err().code,
            RelationshipErrorCode::InvalidArgument
        );

        let mut negative_revision = base.clone();
        negative_revision.revision = -1;
        assert_eq!(
            evolve(&negative_revision, request("event-x"))
                .unwrap_err()
                .code,
            RelationshipErrorCode::InvalidArgument
        );

        let mut foreign_policy = base.clone();
        foreign_policy.policy_version = 2;
        assert_eq!(
            evolve(&foreign_policy, request("event-x"))
                .unwrap_err()
                .code,
            RelationshipErrorCode::InvalidArgument
        );

        let mut zero_policy = base;
        zero_policy.policy_version = 0;
        assert_eq!(
            evolve(&zero_policy, request("event-x")).unwrap_err().code,
            RelationshipErrorCode::InvalidArgument
        );
    }

    #[test]
    fn invalid_requests_fail_closed() {
        let current = state("life-a", PRIMARY_USER_SUBJECT_ID, 10);

        let empty_event = RelationshipPolicyRequest::new(
            "",
            RelationshipEventSource::new("conversation", "turn-1"),
            "policy_successful_turn",
            RelationshipStimulusV1::SuccessfulConversationTurn,
            EVENT_TIME,
        )
        .unwrap_err();
        assert_eq!(empty_event.code, RelationshipErrorCode::InvalidArgument);

        let empty_source_kind = RelationshipPolicyRequest::new(
            "event-y",
            RelationshipEventSource::new("", "turn-1"),
            "policy_successful_turn",
            RelationshipStimulusV1::SuccessfulConversationTurn,
            EVENT_TIME,
        )
        .unwrap_err();
        assert_eq!(
            empty_source_kind.code,
            RelationshipErrorCode::InvalidArgument
        );

        let empty_source_ref = RelationshipPolicyRequest::new(
            "event-y",
            RelationshipEventSource::new("conversation", ""),
            "policy_successful_turn",
            RelationshipStimulusV1::SuccessfulConversationTurn,
            EVENT_TIME,
        )
        .unwrap_err();
        assert_eq!(
            empty_source_ref.code,
            RelationshipErrorCode::InvalidArgument
        );

        let free_text_reason = RelationshipPolicyRequest::new(
            "event-y",
            RelationshipEventSource::new("conversation", "turn-1"),
            "the user seemed pleased with the assistant today",
            RelationshipStimulusV1::SuccessfulConversationTurn,
            EVENT_TIME,
        )
        .unwrap_err();
        assert_eq!(
            free_text_reason.code,
            RelationshipErrorCode::InvalidArgument
        );

        let trailing_underscore_reason = RelationshipPolicyRequest::new(
            "event-y",
            RelationshipEventSource::new("conversation", "turn-1"),
            "policy_bad_",
            RelationshipStimulusV1::SuccessfulConversationTurn,
            EVENT_TIME,
        )
        .unwrap_err();
        assert_eq!(
            trailing_underscore_reason.code,
            RelationshipErrorCode::InvalidArgument
        );

        let empty_time = RelationshipPolicyRequest::new(
            "event-y",
            RelationshipEventSource::new("conversation", "turn-1"),
            "policy_successful_turn",
            RelationshipStimulusV1::SuccessfulConversationTurn,
            "",
        )
        .unwrap_err();
        assert_eq!(empty_time.code, RelationshipErrorCode::InvalidArgument);

        // evolve() fails closed even when a request was built through struct
        // literal without going through new().
        let raw_request = RelationshipPolicyRequest {
            event_id: "event-bad".into(),
            source: RelationshipEventSource::new("conversation", "turn-1"),
            change_reason: "NOT_SNAKE_CASE".into(),
            stimulus: RelationshipStimulusV1::SuccessfulConversationTurn,
            event_time: EVENT_TIME.into(),
        };
        let error = evolve(&current, raw_request).unwrap_err();
        assert_eq!(error.code, RelationshipErrorCode::InvalidArgument);
    }

    #[test]
    fn max_revision_state_produces_typed_invalid_argument() {
        let mut current = state("life-a", PRIMARY_USER_SUBJECT_ID, 10);
        current.revision = i64::MAX;
        let error = evolve(&current, request("event-max")).unwrap_err();
        assert_eq!(error.code, RelationshipErrorCode::InvalidArgument);
    }

    // ---------- D. determinism ----------

    #[test]
    fn identical_inputs_produce_identical_transitions() {
        let build = || {
            let mut current = state("life-a", PRIMARY_USER_SUBJECT_ID, 431);
            current.revision = 17;
            current.values.trust = -55;
            evolve(&current, request("event-det")).unwrap()
        };
        assert_eq!(build(), build());
    }

    // ---------- E. purity isolation ----------

    #[test]
    fn policy_module_source_performs_no_io_storage_or_clock_calls() {
        // Architectural/source proof over the non-test portion of the module
        // (the test section below is excluded so this test's own literals
        // cannot self-match).
        let source = include_str!("policy.rs");
        let implementation = source
            .split("#[cfg(test)]")
            .next()
            .expect("policy.rs always contains a cfg(test) section");
        for forbidden in [
            "StorageService",
            "commit_transition",
            "RelationshipRepository",
            "SystemTime",
            "Instant",
            "std::time",
            "rusqlite",
            "Connection",
            "load_current_state",
        ] {
            assert!(
                !implementation.contains(forbidden),
                "policy.rs implementation must not reference {forbidden}"
            );
        }
    }
}
