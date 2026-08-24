//! D11 emotion domain.
//!
//! The authoritative emotion model is exactly two continuous dimensions kept
//! as bounded INTEGERS so mutation and replay stay deterministic:
//!
//! - `valence`    ∈ [-1000, 1000]
//! - `activation` ∈ [-1000, 1000]
//!
//! SQLite is the only emotion authority. LLM output, prompt text, frontend
//! state and LanceDB must never become emotion authority. This B1 module owns
//! only the domain types, the repository boundary, and the persistence
//! invariants (atomic transition, idempotency, revision conflicts). The policy
//! that decides HOW the next state is calculated belongs to D11-B2 and is not
//! implemented here.

pub(crate) const VALENCE_MIN: i32 = -1000;
pub(crate) const VALENCE_MAX: i32 = 1000;
pub(crate) const ACTIVATION_MIN: i32 = -1000;
pub(crate) const ACTIVATION_MAX: i32 = 1000;
pub(crate) const NEUTRAL_VALENCE: i32 = 0;
pub(crate) const NEUTRAL_ACTIVATION: i32 = 0;
pub(crate) const NEUTRAL_STATE_REVISION: i64 = 0;
pub(crate) const INITIAL_POLICY_VERSION: i64 = 1;

/// One authoritative emotion state row for exactly one life.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EmotionState {
    pub(crate) life_id: String,
    pub(crate) valence: i32,
    pub(crate) activation: i32,
    pub(crate) revision: i64,
    pub(crate) policy_version: i64,
    pub(crate) last_applied_at: String,
    pub(crate) updated_at: String,
}

/// Identity of the bounded evidence that produced an emotion event.
///
/// `kind` and `reference` are free-form but must be non-empty. The ledger
/// stores them only as identity: no message body, memory body, prompt, or
/// model output may ever be stored here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EmotionEventSource {
    pub(crate) kind: String,
    pub(crate) reference: String,
}

impl EmotionEventSource {
    pub(crate) fn new(kind: impl Into<String>, reference: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            reference: reference.into(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), EmotionError> {
        if self.kind.trim().is_empty() {
            return Err(EmotionError::invalid_argument(
                "source kind must not be empty.",
            ));
        }
        if self.reference.trim().is_empty() {
            return Err(EmotionError::invalid_argument(
                "source reference must not be empty.",
            ));
        }
        Ok(())
    }
}

/// One atomic emotion transition proposal.
///
/// B1 does not decide HOW `next_valence` / `next_activation` are calculated;
/// the caller (the future D11-B2 policy) computes them. B1 validates the
/// bounds and commits the event evidence plus the exact proposed next state in
/// one SQLite transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EmotionTransition {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) source: EmotionEventSource,
    pub(crate) valence_delta: i32,
    pub(crate) activation_delta: i32,
    pub(crate) expected_revision: i64,
    pub(crate) next_valence: i32,
    pub(crate) next_activation: i32,
    pub(crate) policy_version: i64,
    pub(crate) event_time: String,
}

impl EmotionTransition {
    /// The transition is a frozen domain contract between the future policy
    /// (D11-B2) and the persistence boundary; the 10 fields are all part of
    /// the atomic transition evidence.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        event_id: impl Into<String>,
        life_id: impl Into<String>,
        source: EmotionEventSource,
        valence_delta: i32,
        activation_delta: i32,
        expected_revision: i64,
        next_valence: i32,
        next_activation: i32,
        policy_version: i64,
        event_time: impl Into<String>,
    ) -> Result<Self, EmotionError> {
        let transition = Self {
            event_id: event_id.into(),
            life_id: life_id.into(),
            source,
            valence_delta,
            activation_delta,
            expected_revision,
            next_valence,
            next_activation,
            policy_version,
            event_time: event_time.into(),
        };
        transition.validate()?;
        Ok(transition)
    }

    pub(crate) fn validate(&self) -> Result<(), EmotionError> {
        if self.event_id.trim().is_empty() {
            return Err(EmotionError::invalid_argument(
                "event identity must not be empty.",
            ));
        }
        if self.life_id.trim().is_empty() {
            return Err(EmotionError::invalid_argument(
                "life identity must not be empty.",
            ));
        }
        self.source.validate()?;
        if !(VALENCE_MIN..=VALENCE_MAX).contains(&self.valence_delta) {
            return Err(EmotionError::invalid_argument(
                "valence delta must be between -1000 and 1000.",
            ));
        }
        if !(ACTIVATION_MIN..=ACTIVATION_MAX).contains(&self.activation_delta) {
            return Err(EmotionError::invalid_argument(
                "activation delta must be between -1000 and 1000.",
            ));
        }
        if self.expected_revision < 0 {
            return Err(EmotionError::invalid_argument(
                "expected state revision must not be negative.",
            ));
        }
        if !(VALENCE_MIN..=VALENCE_MAX).contains(&self.next_valence) {
            return Err(EmotionError::invalid_argument(
                "next valence must be between -1000 and 1000.",
            ));
        }
        if !(ACTIVATION_MIN..=ACTIVATION_MAX).contains(&self.next_activation) {
            return Err(EmotionError::invalid_argument(
                "next activation must be between -1000 and 1000.",
            ));
        }
        if self.policy_version <= 0 {
            return Err(EmotionError::invalid_argument(
                "policy version must be positive.",
            ));
        }
        if self.event_time.trim().is_empty() {
            return Err(EmotionError::invalid_argument(
                "event time must not be empty.",
            ));
        }
        Ok(())
    }

    /// The revision this transition applies at. Derived with `checked_add(1)`
    /// so an unrepresentable next revision (`expected_revision == i64::MAX`) is
    /// a typed `InvalidArgument` error instead of an overflow panic or a
    /// debug/release divergence. Replay equivalence and the normal commit must
    /// reuse the SAME computed value.
    pub(crate) fn target_revision(&self) -> Result<i64, EmotionError> {
        self.expected_revision
            .checked_add(1)
            .ok_or_else(|| EmotionError::invalid_argument("The expected state revision overflows."))
    }
}

/// One immutable ledger row. Bounded state-transition evidence only; it never
/// carries message, memory, prompt, chain-of-thought, or raw model output.
/// `result_valence` / `result_activation` record the state values actually
/// committed by this event, so replay equivalence covers the complete
/// transition payload (deltas AND resulting state).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EmotionEvent {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) source_kind: String,
    pub(crate) source_ref: String,
    pub(crate) valence_delta: i32,
    pub(crate) activation_delta: i32,
    pub(crate) result_valence: i32,
    pub(crate) result_activation: i32,
    pub(crate) applied_revision: i64,
    pub(crate) event_time: String,
    pub(crate) policy_version: i64,
    pub(crate) created_at: String,
}

/// Result of one atomic transition commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EmotionCommitOutcome {
    /// The event was appended and the state advanced exactly once.
    Committed {
        event: EmotionEvent,
        state: EmotionState,
    },
    /// The exact same event was already applied; nothing was mutated.
    Replayed {
        event: EmotionEvent,
        state: EmotionState,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EmotionErrorCode {
    LifeNotFound,
    StateNotFound,
    RevisionConflict,
    EventConflict,
    InvalidArgument,
    DatabaseUnavailable,
}

impl EmotionErrorCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::LifeNotFound => "EMOTION_LIFE_NOT_FOUND",
            Self::StateNotFound => "EMOTION_STATE_NOT_FOUND",
            Self::RevisionConflict => "EMOTION_REVISION_CONFLICT",
            Self::EventConflict => "EMOTION_EVENT_CONFLICT",
            Self::InvalidArgument => "EMOTION_INVALID_ARGUMENT",
            Self::DatabaseUnavailable => "EMOTION_DATABASE_UNAVAILABLE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EmotionError {
    pub(crate) code: EmotionErrorCode,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl EmotionError {
    pub(crate) fn new(code: EmotionErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: matches!(
                code,
                EmotionErrorCode::DatabaseUnavailable | EmotionErrorCode::LifeNotFound
            ),
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(EmotionErrorCode::InvalidArgument, message)
    }

    pub(crate) fn life_not_found() -> Self {
        Self::new(
            EmotionErrorCode::LifeNotFound,
            "The specified life was not found.",
        )
    }

    pub(crate) fn state_not_found() -> Self {
        Self::new(
            EmotionErrorCode::StateNotFound,
            "No authoritative emotion state exists for the specified life.",
        )
    }

    pub(crate) fn revision_conflict() -> Self {
        Self::new(
            EmotionErrorCode::RevisionConflict,
            "The emotion state changed after it was loaded. Refresh and try again.",
        )
    }

    pub(crate) fn event_conflict() -> Self {
        Self::new(
            EmotionErrorCode::EventConflict,
            "An emotion event with the same identity and a conflicting payload already exists.",
        )
    }

    pub(crate) fn database() -> Self {
        Self::new(
            EmotionErrorCode::DatabaseUnavailable,
            "The emotion storage operation failed.",
        )
    }
}

/// Internal emotion persistence boundary. Implementations must keep SQLite the
/// only authority: no content ever crosses into the ledger, and one transition
/// commits the event evidence plus the state update in one transaction.
pub(crate) trait EmotionRepository: Send + Sync {
    fn load_current_state(&self, life_id: &str) -> Result<Option<EmotionState>, EmotionError>;

    fn commit_transition(
        &self,
        transition: EmotionTransition,
    ) -> Result<EmotionCommitOutcome, EmotionError>;

    fn find_event(
        &self,
        life_id: &str,
        source_kind: &str,
        source_ref: &str,
    ) -> Result<Option<EmotionEvent>, EmotionError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(kind: &str, reference: &str) -> EmotionEventSource {
        EmotionEventSource::new(kind, reference)
    }

    fn transition(
        event_id: &str,
        life_id: &str,
        source: EmotionEventSource,
    ) -> Result<EmotionTransition, EmotionError> {
        EmotionTransition::new(
            event_id,
            life_id,
            source,
            10,
            -5,
            0,
            10,
            -5,
            1,
            "2026-08-23T00:00:00.000Z",
        )
    }

    #[test]
    fn neutral_constants_are_zero_states_and_policy_one() {
        assert_eq!(NEUTRAL_VALENCE, 0);
        assert_eq!(NEUTRAL_ACTIVATION, 0);
        assert_eq!(NEUTRAL_STATE_REVISION, 0);
        assert_eq!(INITIAL_POLICY_VERSION, 1);
    }

    #[test]
    fn transition_rejects_empty_identities_and_sources() {
        assert_eq!(
            transition("", "life-a", source("kind", "ref"))
                .unwrap_err()
                .code,
            EmotionErrorCode::InvalidArgument
        );
        assert_eq!(
            transition("event-1", "", source("kind", "ref"))
                .unwrap_err()
                .code,
            EmotionErrorCode::InvalidArgument
        );
        assert_eq!(
            transition("event-1", "life-a", source("", "ref"))
                .unwrap_err()
                .code,
            EmotionErrorCode::InvalidArgument
        );
        assert_eq!(
            transition("event-1", "life-a", source("kind", "  "))
                .unwrap_err()
                .code,
            EmotionErrorCode::InvalidArgument
        );
    }

    #[test]
    fn transition_rejects_unbounded_deltas_and_next_values() {
        for (valence_delta, activation_delta) in [(1001, 0), (-1001, 0), (0, 1001), (0, -1001)] {
            let error = EmotionTransition::new(
                "event-1",
                "life-a",
                source("kind", "ref"),
                valence_delta,
                activation_delta,
                0,
                valence_delta,
                activation_delta,
                1,
                "2026-08-23T00:00:00.000Z",
            )
            .unwrap_err();
            assert_eq!(error.code, EmotionErrorCode::InvalidArgument);
        }
        assert_eq!(
            EmotionTransition::new(
                "event-1",
                "life-a",
                source("kind", "ref"),
                0,
                0,
                0,
                1001,
                -1000,
                1,
                "2026-08-23T00:00:00.000Z",
            )
            .unwrap_err()
            .code,
            EmotionErrorCode::InvalidArgument
        );
        assert_eq!(
            EmotionTransition::new(
                "event-1",
                "life-a",
                source("kind", "ref"),
                0,
                0,
                0,
                -1000,
                1001,
                1,
                "2026-08-23T00:00:00.000Z",
            )
            .unwrap_err()
            .code,
            EmotionErrorCode::InvalidArgument
        );
    }

    #[test]
    fn transition_rejects_negative_expected_revision_zero_policy_and_empty_time() {
        assert_eq!(
            EmotionTransition::new(
                "event-1",
                "life-a",
                source("kind", "ref"),
                1,
                1,
                -1,
                1,
                1,
                1,
                "2026-08-23T00:00:00.000Z",
            )
            .unwrap_err()
            .code,
            EmotionErrorCode::InvalidArgument
        );
        assert_eq!(
            EmotionTransition::new(
                "event-1",
                "life-a",
                source("kind", "ref"),
                1,
                1,
                0,
                1,
                1,
                0,
                "2026-08-23T00:00:00.000Z",
            )
            .unwrap_err()
            .code,
            EmotionErrorCode::InvalidArgument
        );
        assert_eq!(
            EmotionTransition::new(
                "event-1",
                "life-a",
                source("kind", "ref"),
                1,
                1,
                0,
                1,
                1,
                1,
                " ",
            )
            .unwrap_err()
            .code,
            EmotionErrorCode::InvalidArgument
        );
    }

    #[test]
    fn target_revision_is_checked_and_rejects_i64_max() {
        let normal = transition("event-1", "life-a", source("kind", "ref")).unwrap();
        assert_eq!(normal.target_revision().unwrap(), 1);

        let max_transition = EmotionTransition::new(
            "event-max",
            "life-a",
            source("kind", "ref"),
            10,
            -5,
            i64::MAX,
            10,
            -5,
            1,
            "2026-08-23T00:00:00.000Z",
        )
        .unwrap();
        assert_eq!(
            max_transition.target_revision().unwrap_err().code,
            EmotionErrorCode::InvalidArgument
        );
    }

    #[test]
    fn error_codes_are_static_and_typed() {
        assert_eq!(
            EmotionError::revision_conflict().code,
            EmotionErrorCode::RevisionConflict
        );
        assert_eq!(
            EmotionError::revision_conflict().code.as_str(),
            "EMOTION_REVISION_CONFLICT"
        );
        assert_eq!(
            EmotionError::event_conflict().code.as_str(),
            "EMOTION_EVENT_CONFLICT"
        );
        assert!(!EmotionError::revision_conflict().recoverable);
        assert!(!EmotionError::event_conflict().recoverable);
        assert!(EmotionError::life_not_found().recoverable);
        assert!(!EmotionError::invalid_argument("x").recoverable);
    }
}
