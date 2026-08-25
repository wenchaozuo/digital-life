//! D12-B1 relationship domain.
//!
//! The authoritative relationship model is exactly eight bounded INTEGER
//! dimensions kept as integers so mutation and replay stay deterministic:
//!
//! - `familiarity`          ∈ [0, 1000]
//! - `trust`                ∈ [-1000, 1000]
//! - `emotional_closeness`  ∈ [0, 1000]
//! - `collaboration`        ∈ [0, 1000]
//! - `safety`               ∈ [-1000, 1000]
//! - `dependency_tendency`  ∈ [0, 1000]
//! - `boundary_comfort`     ∈ [-1000, 1000]
//! - `tension`              ∈ [0, 1000]
//!
//! Relationship is between one `life_id` and one `subject_id`; D12 V1
//! production exposes only the [`PRIMARY_USER_SUBJECT_ID`] counterpart.
//! There is deliberately NO single affection score and NO categorical label
//! (friend / lover / relationship_level): categorical projection is not
//! authority. SQLite is the only relationship authority. LLM output, prompt
//! text, frontend state and LanceDB must never become relationship authority.
//! Relationship is independent from Emotion and MUST NOT affect permissions
//! or capability grants.
//!
//! This B1 module owns only the domain types, the repository boundary, and
//! the persistence invariants (atomic transition, idempotency, revision
//! conflicts). The policy that decides HOW the next state is calculated
//! belongs to D12-B2 and is not implemented here. There is no passive decay:
//! time fields are audit evidence only.

pub(crate) const PRIMARY_USER_SUBJECT_ID: &str = "primary_user";
pub(crate) const NEUTRAL_STATE_REVISION: i64 = 0;
pub(crate) const INITIAL_POLICY_VERSION: i64 = 1;

pub(crate) const FAMILIARITY_MIN: i32 = 0;
pub(crate) const FAMILIARITY_MAX: i32 = 1000;
pub(crate) const TRUST_MIN: i32 = -1000;
pub(crate) const TRUST_MAX: i32 = 1000;
pub(crate) const EMOTIONAL_CLOSENESS_MIN: i32 = 0;
pub(crate) const EMOTIONAL_CLOSENESS_MAX: i32 = 1000;
pub(crate) const COLLABORATION_MIN: i32 = 0;
pub(crate) const COLLABORATION_MAX: i32 = 1000;
pub(crate) const SAFETY_MIN: i32 = -1000;
pub(crate) const SAFETY_MAX: i32 = 1000;
pub(crate) const DEPENDENCY_TENDENCY_MIN: i32 = 0;
pub(crate) const DEPENDENCY_TENDENCY_MAX: i32 = 1000;
pub(crate) const BOUNDARY_COMFORT_MIN: i32 = -1000;
pub(crate) const BOUNDARY_COMFORT_MAX: i32 = 1000;
pub(crate) const TENSION_MIN: i32 = 0;
pub(crate) const TENSION_MAX: i32 = 1000;

/// Every stored event delta may be signed: a non-negative dimension value can
/// still decrease, so deltas span the signed conceptual domain regardless of
/// the result range of their dimension.
pub(crate) const DELTA_MIN: i32 = -1000;
pub(crate) const DELTA_MAX: i32 = 1000;

/// The eight authoritative relationship values, in frozen order. The same
/// shape carries both proposed deltas (validated against the signed delta
/// domain) and exact next/result values (validated against each dimension's
/// own range). Zero everywhere is the neutral relationship state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RelationshipDimensions {
    pub(crate) familiarity: i32,
    pub(crate) trust: i32,
    pub(crate) emotional_closeness: i32,
    pub(crate) collaboration: i32,
    pub(crate) safety: i32,
    pub(crate) dependency_tendency: i32,
    pub(crate) boundary_comfort: i32,
    pub(crate) tension: i32,
}

impl RelationshipDimensions {
    pub(crate) fn neutral() -> Self {
        Self::default()
    }

    /// Validates the eight values as EXACT RESULT/state values against each
    /// frozen dimension range.
    pub(crate) fn validate_result(&self) -> Result<(), RelationshipError> {
        for (name, value, min, max) in self.iter_dimension_ranges() {
            if !(min..=max).contains(value) {
                return Err(RelationshipError::invalid_argument(format!(
                    "{name} must be between {min} and {max}."
                )));
            }
        }
        Ok(())
    }

    /// Validates the eight values as EVENT DELTAS against the signed delta
    /// domain. A delta may be negative even for a non-negative dimension.
    pub(crate) fn validate_deltas(&self) -> Result<(), RelationshipError> {
        for (name, value) in self.iter_named_values() {
            if !(DELTA_MIN..=DELTA_MAX).contains(value) {
                return Err(RelationshipError::invalid_argument(format!(
                    "{name} delta must be between {DELTA_MIN} and {DELTA_MAX}."
                )));
            }
        }
        Ok(())
    }

    fn iter_dimension_ranges(&self) -> [(&'static str, &i32, i32, i32); 8] {
        [
            (
                "familiarity",
                &self.familiarity,
                FAMILIARITY_MIN,
                FAMILIARITY_MAX,
            ),
            ("trust", &self.trust, TRUST_MIN, TRUST_MAX),
            (
                "emotional_closeness",
                &self.emotional_closeness,
                EMOTIONAL_CLOSENESS_MIN,
                EMOTIONAL_CLOSENESS_MAX,
            ),
            (
                "collaboration",
                &self.collaboration,
                COLLABORATION_MIN,
                COLLABORATION_MAX,
            ),
            ("safety", &self.safety, SAFETY_MIN, SAFETY_MAX),
            (
                "dependency_tendency",
                &self.dependency_tendency,
                DEPENDENCY_TENDENCY_MIN,
                DEPENDENCY_TENDENCY_MAX,
            ),
            (
                "boundary_comfort",
                &self.boundary_comfort,
                BOUNDARY_COMFORT_MIN,
                BOUNDARY_COMFORT_MAX,
            ),
            ("tension", &self.tension, TENSION_MIN, TENSION_MAX),
        ]
    }

    fn iter_named_values(&self) -> [(&'static str, &i32); 8] {
        [
            ("familiarity", &self.familiarity),
            ("trust", &self.trust),
            ("emotional_closeness", &self.emotional_closeness),
            ("collaboration", &self.collaboration),
            ("safety", &self.safety),
            ("dependency_tendency", &self.dependency_tendency),
            ("boundary_comfort", &self.boundary_comfort),
            ("tension", &self.tension),
        ]
    }
}

/// One authoritative relationship state row for exactly one life/subject pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationshipState {
    pub(crate) life_id: String,
    pub(crate) subject_id: String,
    pub(crate) values: RelationshipDimensions,
    pub(crate) revision: i64,
    pub(crate) policy_version: i64,
    pub(crate) last_applied_at: String,
    pub(crate) updated_at: String,
}

/// Identity of the bounded evidence that produced a relationship event.
///
/// `kind` and `reference` are free-form but must be non-empty. The ledger
/// stores them only as identity: no message body, memory body, prompt, model
/// output, or free-text psychological explanation may ever be stored here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationshipEventSource {
    pub(crate) kind: String,
    pub(crate) reference: String,
}

impl RelationshipEventSource {
    pub(crate) fn new(kind: impl Into<String>, reference: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            reference: reference.into(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), RelationshipError> {
        if self.kind.trim().is_empty() {
            return Err(RelationshipError::invalid_argument(
                "source kind must not be empty.",
            ));
        }
        if self.reference.trim().is_empty() {
            return Err(RelationshipError::invalid_argument(
                "source reference must not be empty.",
            ));
        }
        Ok(())
    }
}

/// A change reason is a SAFE STRUCTURED CODE, never arbitrary message text:
/// ASCII lower snake_case ([a-z]([a-z0-9]|_[a-z0-9])*), 1..=64 characters.
/// Free-text psychological explanations are forbidden in the ledger.
fn validate_change_reason(change_reason: &str) -> Result<(), RelationshipError> {
    let bytes = change_reason.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(RelationshipError::invalid_argument(
            "change reason must be 1 to 64 characters.",
        ));
    }
    if !bytes[0].is_ascii_lowercase() {
        return Err(RelationshipError::invalid_argument(
            "change reason must start with a lower-case ASCII letter.",
        ));
    }
    let mut previous_was_underscore = false;
    for (index, &byte) in bytes.iter().enumerate() {
        let allowed = byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_';
        if !allowed {
            return Err(RelationshipError::invalid_argument(
                "change reason must be ASCII lower snake_case.",
            ));
        }
        if byte == b'_' && (index == bytes.len() - 1 || previous_was_underscore) {
            return Err(RelationshipError::invalid_argument(
                "change reason must not contain leading, trailing, or consecutive underscores.",
            ));
        }
        previous_was_underscore = byte == b'_';
    }
    Ok(())
}

/// One atomic relationship transition proposal.
///
/// B1 does not decide HOW the eight next values are calculated; the caller
/// (the future D12-B2 policy) computes them. B1 validates the bounds and
/// commits the event evidence plus the exact proposed next state in one
/// SQLite transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationshipTransition {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) subject_id: String,
    pub(crate) source: RelationshipEventSource,
    pub(crate) change_reason: String,
    pub(crate) deltas: RelationshipDimensions,
    pub(crate) expected_revision: i64,
    pub(crate) next: RelationshipDimensions,
    pub(crate) policy_version: i64,
    pub(crate) event_time: String,
}

impl RelationshipTransition {
    /// The transition is a frozen domain contract between the future policy
    /// (D12-B2) and the persistence boundary; every field is part of the
    /// atomic transition evidence.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        event_id: impl Into<String>,
        life_id: impl Into<String>,
        subject_id: impl Into<String>,
        source: RelationshipEventSource,
        change_reason: impl Into<String>,
        deltas: RelationshipDimensions,
        expected_revision: i64,
        next: RelationshipDimensions,
        policy_version: i64,
        event_time: impl Into<String>,
    ) -> Result<Self, RelationshipError> {
        let transition = Self {
            event_id: event_id.into(),
            life_id: life_id.into(),
            subject_id: subject_id.into(),
            source,
            change_reason: change_reason.into(),
            deltas,
            expected_revision,
            next,
            policy_version,
            event_time: event_time.into(),
        };
        transition.validate()?;
        Ok(transition)
    }

    pub(crate) fn validate(&self) -> Result<(), RelationshipError> {
        if self.event_id.trim().is_empty() {
            return Err(RelationshipError::invalid_argument(
                "event identity must not be empty.",
            ));
        }
        if self.life_id.trim().is_empty() {
            return Err(RelationshipError::invalid_argument(
                "life identity must not be empty.",
            ));
        }
        if self.subject_id.trim().is_empty() {
            return Err(RelationshipError::invalid_argument(
                "subject identity must not be empty.",
            ));
        }
        self.source.validate()?;
        validate_change_reason(&self.change_reason)?;
        self.deltas.validate_deltas()?;
        if self.expected_revision < 0 {
            return Err(RelationshipError::invalid_argument(
                "expected state revision must not be negative.",
            ));
        }
        self.next.validate_result()?;
        if self.policy_version <= 0 {
            return Err(RelationshipError::invalid_argument(
                "policy version must be positive.",
            ));
        }
        if self.event_time.trim().is_empty() {
            return Err(RelationshipError::invalid_argument(
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
    pub(crate) fn target_revision(&self) -> Result<i64, RelationshipError> {
        self.expected_revision.checked_add(1).ok_or_else(|| {
            RelationshipError::invalid_argument("The expected state revision overflows.")
        })
    }
}

/// One immutable ledger row. Bounded state-transition evidence only; it never
/// carries message, memory, prompt, chain-of-thought, raw model output, or
/// unrestricted free-text explanation. `result` records the state values
/// actually committed by this event, so replay equivalence covers the
/// complete transition payload (deltas AND resulting state).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationshipEvent {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) subject_id: String,
    pub(crate) source_kind: String,
    pub(crate) source_ref: String,
    pub(crate) change_reason: String,
    pub(crate) deltas: RelationshipDimensions,
    pub(crate) result: RelationshipDimensions,
    pub(crate) applied_revision: i64,
    pub(crate) event_time: String,
    pub(crate) policy_version: i64,
    pub(crate) created_at: String,
}

/// Result of one atomic transition commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelationshipCommitOutcome {
    /// The event was appended and the state advanced exactly once.
    Committed {
        event: RelationshipEvent,
        state: RelationshipState,
    },
    /// The exact same event was already applied; nothing was mutated.
    Replayed {
        event: RelationshipEvent,
        state: RelationshipState,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelationshipErrorCode {
    LifeNotFound,
    StateNotFound,
    RevisionConflict,
    EventConflict,
    InvalidArgument,
    DatabaseUnavailable,
}

impl RelationshipErrorCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::LifeNotFound => "RELATIONSHIP_LIFE_NOT_FOUND",
            Self::StateNotFound => "RELATIONSHIP_STATE_NOT_FOUND",
            Self::RevisionConflict => "RELATIONSHIP_REVISION_CONFLICT",
            Self::EventConflict => "RELATIONSHIP_EVENT_CONFLICT",
            Self::InvalidArgument => "RELATIONSHIP_INVALID_ARGUMENT",
            Self::DatabaseUnavailable => "RELATIONSHIP_DATABASE_UNAVAILABLE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationshipError {
    pub(crate) code: RelationshipErrorCode,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl RelationshipError {
    pub(crate) fn new(code: RelationshipErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: matches!(
                code,
                RelationshipErrorCode::DatabaseUnavailable | RelationshipErrorCode::LifeNotFound
            ),
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(RelationshipErrorCode::InvalidArgument, message)
    }

    pub(crate) fn life_not_found() -> Self {
        Self::new(
            RelationshipErrorCode::LifeNotFound,
            "The specified life was not found.",
        )
    }

    pub(crate) fn state_not_found() -> Self {
        Self::new(
            RelationshipErrorCode::StateNotFound,
            "No authoritative relationship state exists for the specified life and subject.",
        )
    }

    pub(crate) fn revision_conflict() -> Self {
        Self::new(
            RelationshipErrorCode::RevisionConflict,
            "The relationship state changed after it was loaded. Refresh and try again.",
        )
    }

    pub(crate) fn event_conflict() -> Self {
        Self::new(
            RelationshipErrorCode::EventConflict,
            "A relationship event with the same identity and a conflicting payload already exists.",
        )
    }

    pub(crate) fn database() -> Self {
        Self::new(
            RelationshipErrorCode::DatabaseUnavailable,
            "The relationship storage operation failed.",
        )
    }
}

/// Internal relationship persistence boundary. Implementations must keep
/// SQLite the only authority: no content ever crosses into the ledger, and
/// one transition commits the event evidence plus the state update in one
/// transaction.
pub(crate) trait RelationshipRepository: Send + Sync {
    fn load_current_state(
        &self,
        life_id: &str,
        subject_id: &str,
    ) -> Result<Option<RelationshipState>, RelationshipError>;

    fn commit_transition(
        &self,
        transition: RelationshipTransition,
    ) -> Result<RelationshipCommitOutcome, RelationshipError>;

    fn find_event(
        &self,
        life_id: &str,
        subject_id: &str,
        source_kind: &str,
        source_ref: &str,
    ) -> Result<Option<RelationshipEvent>, RelationshipError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(kind: &str, reference: &str) -> RelationshipEventSource {
        RelationshipEventSource::new(kind, reference)
    }

    fn transition(
        event_id: &str,
        life_id: &str,
        subject_id: &str,
    ) -> Result<RelationshipTransition, RelationshipError> {
        let mut deltas = RelationshipDimensions::neutral();
        deltas.familiarity = 40;
        deltas.trust = -20;
        let mut next = RelationshipDimensions::neutral();
        next.familiarity = 40;
        next.trust = -20;
        RelationshipTransition::new(
            event_id,
            life_id,
            subject_id,
            source("kind", "ref"),
            "test_transition",
            deltas,
            0,
            next,
            1,
            "2026-08-25T00:00:00.000Z",
        )
    }

    #[test]
    fn neutral_constants_are_zero_states_policy_one_and_primary_user_subject() {
        assert_eq!(PRIMARY_USER_SUBJECT_ID, "primary_user");
        assert_eq!(NEUTRAL_STATE_REVISION, 0);
        assert_eq!(INITIAL_POLICY_VERSION, 1);
        assert_eq!(
            RelationshipDimensions::neutral(),
            RelationshipDimensions::default()
        );
        RelationshipDimensions::neutral().validate_result().unwrap();
    }

    #[test]
    fn every_dimension_accepts_both_frozen_boundaries_and_rejects_out_of_range() {
        type DimensionCase = (
            &'static str,
            fn(&mut RelationshipDimensions, i32),
            i32,
            i32,
            i32,
        );
        let cases: [DimensionCase; 8] = [
            (
                "familiarity",
                |d, v| d.familiarity = v,
                FAMILIARITY_MIN,
                FAMILIARITY_MAX,
                FAMILIARITY_MIN - 1,
            ),
            (
                "trust",
                |d, v| d.trust = v,
                TRUST_MIN,
                TRUST_MAX,
                TRUST_MAX + 1,
            ),
            (
                "emotional_closeness",
                |d, v| d.emotional_closeness = v,
                EMOTIONAL_CLOSENESS_MIN,
                EMOTIONAL_CLOSENESS_MAX,
                EMOTIONAL_CLOSENESS_MAX + 1,
            ),
            (
                "collaboration",
                |d, v| d.collaboration = v,
                COLLABORATION_MIN,
                COLLABORATION_MAX,
                COLLABORATION_MIN - 1,
            ),
            (
                "safety",
                |d, v| d.safety = v,
                SAFETY_MIN,
                SAFETY_MAX,
                SAFETY_MIN - 1,
            ),
            (
                "dependency_tendency",
                |d, v| d.dependency_tendency = v,
                DEPENDENCY_TENDENCY_MIN,
                DEPENDENCY_TENDENCY_MAX,
                DEPENDENCY_TENDENCY_MAX + 1,
            ),
            (
                "boundary_comfort",
                |d, v| d.boundary_comfort = v,
                BOUNDARY_COMFORT_MIN,
                BOUNDARY_COMFORT_MAX,
                BOUNDARY_COMFORT_MIN - 1,
            ),
            (
                "tension",
                |d, v| d.tension = v,
                TENSION_MIN,
                TENSION_MAX,
                TENSION_MAX + 1,
            ),
        ];
        for (name, setter, min, max, out_of_range) in cases {
            for value in [min, max] {
                let mut values = RelationshipDimensions::neutral();
                setter(&mut values, value);
                values
                    .validate_result()
                    .unwrap_or_else(|error| panic!("{name}={value} must be valid: {error:?}"));
            }
            {
                let value = out_of_range;
                let mut values = RelationshipDimensions::neutral();
                setter(&mut values, value);
                let error = values.validate_result().unwrap_err();
                assert_eq!(
                    error.code,
                    RelationshipErrorCode::InvalidArgument,
                    "{name}={value} must be rejected"
                );
            }
        }
    }

    #[test]
    fn deltas_accept_the_full_signed_domain_but_reject_beyond_it() {
        let mut deltas = RelationshipDimensions::neutral();
        deltas.familiarity = -1000;
        deltas.tension = 1000;
        deltas.trust = -1000;
        deltas.safety = 1000;
        deltas.validate_deltas().unwrap();

        let mut beyond = RelationshipDimensions::neutral();
        beyond.collaboration = 1001;
        assert_eq!(
            beyond.validate_deltas().unwrap_err().code,
            RelationshipErrorCode::InvalidArgument
        );
        let mut below = RelationshipDimensions::neutral();
        below.boundary_comfort = -1001;
        assert_eq!(
            below.validate_deltas().unwrap_err().code,
            RelationshipErrorCode::InvalidArgument
        );
    }

    #[test]
    fn transition_rejects_empty_identities_sources_and_times() {
        assert_eq!(
            transition("", "life-a", PRIMARY_USER_SUBJECT_ID)
                .unwrap_err()
                .code,
            RelationshipErrorCode::InvalidArgument
        );
        assert_eq!(
            transition("event-1", "", PRIMARY_USER_SUBJECT_ID)
                .unwrap_err()
                .code,
            RelationshipErrorCode::InvalidArgument
        );
        assert_eq!(
            transition("event-1", "life-a", "").unwrap_err().code,
            RelationshipErrorCode::InvalidArgument
        );
        assert_eq!(
            transition("event-1", "life-a", "  ").unwrap_err().code,
            RelationshipErrorCode::InvalidArgument
        );
        let blank_source = RelationshipTransition::new(
            "event-1",
            "life-a",
            PRIMARY_USER_SUBJECT_ID,
            source("", "ref"),
            "reason_code",
            RelationshipDimensions::neutral(),
            0,
            RelationshipDimensions::neutral(),
            1,
            "2026-08-25T00:00:00.000Z",
        )
        .unwrap_err();
        assert_eq!(blank_source.code, RelationshipErrorCode::InvalidArgument);
        let blank_ref = RelationshipTransition::new(
            "event-1",
            "life-a",
            PRIMARY_USER_SUBJECT_ID,
            source("kind", " "),
            "reason_code",
            RelationshipDimensions::neutral(),
            0,
            RelationshipDimensions::neutral(),
            1,
            "",
        )
        .unwrap_err();
        assert_eq!(blank_ref.code, RelationshipErrorCode::InvalidArgument);
    }

    #[test]
    fn change_reason_must_be_a_safe_snake_case_code() {
        for valid in ["policy_delta_v2", "a", &"x".repeat(64)] {
            let mut deltas = RelationshipDimensions::neutral();
            deltas.familiarity = 1;
            RelationshipTransition::new(
                "event-1",
                "life-a",
                PRIMARY_USER_SUBJECT_ID,
                source("kind", "ref"),
                valid,
                deltas,
                0,
                RelationshipDimensions::neutral(),
                1,
                "2026-08-25T00:00:00.000Z",
            )
            .unwrap_or_else(|error| panic!("reason {valid:?} must be accepted: {error:?}"));
        }
        let invalid = [
            "",
            &"x".repeat(65),
            "Upper",
            "has space",
            "has-dash",
            "1starts_with_digit",
            "_leading_underscore",
            "trailing_underscore_",
            "double__underscore",
            "unicode_café",
        ];
        for reason in invalid {
            let error = RelationshipTransition::new(
                "event-1",
                "life-a",
                PRIMARY_USER_SUBJECT_ID,
                source("kind", "ref"),
                reason,
                RelationshipDimensions::neutral(),
                0,
                RelationshipDimensions::neutral(),
                1,
                "2026-08-25T00:00:00.000Z",
            )
            .unwrap_err();
            assert_eq!(
                error.code,
                RelationshipErrorCode::InvalidArgument,
                "reason {reason:?} must be rejected"
            );
        }
    }

    #[test]
    fn transition_rejects_negative_revision_zero_policy_and_out_of_range_next() {
        let mut out_of_range_next = RelationshipDimensions::neutral();
        out_of_range_next.trust = 1001;
        for (expected_revision, policy_version, next) in [
            (-1, 1, RelationshipDimensions::neutral()),
            (0, 0, RelationshipDimensions::neutral()),
            (0, -3, RelationshipDimensions::neutral()),
            (0, 1, out_of_range_next),
        ] {
            let error = RelationshipTransition::new(
                "event-1",
                "life-a",
                PRIMARY_USER_SUBJECT_ID,
                source("kind", "ref"),
                "reason_code",
                RelationshipDimensions::neutral(),
                expected_revision,
                next,
                policy_version,
                "2026-08-25T00:00:00.000Z",
            )
            .unwrap_err();
            assert_eq!(error.code, RelationshipErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn target_revision_is_checked_and_rejects_i64_max() {
        let normal = transition("event-1", "life-a", PRIMARY_USER_SUBJECT_ID).unwrap();
        assert_eq!(normal.target_revision().unwrap(), 1);

        let mut deltas = RelationshipDimensions::neutral();
        deltas.familiarity = 10;
        let mut next = RelationshipDimensions::neutral();
        next.familiarity = 10;
        let max_transition = RelationshipTransition::new(
            "event-max",
            "life-a",
            PRIMARY_USER_SUBJECT_ID,
            source("kind", "ref"),
            "reason_code",
            deltas,
            i64::MAX,
            next,
            1,
            "2026-08-25T00:00:00.000Z",
        )
        .unwrap();
        assert_eq!(
            max_transition.target_revision().unwrap_err().code,
            RelationshipErrorCode::InvalidArgument
        );
    }

    #[test]
    fn error_codes_are_static_and_typed() {
        assert_eq!(
            RelationshipError::revision_conflict().code,
            RelationshipErrorCode::RevisionConflict
        );
        assert_eq!(
            RelationshipError::revision_conflict().code.as_str(),
            "RELATIONSHIP_REVISION_CONFLICT"
        );
        assert_eq!(
            RelationshipError::event_conflict().code.as_str(),
            "RELATIONSHIP_EVENT_CONFLICT"
        );
        assert_eq!(
            RelationshipError::state_not_found().code.as_str(),
            "RELATIONSHIP_STATE_NOT_FOUND"
        );
        assert_eq!(
            RelationshipError::life_not_found().code.as_str(),
            "RELATIONSHIP_LIFE_NOT_FOUND"
        );
        assert!(!RelationshipError::revision_conflict().recoverable);
        assert!(!RelationshipError::event_conflict().recoverable);
        assert!(RelationshipError::life_not_found().recoverable);
        assert!(!RelationshipError::invalid_argument("x").recoverable);
    }
}
