//! D11-B2 deterministic emotion evolution policy (EmotionPolicyV1).
//!
//! A PURE function layer: current [`EmotionState`] + bounded
//! [`EmotionStimulus`] + explicitly injected elapsed time + event identity →
//! an [`EmotionTransition`]. The policy never opens SQLite, never calls the
//! repository, never reads a clock, and has no external I/O. Orchestration and
//! persistence belong to D11-C.
//!
//! Determinism contract: identical inputs always produce identical transition
//! values. All arithmetic is integer-only with i64 intermediates where sums or
//! products could exceed i32.

use super::{
    EmotionError, EmotionEventSource, EmotionState, EmotionTransition, ACTIVATION_MAX,
    ACTIVATION_MIN, INITIAL_POLICY_VERSION, VALENCE_MAX, VALENCE_MIN,
};

/// Linear decay toward zero, per dimension, per hour of injected elapsed time.
const VALENCE_DECAY_PER_HOUR: i64 = 8;
const ACTIVATION_DECAY_PER_HOUR: i64 = 24;

/// Elapsed time beyond one week behaves exactly like one week, bounding decay
/// arithmetic and keeping offline behavior deterministic.
pub(crate) const MAX_DECAY_ELAPSED_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Fixed stimulus gain (inertia V1): raw affect signals are dampened before
/// they may move authoritative state.
const VALENCE_STIMULUS_GAIN_NUMERATOR: i64 = 3;
const VALENCE_STIMULUS_GAIN_DENOMINATOR: i64 = 5;
const ACTIVATION_STIMULUS_GAIN_NUMERATOR: i64 = 7;
const ACTIVATION_STIMULUS_GAIN_DENOMINATOR: i64 = 10;

/// One bounded policy input. Untrusted affect signal only — never authority,
/// never persisted as-is, and free of any message/prompt/model body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EmotionStimulus {
    pub(crate) valence_signal: i32,
    pub(crate) activation_signal: i32,
}

impl EmotionStimulus {
    pub(crate) fn new(valence_signal: i32, activation_signal: i32) -> Result<Self, EmotionError> {
        let stimulus = Self {
            valence_signal,
            activation_signal,
        };
        stimulus.validate()?;
        Ok(stimulus)
    }

    pub(crate) fn validate(&self) -> Result<(), EmotionError> {
        if !(VALENCE_MIN..=VALENCE_MAX).contains(&self.valence_signal) {
            return Err(EmotionError::invalid_argument(
                "valence signal must be between -1000 and 1000.",
            ));
        }
        if !(ACTIVATION_MIN..=ACTIVATION_MAX).contains(&self.activation_signal) {
            return Err(EmotionError::invalid_argument(
                "activation signal must be between -1000 and 1000.",
            ));
        }
        Ok(())
    }
}

/// One pure policy request. `life_id` is deliberately absent: it is derived
/// from the current authoritative state, so a caller can never mismatch a
/// policy input against a foreign life.
#[derive(Clone, Debug)]
pub(crate) struct EmotionPolicyRequest {
    pub(crate) event_id: String,
    pub(crate) source: EmotionEventSource,
    pub(crate) stimulus: EmotionStimulus,
    pub(crate) elapsed_seconds: u64,
    pub(crate) event_time: String,
}

impl EmotionPolicyRequest {
    pub(crate) fn new(
        event_id: impl Into<String>,
        source: EmotionEventSource,
        stimulus: EmotionStimulus,
        elapsed_seconds: u64,
        event_time: impl Into<String>,
    ) -> Result<Self, EmotionError> {
        let request = Self {
            event_id: event_id.into(),
            source,
            stimulus,
            elapsed_seconds,
            event_time: event_time.into(),
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn validate(&self) -> Result<(), EmotionError> {
        if self.event_id.trim().is_empty() {
            return Err(EmotionError::invalid_argument(
                "event identity must not be empty.",
            ));
        }
        self.source.validate()?;
        if self.event_time.trim().is_empty() {
            return Err(EmotionError::invalid_argument(
                "event time must not be empty.",
            ));
        }
        Ok(())
    }
}

/// The decayed affect pair returned by [`effective_after_decay`]. Pure value
/// only; no revision, timestamps, or persistence identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EmotionVector {
    pub(crate) valence: i32,
    pub(crate) activation: i32,
}

/// Pure decayed effective state for the current authoritative state after
/// `elapsed_seconds`. Never advances revision, touches timestamps, persists,
/// or creates an event.
///
/// Elapsed time beyond [`MAX_DECAY_ELAPSED_SECONDS`] decays exactly like the
/// cap. Decay is linear toward zero and never crosses zero.
pub(crate) fn effective_after_decay(
    current: &EmotionState,
    elapsed_seconds: u64,
) -> Result<EmotionVector, EmotionError> {
    validate_current_state(current)?;
    let capped_elapsed = elapsed_seconds.min(MAX_DECAY_ELAPSED_SECONDS) as i64;

    // floor(elapsed * rate / 3600); i64 intermediates keep this overflow-free
    // because capped_elapsed * max_rate <= 604800 * 24 << i64::MAX.
    let valence_decay = capped_elapsed * VALENCE_DECAY_PER_HOUR / 3600;
    let activation_decay = capped_elapsed * ACTIVATION_DECAY_PER_HOUR / 3600;
    Ok(EmotionVector {
        valence: decay_toward_zero(current.valence, valence_decay),
        activation: decay_toward_zero(current.activation, activation_decay),
    })
}

fn decay_toward_zero(value: i32, decay_amount: i64) -> i32 {
    if value > 0 {
        (value as i64 - decay_amount).max(0) as i32
    } else if value < 0 {
        (value as i64 + decay_amount).min(0) as i32
    } else {
        0
    }
}

fn scaled_stimulus(signal: i32, numerator: i64, denominator: i64) -> i32 {
    // Rust signed integer division truncates toward zero, which is exactly
    // the required gain behavior (+100*3/5 = +60, -100*3/5 = -60).
    (signal as i64 * numerator / denominator) as i32
}

fn clamp_to_domain(value: i64) -> i32 {
    value.clamp(VALENCE_MIN as i64, VALENCE_MAX as i64) as i32
}

fn validate_current_state(current: &EmotionState) -> Result<(), EmotionError> {
    if current.life_id.trim().is_empty() {
        return Err(EmotionError::invalid_argument(
            "life identity must not be empty.",
        ));
    }
    if !(VALENCE_MIN..=VALENCE_MAX).contains(&current.valence) {
        return Err(EmotionError::invalid_argument(
            "state valence must be between -1000 and 1000.",
        ));
    }
    if !(ACTIVATION_MIN..=ACTIVATION_MAX).contains(&current.activation) {
        return Err(EmotionError::invalid_argument(
            "state activation must be between -1000 and 1000.",
        ));
    }
    if current.revision < 0 {
        return Err(EmotionError::invalid_argument(
            "state revision must not be negative.",
        ));
    }
    if current.policy_version != INITIAL_POLICY_VERSION {
        return Err(EmotionError::invalid_argument(
            "the emotion state was written by a different policy version.",
        ));
    }
    Ok(())
}

/// EmotionPolicyV1: derive the next atomic emotion transition.
///
/// Pipeline: linear decay toward zero over injected elapsed time → fixed-gain
/// stimulus impulse → desired state clamped to [-1000, 1000] → net delta
/// clamped to [-1000, 1000] (single-transition anti-whiplash cap) → final
/// state re-clamped. The event delta is FINAL persisted result minus CURRENT
/// persisted state on both dimensions.
pub(crate) fn evolve(
    current: &EmotionState,
    request: EmotionPolicyRequest,
) -> Result<EmotionTransition, EmotionError> {
    validate_current_state(current)?;
    request.validate()?;
    request.stimulus.validate()?;

    let effective = effective_after_decay(current, request.elapsed_seconds)?;
    let valence_impulse = scaled_stimulus(
        request.stimulus.valence_signal,
        VALENCE_STIMULUS_GAIN_NUMERATOR,
        VALENCE_STIMULUS_GAIN_DENOMINATOR,
    );
    let activation_impulse = scaled_stimulus(
        request.stimulus.activation_signal,
        ACTIVATION_STIMULUS_GAIN_NUMERATOR,
        ACTIVATION_STIMULUS_GAIN_DENOMINATOR,
    );

    let desired_valence = clamp_to_domain(effective.valence as i64 + valence_impulse as i64);
    let desired_activation =
        clamp_to_domain(effective.activation as i64 + activation_impulse as i64);

    // Anti-whiplash: each NET delta is independently capped at ±1000, so one
    // transition can never jump across the full domain width.
    let valence_net_delta = clamp_to_domain(desired_valence as i64 - current.valence as i64);
    let activation_net_delta =
        clamp_to_domain(desired_activation as i64 - current.activation as i64);

    let next_valence = clamp_to_domain(current.valence as i64 + valence_net_delta as i64);
    let next_activation = clamp_to_domain(current.activation as i64 + activation_net_delta as i64);

    let transition = EmotionTransition::new(
        request.event_id,
        current.life_id.clone(),
        request.source,
        valence_net_delta,
        activation_net_delta,
        current.revision,
        next_valence,
        next_activation,
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
    use crate::emotion::{EmotionErrorCode, NEUTRAL_ACTIVATION, NEUTRAL_VALENCE};

    const EVENT_TIME: &str = "2026-08-24T00:00:00.000Z";

    fn state(life_id: &str, valence: i32, activation: i32) -> EmotionState {
        EmotionState {
            life_id: life_id.into(),
            valence,
            activation,
            revision: 0,
            policy_version: INITIAL_POLICY_VERSION,
            last_applied_at: EVENT_TIME.into(),
            updated_at: EVENT_TIME.into(),
        }
    }

    fn stimulus(valence_signal: i32, activation_signal: i32) -> EmotionStimulus {
        EmotionStimulus::new(valence_signal, activation_signal).unwrap()
    }

    fn request(stimulus: EmotionStimulus, elapsed_seconds: u64) -> EmotionPolicyRequest {
        EmotionPolicyRequest::new(
            "event-1",
            EmotionEventSource::new("conversation", "turn-1"),
            stimulus,
            elapsed_seconds,
            EVENT_TIME,
        )
        .unwrap()
    }

    fn evolved(
        current: &EmotionState,
        valence_signal: i32,
        activation_signal: i32,
        elapsed_seconds: u64,
    ) -> EmotionTransition {
        evolve(
            current,
            request(stimulus(valence_signal, activation_signal), elapsed_seconds),
        )
        .unwrap()
    }

    // ---------- A. decay ----------

    #[test]
    fn zero_elapsed_changes_nothing() {
        let vector = effective_after_decay(&state("life-a", 100, -200), 0).unwrap();
        assert_eq!(
            vector,
            EmotionVector {
                valence: 100,
                activation: -200
            }
        );
    }

    #[test]
    fn positive_valence_decays_toward_zero_by_8_per_hour() {
        // +100 after exactly one hour → +92.
        let vector = effective_after_decay(&state("life-a", 100, 0), 3600).unwrap();
        assert_eq!(vector.valence, 92);
    }

    #[test]
    fn negative_valence_decays_toward_zero_by_8_per_hour() {
        // -100 after exactly one hour → -92.
        let vector = effective_after_decay(&state("life-a", -100, 0), 3600).unwrap();
        assert_eq!(vector.valence, -92);
    }

    #[test]
    fn positive_activation_decays_toward_zero_by_24_per_hour() {
        // +100 after exactly one hour → +76.
        let vector = effective_after_decay(&state("life-a", 0, 100), 3600).unwrap();
        assert_eq!(vector.activation, 76);
    }

    #[test]
    fn negative_activation_decays_toward_zero_by_24_per_hour() {
        // -100 after exactly one hour → -76.
        let vector = effective_after_decay(&state("life-a", 0, -100), 3600).unwrap();
        assert_eq!(vector.activation, -76);
    }

    #[test]
    fn decay_never_crosses_zero_in_either_dimension() {
        // Small magnitudes decay fully to zero, not past it.
        let vector = effective_after_decay(&state("life-a", 3, -5), 3600 * 10).unwrap();
        assert_eq!(vector.valence, 0);
        assert_eq!(vector.activation, 0);
    }

    #[test]
    fn elapsed_beyond_seven_days_behaves_exactly_like_seven_days() {
        let capped =
            effective_after_decay(&state("life-a", 500, -500), MAX_DECAY_ELAPSED_SECONDS).unwrap();
        let far_beyond = effective_after_decay(
            &state("life-a", 500, -500),
            MAX_DECAY_ELAPSED_SECONDS + 86_400,
        )
        .unwrap();
        assert_eq!(capped, far_beyond);

        // Exact expected values at the cap: floor(604800*8/3600)=1344 → clamps
        // to zero; floor(604800*24/3600)=4032 → clamps to zero. Use a value the
        // cap does NOT erase to prove exact equality of the arithmetic:
        // 500 - 1344 < 0 → 0 for both rates here; instead verify via a fresh
        // state where only partial decay is possible (already asserted above).
        assert_eq!(capped.valence, 0);
        assert_eq!(capped.activation, 0);
    }

    #[test]
    fn decay_amounts_use_floor_semantics_for_partial_hours() {
        // 1800s = half hour: floor(1800*8/3600)=4, floor(1800*24/3600)=12.
        let vector = effective_after_decay(&state("life-a", 100, -100), 1800).unwrap();
        assert_eq!(vector.valence, 96);
        assert_eq!(vector.activation, -88);
    }

    // ---------- B. stimulus gain ----------

    #[test]
    fn plus_minus_hundred_valence_signal_scales_to_plus_minus_sixty() {
        let positive = evolved(&state("life-a", 0, 0), 100, 0, 0);
        assert_eq!(positive.valence_delta, 60);
        let negative = evolved(&state("life-a", 0, 0), -100, 0, 0);
        assert_eq!(negative.valence_delta, -60);
    }

    #[test]
    fn plus_minus_hundred_activation_signal_scales_to_plus_minus_seventy() {
        let positive = evolved(&state("life-a", 0, 0), 0, 100, 0);
        assert_eq!(positive.activation_delta, 70);
        let negative = evolved(&state("life-a", 0, 0), 0, -100, 0);
        assert_eq!(negative.activation_delta, -70);
    }

    #[test]
    fn full_scale_signals_remain_safe_and_bounded() {
        let transition = evolved(&state("life-a", 0, 0), 1000, -1000, 0);
        // Truncation toward zero: 1000*3/5=600, -1000*7/10=-700.
        assert_eq!(
            (transition.valence_delta, transition.activation_delta),
            (600, -700)
        );
        assert_eq!(
            (transition.next_valence, transition.next_activation),
            (600, -700)
        );
    }

    #[test]
    fn out_of_range_signals_are_rejected() {
        assert_eq!(
            EmotionStimulus::new(1001, 0).unwrap_err().code,
            EmotionErrorCode::InvalidArgument
        );
        assert_eq!(
            EmotionStimulus::new(0, -1001).unwrap_err().code,
            EmotionErrorCode::InvalidArgument
        );
        // evolve() must also fail closed on an out-of-range stimulus.
        let raw_request = EmotionPolicyRequest {
            event_id: "event-bad".into(),
            source: EmotionEventSource::new("conversation", "turn-1"),
            stimulus: EmotionStimulus {
                valence_signal: 1001,
                activation_signal: 0,
            },
            elapsed_seconds: 0,
            event_time: EVENT_TIME.into(),
        };
        let error = evolve(&state("life-a", 0, 0), raw_request).unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::InvalidArgument);
    }

    // ---------- C. combined evolution ----------

    #[test]
    fn positive_current_with_positive_stimulus_moves_further_positive() {
        // +100, no decay, +100 signal → impulse +60 → next +160.
        let transition = evolved(&state("life-a", 100, 50), 100, 0, 0);
        assert_eq!(transition.next_valence, 160);
        assert_eq!(transition.valence_delta, 60);
    }

    #[test]
    fn positive_current_with_negative_stimulus_pulls_back_toward_negative() {
        // +100, no decay, -200 signal → impulse -120 → next -20.
        let transition = evolved(&state("life-a", 100, 0), -200, 0, 0);
        assert_eq!(transition.next_valence, -20);
        assert_eq!(transition.valence_delta, -120);
    }

    #[test]
    fn negative_current_with_positive_stimulus_pulls_back_toward_positive() {
        // -100, no decay, +200 signal → impulse +120 → next +20.
        let transition = evolved(&state("life-a", -100, 0), 200, 0, 0);
        assert_eq!(transition.next_valence, 20);
        assert_eq!(transition.valence_delta, 120);
    }

    #[test]
    fn neutral_state_receives_only_the_impulse() {
        let transition = evolved(
            &state("life-a", NEUTRAL_VALENCE, NEUTRAL_ACTIVATION),
            40,
            -30,
            0,
        );
        assert_eq!(transition.next_valence, 24); // 40*3/5
        assert_eq!(transition.next_activation, -21); // -30*7/10 truncates toward zero
    }

    #[test]
    fn desired_state_clamps_at_domain_bounds() {
        // +990 current, +100 signal (+60 impulse) would be 1050 → clamp 1000.
        let positive = evolved(&state("life-a", 990, -990), 100, -100, 0);
        assert_eq!(positive.next_valence, 1000);
        assert_eq!(positive.valence_delta, 10);
        assert_eq!(positive.next_activation, -1000);
        assert_eq!(positive.activation_delta, -10);
    }

    #[test]
    fn decay_then_impulse_compose_deterministically() {
        // +100 after one hour decays to +92; then +100 signal (+60) → +152.
        let transition = evolved(&state("life-a", 100, 0), 100, 0, 3600);
        assert_eq!(transition.next_valence, 152);
        assert_eq!(transition.valence_delta, 52);
    }

    // ---------- D. anti-whiplash ----------

    #[test]
    fn single_transition_net_delta_is_capped_at_minus_thousand() {
        // Sol's example: +1000, long decay → 0, strong negative signal
        // (-1000 → impulse -700): desired 0-700 = -700 from ORIGINAL +1000 is
        // a net delta of -1700 → capped at -1000 → next valence 0.
        let transition = evolved(
            &state("life-a", 1000, 0),
            -1000,
            0,
            MAX_DECAY_ELAPSED_SECONDS,
        );
        assert_eq!(transition.valence_delta, -1000);
        assert_eq!(transition.next_valence, 0);
    }

    #[test]
    fn symmetric_negative_to_positive_whiplash_is_capped() {
        // Mirror case: -1000, long decay → 0, strong positive signal
        // (+1000 → impulse +600): net delta would be +1600 → capped +1000 →
        // next valence 0.
        let transition = evolved(
            &state("life-a", -1000, 0),
            1000,
            0,
            MAX_DECAY_ELAPSED_SECONDS,
        );
        assert_eq!(transition.valence_delta, 1000);
        assert_eq!(transition.next_valence, 0);
    }

    #[test]
    fn returned_delta_equals_next_state_minus_original_current() {
        let cases = [
            (state("life-a", 1000, -1000), -1000i32, 1000i32, 0u64),
            (
                state("life-a", 1000, 0),
                -1000,
                0,
                MAX_DECAY_ELAPSED_SECONDS,
            ),
            (
                state("life-a", -1000, 0),
                1000,
                0,
                MAX_DECAY_ELAPSED_SECONDS,
            ),
            (state("life-a", 123, -456), -789, 321, 7200),
            (state("life-a", 0, 0), 1000, -1000, 0),
        ];
        for (current, v_sig, a_sig, elapsed) in cases {
            let transition = evolved(&current, v_sig, a_sig, elapsed);
            assert_eq!(
                transition.valence_delta,
                transition.next_valence - current.valence
            );
            assert_eq!(
                transition.activation_delta,
                transition.next_activation - current.activation
            );
            // And the final state itself stays inside the frozen domain.
            assert!((VALENCE_MIN..=VALENCE_MAX).contains(&transition.next_valence));
            assert!((ACTIVATION_MIN..=ACTIVATION_MAX).contains(&transition.next_activation));
            assert!((VALENCE_MIN..=VALENCE_MAX).contains(&transition.valence_delta));
            assert!((ACTIVATION_MIN..=ACTIVATION_MAX).contains(&transition.activation_delta));
        }
    }

    // ---------- E. authority contract ----------

    #[test]
    fn returned_life_id_comes_only_from_current_state() {
        let current = state("authoritative-life", 10, -10);
        let request = EmotionPolicyRequest::new(
            "event-1",
            EmotionEventSource::new("conversation", "turn-1"),
            stimulus(10, -10),
            0,
            EVENT_TIME,
        )
        .unwrap();
        // The request type has no life_id field at all — compile-level proof.
        let transition = evolve(&current, request).unwrap();
        assert_eq!(transition.life_id, "authoritative-life");
    }

    #[test]
    fn expected_revision_equals_current_revision() {
        let mut current = state("life-a", 10, -10);
        current.revision = 41;
        let transition = evolved(&current, 10, -10, 0);
        assert_eq!(transition.expected_revision, 41);
        assert_eq!(transition.target_revision().unwrap(), 42);
    }

    #[test]
    fn policy_version_is_one_and_taken_from_state_authority() {
        let transition = evolved(&state("life-a", 10, -10), 10, -10, 0);
        assert_eq!(transition.policy_version, 1);
        assert_eq!(transition.policy_version, INITIAL_POLICY_VERSION);
    }

    #[test]
    fn event_identity_source_and_time_are_preserved_exactly() {
        let source = EmotionEventSource::new("memory", "mem-77");
        let request = EmotionPolicyRequest::new(
            "event-abc",
            source.clone(),
            stimulus(10, -10),
            0,
            "2026-08-24T12:34:56.789Z",
        )
        .unwrap();
        let transition = evolve(&state("life-a", 0, 0), request).unwrap();
        assert_eq!(transition.event_id, "event-abc");
        assert_eq!(transition.source, source);
        assert_eq!(transition.event_time, "2026-08-24T12:34:56.789Z");
    }

    #[test]
    fn max_revision_state_produces_typed_invalid_argument() {
        let mut current = state("life-a", 10, -10);
        current.revision = i64::MAX;
        let error = evolve(&current, request(stimulus(10, -10), 0)).unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::InvalidArgument);
    }

    #[test]
    fn foreign_policy_version_is_rejected_not_downgraded() {
        let mut current = state("life-a", 10, -10);
        current.policy_version = 2;
        let error = evolve(&current, request(stimulus(10, -10), 0)).unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::InvalidArgument);
    }

    #[test]
    fn invalid_current_states_fail_closed() {
        let mut current;

        current = state("", 10, -10);
        assert_eq!(
            evolve(&current, request(stimulus(0, 0), 0))
                .unwrap_err()
                .code,
            EmotionErrorCode::InvalidArgument
        );

        current = state("life-a", 1001, -10);
        assert_eq!(
            evolve(&current, request(stimulus(0, 0), 0))
                .unwrap_err()
                .code,
            EmotionErrorCode::InvalidArgument
        );

        current = state("life-a", 10, -1001);
        assert_eq!(
            evolve(&current, request(stimulus(0, 0), 0))
                .unwrap_err()
                .code,
            EmotionErrorCode::InvalidArgument
        );

        current = state("life-a", 10, -10);
        current.revision = -1;
        assert_eq!(
            evolve(&current, request(stimulus(0, 0), 0))
                .unwrap_err()
                .code,
            EmotionErrorCode::InvalidArgument
        );

        // effective_after_decay shares the same validation boundary.
        current = state("life-a", 1001, 0);
        assert_eq!(
            effective_after_decay(&current, 0).unwrap_err().code,
            EmotionErrorCode::InvalidArgument
        );
    }

    // ---------- F. determinism ----------

    #[test]
    fn identical_inputs_produce_identical_transitions() {
        let build = || {
            let current = state("life-a", 250, -750);
            let request = EmotionPolicyRequest::new(
                "event-det",
                EmotionEventSource::new("conversation", "turn-42"),
                stimulus(-300, 900),
                5400,
                EVENT_TIME,
            )
            .unwrap();
            evolve(&current, request).unwrap()
        };
        assert_eq!(build(), build());
    }

    // ---------- G. persistence isolation ----------

    #[test]
    fn policy_module_source_performs_no_io_or_storage_calls() {
        // Architectural/source proof over the non-test portion of the module
        // (the test section below is excluded so this test's own literals
        // cannot self-match). If this ever fails, B2 leaked into persistence
        // or I/O and the architecture contract is broken.
        let source = include_str!("policy.rs");
        let implementation = source
            .split("#[cfg(test)]")
            .next()
            .expect("policy.rs always contains a cfg(test) section");
        for forbidden in [
            "StorageService",
            "commit_transition",
            "EmotionRepository",
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
