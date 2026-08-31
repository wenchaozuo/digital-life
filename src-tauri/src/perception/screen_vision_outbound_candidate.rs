//! Process-local D25-C2 authority for exactly one C1 screen-vision candidate.
//!
//! The broker owns either no candidate or one candidate.  It has no queue,
//! map, history, persistence, network, WebView, or pixel-extraction surface.
//! The candidate locator is only an opaque process-local handle; it is not
//! authorization for D23 consent, D25 policy, session use, provider use, or
//! network transmission.  Future use must re-read every required authority.

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use super::screen_vision_outbound_projection::{
    ScreenVisionOutboundPixelFormat, ScreenVisionOutboundProjection,
};

pub(crate) const SCREEN_VISION_OUTBOUND_CANDIDATE_TTL: Duration = Duration::from_secs(5 * 60);

const MAX_CANDIDATE_SCOPE_LENGTH: usize = 128;
const CANDIDATE_ID_RANDOM_BYTES: usize = 16;
const CANDIDATE_ID_HEX_LENGTH: usize = CANDIDATE_ID_RANDOM_BYTES * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundCandidateErrorCode {
    InvalidArgument,
    NoCurrentCandidate,
    CandidateMismatch,
    ScopeMismatch,
    CandidateExpired,
    SynchronizationUnavailable,
    RandomUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundCandidateError {
    code: ScreenVisionOutboundCandidateErrorCode,
}

impl ScreenVisionOutboundCandidateError {
    const fn new(code: ScreenVisionOutboundCandidateErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn code(self) -> ScreenVisionOutboundCandidateErrorCode {
        self.code
    }
}

/// Bounded metadata returned by `get_exact`.  It contains no RGB bytes and no
/// source crop/mask data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundCandidateMetadata {
    pub(crate) candidate_id: String,
    pub(crate) life_id: String,
    pub(crate) screen_session_fence: String,
    pub(crate) outbound_policy_revision: i64,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) pixel_format: ScreenVisionOutboundPixelFormat,
    pub(crate) age: Duration,
}

struct ScreenVisionOutboundCandidate {
    candidate_id: String,
    life_id: String,
    screen_session_fence: String,
    outbound_policy_revision: i64,
    projection: ScreenVisionOutboundProjection,
    created_at: Instant,
}

enum ScreenVisionOutboundCandidateState {
    Empty,
    Candidate(ScreenVisionOutboundCandidate),
}

trait CandidateClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemCandidateClock;

impl CandidateClock for SystemCandidateClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// The canonical process-local D25-C2 broker.  Its mutex protects the entire
/// state transition, including expiration, replacement, validation, and
/// exact revocation.  Replacing or expiring the state naturally drops the old
/// C1 projection and therefore retires its zeroizing RGB buffer.
pub(crate) struct ScreenVisionOutboundCandidateBroker {
    state: Mutex<ScreenVisionOutboundCandidateState>,
    clock: Arc<dyn CandidateClock>,
}

impl ScreenVisionOutboundCandidateBroker {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(ScreenVisionOutboundCandidateState::Empty),
            clock: Arc::new(SystemCandidateClock),
        }
    }

    #[cfg(test)]
    fn with_clock(clock: Arc<dyn CandidateClock>) -> Self {
        Self {
            state: Mutex::new(ScreenVisionOutboundCandidateState::Empty),
            clock,
        }
    }

    /// Atomically installs one new candidate, replacing the complete prior
    /// state.  The projection is moved into the broker; its bytes are never
    /// cloned here.
    pub(crate) fn replace_candidate(
        &self,
        life_id: &str,
        screen_session_fence: &str,
        outbound_policy_revision: i64,
        projection: ScreenVisionOutboundProjection,
    ) -> Result<String, ScreenVisionOutboundCandidateError> {
        validate_scope(life_id, screen_session_fence, outbound_policy_revision)?;

        // Generate the locator before mutating state.  A random-source or
        // synchronization failure leaves the existing state untouched.
        let candidate_id = generate_candidate_id()?;
        let mut state = self.lock_state()?;
        let created_at = self.clock.now();
        let candidate = ScreenVisionOutboundCandidate {
            candidate_id: candidate_id.clone(),
            life_id: life_id.to_owned(),
            screen_session_fence: screen_session_fence.to_owned(),
            outbound_policy_revision,
            projection,
            created_at,
        };

        // Assignment drops the old candidate while the mutex is held.  There
        // is never a second retrievable candidate or a second projection
        // clone.
        *state = ScreenVisionOutboundCandidateState::Candidate(candidate);
        Ok(candidate_id)
    }

    /// Returns only bounded candidate metadata.  It never returns or copies
    /// the owned C1 projection bytes.
    pub(crate) fn get_exact(
        &self,
        candidate_id: &str,
    ) -> Result<ScreenVisionOutboundCandidateMetadata, ScreenVisionOutboundCandidateError> {
        validate_candidate_id(candidate_id)?;
        let mut state = self.lock_state()?;
        let now = self.clock.now();
        if expire_if_needed(&mut state, now) {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateExpired,
            ));
        }

        match &*state {
            ScreenVisionOutboundCandidateState::Empty => Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::NoCurrentCandidate,
            )),
            ScreenVisionOutboundCandidateState::Candidate(candidate) => {
                if candidate.candidate_id != candidate_id {
                    return Err(candidate_error(
                        ScreenVisionOutboundCandidateErrorCode::CandidateMismatch,
                    ));
                }
                Ok(candidate_metadata(candidate, now))
            }
        }
    }

    /// Confirms only that the exact live candidate and all three exact scope
    /// dimensions match.  This is not a network or provider authorization.
    pub(crate) fn validate_exact_candidate(
        &self,
        candidate_id: &str,
        life_id: &str,
        screen_session_fence: &str,
        outbound_policy_revision: i64,
    ) -> Result<(), ScreenVisionOutboundCandidateError> {
        validate_candidate_id(candidate_id)?;
        validate_scope(life_id, screen_session_fence, outbound_policy_revision)?;

        let mut state = self.lock_state()?;
        let now = self.clock.now();
        if expire_if_needed(&mut state, now) {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateExpired,
            ));
        }

        match &*state {
            ScreenVisionOutboundCandidateState::Empty => Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::NoCurrentCandidate,
            )),
            ScreenVisionOutboundCandidateState::Candidate(candidate) => {
                if candidate.candidate_id != candidate_id {
                    return Err(candidate_error(
                        ScreenVisionOutboundCandidateErrorCode::CandidateMismatch,
                    ));
                }
                if candidate.life_id != life_id
                    || candidate.screen_session_fence != screen_session_fence
                    || candidate.outbound_policy_revision != outbound_policy_revision
                {
                    return Err(candidate_error(
                        ScreenVisionOutboundCandidateErrorCode::ScopeMismatch,
                    ));
                }
                Ok(())
            }
        }
    }

    /// Removes only the currently stored candidate with the exact opaque ID.
    /// A stale ID cannot remove a newer replacement.
    pub(crate) fn revoke_exact(
        &self,
        candidate_id: &str,
    ) -> Result<(), ScreenVisionOutboundCandidateError> {
        validate_candidate_id(candidate_id)?;
        let mut state = self.lock_state()?;
        let now = self.clock.now();
        if expire_if_needed(&mut state, now) {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateExpired,
            ));
        }

        match &*state {
            ScreenVisionOutboundCandidateState::Empty => Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::NoCurrentCandidate,
            )),
            ScreenVisionOutboundCandidateState::Candidate(candidate) => {
                if candidate.candidate_id != candidate_id {
                    return Err(candidate_error(
                        ScreenVisionOutboundCandidateErrorCode::CandidateMismatch,
                    ));
                }
                *state = ScreenVisionOutboundCandidateState::Empty;
                Ok(())
            }
        }
    }

    fn lock_state(
        &self,
    ) -> Result<
        MutexGuard<'_, ScreenVisionOutboundCandidateState>,
        ScreenVisionOutboundCandidateError,
    > {
        self.state.lock().map_err(|_| {
            candidate_error(ScreenVisionOutboundCandidateErrorCode::SynchronizationUnavailable)
        })
    }
}

fn candidate_error(
    code: ScreenVisionOutboundCandidateErrorCode,
) -> ScreenVisionOutboundCandidateError {
    ScreenVisionOutboundCandidateError::new(code)
}

fn validate_scope(
    life_id: &str,
    screen_session_fence: &str,
    outbound_policy_revision: i64,
) -> Result<(), ScreenVisionOutboundCandidateError> {
    validate_bounded_nonblank(life_id)?;
    validate_bounded_nonblank(screen_session_fence)?;
    if outbound_policy_revision < 1 {
        return Err(candidate_error(
            ScreenVisionOutboundCandidateErrorCode::InvalidArgument,
        ));
    }
    Ok(())
}

fn validate_candidate_id(candidate_id: &str) -> Result<(), ScreenVisionOutboundCandidateError> {
    validate_bounded_nonblank(candidate_id)
}

fn validate_bounded_nonblank(value: &str) -> Result<(), ScreenVisionOutboundCandidateError> {
    if value.trim().is_empty() || value.len() > MAX_CANDIDATE_SCOPE_LENGTH {
        return Err(candidate_error(
            ScreenVisionOutboundCandidateErrorCode::InvalidArgument,
        ));
    }
    Ok(())
}

fn generate_candidate_id() -> Result<String, ScreenVisionOutboundCandidateError> {
    let mut random = [0_u8; CANDIDATE_ID_RANDOM_BYTES];
    getrandom::fill(&mut random)
        .map_err(|_| candidate_error(ScreenVisionOutboundCandidateErrorCode::RandomUnavailable))?;

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut candidate_id = String::with_capacity(CANDIDATE_ID_HEX_LENGTH);
    for byte in random {
        candidate_id.push(char::from(HEX[usize::from(byte >> 4)]));
        candidate_id.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(candidate_id)
}

fn expire_if_needed(state: &mut ScreenVisionOutboundCandidateState, now: Instant) -> bool {
    let expired = match state {
        ScreenVisionOutboundCandidateState::Empty => false,
        ScreenVisionOutboundCandidateState::Candidate(candidate) => {
            now.saturating_duration_since(candidate.created_at)
                >= SCREEN_VISION_OUTBOUND_CANDIDATE_TTL
        }
    };
    if expired {
        *state = ScreenVisionOutboundCandidateState::Empty;
    }
    expired
}

fn candidate_metadata(
    candidate: &ScreenVisionOutboundCandidate,
    now: Instant,
) -> ScreenVisionOutboundCandidateMetadata {
    ScreenVisionOutboundCandidateMetadata {
        candidate_id: candidate.candidate_id.clone(),
        life_id: candidate.life_id.clone(),
        screen_session_fence: candidate.screen_session_fence.clone(),
        outbound_policy_revision: candidate.outbound_policy_revision,
        width: candidate.projection.width(),
        height: candidate.projection.height(),
        pixel_format: candidate.projection.pixel_format(),
        age: now.saturating_duration_since(candidate.created_at),
    }
}

#[cfg(test)]
mod tests {
    use super::super::screen_capture::{ScreenFrame, ScreenPixelFormat};
    use super::super::screen_vision_outbound_projection::{
        project_screen_frame, ScreenVisionOutboundPixelFormat, ScreenVisionOutboundProjection,
        ScreenVisionOutboundProjectionRequest, ScreenVisionOutboundRect,
    };
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const LIFE_A: &str = "life-a";
    const LIFE_B: &str = "life-b";
    const FENCE_A: &str = "fence-a";
    const FENCE_B: &str = "fence-b";
    const REVISION_A: i64 = 2;
    const REVISION_B: i64 = 4;

    #[derive(Clone)]
    struct ManualClock {
        now: Arc<Mutex<Instant>>,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                now: Arc::new(Mutex::new(Instant::now())),
            }
        }

        fn advance(&self, duration: Duration) {
            let mut now = self
                .now
                .lock()
                .expect("manual clock should not be poisoned");
            *now = now
                .checked_add(duration)
                .expect("manual test clock should fit");
        }
    }

    impl CandidateClock for ManualClock {
        fn now(&self) -> Instant {
            *self
                .now
                .lock()
                .expect("manual clock should not be poisoned")
        }
    }

    fn broker_with_manual_clock() -> (ScreenVisionOutboundCandidateBroker, ManualClock) {
        let clock = ManualClock::new();
        let broker = ScreenVisionOutboundCandidateBroker::with_clock(Arc::new(clock.clone()));
        (broker, clock)
    }

    fn projection() -> ScreenVisionOutboundProjection {
        let frame = ScreenFrame {
            width: 1,
            height: 1,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: vec![3, 2, 1, 255],
        };
        let request = ScreenVisionOutboundProjectionRequest::new(
            ScreenVisionOutboundRect::new(0, 0, 1, 1),
            Vec::new(),
        );
        project_screen_frame(&frame, &request).expect("test projection should succeed")
    }

    fn install(
        broker: &ScreenVisionOutboundCandidateBroker,
        life_id: &str,
        screen_session_fence: &str,
        outbound_policy_revision: i64,
    ) -> String {
        broker
            .replace_candidate(
                life_id,
                screen_session_fence,
                outbound_policy_revision,
                projection(),
            )
            .expect("candidate installation should succeed")
    }

    fn assert_error_code<T>(
        result: Result<T, ScreenVisionOutboundCandidateError>,
        expected: ScreenVisionOutboundCandidateErrorCode,
    ) {
        match result {
            Ok(_) => panic!("operation should fail"),
            Err(error) => assert_eq!(error.code(), expected),
        }
    }

    #[test]
    fn fresh_broker_is_empty() {
        let (broker, _clock) = broker_with_manual_clock();

        assert_error_code(
            broker.get_exact("candidate"),
            ScreenVisionOutboundCandidateErrorCode::NoCurrentCandidate,
        );
    }

    #[test]
    fn install_produces_one_opaque_csprng_candidate() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);

        assert_eq!(candidate_id.len(), CANDIDATE_ID_HEX_LENGTH);
        assert!(candidate_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }

    #[test]
    fn candidate_metadata_carries_exact_scope_and_projection_shape() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        let metadata = broker
            .get_exact(&candidate_id)
            .expect("candidate should be available");

        assert_eq!(metadata.candidate_id, candidate_id);
        assert_eq!(metadata.life_id, LIFE_A);
        assert_eq!(metadata.screen_session_fence, FENCE_A);
        assert_eq!(metadata.outbound_policy_revision, REVISION_A);
        assert_eq!(metadata.width, 1);
        assert_eq!(metadata.height, 1);
        assert_eq!(metadata.pixel_format, ScreenVisionOutboundPixelFormat::Rgb8);
        assert_eq!(metadata.age, Duration::ZERO);
    }

    #[test]
    fn candidate_id_differs_from_scope_identifiers() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);

        assert_ne!(candidate_id, LIFE_A);
        assert_ne!(candidate_id, FENCE_A);
        assert_ne!(candidate_id, REVISION_A.to_string());
    }

    #[test]
    fn second_install_replaces_first_candidate() {
        let (broker, _clock) = broker_with_manual_clock();
        let first = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        let second = install(&broker, LIFE_B, FENCE_B, REVISION_B);

        assert_ne!(first, second);
        assert_error_code(
            broker.get_exact(&first),
            ScreenVisionOutboundCandidateErrorCode::CandidateMismatch,
        );
        assert_eq!(
            broker
                .get_exact(&second)
                .expect("new candidate should remain")
                .life_id,
            LIFE_B
        );
    }

    #[test]
    fn old_exact_revoke_after_replacement_cannot_remove_new_candidate() {
        let (broker, _clock) = broker_with_manual_clock();
        let first = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        let second = install(&broker, LIFE_B, FENCE_B, REVISION_B);

        assert_error_code(
            broker.revoke_exact(&first),
            ScreenVisionOutboundCandidateErrorCode::CandidateMismatch,
        );
        assert!(broker.get_exact(&second).is_ok());
    }

    #[test]
    fn old_exact_get_after_replacement_reports_mismatch() {
        let (broker, _clock) = broker_with_manual_clock();
        let first = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        let _second = install(&broker, LIFE_B, FENCE_B, REVISION_B);

        assert_error_code(
            broker.get_exact(&first),
            ScreenVisionOutboundCandidateErrorCode::CandidateMismatch,
        );
    }

    #[test]
    fn exact_current_revoke_removes_candidate() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);

        broker
            .revoke_exact(&candidate_id)
            .expect("current candidate should revoke");
        assert_error_code(
            broker.get_exact(&candidate_id),
            ScreenVisionOutboundCandidateErrorCode::NoCurrentCandidate,
        );
    }

    #[test]
    fn wrong_candidate_id_cannot_revoke() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);

        assert_error_code(
            broker.revoke_exact("different-candidate"),
            ScreenVisionOutboundCandidateErrorCode::CandidateMismatch,
        );
        assert!(broker.get_exact(&candidate_id).is_ok());
    }

    #[test]
    fn wrong_life_fails_exact_validation() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);

        assert_error_code(
            broker.validate_exact_candidate(&candidate_id, LIFE_B, FENCE_A, REVISION_A),
            ScreenVisionOutboundCandidateErrorCode::ScopeMismatch,
        );
    }

    #[test]
    fn wrong_fence_fails_exact_validation() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);

        assert_error_code(
            broker.validate_exact_candidate(&candidate_id, LIFE_A, FENCE_B, REVISION_A),
            ScreenVisionOutboundCandidateErrorCode::ScopeMismatch,
        );
    }

    #[test]
    fn wrong_policy_revision_fails_exact_validation() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);

        assert_error_code(
            broker.validate_exact_candidate(&candidate_id, LIFE_A, FENCE_A, REVISION_B),
            ScreenVisionOutboundCandidateErrorCode::ScopeMismatch,
        );
    }

    #[test]
    fn expired_candidate_is_removed_and_becomes_absent() {
        let (broker, clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        clock.advance(SCREEN_VISION_OUTBOUND_CANDIDATE_TTL);

        assert_error_code(
            broker.get_exact(&candidate_id),
            ScreenVisionOutboundCandidateErrorCode::CandidateExpired,
        );
        assert_error_code(
            broker.get_exact(&candidate_id),
            ScreenVisionOutboundCandidateErrorCode::NoCurrentCandidate,
        );
    }

    #[test]
    fn reads_do_not_refresh_ttl() {
        let (broker, clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        clock.advance(Duration::from_secs(299));

        let metadata = broker
            .get_exact(&candidate_id)
            .expect("candidate should still be live");
        assert_eq!(metadata.age, Duration::from_secs(299));

        clock.advance(Duration::from_secs(1));
        assert_error_code(
            broker.validate_exact_candidate(&candidate_id, LIFE_A, FENCE_A, REVISION_A),
            ScreenVisionOutboundCandidateErrorCode::CandidateExpired,
        );
    }

    #[test]
    fn replace_of_expired_candidate_works() {
        let (broker, clock) = broker_with_manual_clock();
        let first = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        clock.advance(SCREEN_VISION_OUTBOUND_CANDIDATE_TTL);
        let second = install(&broker, LIFE_B, FENCE_B, REVISION_B);

        assert_error_code(
            broker.get_exact(&first),
            ScreenVisionOutboundCandidateErrorCode::CandidateMismatch,
        );
        assert_eq!(
            broker
                .get_exact(&second)
                .expect("replacement should be live")
                .life_id,
            LIFE_B
        );
    }

    #[test]
    fn projection_is_moved_into_broker_without_byte_clone() {
        let (broker, _clock) = broker_with_manual_clock();
        let projection = projection();
        let source_pointer = projection.as_bytes().as_ptr();

        let candidate_id = broker
            .replace_candidate(LIFE_A, FENCE_A, REVISION_A, projection)
            .expect("candidate installation should succeed");
        let state = broker.state.lock().expect("state should not be poisoned");
        match &*state {
            ScreenVisionOutboundCandidateState::Empty => panic!("candidate should be installed"),
            ScreenVisionOutboundCandidateState::Candidate(candidate) => {
                assert_eq!(candidate.candidate_id, candidate_id);
                assert_eq!(candidate.projection.as_bytes().as_ptr(), source_pointer);
            }
        }
    }

    #[test]
    fn candidate_uses_the_exact_c1_projection_type() {
        fn assert_c1_projection(_: &ScreenVisionOutboundProjection) {}

        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        let state = broker.state.lock().expect("state should not be poisoned");
        match &*state {
            ScreenVisionOutboundCandidateState::Empty => panic!("candidate should be installed"),
            ScreenVisionOutboundCandidateState::Candidate(candidate) => {
                assert_c1_projection(&candidate.projection);
                assert_eq!(candidate.candidate_id, candidate_id);
            }
        }
    }

    #[test]
    fn synchronization_failure_preserves_state_and_fails_closed() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);

        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _state = broker.state.lock().expect("state should initially lock");
            panic!("intentional test mutex poison");
        }));
        assert!(poisoned.is_err());
        assert_error_code(
            broker.get_exact(&candidate_id),
            ScreenVisionOutboundCandidateErrorCode::SynchronizationUnavailable,
        );

        // Clearing only the test poison marker lets us verify that the broker
        // preserved the candidate; production paths never clear poison.
        broker.state.clear_poison();
        assert_eq!(
            broker
                .get_exact(&candidate_id)
                .expect("state must survive")
                .life_id,
            LIFE_A
        );
    }

    #[test]
    fn broker_has_one_candidate_state_after_replacement() {
        let (broker, _clock) = broker_with_manual_clock();
        let _first = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        let second = install(&broker, LIFE_B, FENCE_B, REVISION_B);

        let state = broker.state.lock().expect("state should not be poisoned");
        match &*state {
            ScreenVisionOutboundCandidateState::Empty => panic!("replacement must remain stored"),
            ScreenVisionOutboundCandidateState::Candidate(candidate) => {
                assert_eq!(candidate.candidate_id, second);
                assert_eq!(candidate.life_id, LIFE_B);
            }
        }
    }

    #[test]
    fn invalid_scope_and_candidate_arguments_fail_closed() {
        let (broker, _clock) = broker_with_manual_clock();

        assert_error_code(
            broker.replace_candidate(" ", FENCE_A, REVISION_A, projection()),
            ScreenVisionOutboundCandidateErrorCode::InvalidArgument,
        );
        assert_error_code(
            broker.replace_candidate(LIFE_A, FENCE_A, 0, projection()),
            ScreenVisionOutboundCandidateErrorCode::InvalidArgument,
        );
        assert_error_code(
            broker.get_exact(" "),
            ScreenVisionOutboundCandidateErrorCode::InvalidArgument,
        );
    }

    #[test]
    fn candidate_metadata_has_no_pixel_extraction_surface() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        let metadata = broker
            .get_exact(&candidate_id)
            .expect("metadata should exist");

        assert_eq!(metadata.width, 1);
        assert_eq!(metadata.height, 1);
        assert_eq!(metadata.pixel_format, ScreenVisionOutboundPixelFormat::Rgb8);
    }
}
