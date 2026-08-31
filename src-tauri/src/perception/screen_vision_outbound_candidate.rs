//! Process-local D25-C2 authority for exactly one C1 screen-vision candidate.
//!
//! The broker owns either no candidate or one candidate.  It has no queue,
//! map, history, persistence, network, WebView, or pixel-extraction surface.
//! The candidate locator is only an opaque process-local handle; it is not
//! authorization for D23 consent, D25 policy, session use, provider use, or
//! network transmission.  Future use must re-read every required authority.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
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
    CandidateInUse,
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
    delivery_lease: Option<DeliveryLeaseRecord>,
}

struct DeliveryLeaseRecord {
    token: u64,
    delivery_id: String,
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
    next_lease_token: AtomicU64,
}

impl ScreenVisionOutboundCandidateBroker {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(ScreenVisionOutboundCandidateState::Empty),
            clock: Arc::new(SystemCandidateClock),
            next_lease_token: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn with_clock(clock: Arc<dyn CandidateClock>) -> Self {
        Self {
            state: Mutex::new(ScreenVisionOutboundCandidateState::Empty),
            clock,
            next_lease_token: AtomicU64::new(0),
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

        let mut state = self.lock_state()?;
        if matches!(
            &*state,
            ScreenVisionOutboundCandidateState::Candidate(candidate)
                if candidate.delivery_lease.is_some()
        ) {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateInUse,
            ));
        }

        // Generate the locator before mutating state.  A random-source failure
        // leaves the existing state untouched.
        let candidate_id = generate_candidate_id()?;
        let created_at = self.clock.now();
        let candidate = ScreenVisionOutboundCandidate {
            candidate_id: candidate_id.clone(),
            life_id: life_id.to_owned(),
            screen_session_fence: screen_session_fence.to_owned(),
            outbound_policy_revision,
            projection,
            created_at,
            delivery_lease: None,
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
        if matches!(
            &*state,
            ScreenVisionOutboundCandidateState::Candidate(candidate)
                if candidate.candidate_id == candidate_id && candidate.delivery_lease.is_some()
        ) {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateInUse,
            ));
        }
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

    /// Reserves the exact candidate for one provider-bound delivery.  The
    /// lease owns no pixel bytes and is intentionally process-local RAII.
    /// Candidate replacement and exact revoke fail closed while it is held.
    pub(crate) fn acquire_exact_delivery_lease<'a>(
        &'a self,
        candidate_id: &str,
        life_id: &str,
        screen_session_fence: &str,
        outbound_policy_revision: i64,
        delivery_id: &str,
    ) -> Result<ScreenVisionOutboundCandidateDeliveryLease<'a>, ScreenVisionOutboundCandidateError>
    {
        validate_candidate_id(candidate_id)?;
        validate_scope(life_id, screen_session_fence, outbound_policy_revision)?;
        validate_bounded_nonblank(delivery_id)?;

        let mut state = self.lock_state()?;
        let now = self.clock.now();
        if expire_if_needed(&mut state, now) {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateExpired,
            ));
        }

        let ScreenVisionOutboundCandidateState::Candidate(candidate) = &mut *state else {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::NoCurrentCandidate,
            ));
        };
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
        if candidate.delivery_lease.is_some() {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateInUse,
            ));
        }

        let token = self
            .next_lease_token
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| {
                candidate_error(ScreenVisionOutboundCandidateErrorCode::SynchronizationUnavailable)
            })?;
        candidate.delivery_lease = Some(DeliveryLeaseRecord {
            token,
            delivery_id: delivery_id.to_string(),
        });

        Ok(ScreenVisionOutboundCandidateDeliveryLease {
            broker: self,
            candidate_id: candidate_id.to_string(),
            delivery_id: delivery_id.to_string(),
            token,
        })
    }

    /// Checks that an exact lease still owns the exact current candidate. It
    /// also enforces the original five-minute TTL; holding a lease never
    /// silently renews authorization.
    pub(crate) fn validate_exact_delivery_lease(
        &self,
        lease: &ScreenVisionOutboundCandidateDeliveryLease<'_>,
        candidate_id: &str,
        life_id: &str,
        screen_session_fence: &str,
        outbound_policy_revision: i64,
        delivery_id: &str,
    ) -> Result<(), ScreenVisionOutboundCandidateError> {
        if !std::ptr::eq(lease.broker, self) {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::SynchronizationUnavailable,
            ));
        }
        validate_candidate_id(candidate_id)?;
        validate_scope(life_id, screen_session_fence, outbound_policy_revision)?;
        validate_bounded_nonblank(delivery_id)?;

        let state = self.lock_state()?;
        let ScreenVisionOutboundCandidateState::Candidate(candidate) = &*state else {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::NoCurrentCandidate,
            ));
        };
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
        if self
            .clock
            .now()
            .saturating_duration_since(candidate.created_at)
            >= SCREEN_VISION_OUTBOUND_CANDIDATE_TTL
        {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateExpired,
            ));
        }
        let Some(record) = &candidate.delivery_lease else {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateInUse,
            ));
        };
        if record.token != lease.token
            || record.delivery_id != delivery_id
            || lease.candidate_id != candidate_id
            || lease.delivery_id != delivery_id
        {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateInUse,
            ));
        }
        Ok(())
    }

    /// Borrows the projection only for the synchronous local closure. The
    /// closure cannot move or clone the projection and must return an owned
    /// bounded result before this method returns.
    pub(crate) fn with_exact_leased_projection<T>(
        &self,
        lease: &ScreenVisionOutboundCandidateDeliveryLease<'_>,
        operation: impl FnOnce(&ScreenVisionOutboundProjection) -> T,
    ) -> Result<T, ScreenVisionOutboundCandidateError> {
        if !std::ptr::eq(lease.broker, self) {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::SynchronizationUnavailable,
            ));
        }
        let state = self.lock_state()?;
        let ScreenVisionOutboundCandidateState::Candidate(candidate) = &*state else {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::NoCurrentCandidate,
            ));
        };
        let Some(record) = &candidate.delivery_lease else {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateInUse,
            ));
        };
        if record.token != lease.token || candidate.candidate_id != lease.candidate_id {
            return Err(candidate_error(
                ScreenVisionOutboundCandidateErrorCode::CandidateInUse,
            ));
        }
        Ok(operation(&candidate.projection))
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

    fn release_delivery_lease(&self, candidate_id: &str, token: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let ScreenVisionOutboundCandidateState::Candidate(candidate) = &mut *state {
            if candidate.candidate_id == candidate_id
                && candidate
                    .delivery_lease
                    .as_ref()
                    .is_some_and(|lease| lease.token == token)
            {
                candidate.delivery_lease = None;
            }
        }
    }

    /// Test-only mutex controls used by the C3 composition tests to exercise
    /// the existing C2 synchronization-failure contract.  Production never
    /// clears a poisoned lock or exposes this seam.
    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _state = self
                .state
                .lock()
                .expect("candidate state should initially lock");
            panic!("intentional test mutex poison");
        }));
    }

    #[cfg(test)]
    pub(crate) fn clear_poison_for_test(&self) {
        self.state.clear_poison();
    }

    /// Test-only age control used by the D25-D2 issue tests.  The production
    /// C2 clock and TTL semantics remain unchanged.
    #[cfg(test)]
    pub(crate) fn expire_current_for_test(&self) {
        let mut state = self
            .state
            .lock()
            .expect("candidate state should initially lock");
        if let ScreenVisionOutboundCandidateState::Candidate(candidate) = &mut *state {
            candidate.created_at = Instant::now()
                .checked_sub(SCREEN_VISION_OUTBOUND_CANDIDATE_TTL)
                .expect("test instant should support candidate expiry");
        }
    }
}

/// Process-local RAII ownership of one exact candidate delivery lease.
pub(crate) struct ScreenVisionOutboundCandidateDeliveryLease<'a> {
    broker: &'a ScreenVisionOutboundCandidateBroker,
    candidate_id: String,
    delivery_id: String,
    token: u64,
}

impl Drop for ScreenVisionOutboundCandidateDeliveryLease<'_> {
    fn drop(&mut self) {
        self.broker
            .release_delivery_lease(&self.candidate_id, self.token);
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
        let leased = matches!(
            &*state,
            ScreenVisionOutboundCandidateState::Candidate(candidate)
                if candidate.delivery_lease.is_some()
        );
        if !leased {
            *state = ScreenVisionOutboundCandidateState::Empty;
        }
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

    #[test]
    fn exact_delivery_lease_blocks_replacement_revoke_and_second_lease() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        let lease = broker
            .acquire_exact_delivery_lease(&candidate_id, LIFE_A, FENCE_A, REVISION_A, "delivery-a")
            .expect("exact candidate lease should be acquired");

        assert_error_code(
            broker.replace_candidate(LIFE_B, FENCE_B, REVISION_B, projection()),
            ScreenVisionOutboundCandidateErrorCode::CandidateInUse,
        );
        assert_error_code(
            broker.revoke_exact(&candidate_id),
            ScreenVisionOutboundCandidateErrorCode::CandidateInUse,
        );
        assert_error_code(
            broker.acquire_exact_delivery_lease(
                &candidate_id,
                LIFE_A,
                FENCE_A,
                REVISION_A,
                "delivery-b",
            ),
            ScreenVisionOutboundCandidateErrorCode::CandidateInUse,
        );
        broker
            .validate_exact_delivery_lease(
                &lease,
                &candidate_id,
                LIFE_A,
                FENCE_A,
                REVISION_A,
                "delivery-a",
            )
            .expect("the original exact lease should remain valid");
    }

    #[test]
    fn delivery_lease_does_not_refresh_candidate_ttl() {
        let (broker, clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        let lease = broker
            .acquire_exact_delivery_lease(&candidate_id, LIFE_A, FENCE_A, REVISION_A, "delivery-a")
            .expect("exact candidate lease should be acquired");
        clock.advance(SCREEN_VISION_OUTBOUND_CANDIDATE_TTL);

        assert_error_code(
            broker.validate_exact_delivery_lease(
                &lease,
                &candidate_id,
                LIFE_A,
                FENCE_A,
                REVISION_A,
                "delivery-a",
            ),
            ScreenVisionOutboundCandidateErrorCode::CandidateExpired,
        );
        drop(lease);
        assert_error_code(
            broker.get_exact(&candidate_id),
            ScreenVisionOutboundCandidateErrorCode::CandidateExpired,
        );
    }

    #[test]
    fn stale_lease_drop_cannot_clear_a_newer_candidate_lease() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_A, REVISION_A);
        let lease = broker
            .acquire_exact_delivery_lease(&candidate_id, LIFE_A, FENCE_A, REVISION_A, "delivery-a")
            .expect("exact candidate lease should be acquired");

        // Simulate a replacement performed by an owning recovery path after
        // the old lease token became stale.  The production replacement path
        // itself rejects a live lease; this test exercises the token fence on
        // the RAII drop directly.
        let newer_candidate = ScreenVisionOutboundCandidate {
            candidate_id: candidate_id.clone(),
            life_id: LIFE_B.to_string(),
            screen_session_fence: FENCE_B.to_string(),
            outbound_policy_revision: REVISION_B,
            projection: projection(),
            created_at: Instant::now(),
            delivery_lease: Some(DeliveryLeaseRecord {
                token: lease.token.wrapping_add(1),
                delivery_id: "delivery-b".to_string(),
            }),
        };
        *broker
            .state
            .lock()
            .expect("candidate state should not be poisoned") =
            ScreenVisionOutboundCandidateState::Candidate(newer_candidate);
        drop(lease);

        let state = broker
            .state
            .lock()
            .expect("candidate state should remain readable");
        let ScreenVisionOutboundCandidateState::Candidate(candidate) = &*state else {
            panic!("newer candidate must remain installed");
        };
        assert!(candidate.delivery_lease.is_some());
        assert_eq!(candidate.life_id, LIFE_B);
    }
}
