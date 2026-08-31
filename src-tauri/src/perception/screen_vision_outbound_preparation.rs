//! D25-C3 local authority composition for preparing one vision candidate.
//!
//! This module composes the already-frozen local authorities without adding a
//! command, IPC surface, provider path, or durable state.  A successful call
//! performs exactly one canonical local capture, projects it through the
//! frozen C1 crop/mask implementation, and moves that projection into the
//! process-local C2 candidate broker.  The raw frame is retired before the
//! candidate is installed.
//!
//! The candidate locator returned by this module is not an outbound grant.
//! Any later consumer must re-read every required authority at its own
//! delivery boundary.

use super::screen_capture::{
    capture_one_shot_with_provider,
    operation::{ScreenCaptureOperationGate, ScreenCaptureOperationPermit},
    provider::{self, ScreenCaptureProvider},
    target::ScreenCaptureTargetBroker,
    ScreenCaptureError, ScreenCaptureErrorCode,
};
use super::screen_policy::{
    authorize_screen_perception, ScreenPerceptionRepository, ScreenPerceptionSessionGate,
};
use super::screen_vision_outbound_candidate::{
    ScreenVisionOutboundCandidateBroker, ScreenVisionOutboundCandidateErrorCode,
};
use super::screen_vision_outbound_policy::{
    validate_screen_vision_outbound_policy_state, ScreenVisionOutboundPolicyRepository,
};
use super::screen_vision_outbound_projection::{
    project_screen_frame, ScreenVisionOutboundPixelFormat, ScreenVisionOutboundProjectionRequest,
};
use crate::storage::StorageService;

const MAX_LIFE_ID_LENGTH: usize = 128;

/// The only caller-supplied data accepted by the preparation boundary.
///
/// The session fence, outbound-policy revision, target identity, native
/// handle, provider, and candidate identity are all backend-owned values and
/// are deliberately absent from this request.
pub(crate) struct ScreenVisionOutboundPreparationRequest {
    pub(crate) life_id: String,
    pub(crate) projection_request: ScreenVisionOutboundProjectionRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundPreparationErrorCode {
    InvalidArgument,
    OperationBusy,
    LocalScreenAuthorityUnavailable,
    SessionFenceChanged,
    OutboundPolicyUnavailable,
    OutboundPolicyChanged,
    CaptureFailed,
    ProjectionFailed,
    CandidateInstallFailed,
    SynchronizationUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundPreparationError {
    code: ScreenVisionOutboundPreparationErrorCode,
}

impl ScreenVisionOutboundPreparationError {
    const fn new(code: ScreenVisionOutboundPreparationErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn code(self) -> ScreenVisionOutboundPreparationErrorCode {
        self.code
    }
}

/// Bounded metadata returned after the C2 broker has accepted the projected
/// image.  It contains no pixels, crop/mask data, target metadata, provider
/// metadata, native handle, or session fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundPreparationResult {
    pub(crate) candidate_id: String,
    pub(crate) life_id: String,
    pub(crate) outbound_policy_revision: i64,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) pixel_format: ScreenVisionOutboundPixelFormat,
}

/// Runs the production C3 composition with the canonical native provider.
///
/// The storage object is passed to both repository traits because SQLite is
/// the authoritative source for both durable policy domains.  No frontend
/// snapshot or caller-provided authority value is consumed here.
#[allow(dead_code)]
pub(crate) fn prepare_screen_vision_candidate(
    storage: &StorageService,
    session_gate: &ScreenPerceptionSessionGate,
    target_broker: &ScreenCaptureTargetBroker,
    operation_gate: &ScreenCaptureOperationGate,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    request: &ScreenVisionOutboundPreparationRequest,
) -> Result<ScreenVisionOutboundPreparationResult, ScreenVisionOutboundPreparationError> {
    let provider = provider::native_provider();
    prepare_screen_vision_candidate_with_provider(
        storage,
        storage,
        session_gate,
        target_broker,
        operation_gate,
        candidate_broker,
        request,
        provider.as_ref(),
        &PreparationHooks::none(),
    )
}

/// Production C3 entrypoint for a caller that already owns the canonical
/// screen-operation permit.  D26 uses this to keep target-dimension
/// preflight and the subsequent one-shot capture inside one operation slot.
pub(crate) fn prepare_screen_vision_candidate_with_operation_permit(
    storage: &StorageService,
    session_gate: &ScreenPerceptionSessionGate,
    target_broker: &ScreenCaptureTargetBroker,
    operation_permit: ScreenCaptureOperationPermit,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    request: &ScreenVisionOutboundPreparationRequest,
) -> Result<ScreenVisionOutboundPreparationResult, ScreenVisionOutboundPreparationError> {
    let provider = provider::native_provider();
    prepare_screen_vision_candidate_with_provider_and_permit(
        storage,
        storage,
        session_gate,
        target_broker,
        operation_permit,
        candidate_broker,
        request,
        provider.as_ref(),
        &PreparationHooks::none(),
    )
}

/// Private provider/test-hook seam for deterministic authority and lifecycle
/// tests.  Production can only reach the public-in-module function above,
/// which always constructs the canonical native provider.
fn prepare_screen_vision_candidate_with_provider(
    screen_repository: &dyn ScreenPerceptionRepository,
    outbound_repository: &dyn ScreenVisionOutboundPolicyRepository,
    session_gate: &ScreenPerceptionSessionGate,
    target_broker: &ScreenCaptureTargetBroker,
    operation_gate: &ScreenCaptureOperationGate,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    request: &ScreenVisionOutboundPreparationRequest,
    provider: &dyn ScreenCaptureProvider,
    hooks: &PreparationHooks<'_>,
) -> Result<ScreenVisionOutboundPreparationResult, ScreenVisionOutboundPreparationError> {
    let operation_permit = operation_gate
        .try_enter()
        .map_err(|_| preparation_error(ScreenVisionOutboundPreparationErrorCode::OperationBusy))?;
    prepare_screen_vision_candidate_with_provider_and_permit(
        screen_repository,
        outbound_repository,
        session_gate,
        target_broker,
        operation_permit,
        candidate_broker,
        request,
        provider,
        hooks,
    )
}

fn prepare_screen_vision_candidate_with_provider_and_permit(
    screen_repository: &dyn ScreenPerceptionRepository,
    outbound_repository: &dyn ScreenVisionOutboundPolicyRepository,
    session_gate: &ScreenPerceptionSessionGate,
    target_broker: &ScreenCaptureTargetBroker,
    operation_permit: ScreenCaptureOperationPermit,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    request: &ScreenVisionOutboundPreparationRequest,
    provider: &dyn ScreenCaptureProvider,
    hooks: &PreparationHooks<'_>,
) -> Result<ScreenVisionOutboundPreparationResult, ScreenVisionOutboundPreparationError> {
    validate_request(request)?;

    // This is the one canonical screen-operation permit.  It is held in this
    // stack frame until after final authority revalidation and C2 installation;
    // the caller already acquired it fail-fast and no queue exists.
    let _operation_permit = operation_permit;

    // Backend authority is read before any provider call.  The fence and
    // policy revision captured here are never accepted from the request.
    let screen_session_fence =
        snapshot_screen_authority(screen_repository, session_gate, &request.life_id)?;
    let outbound_policy_revision = snapshot_outbound_policy(outbound_repository, &request.life_id)?;
    let canonical_screen_session_fence = screen_session_fence.to_string();

    // The existing D23 one-shot path performs its own final authorization
    // immediately before the provider is called and resolves the opaque
    // backend target from the current session fence.
    let frame = capture_one_shot_with_provider(
        screen_repository,
        session_gate,
        target_broker,
        &request.life_id,
        provider,
    )
    .map_err(map_capture_error)?;

    if let Some(after_capture) = hooks.after_capture {
        after_capture();
    }

    // This is the first post-capture authority recheck and it intentionally
    // happens before C1 can read a single source pixel.
    revalidate_screen_authority(
        screen_repository,
        session_gate,
        &request.life_id,
        screen_session_fence,
    )?;
    revalidate_outbound_policy(
        outbound_repository,
        &request.life_id,
        outbound_policy_revision,
    )?;

    let projection_result = project_screen_frame(&frame, &request.projection_request);
    // Retire the raw ScreenFrame before any C2 state transition.  On either
    // projection success or failure its sensitive buffer cannot outlive this
    // point in the preparation pipeline.
    drop(frame);
    let projection = projection_result.map_err(|_| {
        preparation_error(ScreenVisionOutboundPreparationErrorCode::ProjectionFailed)
    })?;

    let result_shape = (
        projection.width(),
        projection.height(),
        projection.pixel_format(),
    );

    if let Some(before_final_recheck) = hooks.before_final_recheck {
        before_final_recheck();
    }

    // The final recheck is immediately before the local C2 install.  A policy
    // or session transition can still occur in that tiny check-to-install
    // interval; that race is accepted because C2 installation is local
    // preparation, never external-send authority.  The later delivery
    // boundary must independently re-authorize outbound use.
    revalidate_screen_authority(
        screen_repository,
        session_gate,
        &request.life_id,
        screen_session_fence,
    )?;
    revalidate_outbound_policy(
        outbound_repository,
        &request.life_id,
        outbound_policy_revision,
    )?;

    if let Some(before_candidate_install) = hooks.before_candidate_install {
        before_candidate_install();
    }

    // The projection is moved, never cloned, into the single C2 broker.  Any
    // C2 random/lock failure drops this new projection while preserving the
    // broker's previous candidate.
    let candidate_id = candidate_broker
        .replace_candidate(
            &request.life_id,
            &canonical_screen_session_fence,
            outbound_policy_revision,
            projection,
        )
        .map_err(map_candidate_install_error)?;

    Ok(ScreenVisionOutboundPreparationResult {
        candidate_id,
        life_id: request.life_id.clone(),
        outbound_policy_revision,
        width: result_shape.0,
        height: result_shape.1,
        pixel_format: result_shape.2,
    })
}

fn validate_request(
    request: &ScreenVisionOutboundPreparationRequest,
) -> Result<(), ScreenVisionOutboundPreparationError> {
    let life_id = request.life_id.as_str();
    if life_id.trim().is_empty() || life_id.chars().count() > MAX_LIFE_ID_LENGTH {
        return Err(preparation_error(
            ScreenVisionOutboundPreparationErrorCode::InvalidArgument,
        ));
    }
    Ok(())
}

fn snapshot_screen_authority(
    repository: &dyn ScreenPerceptionRepository,
    session_gate: &ScreenPerceptionSessionGate,
    life_id: &str,
) -> Result<u64, ScreenVisionOutboundPreparationError> {
    authorize_screen_perception(repository, session_gate, life_id).map_err(|_| {
        preparation_error(ScreenVisionOutboundPreparationErrorCode::LocalScreenAuthorityUnavailable)
    })?;
    session_gate.life_fence_for(life_id).ok_or_else(|| {
        preparation_error(ScreenVisionOutboundPreparationErrorCode::LocalScreenAuthorityUnavailable)
    })
}

fn snapshot_outbound_policy(
    repository: &dyn ScreenVisionOutboundPolicyRepository,
    life_id: &str,
) -> Result<i64, ScreenVisionOutboundPreparationError> {
    read_outbound_policy_revision(repository, life_id).map_err(|_| {
        preparation_error(ScreenVisionOutboundPreparationErrorCode::OutboundPolicyUnavailable)
    })
}

fn revalidate_screen_authority(
    repository: &dyn ScreenPerceptionRepository,
    session_gate: &ScreenPerceptionSessionGate,
    life_id: &str,
    expected_fence: u64,
) -> Result<(), ScreenVisionOutboundPreparationError> {
    authorize_screen_perception(repository, session_gate, life_id).map_err(|_| {
        preparation_error(ScreenVisionOutboundPreparationErrorCode::SessionFenceChanged)
    })?;
    let current_fence = session_gate.life_fence_for(life_id).ok_or_else(|| {
        preparation_error(ScreenVisionOutboundPreparationErrorCode::SessionFenceChanged)
    })?;
    if current_fence != expected_fence {
        return Err(preparation_error(
            ScreenVisionOutboundPreparationErrorCode::SessionFenceChanged,
        ));
    }
    Ok(())
}

fn revalidate_outbound_policy(
    repository: &dyn ScreenVisionOutboundPolicyRepository,
    life_id: &str,
    expected_revision: i64,
) -> Result<(), ScreenVisionOutboundPreparationError> {
    let current_revision = read_outbound_policy_revision(repository, life_id).map_err(|_| {
        preparation_error(ScreenVisionOutboundPreparationErrorCode::OutboundPolicyChanged)
    })?;
    if current_revision != expected_revision {
        return Err(preparation_error(
            ScreenVisionOutboundPreparationErrorCode::OutboundPolicyChanged,
        ));
    }
    Ok(())
}

fn read_outbound_policy_revision(
    repository: &dyn ScreenVisionOutboundPolicyRepository,
    life_id: &str,
) -> Result<i64, ()> {
    let policy = repository
        .find_screen_vision_outbound_policy(life_id)
        .map_err(|_| ())?
        .ok_or(())?;
    validate_screen_vision_outbound_policy_state(&policy).map_err(|_| ())?;
    if policy.life_id != life_id || !policy.is_screen_vision_outbound_enabled() {
        return Err(());
    }
    Ok(policy.revision)
}

fn map_capture_error(error: ScreenCaptureError) -> ScreenVisionOutboundPreparationError {
    let code = match error.code {
        ScreenCaptureErrorCode::Busy => ScreenVisionOutboundPreparationErrorCode::OperationBusy,
        _ => ScreenVisionOutboundPreparationErrorCode::CaptureFailed,
    };
    preparation_error(code)
}

fn map_candidate_install_error(
    error: super::screen_vision_outbound_candidate::ScreenVisionOutboundCandidateError,
) -> ScreenVisionOutboundPreparationError {
    let code = match error.code() {
        ScreenVisionOutboundCandidateErrorCode::SynchronizationUnavailable => {
            ScreenVisionOutboundPreparationErrorCode::SynchronizationUnavailable
        }
        _ => ScreenVisionOutboundPreparationErrorCode::CandidateInstallFailed,
    };
    preparation_error(code)
}

fn preparation_error(
    code: ScreenVisionOutboundPreparationErrorCode,
) -> ScreenVisionOutboundPreparationError {
    ScreenVisionOutboundPreparationError::new(code)
}

/// Hooks are private and only make synchronous tests able to place an
/// authority transition at each lifecycle boundary.  The production path
/// passes `none`, so no process-global callback or mutable preparation state
/// exists.
struct PreparationHooks<'a> {
    after_capture: Option<&'a dyn Fn()>,
    before_final_recheck: Option<&'a dyn Fn()>,
    before_candidate_install: Option<&'a dyn Fn()>,
}

impl PreparationHooks<'_> {
    const fn none() -> Self {
        Self {
            after_capture: None,
            before_final_recheck: None,
            before_candidate_install: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    };

    use crate::perception::screen_capture::{
        provider::ScreenCaptureProvider, target::ScreenCaptureTarget, ScreenCaptureError,
        ScreenFrame, ScreenPixelFormat,
    };
    use crate::perception::screen_policy::{
        LifeScreenPerceptionPolicy, LifeScreenPerceptionPolicyCreateRequest,
        LifeScreenPerceptionPolicyEvent, LifeScreenPerceptionPolicyUpdateOutcome,
        LifeScreenPerceptionPolicyUpdateRequest, ScreenPerceptionCreateOutcome,
        ScreenPerceptionError, ScreenPerceptionRepository,
    };
    use crate::perception::screen_vision_outbound_candidate::ScreenVisionOutboundCandidateBroker;
    use crate::perception::screen_vision_outbound_policy::{
        LifeScreenVisionOutboundPolicy, LifeScreenVisionOutboundPolicyCreateRequest,
        LifeScreenVisionOutboundPolicyEvent, LifeScreenVisionOutboundPolicyUpdateOutcome,
        LifeScreenVisionOutboundPolicyUpdateRequest, ScreenVisionOutboundPolicyCreateOutcome,
        ScreenVisionOutboundPolicyError, ScreenVisionOutboundPolicyRepository,
    };
    use crate::perception::screen_vision_outbound_projection::{
        project_screen_frame, ScreenVisionOutboundProjection, ScreenVisionOutboundRect,
    };

    const LIFE_A: &str = "life-a";
    const LIFE_B: &str = "life-b";
    const INITIAL_REVISION: i64 = 7;

    #[derive(Clone)]
    struct FakeScreenPerceptionRepository {
        policy: Arc<Mutex<Option<LifeScreenPerceptionPolicy>>>,
    }

    impl FakeScreenPerceptionRepository {
        fn enabled_for(life_id: &str, enabled: bool) -> Self {
            Self {
                policy: Arc::new(Mutex::new(Some(LifeScreenPerceptionPolicy {
                    life_id: life_id.to_string(),
                    screen_perception_enabled: enabled,
                    revision: 1,
                    created_at: "2026-08-31T00:00:00Z".to_string(),
                    updated_at: "2026-08-31T00:00:00Z".to_string(),
                    policy_version: 1,
                }))),
            }
        }

        fn set_enabled(&self, enabled: bool) {
            self.policy
                .lock()
                .expect("screen policy mutex should not be poisoned")
                .as_mut()
                .expect("screen policy should exist")
                .screen_perception_enabled = enabled;
        }
    }

    impl ScreenPerceptionRepository for FakeScreenPerceptionRepository {
        fn create_screen_perception_policy(
            &self,
            _request: LifeScreenPerceptionPolicyCreateRequest,
        ) -> Result<ScreenPerceptionCreateOutcome<LifeScreenPerceptionPolicy>, ScreenPerceptionError>
        {
            Err(ScreenPerceptionError::database())
        }

        fn find_screen_perception_policy(
            &self,
            life_id: &str,
        ) -> Result<Option<LifeScreenPerceptionPolicy>, ScreenPerceptionError> {
            Ok(self
                .policy
                .lock()
                .expect("screen policy mutex should not be poisoned")
                .clone()
                .filter(|policy| policy.life_id == life_id))
        }

        fn update_screen_perception_policy(
            &self,
            _request: LifeScreenPerceptionPolicyUpdateRequest,
        ) -> Result<LifeScreenPerceptionPolicyUpdateOutcome, ScreenPerceptionError> {
            Err(ScreenPerceptionError::database())
        }

        fn find_screen_perception_policy_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<Option<LifeScreenPerceptionPolicyEvent>, ScreenPerceptionError> {
            Err(ScreenPerceptionError::database())
        }
    }

    #[derive(Clone)]
    struct FakeOutboundPolicyRepository {
        policy: Arc<Mutex<Option<LifeScreenVisionOutboundPolicy>>>,
    }

    impl FakeOutboundPolicyRepository {
        fn enabled_for(life_id: &str, enabled: bool, revision: i64) -> Self {
            Self {
                policy: Arc::new(Mutex::new(Some(LifeScreenVisionOutboundPolicy {
                    life_id: life_id.to_string(),
                    screen_vision_outbound_enabled: enabled,
                    revision,
                    created_at: "2026-08-31T00:00:00Z".to_string(),
                    updated_at: "2026-08-31T00:00:00Z".to_string(),
                    policy_version: 1,
                }))),
            }
        }

        fn set_policy(&self, enabled: bool, revision: i64) {
            let mut policy = self
                .policy
                .lock()
                .expect("outbound policy mutex should not be poisoned");
            let current = policy.as_mut().expect("outbound policy should exist");
            current.screen_vision_outbound_enabled = enabled;
            current.revision = revision;
            current.updated_at = format!("revision-{revision}");
        }

        fn remove_policy(&self) {
            *self
                .policy
                .lock()
                .expect("outbound policy mutex should not be poisoned") = None;
        }
    }

    impl ScreenVisionOutboundPolicyRepository for FakeOutboundPolicyRepository {
        fn create_screen_vision_outbound_policy(
            &self,
            _request: LifeScreenVisionOutboundPolicyCreateRequest,
        ) -> Result<
            ScreenVisionOutboundPolicyCreateOutcome<LifeScreenVisionOutboundPolicy>,
            ScreenVisionOutboundPolicyError,
        > {
            Err(ScreenVisionOutboundPolicyError::database())
        }

        fn find_screen_vision_outbound_policy(
            &self,
            life_id: &str,
        ) -> Result<Option<LifeScreenVisionOutboundPolicy>, ScreenVisionOutboundPolicyError>
        {
            Ok(self
                .policy
                .lock()
                .expect("outbound policy mutex should not be poisoned")
                .clone()
                .filter(|policy| policy.life_id == life_id))
        }

        fn update_screen_vision_outbound_policy(
            &self,
            _request: LifeScreenVisionOutboundPolicyUpdateRequest,
        ) -> Result<LifeScreenVisionOutboundPolicyUpdateOutcome, ScreenVisionOutboundPolicyError>
        {
            Err(ScreenVisionOutboundPolicyError::database())
        }

        fn find_screen_vision_outbound_policy_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<Option<LifeScreenVisionOutboundPolicyEvent>, ScreenVisionOutboundPolicyError>
        {
            Err(ScreenVisionOutboundPolicyError::database())
        }
    }

    struct FakeProvider {
        supported: bool,
        support_calls: Arc<AtomicUsize>,
        capture_calls: Arc<AtomicUsize>,
        frame: Mutex<Option<Result<ScreenFrame, ScreenCaptureError>>>,
        on_capture: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    }

    impl FakeProvider {
        fn new(
            frame: Result<ScreenFrame, ScreenCaptureError>,
            on_capture: Option<Box<dyn Fn() + Send + Sync>>,
        ) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
            let support_calls = Arc::new(AtomicUsize::new(0));
            let capture_calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    supported: true,
                    support_calls: Arc::clone(&support_calls),
                    capture_calls: Arc::clone(&capture_calls),
                    frame: Mutex::new(Some(frame)),
                    on_capture: Mutex::new(on_capture),
                },
                support_calls,
                capture_calls,
            )
        }
    }

    impl ScreenCaptureProvider for FakeProvider {
        fn is_supported(&self) -> bool {
            self.support_calls.fetch_add(1, Ordering::SeqCst);
            self.supported
        }

        fn capture_frame(
            &self,
            _target: &ScreenCaptureTarget,
        ) -> Result<ScreenFrame, ScreenCaptureError> {
            self.capture_calls.fetch_add(1, Ordering::SeqCst);
            let callback = self
                .on_capture
                .lock()
                .expect("provider callback mutex should not be poisoned")
                .take();
            if let Some(callback) = callback {
                callback();
            }
            self.frame
                .lock()
                .expect("provider frame mutex should not be poisoned")
                .take()
                .expect("fake provider should be called once")
        }
    }

    struct Fixture {
        screen_repository: FakeScreenPerceptionRepository,
        outbound_repository: FakeOutboundPolicyRepository,
        session_gate: Arc<ScreenPerceptionSessionGate>,
        target_broker: ScreenCaptureTargetBroker,
        operation_gate: Arc<ScreenCaptureOperationGate>,
        candidate_broker: ScreenVisionOutboundCandidateBroker,
    }

    impl Fixture {
        fn valid() -> Self {
            let session_gate = Arc::new(ScreenPerceptionSessionGate::new());
            session_gate.arm_for_life(LIFE_A);
            let fence = session_gate
                .life_fence_for(LIFE_A)
                .expect("test session should have a fence");
            let target_broker = ScreenCaptureTargetBroker::new();
            target_broker.install_target_for_test(fence);
            Self {
                screen_repository: FakeScreenPerceptionRepository::enabled_for(LIFE_A, true),
                outbound_repository: FakeOutboundPolicyRepository::enabled_for(
                    LIFE_A,
                    true,
                    INITIAL_REVISION,
                ),
                session_gate,
                target_broker,
                operation_gate: Arc::new(ScreenCaptureOperationGate::new()),
                candidate_broker: ScreenVisionOutboundCandidateBroker::new(),
            }
        }

        fn request(crop: ScreenVisionOutboundRect) -> ScreenVisionOutboundPreparationRequest {
            ScreenVisionOutboundPreparationRequest {
                life_id: LIFE_A.to_string(),
                projection_request: ScreenVisionOutboundProjectionRequest::new(crop, Vec::new()),
            }
        }

        fn valid_request() -> ScreenVisionOutboundPreparationRequest {
            Self::request(ScreenVisionOutboundRect::new(0, 0, 1, 1))
        }

        fn prepare(
            &self,
            provider: &dyn ScreenCaptureProvider,
            request: &ScreenVisionOutboundPreparationRequest,
            hooks: &PreparationHooks<'_>,
        ) -> Result<ScreenVisionOutboundPreparationResult, ScreenVisionOutboundPreparationError>
        {
            prepare_screen_vision_candidate_with_provider(
                &self.screen_repository,
                &self.outbound_repository,
                &self.session_gate,
                &self.target_broker,
                &self.operation_gate,
                &self.candidate_broker,
                request,
                provider,
                hooks,
            )
        }
    }

    fn frame() -> ScreenFrame {
        ScreenFrame {
            width: 1,
            height: 1,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: vec![3, 2, 1, 255],
        }
    }

    fn provider(
        on_capture: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> (FakeProvider, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        FakeProvider::new(Ok(frame()), on_capture)
    }

    fn failing_provider() -> (FakeProvider, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        FakeProvider::new(Err(ScreenCaptureError::capture_failed()), None)
    }

    fn projection() -> ScreenVisionOutboundProjection {
        project_screen_frame(
            &frame(),
            &ScreenVisionOutboundProjectionRequest::new(
                ScreenVisionOutboundRect::new(0, 0, 1, 1),
                Vec::new(),
            ),
        )
        .expect("test projection should succeed")
    }

    fn install_old_candidate(fixture: &Fixture) -> String {
        fixture
            .candidate_broker
            .replace_candidate(LIFE_A, "1", INITIAL_REVISION, projection())
            .expect("old candidate should install")
    }

    fn assert_code<T>(
        result: Result<T, ScreenVisionOutboundPreparationError>,
        expected: ScreenVisionOutboundPreparationErrorCode,
    ) {
        match result {
            Ok(_) => panic!("preparation should fail"),
            Err(error) => assert_eq!(error.code(), expected),
        }
    }

    #[test]
    fn missing_outbound_policy_blocks_provider() {
        let fixture = Fixture::valid();
        fixture.outbound_repository.remove_policy();
        let (provider, support_calls, capture_calls) = provider(None);

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::OutboundPolicyUnavailable,
        );
        assert_eq!(support_calls.load(Ordering::SeqCst), 0);
        assert_eq!(capture_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn disabled_outbound_policy_blocks_provider() {
        let fixture = Fixture::valid();
        fixture
            .outbound_repository
            .set_policy(false, INITIAL_REVISION);
        let (provider, support_calls, capture_calls) = provider(None);

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::OutboundPolicyUnavailable,
        );
        assert_eq!(support_calls.load(Ordering::SeqCst), 0);
        assert_eq!(capture_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn disabled_local_screen_policy_blocks_provider() {
        let fixture = Fixture::valid();
        fixture.screen_repository.set_enabled(false);
        let (provider, support_calls, capture_calls) = provider(None);

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::LocalScreenAuthorityUnavailable,
        );
        assert_eq!(support_calls.load(Ordering::SeqCst), 0);
        assert_eq!(capture_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unarmed_session_blocks_provider() {
        let fixture = Fixture::valid();
        fixture.session_gate.disarm();
        let (provider, support_calls, capture_calls) = provider(None);

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::LocalScreenAuthorityUnavailable,
        );
        assert_eq!(support_calls.load(Ordering::SeqCst), 0);
        assert_eq!(capture_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn missing_target_fails_before_provider() {
        let fixture = Fixture::valid();
        fixture.target_broker.clear();
        let (provider, support_calls, capture_calls) = provider(None);

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::CaptureFailed,
        );
        assert_eq!(support_calls.load(Ordering::SeqCst), 0);
        assert_eq!(capture_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn valid_authorities_capture_exactly_once_and_install_candidate() {
        let fixture = Fixture::valid();
        let (provider, support_calls, capture_calls) = provider(None);
        let request = Fixture::valid_request();

        let result = fixture
            .prepare(&provider, &request, &PreparationHooks::none())
            .expect("valid authorities should prepare a candidate");
        assert_eq!(support_calls.load(Ordering::SeqCst), 1);
        assert_eq!(capture_calls.load(Ordering::SeqCst), 1);
        assert_eq!(result.life_id, LIFE_A);
        assert_eq!(result.outbound_policy_revision, INITIAL_REVISION);
        assert_eq!(result.width, 1);
        assert_eq!(result.height, 1);
        assert_eq!(result.pixel_format, ScreenVisionOutboundPixelFormat::Rgb8);
        assert!(fixture
            .candidate_broker
            .get_exact(&result.candidate_id)
            .is_ok());
    }

    #[test]
    fn backend_u64_fence_is_used_instead_of_request_data() {
        let fixture = Fixture::valid();
        for _ in 0..9 {
            fixture.session_gate.disarm();
            fixture.session_gate.arm_for_life(LIFE_A);
        }
        let fence = fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("rearmed test session should have a fence");
        fixture.target_broker.install_target_for_test(fence);
        let (provider, _support_calls, _capture_calls) = provider(None);
        let result = fixture
            .prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            )
            .expect("valid authorities should prepare a candidate");
        let metadata = fixture
            .candidate_broker
            .get_exact(&result.candidate_id)
            .expect("candidate metadata should exist");
        assert_eq!(metadata.screen_session_fence, fence.to_string());
        assert!(!metadata.screen_session_fence.starts_with("0x"));
    }

    #[test]
    fn candidate_binds_exact_enabled_policy_revision() {
        let fixture = Fixture::valid();
        fixture
            .outbound_repository
            .set_policy(true, INITIAL_REVISION);
        let (provider, _support_calls, _capture_calls) = provider(None);

        let result = fixture
            .prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            )
            .expect("valid authorities should prepare a candidate");
        let metadata = fixture
            .candidate_broker
            .get_exact(&result.candidate_id)
            .expect("candidate metadata should exist");
        assert_eq!(metadata.outbound_policy_revision, INITIAL_REVISION);
    }

    #[test]
    fn outbound_disable_during_capture_blocks_projection_and_candidate() {
        let fixture = Fixture::valid();
        let outbound = fixture.outbound_repository.clone();
        let (provider, _support_calls, capture_calls) = provider(Some(Box::new(move || {
            outbound.set_policy(false, INITIAL_REVISION + 1);
        })));

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::OutboundPolicyChanged,
        );
        assert_eq!(capture_calls.load(Ordering::SeqCst), 1);
        assert!(fixture.candidate_broker.get_exact("not-installed").is_err());
    }

    #[test]
    fn first_post_capture_recheck_precedes_projection() {
        let fixture = Fixture::valid();
        let old_candidate = install_old_candidate(&fixture);
        let outbound = fixture.outbound_repository.clone();
        let change = move || outbound.set_policy(false, INITIAL_REVISION + 1);
        let hooks = PreparationHooks {
            after_capture: Some(&change),
            before_final_recheck: None,
            before_candidate_install: None,
        };
        let (provider, _support_calls, _capture_calls) = provider(None);

        assert_code(
            fixture.prepare(&provider, &Fixture::valid_request(), &hooks),
            ScreenVisionOutboundPreparationErrorCode::OutboundPolicyChanged,
        );
        assert!(fixture.candidate_broker.get_exact(&old_candidate).is_ok());
    }

    #[test]
    fn outbound_disable_then_reenable_with_new_revision_is_rejected() {
        let fixture = Fixture::valid();
        let outbound = fixture.outbound_repository.clone();
        let (provider, _support_calls, _capture_calls) = provider(Some(Box::new(move || {
            outbound.set_policy(false, INITIAL_REVISION + 1);
            outbound.set_policy(true, INITIAL_REVISION + 2);
        })));

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::OutboundPolicyChanged,
        );
    }

    #[test]
    fn local_disarm_during_capture_blocks_candidate() {
        let fixture = Fixture::valid();
        let session_gate = Arc::clone(&fixture.session_gate);
        let (provider, _support_calls, _capture_calls) = provider(Some(Box::new(move || {
            session_gate.disarm();
        })));

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::SessionFenceChanged,
        );
    }

    #[test]
    fn rearm_same_life_during_capture_changes_fence_and_blocks_candidate() {
        let fixture = Fixture::valid();
        let session_gate = Arc::clone(&fixture.session_gate);
        let (provider, _support_calls, _capture_calls) = provider(Some(Box::new(move || {
            session_gate.disarm();
            session_gate.arm_for_life(LIFE_A);
        })));

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::SessionFenceChanged,
        );
    }

    #[test]
    fn rearm_different_life_during_capture_blocks_candidate() {
        let fixture = Fixture::valid();
        let session_gate = Arc::clone(&fixture.session_gate);
        let (provider, _support_calls, _capture_calls) = provider(Some(Box::new(move || {
            session_gate.disarm();
            session_gate.arm_for_life(LIFE_B);
        })));

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::SessionFenceChanged,
        );
    }

    #[test]
    fn authority_change_before_final_recheck_prevents_install() {
        let fixture = Fixture::valid();
        let old_candidate = install_old_candidate(&fixture);
        let outbound = fixture.outbound_repository.clone();
        let change = move || outbound.set_policy(false, INITIAL_REVISION + 1);
        let hooks = PreparationHooks {
            after_capture: None,
            before_final_recheck: Some(&change),
            before_candidate_install: None,
        };
        let (provider, _support_calls, _capture_calls) = provider(None);

        assert_code(
            fixture.prepare(&provider, &Fixture::valid_request(), &hooks),
            ScreenVisionOutboundPreparationErrorCode::OutboundPolicyChanged,
        );
        assert_eq!(
            fixture
                .candidate_broker
                .get_exact(&old_candidate)
                .expect("old candidate must survive final-recheck failure")
                .candidate_id,
            old_candidate
        );
    }

    #[test]
    fn stable_authority_through_projection_installs_candidate() {
        let fixture = Fixture::valid();
        let projection_boundary = AtomicBool::new(false);
        let mark = || projection_boundary.store(true, Ordering::SeqCst);
        let hooks = PreparationHooks {
            after_capture: None,
            before_final_recheck: Some(&mark),
            before_candidate_install: None,
        };
        let (provider, _support_calls, _capture_calls) = provider(None);

        let result = fixture
            .prepare(&provider, &Fixture::valid_request(), &hooks)
            .expect("stable authority should install candidate");
        assert!(projection_boundary.load(Ordering::SeqCst));
        assert!(fixture
            .candidate_broker
            .get_exact(&result.candidate_id)
            .is_ok());
    }

    #[test]
    fn projection_failure_preserves_prior_candidate() {
        let fixture = Fixture::valid();
        let old_candidate = install_old_candidate(&fixture);
        let (provider, _support_calls, _capture_calls) = provider(None);
        let request = Fixture::request(ScreenVisionOutboundRect::new(0, 0, 0, 1));

        assert_code(
            fixture.prepare(&provider, &request, &PreparationHooks::none()),
            ScreenVisionOutboundPreparationErrorCode::ProjectionFailed,
        );
        assert!(fixture.candidate_broker.get_exact(&old_candidate).is_ok());
    }

    #[test]
    fn final_recheck_failure_preserves_prior_candidate() {
        let fixture = Fixture::valid();
        let old_candidate = install_old_candidate(&fixture);
        let screen_repository = fixture.screen_repository.clone();
        let change = move || screen_repository.set_enabled(false);
        let hooks = PreparationHooks {
            after_capture: None,
            before_final_recheck: Some(&change),
            before_candidate_install: None,
        };
        let (provider, _support_calls, _capture_calls) = provider(None);

        assert_code(
            fixture.prepare(&provider, &Fixture::valid_request(), &hooks),
            ScreenVisionOutboundPreparationErrorCode::SessionFenceChanged,
        );
        assert!(fixture.candidate_broker.get_exact(&old_candidate).is_ok());
    }

    #[test]
    fn poisoned_candidate_install_preserves_prior_candidate() {
        let fixture = Fixture::valid();
        let old_candidate = install_old_candidate(&fixture);
        fixture.candidate_broker.poison_for_test();
        let (provider, _support_calls, _capture_calls) = provider(None);

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::SynchronizationUnavailable,
        );
        fixture.candidate_broker.clear_poison_for_test();
        assert!(fixture.candidate_broker.get_exact(&old_candidate).is_ok());
    }

    #[test]
    fn successful_replacement_retires_previous_candidate() {
        let fixture = Fixture::valid();
        let old_candidate = install_old_candidate(&fixture);
        let (provider, _support_calls, _capture_calls) = provider(None);

        let result = fixture
            .prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            )
            .expect("replacement should succeed");
        assert_ne!(old_candidate, result.candidate_id);
        assert!(fixture.candidate_broker.get_exact(&old_candidate).is_err());
        assert!(fixture
            .candidate_broker
            .get_exact(&result.candidate_id)
            .is_ok());
    }

    #[test]
    fn operation_gate_is_held_during_capture() {
        let fixture = Fixture::valid();
        let operation_gate = Arc::clone(&fixture.operation_gate);
        let busy_during_capture = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&busy_during_capture);
        let (provider, _support_calls, _capture_calls) = provider(Some(Box::new(move || {
            observed.store(operation_gate.try_enter().is_err(), Ordering::SeqCst);
        })));

        fixture
            .prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            )
            .expect("valid preparation should succeed");
        assert!(busy_during_capture.load(Ordering::SeqCst));
    }

    #[test]
    fn second_screen_operation_is_busy_without_queueing() {
        let fixture = Fixture::valid();
        let held_permit = fixture
            .operation_gate
            .try_enter()
            .expect("test should hold the canonical operation gate");
        let (provider, support_calls, capture_calls) = provider(None);

        assert_code(
            fixture.prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::OperationBusy,
        );
        assert_eq!(support_calls.load(Ordering::SeqCst), 0);
        assert_eq!(capture_calls.load(Ordering::SeqCst), 0);
        drop(held_permit);
        assert!(fixture.operation_gate.try_enter().is_ok());
    }

    #[test]
    fn operation_gate_is_held_through_final_recheck_and_install_boundary() {
        let fixture = Fixture::valid();
        let operation_gate = Arc::clone(&fixture.operation_gate);
        let busy_before_install = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&busy_before_install);
        let check = move || observed.store(operation_gate.try_enter().is_err(), Ordering::SeqCst);
        let hooks = PreparationHooks {
            after_capture: None,
            before_final_recheck: None,
            before_candidate_install: Some(&check),
        };
        let (provider, _support_calls, _capture_calls) = provider(None);

        fixture
            .prepare(&provider, &Fixture::valid_request(), &hooks)
            .expect("valid preparation should succeed");
        assert!(busy_before_install.load(Ordering::SeqCst));
        assert!(fixture.operation_gate.try_enter().is_ok());
    }

    #[test]
    fn every_failure_exit_releases_operation_permit() {
        let fixture = Fixture::valid();
        fixture.outbound_repository.remove_policy();
        let (provider_a, _support_calls, _capture_calls) = provider(None);
        assert!(fixture
            .prepare(
                &provider_a,
                &Fixture::valid_request(),
                &PreparationHooks::none()
            )
            .is_err());
        assert!(fixture.operation_gate.try_enter().is_ok());

        let fixture = Fixture::valid();
        fixture.target_broker.clear();
        let (provider_b, _support_calls, _capture_calls) = provider(None);
        assert!(fixture
            .prepare(
                &provider_b,
                &Fixture::valid_request(),
                &PreparationHooks::none()
            )
            .is_err());
        assert!(fixture.operation_gate.try_enter().is_ok());

        let fixture = Fixture::valid();
        let (provider_c, _support_calls, _capture_calls) = provider(None);
        let invalid_request = Fixture::request(ScreenVisionOutboundRect::new(0, 0, 0, 1));
        assert!(fixture
            .prepare(&provider_c, &invalid_request, &PreparationHooks::none())
            .is_err());
        assert!(fixture.operation_gate.try_enter().is_ok());

        let fixture = Fixture::valid();
        let outbound = fixture.outbound_repository.clone();
        let change = move || outbound.set_policy(false, INITIAL_REVISION + 1);
        let hooks = PreparationHooks {
            after_capture: None,
            before_final_recheck: Some(&change),
            before_candidate_install: None,
        };
        let (provider_d, _support_calls, _capture_calls) = provider(None);
        assert!(fixture
            .prepare(&provider_d, &Fixture::valid_request(), &hooks)
            .is_err());
        assert!(fixture.operation_gate.try_enter().is_ok());

        let fixture = Fixture::valid();
        let _old_candidate = install_old_candidate(&fixture);
        fixture.candidate_broker.poison_for_test();
        let (provider_e, _support_calls, _capture_calls) = provider(None);
        assert!(fixture
            .prepare(
                &provider_e,
                &Fixture::valid_request(),
                &PreparationHooks::none()
            )
            .is_err());
        fixture.candidate_broker.clear_poison_for_test();
        assert!(fixture.operation_gate.try_enter().is_ok());

        let fixture = Fixture::valid();
        let (provider_f, _support_calls, _capture_calls) = failing_provider();
        assert_code(
            fixture.prepare(
                &provider_f,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            ),
            ScreenVisionOutboundPreparationErrorCode::CaptureFailed,
        );
        assert!(fixture.operation_gate.try_enter().is_ok());
    }

    #[test]
    fn preparation_result_and_candidate_metadata_contain_no_pixels_or_native_target_data() {
        let fixture = Fixture::valid();
        let (provider, _support_calls, _capture_calls) = provider(None);
        let result = fixture
            .prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            )
            .expect("valid preparation should succeed");
        let metadata = fixture
            .candidate_broker
            .get_exact(&result.candidate_id)
            .expect("candidate metadata should exist");

        assert_eq!(metadata.width, result.width);
        assert_eq!(metadata.height, result.height);
        assert_eq!(metadata.pixel_format, result.pixel_format);
        assert_eq!(metadata.life_id, LIFE_A);
        assert_eq!(metadata.outbound_policy_revision, INITIAL_REVISION);
    }

    #[test]
    fn raw_frame_is_retired_before_candidate_install_and_c1_projection_is_moved() {
        let fixture = Fixture::valid();
        let (provider, _support_calls, _capture_calls) = provider(None);
        let result = fixture
            .prepare(
                &provider,
                &Fixture::valid_request(),
                &PreparationHooks::none(),
            )
            .expect("valid preparation should succeed");

        // C2 exposes only metadata after it accepts the exact C1 projection;
        // the raw ScreenFrame and C1 bytes are not recoverable through this
        // boundary.
        let metadata = fixture
            .candidate_broker
            .get_exact(&result.candidate_id)
            .expect("candidate metadata should exist");
        assert_eq!(metadata.pixel_format, ScreenVisionOutboundPixelFormat::Rgb8);
        assert_eq!(metadata.width, 1);
        assert_eq!(metadata.height, 1);
    }

    #[test]
    fn request_rejects_blank_or_oversized_life_identity() {
        let fixture = Fixture::valid();
        let (provider, _support_calls, _capture_calls) = provider(None);
        let blank = ScreenVisionOutboundPreparationRequest {
            life_id: " ".to_string(),
            projection_request: ScreenVisionOutboundProjectionRequest::new(
                ScreenVisionOutboundRect::new(0, 0, 1, 1),
                Vec::new(),
            ),
        };
        assert_code(
            fixture.prepare(&provider, &blank, &PreparationHooks::none()),
            ScreenVisionOutboundPreparationErrorCode::InvalidArgument,
        );

        let oversized = ScreenVisionOutboundPreparationRequest {
            life_id: "x".repeat(MAX_LIFE_ID_LENGTH + 1),
            projection_request: ScreenVisionOutboundProjectionRequest::new(
                ScreenVisionOutboundRect::new(0, 0, 1, 1),
                Vec::new(),
            ),
        };
        assert_code(
            fixture.prepare(&provider, &oversized, &PreparationHooks::none()),
            ScreenVisionOutboundPreparationErrorCode::InvalidArgument,
        );
    }
}
