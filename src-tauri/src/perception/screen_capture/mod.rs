//! D23-C1 one-shot Windows screen capture authority.
//!
//! This module implements the frozen C1 objective:
//!
//! ```text
//! user explicitly selects a Windows capture target
//! → process-local target authority
//! → explicit one-shot capture request
//! → bounded in-memory frame
//! → frame immediately retired after consumer returns
//! ```
//!
//! Every capture re-validates the frozen three-part authority chain before
//! any pixel is read:
//!
//! ```text
//! durable policy enabled          (Migration027, re-read every call)
//! AND canonical gate armed for the same life
//! AND valid process-local capture target bound to that life's fence
//! ```
//!
//! There is deliberately no OCR, no polling, no background capture, no frame
//! persistence, no network/model path, and no raw-pixel frontend exposure.

/// Ensures COM is initialized on the calling thread for WGC/WinRT use.
///
/// WGC (`GraphicsCaptureItem`, frame pool, D3D11 device interop) requires a
/// COM-initialized thread.  This helper initializes the current thread in MTA
/// (the documented mode for desktop WGC) and tolerates an already-initialized
/// thread (`S_FALSE`).  A thread already initialized in a *different* mode is
/// left untouched and reported so the caller can fail closed rather than
/// silently changing apartment semantics.
#[cfg(windows)]
pub(crate) fn ensure_com_initialized() -> Result<(), ScreenCaptureError> {
    use windows::Win32::{
        Foundation::RPC_E_CHANGED_MODE,
        System::Com::{CoInitializeEx, COINIT_MULTITHREADED},
    };
    let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    match result.0 {
        // S_OK: newly initialized.  S_FALSE (1): already initialized on this
        // thread (any compatible mode).  Both are fine for our use.
        0 | 1 => Ok(()),
        _ if result == RPC_E_CHANGED_MODE => Err(ScreenCaptureError::not_supported()),
        _ => Err(ScreenCaptureError::capture_failed()),
    }
}

pub(crate) mod provider;
#[cfg(windows)]
pub(crate) mod selection;
pub(crate) mod target;
#[cfg(windows)]
pub(crate) mod windows_provider;

use std::fmt;

use serde::Serialize;

use super::screen_policy::{authorize_screen_perception, ScreenPerceptionRepository};
use super::screen_settings::ScreenPerceptionCommandError;
use crate::storage::StorageService;

/// Conservative hard bounds for one captured frame.
///
/// - Maximum width/height: 16_384 px each (16K-class surfaces are the largest
///   Windows Graphics Capture can legitimately produce; anything larger is
///   treated as invalid rather than allocated).
/// - Maximum byte size: 1 GiB, which also bounds `width * height * bpp`
///   without relying on platform `usize` width.
pub(crate) const MAX_FRAME_WIDTH: u32 = 16_384;
pub(crate) const MAX_FRAME_HEIGHT: u32 = 16_384;
pub(crate) const MAX_FRAME_BYTES: usize = 1024 * 1024 * 1024;

/// Bytes per pixel for the only pixel format C1 reads back: BGRA8.
pub(crate) const FRAME_BYTES_PER_PIXEL: u32 = 4;

/// The bounded pixel formats C1 can produce.  Only BGRA8 is produced by the
/// Windows provider; the enum is kept narrow so D23-D1 OCR has a fixed
/// contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenPixelFormat {
    Bgra8,
}

impl ScreenPixelFormat {
    pub(crate) const fn bytes_per_pixel(self) -> u32 {
        match self {
            Self::Bgra8 => FRAME_BYTES_PER_PIXEL,
        }
    }
}

/// A bounded, crate-internal raw frame.
///
/// It carries exactly the geometry and pixel payload a later D23-D1 OCR stage
/// needs, plus no unrelated OS metadata: no title, no process path, no HWND,
/// no PID, no monitor identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenFrame {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) pixel_format: ScreenPixelFormat,
    pub(crate) bytes: Vec<u8>,
}

impl ScreenFrame {
    pub(crate) fn expected_byte_len(&self) -> Option<usize> {
        let width = usize::try_from(self.width).ok()?;
        let height = usize::try_from(self.height).ok()?;
        let bpp = usize::try_from(self.pixel_format.bytes_per_pixel()).ok()?;
        width.checked_mul(height)?.checked_mul(bpp)
    }

    /// Validates the bounded frame invariants.  A frame with zero dimensions,
    /// an overflowing size, an absurd size, or a byte length that does not
    /// match its declared geometry is invalid.
    pub(crate) fn validate(&self) -> Result<(), ScreenCaptureError> {
        if self.width == 0 || self.height == 0 {
            return Err(ScreenCaptureError::frame_invalid());
        }
        if self.width > MAX_FRAME_WIDTH || self.height > MAX_FRAME_HEIGHT {
            return Err(ScreenCaptureError::frame_invalid());
        }
        let expected = self
            .expected_byte_len()
            .ok_or_else(ScreenCaptureError::frame_invalid)?;
        if expected > MAX_FRAME_BYTES {
            return Err(ScreenCaptureError::frame_invalid());
        }
        if self.bytes.len() != expected {
            return Err(ScreenCaptureError::frame_invalid());
        }
        Ok(())
    }
}

/// Bounded D23-C1 error categories.  No raw HWND, PID, title, process path,
/// screen content, or COM debug dump ever appears in user-facing errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenCaptureErrorCode {
    NotSupported,
    TargetRequired,
    TargetUnavailable,
    SessionDenied,
    FrameInvalid,
    CaptureFailed,
    InvalidArgument,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenCaptureError {
    pub(crate) code: ScreenCaptureErrorCode,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl ScreenCaptureError {
    pub(crate) fn new(code: ScreenCaptureErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: matches!(
                code,
                ScreenCaptureErrorCode::NotSupported
                    | ScreenCaptureErrorCode::TargetRequired
                    | ScreenCaptureErrorCode::TargetUnavailable
                    | ScreenCaptureErrorCode::CaptureFailed
            ),
        }
    }

    pub(crate) fn not_supported() -> Self {
        Self::new(
            ScreenCaptureErrorCode::NotSupported,
            "Screen capture is not supported on this device.",
        )
    }

    pub(crate) fn target_required() -> Self {
        Self::new(
            ScreenCaptureErrorCode::TargetRequired,
            "No capture target is selected for this session.",
        )
    }

    pub(crate) fn target_unavailable() -> Self {
        Self::new(
            ScreenCaptureErrorCode::TargetUnavailable,
            "The selected capture target is no longer available.",
        )
    }

    pub(crate) fn session_denied() -> Self {
        Self::new(
            ScreenCaptureErrorCode::SessionDenied,
            "Screen capture was not authorized for this session.",
        )
    }

    pub(crate) fn frame_invalid() -> Self {
        Self::new(
            ScreenCaptureErrorCode::FrameInvalid,
            "The captured frame is invalid or out of bounds.",
        )
    }

    pub(crate) fn capture_failed() -> Self {
        Self::new(
            ScreenCaptureErrorCode::CaptureFailed,
            "The screen capture could not be completed.",
        )
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ScreenCaptureErrorCode::InvalidArgument, message)
    }
}

impl fmt::Display for ScreenCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ScreenCaptureError {}

/// Maps a screen-policy authorization failure to the bounded capture error
/// surface.  The D23-B1/B2 authority chain is never bypassed: a capture that
/// is not durably consented or not session-armed fails here as
/// `SessionDenied`, before any provider call.
pub(crate) fn map_authorization_error(
    error: super::screen_policy::ScreenPerceptionError,
) -> ScreenCaptureError {
    let _ = error;
    ScreenCaptureError::session_denied()
}

/// DTO surface for bounded capture smoke metadata returned to Settings.
/// It deliberately contains no image bytes and no OS target metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScreenCaptureSmokeDto {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) pixel_format: String,
}

/// DTO for the current process-local target status.  Only the de-identified
/// descriptor (or none) is exposed; never a raw handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScreenCaptureTargetStatusDto {
    pub(crate) selected: Option<target::ScreenCaptureTargetDescriptor>,
}

/// Lists the currently available capture targets as de-identified
/// descriptors.  This is the only target-selection surface exposed to
/// Settings; the frontend can never supply an HWND/PID/title.
#[tauri::command]
pub fn list_screen_capture_targets(
) -> Result<Vec<target::ScreenCaptureTargetDescriptor>, ScreenPerceptionCommandError> {
    #[cfg(windows)]
    {
        selection::list_target_descriptors().map_err(map_command_error)
    }
    #[cfg(not(windows))]
    {
        Err(map_command_error(ScreenCaptureError::not_supported()))
    }
}

/// Selects the target with the given de-identified index.  The backend
/// re-enumerates, derives the handle, creates the opaque capture item via the
/// canonical interop path, and binds it to the current session fence.
#[tauri::command]
pub fn select_screen_capture_target(
    gate: tauri::State<'_, super::screen_policy::ScreenPerceptionSessionGate>,
    broker: tauri::State<'_, target::ScreenCaptureTargetBroker>,
    request: ScreenCaptureTargetSelectionRequest,
) -> Result<target::ScreenCaptureTargetDescriptor, ScreenPerceptionCommandError> {
    select_screen_capture_target_service(gate.inner(), broker.inner(), &request)
        .map_err(map_command_error)
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScreenCaptureTargetSelectionRequest {
    pub(crate) life_id: String,
    pub(crate) selection_index: u64,
}

#[cfg(windows)]
pub(crate) fn select_screen_capture_target_service(
    gate: &super::screen_policy::ScreenPerceptionSessionGate,
    broker: &target::ScreenCaptureTargetBroker,
    request: &ScreenCaptureTargetSelectionRequest,
) -> Result<target::ScreenCaptureTargetDescriptor, ScreenCaptureError> {
    selection::select_target_service(gate, broker, &request.life_id, request.selection_index)
}

#[cfg(not(windows))]
pub(crate) fn select_screen_capture_target_service(
    _gate: &super::screen_policy::ScreenPerceptionSessionGate,
    _broker: &target::ScreenCaptureTargetBroker,
    _request: &ScreenCaptureTargetSelectionRequest,
) -> Result<target::ScreenCaptureTargetDescriptor, ScreenCaptureError> {
    Err(ScreenCaptureError::not_supported())
}

/// Returns the current de-identified target status.
#[tauri::command]
pub fn get_screen_capture_target_status(
    broker: tauri::State<'_, target::ScreenCaptureTargetBroker>,
) -> ScreenCaptureTargetStatusDto {
    ScreenCaptureTargetStatusDto {
        selected: broker.current_descriptor(),
    }
}

/// Clears the current process-local target.  Used by Settings as an explicit
/// user action; correctness never depends on it (a rearmed session or
/// revoked consent already invalidates the target through the fence).
#[tauri::command]
pub fn clear_screen_capture_target(
    broker: tauri::State<'_, target::ScreenCaptureTargetBroker>,
) -> ScreenCaptureTargetStatusDto {
    broker.clear();
    ScreenCaptureTargetStatusDto { selected: None }
}

/// The bounded Settings-only smoke command.  It authorizes, captures one
/// frame through the canonical provider, validates the frame, drops it, and
/// returns only geometry metadata.
#[tauri::command]
pub fn capture_screen_smoke(
    storage: tauri::State<'_, StorageService>,
    gate: tauri::State<'_, super::screen_policy::ScreenPerceptionSessionGate>,
    broker: tauri::State<'_, target::ScreenCaptureTargetBroker>,
    life_id: String,
) -> Result<ScreenCaptureSmokeDto, ScreenPerceptionCommandError> {
    capture_screen_smoke_service(storage.inner(), gate.inner(), broker.inner(), &life_id)
        .map_err(map_command_error)
}

pub(crate) fn capture_screen_smoke_service(
    storage: &StorageService,
    gate: &super::screen_policy::ScreenPerceptionSessionGate,
    broker: &target::ScreenCaptureTargetBroker,
    life_id: &str,
) -> Result<ScreenCaptureSmokeDto, ScreenCaptureError> {
    let frame = capture_one_shot(storage, gate, broker, life_id)?;
    let dto = ScreenCaptureSmokeDto {
        width: frame.width,
        height: frame.height,
        pixel_format: "bgra8".to_string(),
    };
    drop(frame);
    Ok(dto)
}

/// The single one-shot capture path.  Authorization is re-read from durable
/// storage on every call; the canonical provider is invoked at most once; the
/// resulting frame is validated, handed to the caller, and then retired when
/// the caller drops it.
///
/// `provider` is injected so unit tests can prove authorization-before-pixels
/// with a counting fake; production passes the canonical native provider.
pub(crate) fn capture_one_shot_with_provider(
    repository: &dyn ScreenPerceptionRepository,
    gate: &super::screen_policy::ScreenPerceptionSessionGate,
    broker: &target::ScreenCaptureTargetBroker,
    life_id: &str,
    provider: &dyn provider::ScreenCaptureProvider,
) -> Result<ScreenFrame, ScreenCaptureError> {
    authorize_screen_perception(repository, gate, life_id).map_err(map_authorization_error)?;

    let target = broker
        .current_target_for_life(gate, life_id)
        .ok_or_else(ScreenCaptureError::target_required)?;

    if !provider.is_supported() {
        return Err(ScreenCaptureError::not_supported());
    }

    let frame = provider
        .capture_frame(&target)
        .map_err(|error| match error.code {
            ScreenCaptureErrorCode::NotSupported => error,
            ScreenCaptureErrorCode::FrameInvalid => error,
            _ => ScreenCaptureError::target_unavailable(),
        })?;
    frame.validate()?;
    Ok(frame)
}

pub(crate) fn capture_one_shot(
    repository: &dyn ScreenPerceptionRepository,
    gate: &super::screen_policy::ScreenPerceptionSessionGate,
    broker: &target::ScreenCaptureTargetBroker,
    life_id: &str,
) -> Result<ScreenFrame, ScreenCaptureError> {
    let provider = provider::native_provider();
    capture_one_shot_with_provider(repository, gate, broker, life_id, provider.as_ref())
}

fn map_command_error(error: ScreenCaptureError) -> ScreenPerceptionCommandError {
    let (code, message) = match error.code {
        ScreenCaptureErrorCode::NotSupported => (
            "SCREEN_CAPTURE_NOT_SUPPORTED",
            "Screen capture is not supported on this device.",
        ),
        ScreenCaptureErrorCode::TargetRequired => (
            "SCREEN_CAPTURE_TARGET_REQUIRED",
            "Select a capture target before capturing.",
        ),
        ScreenCaptureErrorCode::TargetUnavailable => (
            "SCREEN_CAPTURE_TARGET_UNAVAILABLE",
            "The selected capture target is no longer available.",
        ),
        ScreenCaptureErrorCode::SessionDenied => (
            "SCREEN_CAPTURE_SESSION_DENIED",
            "Screen capture is not authorized for this session.",
        ),
        ScreenCaptureErrorCode::FrameInvalid => (
            "SCREEN_CAPTURE_FRAME_INVALID",
            "The captured frame was invalid or out of bounds.",
        ),
        ScreenCaptureErrorCode::CaptureFailed => (
            "SCREEN_CAPTURE_FAILED",
            "The screen capture could not be completed.",
        ),
        ScreenCaptureErrorCode::InvalidArgument => (
            "SCREEN_CAPTURE_INVALID_ARGUMENT",
            "The screen capture request is invalid.",
        ),
    };
    ScreenPerceptionCommandError {
        code: code.to_string(),
        message: message.to_string(),
        recoverable: error.recoverable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_validation_accepts_valid_bounded_geometry() {
        let frame = ScreenFrame {
            width: 1920,
            height: 1080,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: vec![0u8; 1920 * 1080 * 4],
        };
        frame.validate().unwrap();
    }

    #[test]
    fn frame_validation_rejects_zero_dimensions() {
        for (width, height) in [(0, 1080), (1920, 0)] {
            let frame = ScreenFrame {
                width,
                height,
                pixel_format: ScreenPixelFormat::Bgra8,
                bytes: Vec::new(),
            };
            assert_eq!(
                frame.validate().unwrap_err().code,
                ScreenCaptureErrorCode::FrameInvalid
            );
        }
    }

    #[test]
    fn frame_validation_rejects_absurd_dimensions() {
        let frame = ScreenFrame {
            width: 1_000_000,
            height: 1_000_000,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: Vec::new(),
        };
        assert_eq!(
            frame.validate().unwrap_err().code,
            ScreenCaptureErrorCode::FrameInvalid
        );
    }

    #[test]
    fn frame_validation_rejects_overflowing_byte_len() {
        let frame = ScreenFrame {
            width: u32::MAX,
            height: u32::MAX,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: Vec::new(),
        };
        assert_eq!(
            frame.validate().unwrap_err().code,
            ScreenCaptureErrorCode::FrameInvalid
        );
    }

    #[test]
    fn frame_validation_rejects_byte_length_mismatch() {
        let frame = ScreenFrame {
            width: 4,
            height: 4,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: vec![0u8; 15],
        };
        assert_eq!(
            frame.validate().unwrap_err().code,
            ScreenCaptureErrorCode::FrameInvalid
        );
    }

    #[test]
    fn frame_validation_rejects_over_max_bytes() {
        let frame = ScreenFrame {
            width: MAX_FRAME_WIDTH,
            height: MAX_FRAME_HEIGHT,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: Vec::new(),
        };
        assert_eq!(
            frame.validate().unwrap_err().code,
            ScreenCaptureErrorCode::FrameInvalid
        );
    }

    // --- §27 authorization-before-pixels test seams -----------------------

    /// In-memory repository with a durable screen-perception policy.
    struct FakeRepository {
        policy: std::sync::Mutex<Option<super::super::screen_policy::LifeScreenPerceptionPolicy>>,
    }

    impl FakeRepository {
        fn with_policy(enabled: bool) -> Self {
            Self {
                policy: std::sync::Mutex::new(Some(
                    super::super::screen_policy::LifeScreenPerceptionPolicy {
                        life_id: "life-a".to_string(),
                        screen_perception_enabled: enabled,
                        revision: 1,
                        created_at: "2026-08-29T00:00:00.000Z".to_string(),
                        updated_at: "2026-08-29T00:00:00.000Z".to_string(),
                        policy_version: 1,
                    },
                )),
            }
        }
    }

    impl ScreenPerceptionRepository for FakeRepository {
        fn create_screen_perception_policy(
            &self,
            request: super::super::screen_policy::LifeScreenPerceptionPolicyCreateRequest,
        ) -> Result<
            super::super::screen_policy::ScreenPerceptionCreateOutcome<
                super::super::screen_policy::LifeScreenPerceptionPolicy,
            >,
            super::super::screen_policy::ScreenPerceptionError,
        > {
            let mut slot = self.policy.lock().unwrap();
            if let Some(existing) = &*slot {
                if existing.screen_perception_enabled == request.screen_perception_enabled {
                    return Ok(
                        super::super::screen_policy::ScreenPerceptionCreateOutcome::Replayed(
                            existing.clone(),
                        ),
                    );
                }
                return Err(super::super::screen_policy::ScreenPerceptionError::policy_conflict());
            }
            let now = "2026-08-29T00:00:00.000Z".to_string();
            let policy = super::super::screen_policy::LifeScreenPerceptionPolicy {
                life_id: request.life_id,
                screen_perception_enabled: request.screen_perception_enabled,
                revision: 1,
                created_at: now.clone(),
                updated_at: now,
                policy_version: 1,
            };
            *slot = Some(policy.clone());
            Ok(super::super::screen_policy::ScreenPerceptionCreateOutcome::Applied(policy))
        }

        fn find_screen_perception_policy(
            &self,
            life_id: &str,
        ) -> Result<
            Option<super::super::screen_policy::LifeScreenPerceptionPolicy>,
            super::super::screen_policy::ScreenPerceptionError,
        > {
            Ok(self
                .policy
                .lock()
                .unwrap()
                .clone()
                .filter(|policy| policy.life_id == life_id))
        }

        fn update_screen_perception_policy(
            &self,
            request: super::super::screen_policy::LifeScreenPerceptionPolicyUpdateRequest,
        ) -> Result<
            super::super::screen_policy::LifeScreenPerceptionPolicyUpdateOutcome,
            super::super::screen_policy::ScreenPerceptionError,
        > {
            let mut slot = self.policy.lock().unwrap();
            let current = slot
                .clone()
                .filter(|policy| policy.life_id == request.life_id)
                .ok_or_else(super::super::screen_policy::ScreenPerceptionError::policy_not_found)?;
            if current.revision != request.expected_revision {
                return Err(
                    super::super::screen_policy::ScreenPerceptionError::revision_conflict(),
                );
            }
            if current.screen_perception_enabled == request.screen_perception_enabled {
                return Err(
                    super::super::screen_policy::ScreenPerceptionError::invalid_transition(),
                );
            }
            let updated = super::super::screen_policy::LifeScreenPerceptionPolicy {
                life_id: current.life_id.clone(),
                screen_perception_enabled: request.screen_perception_enabled,
                revision: request.expected_revision + 1,
                created_at: current.created_at.clone(),
                updated_at: "2026-08-29T00:00:01.000Z".to_string(),
                policy_version: current.policy_version,
            };
            *slot = Some(updated.clone());
            Ok(
                super::super::screen_policy::LifeScreenPerceptionPolicyUpdateOutcome::Applied {
                    event: super::super::screen_policy::LifeScreenPerceptionPolicyEvent {
                        event_id: request.event_id,
                        life_id: request.life_id,
                        old_screen_perception_enabled: current.screen_perception_enabled,
                        new_screen_perception_enabled: request.screen_perception_enabled,
                        expected_revision: request.expected_revision,
                        applied_revision: request.expected_revision + 1,
                        actor_kind: super::super::screen_policy::SCREEN_PERCEPTION_POLICY_ACTOR_KIND_USER_EXPLICIT
                            .to_string(),
                        occurred_at: "2026-08-29T00:00:01.000Z".to_string(),
                        event_version: 1,
                    },
                    policy: updated,
                },
            )
        }

        fn find_screen_perception_policy_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<
            Option<super::super::screen_policy::LifeScreenPerceptionPolicyEvent>,
            super::super::screen_policy::ScreenPerceptionError,
        > {
            Ok(None)
        }
    }

    /// Counting fake provider.  It records how often `capture_frame` is
    /// called, so tests can prove the native provider is never invoked when
    /// authorization fails and is invoked exactly once when it succeeds.
    struct CountingProvider {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        result: Result<ScreenFrame, ScreenCaptureError>,
        supported: bool,
        panic_if_called: bool,
    }

    impl CountingProvider {
        fn returning(frame: ScreenFrame) -> Self {
            Self {
                calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                result: Ok(frame),
                supported: true,
                panic_if_called: false,
            }
        }

        fn failing(error: ScreenCaptureError) -> Self {
            Self {
                calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                result: Err(error),
                supported: true,
                panic_if_called: false,
            }
        }

        fn rejecting() -> Self {
            Self {
                calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                result: Err(ScreenCaptureError::capture_failed()),
                supported: true,
                panic_if_called: true,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl provider::ScreenCaptureProvider for CountingProvider {
        fn is_supported(&self) -> bool {
            self.supported
        }

        fn capture_frame(
            &self,
            _target: &target::ScreenCaptureTarget,
        ) -> Result<ScreenFrame, ScreenCaptureError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert!(!self.panic_if_called, "provider must not be called");
            self.result.clone()
        }
    }

    fn valid_frame() -> ScreenFrame {
        ScreenFrame {
            width: 16,
            height: 16,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: vec![0u8; 16 * 16 * 4],
        }
    }

    #[test]
    fn disabled_durable_consent_never_calls_provider() {
        let repository = FakeRepository::with_policy(false);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let fence = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(
            fence,
            target::ScreenCaptureTargetDescriptor {
                index: 0,
                kind: "test".to_string(),
                label: "A".to_string(),
            },
        );
        let provider = CountingProvider::rejecting();

        let error =
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-a", &provider)
                .unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::SessionDenied);
        assert_eq!(provider.calls(), 0);
    }

    #[test]
    fn session_disarmed_never_calls_provider() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        // Never armed.
        let broker = target::ScreenCaptureTargetBroker::new();
        let provider = CountingProvider::rejecting();

        let error =
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-a", &provider)
                .unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::SessionDenied);
        assert_eq!(provider.calls(), 0);
    }

    #[test]
    fn wrong_life_armed_never_calls_provider() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-b");
        let broker = target::ScreenCaptureTargetBroker::new();
        let provider = CountingProvider::rejecting();

        let error =
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-a", &provider)
                .unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::SessionDenied);
        assert_eq!(provider.calls(), 0);
    }

    #[test]
    fn no_target_denies_without_calling_provider() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let provider = CountingProvider::rejecting();

        let error =
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-a", &provider)
                .unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::TargetRequired);
        assert_eq!(provider.calls(), 0);
    }

    #[test]
    fn target_bound_to_a_rejected_after_rebind_to_b_without_calling_provider() {
        // Life B is armed and has no durable policy of its own, so
        // authorization fails before the target check; either way the result
        // is a bounded denial and the provider is never called.
        let repository = FakeRepository::with_policy(true); // policy only for life-a
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        let broker = target::ScreenCaptureTargetBroker::new();

        gate.arm_for_life("life-a");
        let fence_a = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(
            fence_a,
            target::ScreenCaptureTargetDescriptor {
                index: 0,
                kind: "test".to_string(),
                label: "A".to_string(),
            },
        );
        gate.arm_for_life("life-b");
        let provider = CountingProvider::rejecting();

        // Life B has no target (A's target is fenced out) and no policy →
        // bounded denial, no provider call.
        let error =
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-b", &provider)
                .unwrap_err();
        assert!(matches!(
            error.code,
            ScreenCaptureErrorCode::SessionDenied | ScreenCaptureErrorCode::TargetRequired
        ));
        assert_eq!(provider.calls(), 0);
    }

    #[test]
    fn valid_authorization_and_target_calls_provider_exactly_once() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let fence = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(
            fence,
            target::ScreenCaptureTargetDescriptor {
                index: 0,
                kind: "test".to_string(),
                label: "A".to_string(),
            },
        );
        let provider = CountingProvider::returning(valid_frame());

        let frame =
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-a", &provider)
                .unwrap();
        assert_eq!(frame.width, 16);
        assert_eq!(frame.height, 16);
        assert_eq!(provider.calls(), 1);
        drop(frame);
    }

    #[test]
    fn provider_failure_maps_to_bounded_error() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let fence = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(
            fence,
            target::ScreenCaptureTargetDescriptor {
                index: 0,
                kind: "test".to_string(),
                label: "A".to_string(),
            },
        );
        let provider = CountingProvider::failing(ScreenCaptureError::capture_failed());

        let error =
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-a", &provider)
                .unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::TargetUnavailable);
        assert_eq!(provider.calls(), 1);
    }

    #[test]
    fn provider_invalid_frame_is_rejected() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let fence = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(
            fence,
            target::ScreenCaptureTargetDescriptor {
                index: 0,
                kind: "test".to_string(),
                label: "A".to_string(),
            },
        );
        let provider = CountingProvider::returning(ScreenFrame {
            width: 4,
            height: 4,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: vec![0u8; 15], // wrong length
        });

        let error =
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-a", &provider)
                .unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::FrameInvalid);
        assert_eq!(provider.calls(), 1);
    }

    #[test]
    fn provider_oversized_frame_is_rejected() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let fence = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(
            fence,
            target::ScreenCaptureTargetDescriptor {
                index: 0,
                kind: "test".to_string(),
                label: "A".to_string(),
            },
        );
        let provider = CountingProvider::returning(ScreenFrame {
            width: 1_000_000,
            height: 1_000_000,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: Vec::new(),
        });

        let error =
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-a", &provider)
                .unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::FrameInvalid);
        assert_eq!(provider.calls(), 1);
    }

    #[test]
    fn revoked_durable_policy_denies_even_with_armed_gate_and_target() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let fence = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(
            fence,
            target::ScreenCaptureTargetDescriptor {
                index: 0,
                kind: "test".to_string(),
                label: "A".to_string(),
            },
        );
        let provider = CountingProvider::returning(valid_frame());
        assert!(
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-a", &provider)
                .is_ok()
        );

        // Revoke durable consent through the repository (gate stays armed).
        repository
            .update_screen_perception_policy(
                super::super::screen_policy::LifeScreenPerceptionPolicyUpdateRequest {
                    event_id: "revoke-1".into(),
                    life_id: "life-a".into(),
                    screen_perception_enabled: false,
                    expected_revision: 1,
                },
            )
            .unwrap();
        let calls_before = provider.calls();
        let error =
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-a", &provider)
                .unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::SessionDenied);
        assert_eq!(provider.calls(), calls_before);
    }

    /// §28 static boundary evidence: the C1 production source introduces no
    /// frame-persistence path.  It scans only the production (non-test) parts
    /// of the capture modules for filesystem/SQLite/observation-history write
    /// primitives; it does not ban harmless words in comments.
    #[test]
    fn production_capture_source_has_no_frame_persistence_path() {
        for (path, source) in [
            (
                "mod.rs",
                include_str!("mod.rs")
                    .split_once("#[cfg(test)]")
                    .map_or(include_str!("mod.rs"), |(production, _)| production),
            ),
            (
                "provider.rs",
                include_str!("provider.rs")
                    .split_once("#[cfg(test)]")
                    .map_or(include_str!("provider.rs"), |(production, _)| production),
            ),
            (
                "target.rs",
                include_str!("target.rs")
                    .split_once("#[cfg(test)]")
                    .map_or(include_str!("target.rs"), |(production, _)| production),
            ),
            #[cfg(windows)]
            (
                "selection.rs",
                include_str!("selection.rs")
                    .split_once("#[cfg(test)]")
                    .map_or(include_str!("selection.rs"), |(production, _)| production),
            ),
            #[cfg(windows)]
            (
                "windows_provider.rs",
                include_str!("windows_provider.rs")
                    .split_once("#[cfg(test)]")
                    .map_or(include_str!("windows_provider.rs"), |(production, _)| {
                        production
                    }),
            ),
        ] {
            // Filesystem frame writes: the only fs primitives allowed are none.
            for token in [
                "std::fs::",
                "File::create",
                "fs::write",
                "fs::File",
                "OpenOptions",
            ] {
                assert!(
                    !source.contains(token),
                    "{path} must not contain filesystem frame-write primitive {token}"
                );
            }
            // SQLite frame storage: no rusqlite usage.
            assert!(
                !source.contains("rusqlite"),
                "{path} must not contain SQLite frame storage"
            );
            // Observation-history rows / persistence.
            for token in [
                "observation_history",
                "life_observation",
                "INSERT INTO",
                "CREATE TABLE",
            ] {
                assert!(
                    !source.contains(token),
                    "{path} must not contain observation-history persistence {token}"
                );
            }
            // No base64 frame retention in app state.
            assert!(
                !source.contains("base64"),
                "{path} must not contain base64 frame retention"
            );
        }
    }
}
