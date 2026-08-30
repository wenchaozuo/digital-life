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

/// COM apartment mode for the calling thread.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ComMode {
    /// Single-threaded apartment — required by the system `GraphicsCapturePicker`
    /// UI.
    Sta,
    /// Multithreaded apartment — sufficient for the capture session itself.
    Mta,
}

/// A balanced COM lifetime guard for the calling thread.
///
/// WGC/WinRT require a COM-initialized thread.  `ComGuard::acquire` calls
/// `CoInitializeEx` with the requested mode and records whether *this* call
/// performed the initialization (`S_OK`) or found the thread already
/// initialized (`S_FALSE`).  In both cases `Drop` runs exactly one matching
/// `CoUninitialize`.  On `RPC_E_CHANGED_MODE` the guard is not created and no
/// `CoUninitialize` is issued for the failed call (fail closed).  The guard
/// must be kept alive for the whole COM/WinRT operation that requires it.
#[cfg(windows)]
pub(crate) struct ComGuard {
    initialized: bool,
}

#[cfg(windows)]
impl ComGuard {
    pub(crate) fn acquire(mode: ComMode) -> Result<Self, ScreenCaptureError> {
        use windows::Win32::{
            Foundation::RPC_E_CHANGED_MODE,
            System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED},
        };
        let coinit = match mode {
            ComMode::Sta => COINIT_APARTMENTTHREADED,
            ComMode::Mta => COINIT_MULTITHREADED,
        };
        let result = unsafe { CoInitializeEx(None, coinit) };
        match result.0 {
            // S_OK (0): this call initialized the thread.
            0 => Ok(Self { initialized: true }),
            // S_FALSE (1): the thread was already initialized; still needs a
            // matching CoUninitialize per COM rules.
            1 => Ok(Self { initialized: true }),
            _ if result == RPC_E_CHANGED_MODE => Err(ScreenCaptureError::not_supported()),
            _ => Err(ScreenCaptureError::capture_failed()),
        }
    }
}

#[cfg(windows)]
impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                let _ = windows::Win32::System::Com::CoUninitialize();
            }
        }
    }
}

pub(crate) mod operation;
pub(crate) mod provider;
#[cfg(windows)]
pub(crate) mod selection;
pub(crate) mod target;
#[cfg(windows)]
pub(crate) mod windows_provider;

use std::fmt;

use serde::Serialize;
use tauri::Manager;

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

/// The checked geometry and byte sizes used by the native capture path.
/// Keeping these values together prevents allocation and unsafe-copy callers
/// from recomputing a size with unchecked arithmetic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedFrameGeometry {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) row_bytes: usize,
    pub(crate) byte_count: usize,
}

/// Validates signed native dimensions before any frame-pool, texture, or CPU
/// buffer allocation.  Native Windows APIs expose dimensions as `i32`, so a
/// negative value must be rejected rather than cast to an unsigned size.
pub(crate) fn validate_capture_geometry(
    width: i32,
    height: i32,
) -> Result<ValidatedFrameGeometry, ScreenCaptureError> {
    validate_capture_geometry_with_limit(width, height, MAX_FRAME_BYTES)
}

fn validate_capture_geometry_with_limit(
    width: i32,
    height: i32,
    max_frame_bytes: usize,
) -> Result<ValidatedFrameGeometry, ScreenCaptureError> {
    if width <= 0 || height <= 0 {
        return Err(ScreenCaptureError::frame_invalid());
    }

    let width = u32::try_from(width).map_err(|_| ScreenCaptureError::frame_invalid())?;
    let height = u32::try_from(height).map_err(|_| ScreenCaptureError::frame_invalid())?;
    if width > MAX_FRAME_WIDTH || height > MAX_FRAME_HEIGHT {
        return Err(ScreenCaptureError::frame_invalid());
    }

    let width_usize = usize::try_from(width).map_err(|_| ScreenCaptureError::frame_invalid())?;
    let height_usize = usize::try_from(height).map_err(|_| ScreenCaptureError::frame_invalid())?;
    let bytes_per_pixel =
        usize::try_from(FRAME_BYTES_PER_PIXEL).map_err(|_| ScreenCaptureError::frame_invalid())?;
    let row_bytes = width_usize
        .checked_mul(bytes_per_pixel)
        .ok_or_else(ScreenCaptureError::frame_invalid)?;
    let byte_count = row_bytes
        .checked_mul(height_usize)
        .ok_or_else(ScreenCaptureError::frame_invalid)?;
    if byte_count > max_frame_bytes {
        return Err(ScreenCaptureError::frame_invalid());
    }

    Ok(ValidatedFrameGeometry {
        width,
        height,
        row_bytes,
        byte_count,
    })
}

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
    Busy,
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
                    | ScreenCaptureErrorCode::Busy
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

    pub(crate) fn busy() -> Self {
        Self::new(
            ScreenCaptureErrorCode::Busy,
            "Another screen-perception operation is already in progress.",
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

/// DTO for the current process-local target status.  Only the bounded
/// non-sensitive status (`none` / `selected`) is exposed; never a raw handle
/// or a display label.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScreenCaptureTargetStatusDto {
    pub(crate) status: target::ScreenCaptureTargetStatus,
}

/// DTO returned after the native picker closes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScreenCapturePickDto {
    pub(crate) status: target::ScreenCaptureTargetStatus,
    pub(crate) cancelled: bool,
}

/// Runs the Windows system capture picker for the given Life.
///
/// Authority order:
/// 1. validate `life_id`;
/// 2. `authorize_screen_perception(...)` — durable policy + session gate;
/// 3. only if authorized, invoke the Windows system picker (parented to the
///    backend-derived Settings window HWND);
/// 4. receive the opaque `GraphicsCaptureItem` (or cancellation);
/// 5. re-check the session fence before installing;
/// 6. install into the canonical broker.
///
/// Picker cancellation returns `cancelled: true` and never silently changes
/// an existing valid target.  If durable/session authorization disappears
/// while the picker is open, the returned item is NOT installed.
#[tauri::command]
pub async fn pick_screen_capture_target(
    app: tauri::AppHandle,
    request: ScreenCapturePickRequest,
) -> Result<ScreenCapturePickDto, ScreenPerceptionCommandError> {
    dispatch_screen_capture_blocking(move || {
        let operation_gate = app.state::<operation::ScreenCaptureOperationGate>();
        with_screen_capture_operation(operation_gate.inner(), || {
            let storage = app.state::<StorageService>();
            let gate = app.state::<super::screen_policy::ScreenPerceptionSessionGate>();
            let broker = app.state::<target::ScreenCaptureTargetBroker>();
            pick_screen_capture_target_service(
                app.clone(),
                storage.inner(),
                gate.inner(),
                broker.inner(),
                &request,
            )
        })
    })
    .await
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScreenCapturePickRequest {
    pub(crate) life_id: String,
}

#[cfg(windows)]
pub(crate) fn pick_screen_capture_target_service(
    app: tauri::AppHandle,
    repository: &dyn ScreenPerceptionRepository,
    gate: &super::screen_policy::ScreenPerceptionSessionGate,
    broker: &target::ScreenCaptureTargetBroker,
    request: &ScreenCapturePickRequest,
) -> Result<ScreenCapturePickDto, ScreenCaptureError> {
    // 1. validate life_id.
    if request.life_id.trim().is_empty() {
        return Err(ScreenCaptureError::invalid_argument(
            "life identity must not be empty.",
        ));
    }
    // 2. authorize before the picker (durable policy + session gate).
    authorize_screen_perception(repository, gate, &request.life_id)
        .map_err(map_authorization_error)?;

    // Capture the fence that authorized this picker session; a rearm while
    // the picker is open changes it.
    let fence = gate
        .life_fence_for(&request.life_id)
        .ok_or_else(ScreenCaptureError::session_denied)?;

    // 3. derive the trusted owner HWND from the Settings window (never
    //    supplied by the frontend) and run the system picker.
    let settings_window = app
        .get_webview_window("settings")
        .ok_or_else(ScreenCaptureError::capture_failed)?;
    let owner_hwnd = selection::settings_owner_hwnd(&settings_window)
        .ok_or_else(ScreenCaptureError::capture_failed)?;
    let outcome = selection::pick_capture_item(owner_hwnd)?;

    install_picker_outcome(repository, gate, broker, &request.life_id, fence, outcome)
}

/// Installs a picker outcome after the authority re-check.  Split out so unit
/// tests can exercise the post-picker fence recheck and cancellation
/// semantics without a real Windows picker.
pub(crate) fn install_picker_outcome(
    repository: &dyn ScreenPerceptionRepository,
    gate: &super::screen_policy::ScreenPerceptionSessionGate,
    broker: &target::ScreenCaptureTargetBroker,
    life_id: &str,
    picker_fence: u64,
    outcome: selection::PickOutcome,
) -> Result<ScreenCapturePickDto, ScreenCaptureError> {
    match outcome {
        selection::PickOutcome::Cancelled => {
            // Cancellation must not fabricate a target nor clear an existing
            // valid one.
            let _ = repository;
            Ok(ScreenCapturePickDto {
                status: broker.current_status(),
                cancelled: true,
            })
        }
        selection::PickOutcome::Selected(item) => install_selected_picker_item(
            repository,
            gate,
            life_id,
            picker_fence,
            item,
            |current_fence, item| broker.select(current_fence, item),
        ),
    }
}

/// Re-checks both durable consent and the process-local generation immediately
/// after a picker returns, then invokes the installation closure only when the
/// opaque selected item is still authorized.  The generic closure is a narrow
/// test seam: tests can prove that a selected item is not installed without
/// constructing a platform-native `GraphicsCaptureItem`.
fn install_selected_picker_item<T>(
    repository: &dyn ScreenPerceptionRepository,
    gate: &super::screen_policy::ScreenPerceptionSessionGate,
    life_id: &str,
    picker_fence: u64,
    item: T,
    install: impl FnOnce(u64, T),
) -> Result<ScreenCapturePickDto, ScreenCaptureError> {
    // Durable consent is authoritative even when the process-local gate was
    // not proactively disarmed by the Settings command layer.
    authorize_screen_perception(repository, gate, life_id).map_err(map_authorization_error)?;

    // A rearm/disarm/rebind while the picker was open invalidates the opaque
    // item.  Dropping `item` on this error releases the native reference.
    let current_fence = gate
        .life_fence_for(life_id)
        .ok_or_else(ScreenCaptureError::session_denied)?;
    if current_fence != picker_fence {
        return Err(ScreenCaptureError::session_denied());
    }

    install(current_fence, item);
    Ok(ScreenCapturePickDto {
        status: target::ScreenCaptureTargetStatus::Selected,
        cancelled: false,
    })
}

/// The post-picker fence recheck: true only when the gate is still armed for
/// the same life with the same generation the picker was opened under.
pub(crate) fn fence_is_current(
    gate: &super::screen_policy::ScreenPerceptionSessionGate,
    life_id: &str,
    picker_fence: u64,
) -> bool {
    gate.life_fence_for(life_id) == Some(picker_fence)
}

#[cfg(not(windows))]
pub(crate) fn pick_screen_capture_target_service(
    _app: tauri::AppHandle,
    _repository: &dyn ScreenPerceptionRepository,
    _gate: &super::screen_policy::ScreenPerceptionSessionGate,
    _broker: &target::ScreenCaptureTargetBroker,
    _request: &ScreenCapturePickRequest,
) -> Result<ScreenCapturePickDto, ScreenCaptureError> {
    Err(ScreenCaptureError::not_supported())
}

/// Returns the current bounded target status.
#[tauri::command]
pub fn get_screen_capture_target_status(
    broker: tauri::State<'_, target::ScreenCaptureTargetBroker>,
) -> ScreenCaptureTargetStatusDto {
    ScreenCaptureTargetStatusDto {
        status: broker.current_status(),
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
    ScreenCaptureTargetStatusDto {
        status: target::ScreenCaptureTargetStatus::None,
    }
}

/// The bounded Settings-only smoke command.  It authorizes, captures one
/// frame through the canonical provider, validates the frame, drops it, and
/// returns only geometry metadata.
#[tauri::command]
pub async fn capture_screen_smoke(
    app: tauri::AppHandle,
    life_id: String,
) -> Result<ScreenCaptureSmokeDto, ScreenPerceptionCommandError> {
    dispatch_screen_capture_blocking(move || {
        let operation_gate = app.state::<operation::ScreenCaptureOperationGate>();
        with_screen_capture_operation(operation_gate.inner(), || {
            let storage = app.state::<StorageService>();
            let gate = app.state::<super::screen_policy::ScreenPerceptionSessionGate>();
            let broker = app.state::<target::ScreenCaptureTargetBroker>();
            capture_screen_smoke_service(storage.inner(), gate.inner(), broker.inner(), &life_id)
        })
    })
    .await
}

/// Enters the one canonical process-local screen-operation slot and releases
/// it when the operation returns or unwinds.  Picker and capture commands both
/// use this helper, so they cannot race through separate permits.
fn with_screen_capture_operation<R>(
    operation_gate: &operation::ScreenCaptureOperationGate,
    operation: impl FnOnce() -> Result<R, ScreenCaptureError>,
) -> Result<R, ScreenCaptureError> {
    let _permit = operation_gate
        .try_enter()
        .map_err(|_| ScreenCaptureError::busy())?;
    operation()
}

/// Runs one blocking screen-capture operation on Tauri's blocking executor.
///
/// Both the native picker and one-shot WGC capture may wait on OS work.  The
/// Tauri command boundary must therefore await this helper rather than run the
/// operation inline on the application/event-loop thread.  The closure is
/// intentionally owned and synchronous: callers reacquire canonical managed
/// state inside it, and no borrowed `State<'_>` can cross the await boundary.
async fn dispatch_screen_capture_blocking<R, F>(
    operation: F,
) -> Result<R, ScreenPerceptionCommandError>
where
    R: Send + 'static,
    F: FnOnce() -> Result<R, ScreenCaptureError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(operation)
        .await
        .map_err(|_| map_command_error(ScreenCaptureError::capture_failed()))?
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
        ScreenCaptureErrorCode::Busy => (
            "SCREEN_CAPTURE_BUSY",
            "Another screen-perception operation is already in progress.",
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
    fn blocking_capture_dispatch_runs_long_operation_off_caller_thread() {
        let caller_thread = std::thread::current().id();
        let result = tauri::async_runtime::block_on(async move {
            let (started_sender, started_receiver) = std::sync::mpsc::channel();
            let (release_sender, release_receiver) = std::sync::mpsc::channel();
            let task = tauri::async_runtime::spawn(dispatch_screen_capture_blocking(move || {
                started_sender
                    .send(std::thread::current().id())
                    .map_err(|_| ScreenCaptureError::capture_failed())?;
                release_receiver
                    .recv()
                    .map_err(|_| ScreenCaptureError::capture_failed())?;
                Ok::<(), ScreenCaptureError>(())
            }));

            let worker_thread = started_receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("blocking operation did not start");
            assert_ne!(worker_thread, caller_thread);
            release_sender
                .send(())
                .expect("blocking operation did not accept release");
            task.await.expect("dispatch task panicked")
        });

        assert!(result.is_ok());
    }

    #[test]
    fn picker_holding_shared_gate_rejects_capture_without_entering() {
        use std::sync::{mpsc, Arc};

        let operation_gate = Arc::new(operation::ScreenCaptureOperationGate::new());
        let (entered_sender, entered_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let picker_gate = Arc::clone(&operation_gate);
        let picker = std::thread::spawn(move || {
            with_screen_capture_operation(&picker_gate, || {
                entered_sender
                    .send(())
                    .expect("picker operation must report entry");
                release_receiver
                    .recv()
                    .expect("picker operation must receive release");
                Ok::<(), ScreenCaptureError>(())
            })
        });

        entered_receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("picker operation did not enter shared gate");

        let capture_entered = std::sync::atomic::AtomicUsize::new(0);
        let result = with_screen_capture_operation(&operation_gate, || {
            capture_entered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<(), ScreenCaptureError>(())
        });
        assert_eq!(result.unwrap_err().code, ScreenCaptureErrorCode::Busy);
        assert_eq!(capture_entered.load(std::sync::atomic::Ordering::SeqCst), 0);

        release_sender.send(()).expect("picker must be released");
        picker
            .join()
            .expect("picker operation must not panic")
            .unwrap();
    }

    #[test]
    fn capture_holding_shared_gate_rejects_picker_without_entering() {
        use std::sync::{mpsc, Arc};

        let operation_gate = Arc::new(operation::ScreenCaptureOperationGate::new());
        let (entered_sender, entered_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let capture_gate = Arc::clone(&operation_gate);
        let capture = std::thread::spawn(move || {
            with_screen_capture_operation(&capture_gate, || {
                entered_sender
                    .send(())
                    .expect("capture operation must report entry");
                release_receiver
                    .recv()
                    .expect("capture operation must receive release");
                Ok::<(), ScreenCaptureError>(())
            })
        });

        entered_receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("capture operation did not enter shared gate");

        let picker_entered = std::sync::atomic::AtomicUsize::new(0);
        let result = with_screen_capture_operation(&operation_gate, || {
            picker_entered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<(), ScreenCaptureError>(())
        });
        assert_eq!(result.unwrap_err().code, ScreenCaptureErrorCode::Busy);
        assert_eq!(picker_entered.load(std::sync::atomic::Ordering::SeqCst), 0);

        release_sender.send(()).expect("capture must be released");
        capture
            .join()
            .expect("capture operation must not panic")
            .unwrap();
    }

    #[test]
    fn busy_capture_rejects_before_provider_call() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let fence = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(fence);
        let provider = CountingProvider::rejecting();
        let operation_gate = operation::ScreenCaptureOperationGate::new();
        let _permit = operation_gate
            .try_enter()
            .expect("the first capture operation must enter");

        let result = with_screen_capture_operation(&operation_gate, || {
            capture_one_shot_with_provider(&repository, &gate, &broker, "life-a", &provider)
        });
        assert_eq!(result.unwrap_err().code, ScreenCaptureErrorCode::Busy);
        assert_eq!(provider.calls(), 0);
    }

    #[test]
    fn failed_operation_releases_shared_gate_for_the_next_operation() {
        let operation_gate = operation::ScreenCaptureOperationGate::new();
        let failed = with_screen_capture_operation(&operation_gate, || {
            Err::<(), ScreenCaptureError>(ScreenCaptureError::capture_failed())
        });
        assert_eq!(
            failed.unwrap_err().code,
            ScreenCaptureErrorCode::CaptureFailed
        );

        let mut entered = false;
        with_screen_capture_operation(&operation_gate, || {
            entered = true;
            Ok::<(), ScreenCaptureError>(())
        })
        .unwrap();
        assert!(entered);
    }

    #[test]
    fn busy_error_maps_to_bounded_frontend_code() {
        let mapped = map_command_error(ScreenCaptureError::busy());
        assert_eq!(mapped.code, "SCREEN_CAPTURE_BUSY");
        assert_eq!(
            mapped.message,
            "Another screen-perception operation is already in progress."
        );
        assert!(mapped.recoverable);
    }

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

    #[test]
    fn native_geometry_rejects_non_positive_dimensions_before_allocation() {
        for (width, height) in [(0, 1080), (-1, 1080), (1920, 0), (1920, -1)] {
            assert_eq!(
                validate_capture_geometry(width, height).unwrap_err().code,
                ScreenCaptureErrorCode::FrameInvalid
            );
        }
    }

    #[test]
    fn native_geometry_rejects_dimensions_over_hard_bounds() {
        for (width, height) in [
            (i32::try_from(MAX_FRAME_WIDTH).unwrap() + 1, 1),
            (1, i32::try_from(MAX_FRAME_HEIGHT).unwrap() + 1),
            (i32::MAX, i32::MAX),
        ] {
            assert_eq!(
                validate_capture_geometry(width, height).unwrap_err().code,
                ScreenCaptureErrorCode::FrameInvalid
            );
        }
    }

    #[test]
    fn native_geometry_uses_checked_byte_arithmetic_and_keeps_sizes_together() {
        let geometry = validate_capture_geometry(
            i32::try_from(MAX_FRAME_WIDTH).unwrap(),
            i32::try_from(MAX_FRAME_HEIGHT).unwrap(),
        )
        .unwrap();
        assert_eq!(geometry.row_bytes, 16_384usize * 4);
        assert_eq!(geometry.byte_count, MAX_FRAME_BYTES);

        assert_eq!(
            validate_capture_geometry(i32::MAX, 1).unwrap_err().code,
            ScreenCaptureErrorCode::FrameInvalid
        );
    }

    #[test]
    fn native_geometry_rejects_byte_count_over_limit_without_allocating() {
        let width = i32::try_from(MAX_FRAME_WIDTH).unwrap();
        let height = i32::try_from(MAX_FRAME_HEIGHT).unwrap();
        let error = validate_capture_geometry_with_limit(
            width,
            height,
            MAX_FRAME_BYTES.checked_sub(1).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::FrameInvalid);
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
        broker.install_target_for_test(fence);
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
        broker.install_target_for_test(fence_a);
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
        broker.install_target_for_test(fence);
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
        broker.install_target_for_test(fence);
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
        broker.install_target_for_test(fence);
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
        broker.install_target_for_test(fence);
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
        broker.install_target_for_test(fence);
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

    // --- C1-R1 picker authority regression tests --------------------------

    #[test]
    fn picker_cannot_run_while_policy_disabled() {
        let repository = FakeRepository::with_policy(false);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();

        // The picker itself is never invoked (authorization fails first).
        let result =
            pick_screen_capture_target_authorize_only(&repository, &gate, &broker, "life-a");
        assert_eq!(
            result.unwrap_err().code,
            ScreenCaptureErrorCode::SessionDenied
        );
        assert_eq!(
            broker.current_status(),
            target::ScreenCaptureTargetStatus::None
        );
    }

    #[test]
    fn picker_cannot_run_while_session_disarmed() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        // Never armed.
        let broker = target::ScreenCaptureTargetBroker::new();

        let result =
            pick_screen_capture_target_authorize_only(&repository, &gate, &broker, "life-a");
        assert_eq!(
            result.unwrap_err().code,
            ScreenCaptureErrorCode::SessionDenied
        );
    }

    #[test]
    fn picker_cancel_preserves_existing_valid_target() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let fence = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(fence);
        assert_eq!(
            broker.current_status(),
            target::ScreenCaptureTargetStatus::Selected
        );

        let outcome = install_picker_outcome(
            &repository,
            &gate,
            &broker,
            "life-a",
            fence,
            selection::PickOutcome::Cancelled,
        )
        .unwrap();
        assert!(outcome.cancelled);
        assert_eq!(outcome.status, target::ScreenCaptureTargetStatus::Selected);
        // Existing target unchanged.
        assert_eq!(
            broker.current_status(),
            target::ScreenCaptureTargetStatus::Selected
        );
    }

    #[test]
    fn picker_selected_item_not_installed_after_fence_change_while_open() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let picker_fence = gate.life_fence_for("life-a").unwrap();

        // While the picker is "open", the session is rearmed (fence changes).
        gate.disarm();
        gate.arm_for_life("life-a");
        let new_fence = gate.life_fence_for("life-a").unwrap();
        assert_ne!(picker_fence, new_fence);

        // The post-picker recheck must reject the stale fence.
        assert!(!fence_is_current(&gate, "life-a", picker_fence));

        // On platforms where a fake item exists, the full install path also
        // denies and leaves the broker untouched.
        #[cfg(not(windows))]
        {
            let error = install_picker_outcome(
                &repository,
                &gate,
                &broker,
                "life-a",
                picker_fence,
                selection::test_pick_outcome_selected(),
            )
            .unwrap_err();
            assert_eq!(error.code, ScreenCaptureErrorCode::SessionDenied);
            assert_eq!(
                broker.current_status(),
                target::ScreenCaptureTargetStatus::None
            );
        }
        #[cfg(windows)]
        {
            let _ = repository;
            assert_eq!(
                broker.current_status(),
                target::ScreenCaptureTargetStatus::None
            );
        }
    }

    #[test]
    fn picker_selected_item_not_installed_after_disarm_while_open() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let picker_fence = gate.life_fence_for("life-a").unwrap();

        // While the picker is "open", the session is disarmed.
        gate.disarm();

        // The post-picker recheck must reject the stale fence.
        assert!(!fence_is_current(&gate, "life-a", picker_fence));

        #[cfg(not(windows))]
        {
            let error = install_picker_outcome(
                &repository,
                &gate,
                &broker,
                "life-a",
                picker_fence,
                selection::test_pick_outcome_selected(),
            )
            .unwrap_err();
            assert_eq!(error.code, ScreenCaptureErrorCode::SessionDenied);
            assert_eq!(
                broker.current_status(),
                target::ScreenCaptureTargetStatus::None
            );
        }
        #[cfg(windows)]
        {
            let _ = repository;
            assert_eq!(
                broker.current_status(),
                target::ScreenCaptureTargetStatus::None
            );
        }
    }

    #[test]
    fn picker_selected_item_not_installed_after_durable_revoke_with_unchanged_fence() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let picker_fence = gate.life_fence_for("life-a").unwrap();

        // Revoke the durable policy directly while the picker is open.  The
        // process-local gate intentionally remains armed with the same fence.
        repository
            .update_screen_perception_policy(
                super::super::screen_policy::LifeScreenPerceptionPolicyUpdateRequest {
                    event_id: "revoke-picker-1".into(),
                    life_id: "life-a".into(),
                    screen_perception_enabled: false,
                    expected_revision: 1,
                },
            )
            .unwrap();
        assert_eq!(gate.life_fence_for("life-a"), Some(picker_fence));

        let mut installed = false;
        let result = install_selected_picker_item(
            &repository,
            &gate,
            "life-a",
            picker_fence,
            (),
            |_, ()| installed = true,
        );
        let error = result.unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::SessionDenied);
        assert!(!installed);
        assert_eq!(
            broker.current_status(),
            target::ScreenCaptureTargetStatus::None
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn picker_selected_item_installed_when_fence_unchanged() {
        let repository = FakeRepository::with_policy(true);
        let gate = super::super::screen_policy::ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let broker = target::ScreenCaptureTargetBroker::new();
        let picker_fence = gate.life_fence_for("life-a").unwrap();

        let outcome = install_picker_outcome(
            &repository,
            &gate,
            &broker,
            "life-a",
            picker_fence,
            selection::test_pick_outcome_selected(),
        )
        .unwrap();
        assert!(!outcome.cancelled);
        assert_eq!(outcome.status, target::ScreenCaptureTargetStatus::Selected);
        assert_eq!(
            broker.current_status(),
            target::ScreenCaptureTargetStatus::Selected
        );
    }

    /// The authorization-only prefix of the picker service, used to prove the
    /// picker cannot run without authorization.  It never touches the real
    /// picker.
    fn pick_screen_capture_target_authorize_only(
        repository: &dyn ScreenPerceptionRepository,
        gate: &super::super::screen_policy::ScreenPerceptionSessionGate,
        broker: &target::ScreenCaptureTargetBroker,
        life_id: &str,
    ) -> Result<ScreenCapturePickDto, ScreenCaptureError> {
        if life_id.trim().is_empty() {
            return Err(ScreenCaptureError::invalid_argument(
                "life identity must not be empty.",
            ));
        }
        authorize_screen_perception(repository, gate, life_id).map_err(map_authorization_error)?;
        let _fence = gate
            .life_fence_for(life_id)
            .ok_or_else(ScreenCaptureError::session_denied)?;
        // The real picker would run here; tests never reach it when
        // authorization fails.
        let _ = broker;
        Ok(ScreenCapturePickDto {
            status: target::ScreenCaptureTargetStatus::Selected,
            cancelled: false,
        })
    }

    /// C1-R1: production target-selection source must not contain
    /// `GetWindowTextW` or mutable index authority.
    #[test]
    fn production_selection_has_no_title_observation_or_index_authority() {
        for (path, source) in [
            (
                "selection.rs",
                include_str!("selection.rs")
                    .split_once("#[cfg(test)]")
                    .map_or(include_str!("selection.rs"), |(production, _)| production),
            ),
            (
                "mod.rs",
                include_str!("mod.rs")
                    .split_once("#[cfg(test)]")
                    .map_or(include_str!("mod.rs"), |(production, _)| production),
            ),
            (
                "target.rs",
                include_str!("target.rs")
                    .split_once("#[cfg(test)]")
                    .map_or(include_str!("target.rs"), |(production, _)| production),
            ),
        ] {
            assert!(
                !source.contains("GetWindowTextW"),
                "{path} must not observe window titles"
            );
            assert!(
                !source.contains("EnumWindows"),
                "{path} must not enumerate windows for target selection"
            );
            assert!(
                !source.contains("selection_index"),
                "{path} must not carry mutable index authority"
            );
        }
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
