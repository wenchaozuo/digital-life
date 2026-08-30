//! D23-D1 local OCR and ephemeral bounded screen observation.
//!
//! The module deliberately sits behind the frozen D23-C1 capture authority:
//! the public-in-crate composition entry point acquires the one canonical
//! operation permit before it captures anything, and keeps that permit until
//! OCR and observation construction have finished.  A raw [`ScreenFrame`] is
//! never stored in the observation, sent to a provider transport, or written
//! to storage.

use std::{
    borrow::Cow,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::{
    screen_capture::{
        self, operation::ScreenCaptureOperationPermit, provider::ScreenCaptureProvider,
        target::ScreenCaptureTargetBroker, ScreenCaptureErrorCode, ScreenFrame,
    },
    screen_policy::{ScreenPerceptionRepository, ScreenPerceptionSessionGate},
};

/// Hard upper bound for the text returned by one ephemeral observation.
pub(crate) const MAX_OBSERVATION_TEXT_BYTES: usize = 32 * 1024;
/// Hard upper bound for OCR lines retained by one ephemeral observation.
pub(crate) const MAX_OBSERVATION_LINES: usize = 256;

/// OCR is kept in memory only.  This bound prevents a large C1 frame from
/// turning the Windows buffer bridge into an unbounded allocation even when a
/// platform reports a larger OCR dimension than the usual 2048-pixel limit.
const MAX_OCR_IMAGE_BYTES: usize = 64 * 1024 * 1024;
const OCR_TIMEOUT: Duration = Duration::from_secs(10);
const OCR_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenObservationStatus {
    Recognized,
    NoText,
}

/// Ephemeral, bounded screen text.  This object intentionally contains no
/// frame, native target, window identity, process identity, or OCR geometry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenObservation {
    pub(crate) captured_at: String,
    pub(crate) status: ScreenObservationStatus,
    pub(crate) text: String,
    pub(crate) truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenObservationErrorCode {
    OcrUnavailable,
    OcrFailed,
    OcrTimeout,
    ObservationBusy,
    SessionDenied,
    TargetRequired,
    TargetUnavailable,
    FrameInvalid,
    CaptureFailed,
}

impl ScreenObservationErrorCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OcrUnavailable => "OCR_UNAVAILABLE",
            Self::OcrFailed => "OCR_FAILED",
            Self::OcrTimeout => "OCR_TIMEOUT",
            Self::ObservationBusy => "OBSERVATION_BUSY",
            Self::SessionDenied => "SESSION_DENIED",
            Self::TargetRequired => "TARGET_REQUIRED",
            Self::TargetUnavailable => "TARGET_UNAVAILABLE",
            Self::FrameInvalid => "FRAME_INVALID",
            Self::CaptureFailed => "CAPTURE_FAILED",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenObservationError {
    pub(crate) code: ScreenObservationErrorCode,
    pub(crate) message: &'static str,
    pub(crate) recoverable: bool,
}

impl ScreenObservationError {
    fn new(code: ScreenObservationErrorCode) -> Self {
        let (message, recoverable) = match code {
            ScreenObservationErrorCode::OcrUnavailable => {
                ("A usable local Windows OCR engine is unavailable.", true)
            }
            ScreenObservationErrorCode::OcrFailed => {
                ("Local screen OCR could not be completed.", true)
            }
            ScreenObservationErrorCode::OcrTimeout => {
                ("Local screen OCR exceeded its bounded time limit.", true)
            }
            ScreenObservationErrorCode::ObservationBusy => (
                "Another screen-perception operation is already in progress.",
                true,
            ),
            ScreenObservationErrorCode::SessionDenied => (
                "Screen observation was not authorized for this session.",
                false,
            ),
            ScreenObservationErrorCode::TargetRequired => {
                ("No capture target is selected for this session.", true)
            }
            ScreenObservationErrorCode::TargetUnavailable => {
                ("The selected capture target is no longer available.", true)
            }
            ScreenObservationErrorCode::FrameInvalid => {
                ("The captured frame is invalid or out of bounds.", false)
            }
            ScreenObservationErrorCode::CaptureFailed => {
                ("The screen capture could not be completed.", true)
            }
        };
        Self {
            code,
            message,
            recoverable,
        }
    }

    fn ocr_unavailable() -> Self {
        Self::new(ScreenObservationErrorCode::OcrUnavailable)
    }

    fn ocr_failed() -> Self {
        Self::new(ScreenObservationErrorCode::OcrFailed)
    }

    fn ocr_timeout() -> Self {
        Self::new(ScreenObservationErrorCode::OcrTimeout)
    }

    fn observation_busy() -> Self {
        Self::new(ScreenObservationErrorCode::ObservationBusy)
    }

    fn frame_invalid() -> Self {
        Self::new(ScreenObservationErrorCode::FrameInvalid)
    }

    fn from_capture(error: super::screen_capture::ScreenCaptureError) -> Self {
        let code = match error.code {
            ScreenCaptureErrorCode::TargetRequired => ScreenObservationErrorCode::TargetRequired,
            ScreenCaptureErrorCode::TargetUnavailable => {
                ScreenObservationErrorCode::TargetUnavailable
            }
            ScreenCaptureErrorCode::SessionDenied => ScreenObservationErrorCode::SessionDenied,
            ScreenCaptureErrorCode::FrameInvalid => ScreenObservationErrorCode::FrameInvalid,
            ScreenCaptureErrorCode::Busy => ScreenObservationErrorCode::ObservationBusy,
            ScreenCaptureErrorCode::NotSupported | ScreenCaptureErrorCode::InvalidArgument => {
                ScreenObservationErrorCode::CaptureFailed
            }
            ScreenCaptureErrorCode::CaptureFailed => ScreenObservationErrorCode::CaptureFailed,
        };
        Self::new(code)
    }
}

impl fmt::Display for ScreenObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for ScreenObservationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OcrAsyncStatus {
    Started,
    Completed,
    Canceled,
    Error,
}

/// Minimal lifecycle seam for the WinRT OCR operation.
///
/// `close` is deliberately part of the seam: an operation may only be
/// retired after [`OcrAsyncStatus`] is terminal.  The test implementation
/// uses the same state machine as the Windows adapter, so cancellation
/// settlement cannot be accidentally replaced by a timer-only return.
trait OcrAsyncOperation {
    fn status(&self) -> Result<OcrAsyncStatus, ScreenObservationError>;
    fn cancel(&self) -> Result<(), ScreenObservationError>;
    fn get_results(&self) -> Result<ScreenOcrResult, ScreenObservationError>;
    fn close(&self) -> Result<(), ScreenObservationError>;
}

#[derive(Clone, Copy, Debug)]
struct OcrWaitPolicy {
    timeout: Duration,
    poll_interval: Duration,
}

impl OcrWaitPolicy {
    fn production() -> Self {
        Self {
            timeout: OCR_TIMEOUT,
            poll_interval: OCR_POLL_INTERVAL,
        }
    }

    #[cfg(test)]
    fn immediate() -> Self {
        Self {
            timeout: Duration::ZERO,
            poll_interval: Duration::ZERO,
        }
    }
}

/// A provider result is line-oriented so the composition boundary can impose
/// the observation byte and line limits without retaining OCR rectangles or
/// any other native metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenOcrResult {
    pub(crate) lines: Vec<String>,
    pub(crate) truncated: bool,
}

impl ScreenOcrResult {
    #[cfg(test)]
    fn from_lines(lines: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            lines: lines.into_iter().map(Into::into).collect(),
            truncated: false,
        }
    }
}

/// A bounded in-memory OCR input.  The common path borrows the C1 frame; a
/// proportional resize owns only the bounded resized bytes.
#[derive(Debug)]
pub(crate) struct PreparedOcrImage<'frame> {
    pub(crate) width: u32,
    pub(crate) height: u32,
    bytes: Cow<'frame, [u8]>,
}

impl<'frame> PreparedOcrImage<'frame> {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Narrow internal seam for local OCR.  It has no network, storage, or
/// frontend authority.
pub(crate) trait ScreenOcrProvider: Send + Sync {
    fn max_image_dimension(&self) -> Result<u32, ScreenObservationError>;

    fn recognize(
        &self,
        image: &PreparedOcrImage<'_>,
    ) -> Result<ScreenOcrResult, ScreenObservationError>;
}

/// Production D23-D1 entry point.  The canonical C1 operation permit is
/// acquired before capture, retained through preprocessing/OCR/observation,
/// and released only after the frame and OCR intermediate have retired.
pub(crate) fn capture_screen_observation(
    operation_gate: &screen_capture::operation::ScreenCaptureOperationGate,
    repository: &dyn ScreenPerceptionRepository,
    session_gate: &ScreenPerceptionSessionGate,
    broker: &ScreenCaptureTargetBroker,
    life_id: &str,
) -> Result<ScreenObservation, ScreenObservationError> {
    let operation_permit = operation_gate
        .try_enter()
        .map_err(|_| ScreenObservationError::observation_busy())?;
    let capture_provider = screen_capture::provider::native_provider();

    // Capture before creating the OCR engine so denied/no-target requests do
    // not even enter the local OCR provider boundary.
    let frame = screen_capture::capture_one_shot_with_provider(
        repository,
        session_gate,
        broker,
        life_id,
        capture_provider.as_ref(),
    )
    .map_err(ScreenObservationError::from_capture)?;
    let captured_at = utc_now_timestamp();
    let ocr_provider = native_ocr_provider()?;
    let observation = observe_frame(frame, captured_at, ocr_provider.as_ref())?;

    // `operation_permit` remains in this scope until `observe_frame` has
    // explicitly retired the raw frame and its resized OCR input.
    drop(operation_permit);
    Ok(observation)
}

/// Testable composition boundary.  The owned permit is intentionally part of
/// the signature: callers cannot invoke this complete pipeline without
/// demonstrating ownership of the canonical C1 single-flight slot.
pub(crate) fn observe_screen_once_with_permit(
    operation_permit: ScreenCaptureOperationPermit,
    repository: &dyn ScreenPerceptionRepository,
    session_gate: &ScreenPerceptionSessionGate,
    broker: &ScreenCaptureTargetBroker,
    life_id: &str,
    capture_provider: &dyn ScreenCaptureProvider,
    ocr_provider: &dyn ScreenOcrProvider,
) -> Result<ScreenObservation, ScreenObservationError> {
    let frame = screen_capture::capture_one_shot_with_provider(
        repository,
        session_gate,
        broker,
        life_id,
        capture_provider,
    )
    .map_err(ScreenObservationError::from_capture)?;
    let captured_at = utc_now_timestamp();
    let observation = observe_frame(frame, captured_at, ocr_provider)?;

    // The permit is deliberately dropped after observe_frame returns.  The
    // frame and any resized bytes have already been retired at that point.
    drop(operation_permit);
    Ok(observation)
}

/// Acquires the canonical permit and runs the complete pipeline with injected
/// providers.  Production uses `capture_screen_observation`; this seam keeps
/// authorization and single-flight tests independent of Windows OCR.
#[cfg(test)]
fn observe_screen_once_with_providers(
    operation_gate: &screen_capture::operation::ScreenCaptureOperationGate,
    repository: &dyn ScreenPerceptionRepository,
    session_gate: &ScreenPerceptionSessionGate,
    broker: &ScreenCaptureTargetBroker,
    life_id: &str,
    capture_provider: &dyn ScreenCaptureProvider,
    ocr_provider: &dyn ScreenOcrProvider,
) -> Result<ScreenObservation, ScreenObservationError> {
    let operation_permit = operation_gate
        .try_enter()
        .map_err(|_| ScreenObservationError::observation_busy())?;
    observe_screen_once_with_permit(
        operation_permit,
        repository,
        session_gate,
        broker,
        life_id,
        capture_provider,
        ocr_provider,
    )
}

fn observe_frame(
    frame: ScreenFrame,
    captured_at: String,
    ocr_provider: &dyn ScreenOcrProvider,
) -> Result<ScreenObservation, ScreenObservationError> {
    let max_image_dimension = ocr_provider.max_image_dimension()?;
    let prepared = prepare_ocr_image(&frame, max_image_dimension)?;
    let recognized = ocr_provider.recognize(&prepared)?;
    let observation = build_observation(captured_at, recognized);

    // Make the retirement order explicit: provider result, prepared image,
    // and then raw C1 frame are all gone before the caller's permit drops.
    drop(prepared);
    drop(frame);
    Ok(observation)
}

fn build_observation(captured_at: String, recognized: ScreenOcrResult) -> ScreenObservation {
    let mut text = String::new();
    let mut truncated = recognized.truncated;
    let line_count = recognized.lines.len();
    if line_count > MAX_OBSERVATION_LINES {
        truncated = true;
    }

    for (line_index, line) in recognized
        .lines
        .iter()
        .take(MAX_OBSERVATION_LINES)
        .enumerate()
    {
        if line_index > 0 && !append_bounded_text(&mut text, "\n") {
            truncated = true;
            break;
        }
        if !append_bounded_text(&mut text, line) {
            truncated = true;
            break;
        }
    }

    let has_text = text.chars().any(|character| !character.is_whitespace());
    if !has_text {
        text.clear();
    }

    ScreenObservation {
        captured_at,
        status: if has_text {
            ScreenObservationStatus::Recognized
        } else {
            ScreenObservationStatus::NoText
        },
        text,
        truncated,
    }
}

/// Appends whole Unicode scalar values only.  The returned boolean is true
/// when the complete source fit in the remaining UTF-8 byte budget.
fn append_bounded_text(destination: &mut String, source: &str) -> bool {
    for character in source.chars() {
        let Some(next_length) = destination.len().checked_add(character.len_utf8()) else {
            return false;
        };
        if next_length > MAX_OBSERVATION_TEXT_BYTES {
            return false;
        }
        destination.push(character);
    }
    true
}

/// Validates and, when necessary, proportionally downsizes a BGRA8 frame for
/// the local OCR API.  No encoded image or temporary file is created.
pub(crate) fn prepare_ocr_image(
    frame: &ScreenFrame,
    max_image_dimension: u32,
) -> Result<PreparedOcrImage<'_>, ScreenObservationError> {
    frame
        .validate()
        .map_err(|_| ScreenObservationError::frame_invalid())?;
    if max_image_dimension == 0 {
        return Err(ScreenObservationError::frame_invalid());
    }

    let source_byte_count = checked_ocr_byte_count(frame.width, frame.height)?;
    if frame.width.max(frame.height) <= max_image_dimension {
        if source_byte_count > MAX_OCR_IMAGE_BYTES {
            return Err(ScreenObservationError::frame_invalid());
        }
        return Ok(PreparedOcrImage {
            width: frame.width,
            height: frame.height,
            bytes: Cow::Borrowed(&frame.bytes),
        });
    }

    let (width, height) = scaled_dimensions(frame.width, frame.height, max_image_dimension)?;
    let byte_count = checked_ocr_byte_count(width, height)?;
    if byte_count > MAX_OCR_IMAGE_BYTES {
        return Err(ScreenObservationError::frame_invalid());
    }
    let bytes = resize_bgra8_nearest(frame, width, height, byte_count)?;
    Ok(PreparedOcrImage {
        width,
        height,
        bytes: Cow::Owned(bytes),
    })
}

pub(crate) fn scaled_dimensions(
    width: u32,
    height: u32,
    max_image_dimension: u32,
) -> Result<(u32, u32), ScreenObservationError> {
    if width == 0 || height == 0 || max_image_dimension == 0 {
        return Err(ScreenObservationError::frame_invalid());
    }
    if width.max(height) <= max_image_dimension {
        return Ok((width, height));
    }

    let source_max = u64::from(width.max(height));
    let target_max = u64::from(max_image_dimension);
    let scaled_width = scale_dimension(width, target_max, source_max)?;
    let scaled_height = scale_dimension(height, target_max, source_max)?;
    if scaled_width == 0
        || scaled_height == 0
        || scaled_width > max_image_dimension
        || scaled_height > max_image_dimension
    {
        return Err(ScreenObservationError::frame_invalid());
    }
    Ok((scaled_width, scaled_height))
}

fn scale_dimension(
    dimension: u32,
    target_max: u64,
    source_max: u64,
) -> Result<u32, ScreenObservationError> {
    let scaled = u64::from(dimension)
        .checked_mul(target_max)
        .ok_or_else(ScreenObservationError::frame_invalid)?
        / source_max;
    u32::try_from(scaled.max(1)).map_err(|_| ScreenObservationError::frame_invalid())
}

fn checked_ocr_byte_count(width: u32, height: u32) -> Result<usize, ScreenObservationError> {
    let width = usize::try_from(width).map_err(|_| ScreenObservationError::frame_invalid())?;
    let height = usize::try_from(height).map_err(|_| ScreenObservationError::frame_invalid())?;
    width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(ScreenObservationError::frame_invalid)
}

fn resize_bgra8_nearest(
    frame: &ScreenFrame,
    width: u32,
    height: u32,
    byte_count: usize,
) -> Result<Vec<u8>, ScreenObservationError> {
    let source_width =
        usize::try_from(frame.width).map_err(|_| ScreenObservationError::frame_invalid())?;
    let source_height =
        usize::try_from(frame.height).map_err(|_| ScreenObservationError::frame_invalid())?;
    let target_width =
        usize::try_from(width).map_err(|_| ScreenObservationError::frame_invalid())?;
    let target_height =
        usize::try_from(height).map_err(|_| ScreenObservationError::frame_invalid())?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(byte_count)
        .map_err(|_| ScreenObservationError::frame_invalid())?;

    for target_y in 0..target_height {
        let source_y = usize::try_from(
            u64::try_from(target_y)
                .map_err(|_| ScreenObservationError::frame_invalid())?
                .checked_mul(
                    u64::try_from(source_height)
                        .map_err(|_| ScreenObservationError::frame_invalid())?,
                )
                .ok_or_else(ScreenObservationError::frame_invalid)?
                / u64::try_from(target_height)
                    .map_err(|_| ScreenObservationError::frame_invalid())?,
        )
        .map_err(|_| ScreenObservationError::frame_invalid())?;
        if source_y >= source_height {
            return Err(ScreenObservationError::frame_invalid());
        }
        let source_row = source_y
            .checked_mul(source_width)
            .and_then(|offset| offset.checked_mul(4))
            .ok_or_else(ScreenObservationError::frame_invalid)?;

        for target_x in 0..target_width {
            let source_x = usize::try_from(
                u64::try_from(target_x)
                    .map_err(|_| ScreenObservationError::frame_invalid())?
                    .checked_mul(
                        u64::try_from(source_width)
                            .map_err(|_| ScreenObservationError::frame_invalid())?,
                    )
                    .ok_or_else(ScreenObservationError::frame_invalid)?
                    / u64::try_from(target_width)
                        .map_err(|_| ScreenObservationError::frame_invalid())?,
            )
            .map_err(|_| ScreenObservationError::frame_invalid())?;
            if source_x >= source_width {
                return Err(ScreenObservationError::frame_invalid());
            }
            let source_offset = source_row
                .checked_add(
                    source_x
                        .checked_mul(4)
                        .ok_or_else(ScreenObservationError::frame_invalid)?,
                )
                .ok_or_else(ScreenObservationError::frame_invalid)?;
            let source_end = source_offset
                .checked_add(4)
                .ok_or_else(ScreenObservationError::frame_invalid)?;
            let pixel = frame
                .bytes
                .get(source_offset..source_end)
                .ok_or_else(ScreenObservationError::frame_invalid)?;
            bytes.extend_from_slice(pixel);
        }
    }

    if bytes.len() != byte_count {
        return Err(ScreenObservationError::frame_invalid());
    }
    Ok(bytes)
}

fn utc_now_timestamp() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_seconds = elapsed.as_secs();
    let days = total_seconds / 86_400;
    let day_seconds = total_seconds % 86_400;
    let days = i64::try_from(days).unwrap_or(i64::MAX);
    let (year, month, day) = civil_date_from_unix_days(days);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
        elapsed.subsec_millis()
    )
}

// Gregorian civil date conversion, using only the standard library so D1
// does not add a time dependency for a non-persisted field.
fn civil_date_from_unix_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted / 146_097
    } else {
        (shifted - 146_096) / 146_097
    };
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(windows)]
fn native_ocr_provider() -> Result<Box<dyn ScreenOcrProvider>, ScreenObservationError> {
    WindowsLocalOcrProvider::new().map(|provider| Box::new(provider) as Box<dyn ScreenOcrProvider>)
}

#[cfg(not(windows))]
fn native_ocr_provider() -> Result<Box<dyn ScreenOcrProvider>, ScreenObservationError> {
    Err(ScreenObservationError::ocr_unavailable())
}

#[cfg(windows)]
struct WindowsLocalOcrProvider {
    engine: windows::Media::Ocr::OcrEngine,
    max_image_dimension: u32,
}

#[cfg(windows)]
impl WindowsLocalOcrProvider {
    fn new() -> Result<Self, ScreenObservationError> {
        use windows::Media::Ocr::OcrEngine;

        let _com = screen_capture::ComGuard::acquire(screen_capture::ComMode::Mta)
            .map_err(|_| ScreenObservationError::ocr_unavailable())?;
        let engine = OcrEngine::TryCreateFromUserProfileLanguages()
            .map_err(|_| ScreenObservationError::ocr_unavailable())?;
        let max_image_dimension = OcrEngine::MaxImageDimension()
            .map_err(|_| ScreenObservationError::ocr_unavailable())?;
        if max_image_dimension == 0 {
            return Err(ScreenObservationError::ocr_unavailable());
        }
        Ok(Self {
            engine,
            max_image_dimension,
        })
    }
}

#[cfg(windows)]
impl ScreenOcrProvider for WindowsLocalOcrProvider {
    fn max_image_dimension(&self) -> Result<u32, ScreenObservationError> {
        Ok(self.max_image_dimension)
    }

    fn recognize(
        &self,
        image: &PreparedOcrImage<'_>,
    ) -> Result<ScreenOcrResult, ScreenObservationError> {
        use windows::{
            Graphics::Imaging::{BitmapAlphaMode, BitmapPixelFormat, SoftwareBitmap},
            Storage::Streams::DataWriter,
        };

        let _com = screen_capture::ComGuard::acquire(screen_capture::ComMode::Mta)
            .map_err(|_| ScreenObservationError::ocr_failed())?;
        let width =
            i32::try_from(image.width).map_err(|_| ScreenObservationError::frame_invalid())?;
        let height =
            i32::try_from(image.height).map_err(|_| ScreenObservationError::frame_invalid())?;
        let byte_count = checked_ocr_byte_count(image.width, image.height)?;
        if image.bytes().len() != byte_count || byte_count > MAX_OCR_IMAGE_BYTES {
            return Err(ScreenObservationError::frame_invalid());
        }
        let byte_count_u32 =
            u32::try_from(byte_count).map_err(|_| ScreenObservationError::frame_invalid())?;

        let writer = DataWriter::new().map_err(|_| ScreenObservationError::ocr_failed())?;
        writer
            .WriteBytes(image.bytes())
            .map_err(|_| ScreenObservationError::ocr_failed())?;
        if writer
            .UnstoredBufferLength()
            .map_err(|_| ScreenObservationError::ocr_failed())?
            != byte_count_u32
        {
            return Err(ScreenObservationError::ocr_failed());
        }
        let buffer = writer
            .DetachBuffer()
            .map_err(|_| ScreenObservationError::ocr_failed())?;
        let _ = writer.Close();
        let buffer_length = buffer
            .Length()
            .map_err(|_| ScreenObservationError::ocr_failed())?;
        if buffer_length != byte_count_u32 {
            return Err(ScreenObservationError::ocr_failed());
        }

        let bitmap = SoftwareBitmap::CreateCopyWithAlphaFromBuffer(
            &buffer,
            BitmapPixelFormat::Bgra8,
            width,
            height,
            BitmapAlphaMode::Premultiplied,
        )
        .map_err(|_| ScreenObservationError::ocr_failed())?;
        if bitmap
            .BitmapPixelFormat()
            .map_err(|_| ScreenObservationError::ocr_failed())?
            != BitmapPixelFormat::Bgra8
            || bitmap
                .BitmapAlphaMode()
                .map_err(|_| ScreenObservationError::ocr_failed())?
                != BitmapAlphaMode::Premultiplied
            || bitmap
                .PixelWidth()
                .map_err(|_| ScreenObservationError::ocr_failed())?
                != width
            || bitmap
                .PixelHeight()
                .map_err(|_| ScreenObservationError::ocr_failed())?
                != height
        {
            let _ = bitmap.Close();
            return Err(ScreenObservationError::frame_invalid());
        }

        let result = self
            .engine
            .RecognizeAsync(&bitmap)
            .map_err(|_| ScreenObservationError::ocr_failed())
            .and_then(|operation| wait_for_ocr_result(&operation));
        let bitmap_close = bitmap
            .Close()
            .map_err(|_| ScreenObservationError::ocr_failed());
        let result = result?;
        bitmap_close?;
        Ok(result)
    }
}

#[cfg(windows)]
fn wait_for_ocr_result(
    operation: &windows_future::IAsyncOperation<windows::Media::Ocr::OcrResult>,
) -> Result<ScreenOcrResult, ScreenObservationError> {
    let operation = WindowsOcrAsyncOperation { operation };
    wait_for_ocr_operation(&operation, OcrWaitPolicy::production())
}

#[cfg(windows)]
struct WindowsOcrAsyncOperation<'operation> {
    operation: &'operation windows_future::IAsyncOperation<windows::Media::Ocr::OcrResult>,
}

#[cfg(windows)]
impl OcrAsyncOperation for WindowsOcrAsyncOperation<'_> {
    fn status(&self) -> Result<OcrAsyncStatus, ScreenObservationError> {
        use windows_future::AsyncStatus;

        match self
            .operation
            .Status()
            .map_err(|_| ScreenObservationError::ocr_failed())?
        {
            AsyncStatus::Started => Ok(OcrAsyncStatus::Started),
            AsyncStatus::Completed => Ok(OcrAsyncStatus::Completed),
            AsyncStatus::Canceled => Ok(OcrAsyncStatus::Canceled),
            AsyncStatus::Error => Ok(OcrAsyncStatus::Error),
            _ => Err(ScreenObservationError::ocr_failed()),
        }
    }

    fn cancel(&self) -> Result<(), ScreenObservationError> {
        self.operation
            .Cancel()
            .map_err(|_| ScreenObservationError::ocr_failed())
    }

    fn get_results(&self) -> Result<ScreenOcrResult, ScreenObservationError> {
        self.operation
            .GetResults()
            .map_err(|_| ScreenObservationError::ocr_failed())
            .and_then(extract_ocr_result)
    }

    fn close(&self) -> Result<(), ScreenObservationError> {
        self.operation
            .Close()
            .map_err(|_| ScreenObservationError::ocr_failed())
    }
}

/// Waits for a terminal OCR state and retires the operation only then.
///
/// The initial deadline is the point at which cancellation is requested.  A
/// second deadline must not release the operation while it remains Started:
/// `IAsyncInfo::Close` is not valid before completion, and dropping the
/// operation/bitmap at that point would let the sensitive operation escape
/// the C1 permit.  Therefore this state machine has exactly one cancellation
/// request and returns only after a terminal status has been observed and the
/// async object has been closed.
fn wait_for_ocr_operation<O: OcrAsyncOperation + ?Sized>(
    operation: &O,
    policy: OcrWaitPolicy,
) -> Result<ScreenOcrResult, ScreenObservationError> {
    let deadline = std::time::Instant::now()
        .checked_add(policy.timeout)
        .unwrap_or_else(std::time::Instant::now);
    let mut cancellation_requested = false;
    let mut cancellation_failed = false;

    loop {
        let status = operation.status()?;
        match status {
            OcrAsyncStatus::Completed => {
                return finish_ocr_operation(operation, status, cancellation_failed);
            }
            OcrAsyncStatus::Canceled => {
                return finish_ocr_operation(operation, status, cancellation_failed);
            }
            OcrAsyncStatus::Error => {
                return finish_ocr_operation(operation, status, cancellation_failed);
            }
            OcrAsyncStatus::Started => {}
        }

        if !cancellation_requested && std::time::Instant::now() >= deadline {
            cancellation_requested = true;
            if operation.cancel().is_err() {
                // Do not convert a failed cancellation request into a false
                // OCR_TIMEOUT.  Continue observing until the operation itself
                // reaches a terminal state.
                cancellation_failed = true;
            }
            continue;
        }

        if !policy.poll_interval.is_zero() {
            std::thread::sleep(policy.poll_interval);
        }
    }
}

fn finish_ocr_operation<O: OcrAsyncOperation + ?Sized>(
    operation: &O,
    status: OcrAsyncStatus,
    cancellation_failed: bool,
) -> Result<ScreenOcrResult, ScreenObservationError> {
    let result = if cancellation_failed {
        // A failed cancellation request cannot be reported as a successful
        // OCR result, even if the operation later completes normally.  The
        // terminal observation below is still required before retirement.
        Err(ScreenObservationError::ocr_failed())
    } else {
        match status {
            OcrAsyncStatus::Completed => operation.get_results(),
            OcrAsyncStatus::Canceled => Err(ScreenObservationError::ocr_timeout()),
            OcrAsyncStatus::Error => Err(ScreenObservationError::ocr_failed()),
            OcrAsyncStatus::Started => Err(ScreenObservationError::ocr_failed()),
        }
    };

    // The status was terminal before this call.  Close is intentionally
    // checked rather than discarded; a failed retirement is not reported as
    // a successful timeout or OCR result.
    let close_result = operation.close();
    match close_result {
        Ok(()) => result,
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn extract_ocr_result(
    result: windows::Media::Ocr::OcrResult,
) -> Result<ScreenOcrResult, ScreenObservationError> {
    let lines = result
        .Lines()
        .map_err(|_| ScreenObservationError::ocr_failed())?;
    let line_count = lines
        .Size()
        .map_err(|_| ScreenObservationError::ocr_failed())?;
    let retained_count = usize::try_from(line_count)
        .map_err(|_| ScreenObservationError::ocr_failed())?
        .min(MAX_OBSERVATION_LINES.saturating_add(1));
    let mut extracted = Vec::new();
    extracted
        .try_reserve_exact(retained_count)
        .map_err(|_| ScreenObservationError::ocr_failed())?;
    let mut truncated = usize::try_from(line_count)
        .map(|count| count > MAX_OBSERVATION_LINES)
        .unwrap_or(true);

    for index in 0..retained_count {
        let index = u32::try_from(index).map_err(|_| ScreenObservationError::ocr_failed())?;
        let line = lines
            .GetAt(index)
            .map_err(|_| ScreenObservationError::ocr_failed())?;
        let line_text = line
            .Text()
            .map_err(|_| ScreenObservationError::ocr_failed())?;
        let (line_text, line_truncated) = bounded_hstring_line(&line_text);
        truncated |= line_truncated;
        extracted.push(line_text);
    }
    Ok(ScreenOcrResult {
        lines: extracted,
        truncated,
    })
}

#[cfg(windows)]
fn bounded_hstring_line(value: &windows::core::HSTRING) -> (String, bool) {
    let mut line = String::new();
    for decoded in std::char::decode_utf16(value.iter().copied()) {
        let character = decoded.unwrap_or('\u{FFFD}');
        let Some(next_length) = line.len().checked_add(character.len_utf8()) else {
            return (line, true);
        };
        if next_length > MAX_OBSERVATION_TEXT_BYTES {
            return (line, true);
        }
        line.push(character);
    }
    (line, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    };

    use crate::perception::{
        screen_capture::{self, provider::ScreenCaptureProvider},
        screen_policy::{
            LifeScreenPerceptionPolicy, LifeScreenPerceptionPolicyCreateRequest,
            LifeScreenPerceptionPolicyEvent, LifeScreenPerceptionPolicyUpdateOutcome,
            LifeScreenPerceptionPolicyUpdateRequest, ScreenPerceptionCreateOutcome,
            ScreenPerceptionError, ScreenPerceptionRepository, ScreenPerceptionSessionGate,
        },
    };

    #[derive(Default)]
    struct FakeRepository {
        enabled: bool,
    }

    impl FakeRepository {
        fn enabled() -> Self {
            Self { enabled: true }
        }
    }

    impl ScreenPerceptionRepository for FakeRepository {
        fn create_screen_perception_policy(
            &self,
            _request: LifeScreenPerceptionPolicyCreateRequest,
        ) -> Result<ScreenPerceptionCreateOutcome<LifeScreenPerceptionPolicy>, ScreenPerceptionError>
        {
            Ok(ScreenPerceptionCreateOutcome::Applied(
                LifeScreenPerceptionPolicy {
                    life_id: "life-a".into(),
                    screen_perception_enabled: self.enabled,
                    revision: 1,
                    created_at: "2026-08-30T00:00:00.000Z".into(),
                    updated_at: "2026-08-30T00:00:00.000Z".into(),
                    policy_version: 1,
                },
            ))
        }

        fn find_screen_perception_policy(
            &self,
            life_id: &str,
        ) -> Result<Option<LifeScreenPerceptionPolicy>, ScreenPerceptionError> {
            if life_id == "life-a" {
                Ok(Some(LifeScreenPerceptionPolicy {
                    life_id: life_id.into(),
                    screen_perception_enabled: self.enabled,
                    revision: 1,
                    created_at: "2026-08-30T00:00:00.000Z".into(),
                    updated_at: "2026-08-30T00:00:00.000Z".into(),
                    policy_version: 1,
                }))
            } else {
                Ok(None)
            }
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
            Ok(None)
        }
    }

    struct FakeCaptureProvider {
        calls: Arc<AtomicUsize>,
        result: Result<ScreenFrame, screen_capture::ScreenCaptureError>,
        supported: bool,
    }

    impl FakeCaptureProvider {
        fn returning(frame: ScreenFrame) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                result: Ok(frame),
                supported: true,
            }
        }

        fn failing() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                result: Err(screen_capture::ScreenCaptureError::capture_failed()),
                supported: true,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl ScreenCaptureProvider for FakeCaptureProvider {
        fn is_supported(&self) -> bool {
            self.supported
        }

        fn capture_frame(
            &self,
            _target: &screen_capture::target::ScreenCaptureTarget,
        ) -> Result<ScreenFrame, screen_capture::ScreenCaptureError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    struct FakeOcrProvider {
        max_image_dimension: u32,
        calls: Arc<AtomicUsize>,
        result: Result<ScreenOcrResult, ScreenObservationError>,
    }

    impl FakeOcrProvider {
        fn returning(lines: impl IntoIterator<Item = impl Into<String>>) -> Self {
            Self {
                max_image_dimension: 2048,
                calls: Arc::new(AtomicUsize::new(0)),
                result: Ok(ScreenOcrResult::from_lines(lines)),
            }
        }

        fn failing() -> Self {
            Self {
                max_image_dimension: 2048,
                calls: Arc::new(AtomicUsize::new(0)),
                result: Err(ScreenObservationError::ocr_failed()),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl ScreenOcrProvider for FakeOcrProvider {
        fn max_image_dimension(&self) -> Result<u32, ScreenObservationError> {
            Ok(self.max_image_dimension)
        }

        fn recognize(
            &self,
            _image: &PreparedOcrImage<'_>,
        ) -> Result<ScreenOcrResult, ScreenObservationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    struct ScriptedOcrOperation {
        statuses: std::sync::Mutex<VecDeque<OcrAsyncStatus>>,
        cancel_result: std::sync::Mutex<Result<(), ScreenObservationError>>,
        result: Result<ScreenOcrResult, ScreenObservationError>,
        cancel_calls: AtomicUsize,
        get_results_calls: AtomicUsize,
        close_calls: AtomicUsize,
        status_calls: AtomicUsize,
    }

    impl ScriptedOcrOperation {
        fn new(
            statuses: impl IntoIterator<Item = OcrAsyncStatus>,
            cancel_result: Result<(), ScreenObservationError>,
            result: Result<ScreenOcrResult, ScreenObservationError>,
        ) -> Self {
            Self {
                statuses: std::sync::Mutex::new(statuses.into_iter().collect()),
                cancel_result: std::sync::Mutex::new(cancel_result),
                result,
                cancel_calls: AtomicUsize::new(0),
                get_results_calls: AtomicUsize::new(0),
                close_calls: AtomicUsize::new(0),
                status_calls: AtomicUsize::new(0),
            }
        }
    }

    impl OcrAsyncOperation for ScriptedOcrOperation {
        fn status(&self) -> Result<OcrAsyncStatus, ScreenObservationError> {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .statuses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(OcrAsyncStatus::Error))
        }

        fn cancel(&self) -> Result<(), ScreenObservationError> {
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
            self.cancel_result.lock().unwrap().clone()
        }

        fn get_results(&self) -> Result<ScreenOcrResult, ScreenObservationError> {
            self.get_results_calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }

        fn close(&self) -> Result<(), ScreenObservationError> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct BlockingSettlementOperation {
        settlement_started: mpsc::Sender<()>,
        release: Arc<MutexReceiver>,
        cancel_calls: AtomicUsize,
        close_calls: AtomicUsize,
        status_calls: AtomicUsize,
    }

    impl BlockingSettlementOperation {
        fn new(settlement_started: mpsc::Sender<()>, release: mpsc::Receiver<()>) -> Self {
            Self {
                settlement_started,
                release: Arc::new(MutexReceiver(std::sync::Mutex::new(release))),
                cancel_calls: AtomicUsize::new(0),
                close_calls: AtomicUsize::new(0),
                status_calls: AtomicUsize::new(0),
            }
        }
    }

    impl OcrAsyncOperation for BlockingSettlementOperation {
        fn status(&self) -> Result<OcrAsyncStatus, ScreenObservationError> {
            let call = self.status_calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                return Ok(OcrAsyncStatus::Started);
            }
            if call == 1 {
                self.settlement_started.send(()).unwrap();
                self.release.0.lock().unwrap().recv().unwrap();
            }
            Ok(OcrAsyncStatus::Canceled)
        }

        fn cancel(&self) -> Result<(), ScreenObservationError> {
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn get_results(&self) -> Result<ScreenOcrResult, ScreenObservationError> {
            panic!("a canceled OCR operation must not request results")
        }

        fn close(&self) -> Result<(), ScreenObservationError> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct BlockingSettlementOcrProvider {
        operation: Arc<BlockingSettlementOperation>,
    }

    impl ScreenOcrProvider for BlockingSettlementOcrProvider {
        fn max_image_dimension(&self) -> Result<u32, ScreenObservationError> {
            Ok(2048)
        }

        fn recognize(
            &self,
            _image: &PreparedOcrImage<'_>,
        ) -> Result<ScreenOcrResult, ScreenObservationError> {
            wait_for_ocr_operation(self.operation.as_ref(), OcrWaitPolicy::immediate())
        }
    }

    struct BlockingOcrProvider {
        started: mpsc::Sender<()>,
        release: Arc<MutexReceiver>,
        calls: Arc<AtomicUsize>,
    }

    struct MutexReceiver(std::sync::Mutex<mpsc::Receiver<()>>);

    impl BlockingOcrProvider {
        fn new(started: mpsc::Sender<()>, release: mpsc::Receiver<()>) -> Self {
            Self {
                started,
                release: Arc::new(MutexReceiver(std::sync::Mutex::new(release))),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl ScreenOcrProvider for BlockingOcrProvider {
        fn max_image_dimension(&self) -> Result<u32, ScreenObservationError> {
            Ok(2048)
        }

        fn recognize(
            &self,
            _image: &PreparedOcrImage<'_>,
        ) -> Result<ScreenOcrResult, ScreenObservationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.send(()).unwrap();
            self.release.0.lock().unwrap().recv().unwrap();
            Ok(ScreenOcrResult::from_lines(["released"]))
        }
    }

    fn valid_frame(width: u32, height: u32) -> ScreenFrame {
        let byte_count = usize::try_from(width).unwrap() * usize::try_from(height).unwrap() * 4;
        ScreenFrame {
            width,
            height,
            pixel_format: screen_capture::ScreenPixelFormat::Bgra8,
            bytes: vec![0; byte_count],
        }
    }

    fn authorized_fixture() -> (
        FakeRepository,
        ScreenPerceptionSessionGate,
        screen_capture::target::ScreenCaptureTargetBroker,
    ) {
        let repository = FakeRepository::enabled();
        let session_gate = ScreenPerceptionSessionGate::new();
        session_gate.arm_for_life("life-a");
        let broker = screen_capture::target::ScreenCaptureTargetBroker::new();
        let fence = session_gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(fence);
        (repository, session_gate, broker)
    }

    #[test]
    fn screen_observation_valid_authorization_captures_and_ocr_once() {
        let (repository, session_gate, broker) = authorized_fixture();
        let capture = FakeCaptureProvider::returning(valid_frame(16, 16));
        let ocr = FakeOcrProvider::returning(["D23 local", "OCR"]);
        let operation_gate = screen_capture::operation::ScreenCaptureOperationGate::new();

        let observation = observe_screen_once_with_providers(
            &operation_gate,
            &repository,
            &session_gate,
            &broker,
            "life-a",
            &capture,
            &ocr,
        )
        .unwrap();

        assert_eq!(capture.calls(), 1);
        assert_eq!(ocr.calls(), 1);
        assert_eq!(observation.status, ScreenObservationStatus::Recognized);
        assert_eq!(observation.text, "D23 local\nOCR");
        assert!(!observation.captured_at.is_empty());
        assert!(!observation.truncated);
        assert!(operation_gate.try_enter().is_ok());
    }

    #[test]
    fn screen_observation_denied_authority_never_calls_capture_or_ocr() {
        for (repository, session_gate, life_id) in [
            (
                FakeRepository { enabled: false },
                {
                    let gate = ScreenPerceptionSessionGate::new();
                    gate.arm_for_life("life-a");
                    gate
                },
                "life-a",
            ),
            (
                FakeRepository::enabled(),
                ScreenPerceptionSessionGate::new(),
                "life-a",
            ),
            (
                FakeRepository::enabled(),
                {
                    let gate = ScreenPerceptionSessionGate::new();
                    gate.arm_for_life("life-b");
                    gate
                },
                "life-a",
            ),
        ] {
            let broker = screen_capture::target::ScreenCaptureTargetBroker::new();
            let capture = FakeCaptureProvider::returning(valid_frame(4, 4));
            let ocr = FakeOcrProvider::returning(["must not run"]);
            let operation_gate = screen_capture::operation::ScreenCaptureOperationGate::new();
            let result = observe_screen_once_with_providers(
                &operation_gate,
                &repository,
                &session_gate,
                &broker,
                life_id,
                &capture,
                &ocr,
            );
            assert_eq!(
                result.unwrap_err().code,
                ScreenObservationErrorCode::SessionDenied
            );
            assert_eq!(capture.calls(), 0);
            assert_eq!(ocr.calls(), 0);
        }

        let repository = FakeRepository::enabled();
        let session_gate = ScreenPerceptionSessionGate::new();
        session_gate.arm_for_life("life-a");
        let broker = screen_capture::target::ScreenCaptureTargetBroker::new();
        let capture = FakeCaptureProvider::returning(valid_frame(4, 4));
        let ocr = FakeOcrProvider::returning(["must not run"]);
        let operation_gate = screen_capture::operation::ScreenCaptureOperationGate::new();
        let result = observe_screen_once_with_providers(
            &operation_gate,
            &repository,
            &session_gate,
            &broker,
            "life-a",
            &capture,
            &ocr,
        );
        assert_eq!(
            result.unwrap_err().code,
            ScreenObservationErrorCode::TargetRequired
        );
        assert_eq!(capture.calls(), 0);
        assert_eq!(ocr.calls(), 0);
    }

    #[test]
    fn screen_observation_busy_rejects_before_capture_and_ocr() {
        let (repository, session_gate, broker) = authorized_fixture();
        let capture = FakeCaptureProvider::returning(valid_frame(16, 16));
        let ocr = FakeOcrProvider::returning(["must not run"]);
        let operation_gate = screen_capture::operation::ScreenCaptureOperationGate::new();
        let _permit = operation_gate.try_enter().unwrap();

        let result = observe_screen_once_with_providers(
            &operation_gate,
            &repository,
            &session_gate,
            &broker,
            "life-a",
            &capture,
            &ocr,
        );
        assert_eq!(
            result.unwrap_err().code,
            ScreenObservationErrorCode::ObservationBusy
        );
        assert_eq!(capture.calls(), 0);
        assert_eq!(ocr.calls(), 0);
    }

    #[test]
    fn screen_observation_capture_failure_or_invalid_frame_skips_ocr() {
        let (repository, session_gate, broker) = authorized_fixture();
        let operation_gate = screen_capture::operation::ScreenCaptureOperationGate::new();
        let failing_capture = FakeCaptureProvider::failing();
        let ocr = FakeOcrProvider::returning(["must not run"]);
        let result = observe_screen_once_with_providers(
            &operation_gate,
            &repository,
            &session_gate,
            &broker,
            "life-a",
            &failing_capture,
            &ocr,
        );
        assert_eq!(
            result.unwrap_err().code,
            ScreenObservationErrorCode::TargetUnavailable
        );
        assert_eq!(ocr.calls(), 0);

        let invalid_capture = FakeCaptureProvider::returning(ScreenFrame {
            width: 4,
            height: 4,
            pixel_format: screen_capture::ScreenPixelFormat::Bgra8,
            bytes: vec![0; 15],
        });
        let result = observe_screen_once_with_providers(
            &operation_gate,
            &repository,
            &session_gate,
            &broker,
            "life-a",
            &invalid_capture,
            &ocr,
        );
        assert_eq!(
            result.unwrap_err().code,
            ScreenObservationErrorCode::FrameInvalid
        );
        assert_eq!(ocr.calls(), 0);
    }

    #[test]
    fn screen_observation_ocr_failure_is_bounded() {
        let (repository, session_gate, broker) = authorized_fixture();
        let capture = FakeCaptureProvider::returning(valid_frame(4, 4));
        let ocr = FakeOcrProvider::failing();
        let operation_gate = screen_capture::operation::ScreenCaptureOperationGate::new();
        let result = observe_screen_once_with_providers(
            &operation_gate,
            &repository,
            &session_gate,
            &broker,
            "life-a",
            &capture,
            &ocr,
        );
        assert_eq!(
            result.unwrap_err().code,
            ScreenObservationErrorCode::OcrFailed
        );
        assert!(operation_gate.try_enter().is_ok());
    }

    #[test]
    fn screen_observation_no_text_is_empty_no_text() {
        let (repository, session_gate, broker) = authorized_fixture();
        let capture = FakeCaptureProvider::returning(valid_frame(4, 4));
        let ocr = FakeOcrProvider::returning(["", " \t"]);
        let operation_gate = screen_capture::operation::ScreenCaptureOperationGate::new();
        let observation = observe_screen_once_with_providers(
            &operation_gate,
            &repository,
            &session_gate,
            &broker,
            "life-a",
            &capture,
            &ocr,
        )
        .unwrap();
        assert_eq!(observation.status, ScreenObservationStatus::NoText);
        assert!(observation.text.is_empty());
    }

    #[test]
    fn screen_observation_text_bounds_are_unicode_safe_and_line_bounded() {
        let captured_at = "2026-08-30T00:00:00.000Z".to_string();
        let cjk = "界".repeat(MAX_OBSERVATION_TEXT_BYTES);
        let observation =
            build_observation(captured_at.clone(), ScreenOcrResult::from_lines([cjk]));
        assert_eq!(observation.status, ScreenObservationStatus::Recognized);
        assert!(observation.truncated);
        assert!(observation.text.len() <= MAX_OBSERVATION_TEXT_BYTES);
        assert!(std::str::from_utf8(observation.text.as_bytes()).is_ok());

        let many_lines = ScreenOcrResult {
            lines: (0..(MAX_OBSERVATION_LINES + 2))
                .map(|index| format!("line-{index}"))
                .collect(),
            truncated: false,
        };
        let observation = build_observation(captured_at, many_lines);
        assert!(observation.truncated);
        assert_eq!(observation.text.lines().count(), MAX_OBSERVATION_LINES);
    }

    #[test]
    fn screen_observation_dimension_policy_preserves_or_scales_aspect_ratio() {
        let frame = valid_frame(100, 50);
        let prepared = prepare_ocr_image(&frame, 200).unwrap();
        assert_eq!((prepared.width, prepared.height), (100, 50));
        assert!(matches!(prepared.bytes, Cow::Borrowed(_)));

        let prepared = prepare_ocr_image(&frame, 20).unwrap();
        assert_eq!((prepared.width, prepared.height), (20, 10));
        assert_eq!(prepared.bytes.len(), 20 * 10 * 4);

        let tall = valid_frame(50, 100);
        let prepared = prepare_ocr_image(&tall, 20).unwrap();
        assert_eq!((prepared.width, prepared.height), (10, 20));
        assert_eq!(prepared.bytes.len(), 10 * 20 * 4);
    }

    #[test]
    fn screen_observation_dimension_policy_rejects_zero_and_checked_overflow() {
        assert!(scaled_dimensions(0, 10, 10).is_err());
        assert!(scaled_dimensions(10, 10, 0).is_err());
        assert!(checked_ocr_byte_count(u32::MAX, u32::MAX).is_err());

        let oversized = ScreenFrame {
            width: 16_384,
            height: 16_384,
            pixel_format: screen_capture::ScreenPixelFormat::Bgra8,
            bytes: Vec::new(),
        };
        assert!(prepare_ocr_image(&oversized, 2_048).is_err());
    }

    #[test]
    fn screen_observation_permit_spans_capture_and_ocr() {
        let (repository, session_gate, broker) = authorized_fixture();
        let capture = FakeCaptureProvider::returning(valid_frame(16, 16));
        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let ocr = Arc::new(BlockingOcrProvider::new(started_sender, release_receiver));
        let operation_gate = Arc::new(screen_capture::operation::ScreenCaptureOperationGate::new());
        let worker_gate = Arc::clone(&operation_gate);
        let worker_ocr = Arc::clone(&ocr);
        let worker = std::thread::spawn(move || {
            observe_screen_once_with_providers(
                &worker_gate,
                &repository,
                &session_gate,
                &broker,
                "life-a",
                &capture,
                worker_ocr.as_ref(),
            )
        });

        started_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("OCR should be entered before the permit can release");

        let (repository_2, session_gate_2, broker_2) = authorized_fixture();
        let capture_2 = FakeCaptureProvider::returning(valid_frame(4, 4));
        let ocr_2 = FakeOcrProvider::returning(["must not run"]);
        let busy = observe_screen_once_with_providers(
            &operation_gate,
            &repository_2,
            &session_gate_2,
            &broker_2,
            "life-a",
            &capture_2,
            &ocr_2,
        )
        .unwrap_err();
        assert_eq!(busy.code, ScreenObservationErrorCode::ObservationBusy);
        assert_eq!(capture_2.calls(), 0);
        assert_eq!(ocr_2.calls(), 0);

        release_sender.send(()).unwrap();
        let observation = worker.join().unwrap().unwrap();
        assert_eq!(observation.status, ScreenObservationStatus::Recognized);
        assert!(operation_gate.try_enter().is_ok());
    }

    #[test]
    fn ocr_started_then_completed_gets_results_and_closes_after_terminal() {
        let operation = ScriptedOcrOperation::new(
            [OcrAsyncStatus::Started, OcrAsyncStatus::Completed],
            Ok(()),
            Ok(ScreenOcrResult::from_lines(["completed"])),
        );
        let result = wait_for_ocr_operation(
            &operation,
            OcrWaitPolicy {
                timeout: Duration::from_secs(1),
                poll_interval: Duration::ZERO,
            },
        )
        .unwrap();

        assert_eq!(result, ScreenOcrResult::from_lines(["completed"]));
        assert_eq!(operation.cancel_calls.load(Ordering::SeqCst), 0);
        assert_eq!(operation.get_results_calls.load(Ordering::SeqCst), 1);
        assert_eq!(operation.close_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ocr_timeout_cancels_once_and_waits_for_terminal_canceled() {
        let operation = ScriptedOcrOperation::new(
            [
                OcrAsyncStatus::Started,
                OcrAsyncStatus::Started,
                OcrAsyncStatus::Canceled,
            ],
            Ok(()),
            Ok(ScreenOcrResult::from_lines(["must not run"])),
        );
        let error = wait_for_ocr_operation(&operation, OcrWaitPolicy::immediate()).unwrap_err();

        assert_eq!(error.code, ScreenObservationErrorCode::OcrTimeout);
        assert_eq!(operation.cancel_calls.load(Ordering::SeqCst), 1);
        assert_eq!(operation.status_calls.load(Ordering::SeqCst), 3);
        assert_eq!(operation.get_results_calls.load(Ordering::SeqCst), 0);
        assert_eq!(operation.close_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ocr_cancel_failure_waits_for_terminal_and_maps_to_failure() {
        let operation = ScriptedOcrOperation::new(
            [OcrAsyncStatus::Started, OcrAsyncStatus::Completed],
            Err(ScreenObservationError::ocr_failed()),
            Ok(ScreenOcrResult::from_lines(["must not be published"])),
        );
        let error = wait_for_ocr_operation(&operation, OcrWaitPolicy::immediate()).unwrap_err();

        assert_eq!(error.code, ScreenObservationErrorCode::OcrFailed);
        assert_eq!(operation.cancel_calls.load(Ordering::SeqCst), 1);
        assert_eq!(operation.status_calls.load(Ordering::SeqCst), 2);
        assert_eq!(operation.get_results_calls.load(Ordering::SeqCst), 0);
        assert_eq!(operation.close_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ocr_cancel_failure_waits_for_terminal_error_and_maps_to_failure() {
        let operation = ScriptedOcrOperation::new(
            [OcrAsyncStatus::Started, OcrAsyncStatus::Error],
            Err(ScreenObservationError::ocr_failed()),
            Ok(ScreenOcrResult::from_lines(["must not run"])),
        );
        let error = wait_for_ocr_operation(&operation, OcrWaitPolicy::immediate()).unwrap_err();

        assert_eq!(error.code, ScreenObservationErrorCode::OcrFailed);
        assert_eq!(operation.cancel_calls.load(Ordering::SeqCst), 1);
        assert_eq!(operation.status_calls.load(Ordering::SeqCst), 2);
        assert_eq!(operation.get_results_calls.load(Ordering::SeqCst), 0);
        assert_eq!(operation.close_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ocr_error_is_terminal_failure_and_is_closed() {
        let operation = ScriptedOcrOperation::new(
            [OcrAsyncStatus::Error],
            Ok(()),
            Ok(ScreenOcrResult::from_lines(["must not run"])),
        );
        let error = wait_for_ocr_operation(&operation, OcrWaitPolicy::immediate()).unwrap_err();

        assert_eq!(error.code, ScreenObservationErrorCode::OcrFailed);
        assert_eq!(operation.cancel_calls.load(Ordering::SeqCst), 0);
        assert_eq!(operation.close_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ocr_canceled_is_terminal_timeout_and_is_closed() {
        let operation = ScriptedOcrOperation::new(
            [OcrAsyncStatus::Canceled],
            Ok(()),
            Ok(ScreenOcrResult::from_lines(["must not run"])),
        );
        let error = wait_for_ocr_operation(&operation, OcrWaitPolicy::immediate()).unwrap_err();

        assert_eq!(error.code, ScreenObservationErrorCode::OcrTimeout);
        assert_eq!(operation.cancel_calls.load(Ordering::SeqCst), 0);
        assert_eq!(operation.close_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn operation_permit_remains_busy_during_ocr_cancellation_settlement() {
        let (repository, session_gate, broker) = authorized_fixture();
        let capture = FakeCaptureProvider::returning(valid_frame(16, 16));
        let (settlement_started_sender, settlement_started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let operation = Arc::new(BlockingSettlementOperation::new(
            settlement_started_sender,
            release_receiver,
        ));
        let ocr = Arc::new(BlockingSettlementOcrProvider {
            operation: Arc::clone(&operation),
        });
        let operation_gate = Arc::new(screen_capture::operation::ScreenCaptureOperationGate::new());
        let worker_gate = Arc::clone(&operation_gate);
        let worker = std::thread::spawn(move || {
            observe_screen_once_with_providers(
                &worker_gate,
                &repository,
                &session_gate,
                &broker,
                "life-a",
                &capture,
                ocr.as_ref(),
            )
        });

        settlement_started_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("OCR cancellation settlement should be entered before release");

        let (repository_2, session_gate_2, broker_2) = authorized_fixture();
        let capture_2 = FakeCaptureProvider::returning(valid_frame(4, 4));
        let ocr_2 = FakeOcrProvider::returning(["must not run"]);
        let busy = observe_screen_once_with_providers(
            &operation_gate,
            &repository_2,
            &session_gate_2,
            &broker_2,
            "life-a",
            &capture_2,
            &ocr_2,
        )
        .unwrap_err();
        assert_eq!(busy.code, ScreenObservationErrorCode::ObservationBusy);
        assert_eq!(capture_2.calls(), 0);
        assert_eq!(ocr_2.calls(), 0);

        release_sender.send(()).unwrap();
        let error = worker.join().unwrap().unwrap_err();
        assert_eq!(error.code, ScreenObservationErrorCode::OcrTimeout);
        assert_eq!(operation.cancel_calls.load(Ordering::SeqCst), 1);
        assert_eq!(operation.close_calls.load(Ordering::SeqCst), 1);
        assert!(operation_gate.try_enter().is_ok());
    }

    #[test]
    fn screen_observation_timestamp_uses_bounded_utc_shape() {
        let timestamp = utc_now_timestamp();
        assert_eq!(timestamp.len(), 24);
        assert_eq!(&timestamp[4..5], "-");
        assert_eq!(&timestamp[10..11], "T");
        assert!(timestamp.ends_with('Z'));
    }
}
