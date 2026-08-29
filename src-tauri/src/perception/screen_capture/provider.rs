//! Narrow internal backend seam for the D23-C1 one-shot capture provider.
//!
//! Production uses the Windows Graphics Capture provider; tests use a fake
//! provider so correctness never depends on Windows integration tests alone.
//! The trait is deliberately minimal: `is_supported` and one synchronous
//! `capture_frame`.  There is no polling, no background loop, no frame pool
//! retention, and no way to persist a frame through this boundary.

use super::target::ScreenCaptureTarget;
use super::{ScreenCaptureError, ScreenFrame};

pub(crate) trait ScreenCaptureProvider: Send + Sync {
    fn is_supported(&self) -> bool;

    /// Performs exactly one capture of the given target and returns the
    /// bounded frame.  Implementations must not retain the frame after
    /// returning.
    fn capture_frame(
        &self,
        target: &ScreenCaptureTarget,
    ) -> Result<ScreenFrame, ScreenCaptureError>;
}

/// Returns the canonical production provider (Windows WGC on Windows; an
/// explicit unsupported provider elsewhere).
pub(crate) fn native_provider() -> Box<dyn ScreenCaptureProvider> {
    #[cfg(windows)]
    {
        Box::new(super::windows_provider::WindowsGraphicsCaptureProvider::new())
    }
    #[cfg(not(windows))]
    {
        Box::new(UnsupportedProvider)
    }
}

/// Non-Windows production provider: capture is explicitly unsupported.
#[cfg(not(windows))]
pub(crate) struct UnsupportedProvider;

#[cfg(not(windows))]
impl ScreenCaptureProvider for UnsupportedProvider {
    fn is_supported(&self) -> bool {
        false
    }

    fn capture_frame(
        &self,
        _target: &ScreenCaptureTarget,
    ) -> Result<ScreenFrame, ScreenCaptureError> {
        Err(ScreenCaptureError::not_supported())
    }
}
