//! Native Windows Graphics Capture Picker selection for D23-C1-R1.
//!
//! Target selection uses the official
//! `Windows.Graphics.Capture.GraphicsCapturePicker` system UI: the user
//! explicitly picks a window or display in Windows UI, and the picker returns
//! the exact opaque `GraphicsCaptureItem` that becomes the process-local
//! capture target.
//!
//! There is deliberately NO window enumeration, NO window-title observation,
//! NO frontend-supplied selection index, and NO HWND/PID/title/process-path/
//! monitor-device-path exposure to the frontend.  The picker is parented to a
//! backend-derived trusted Settings window HWND via `IInitializeWithWindow`;
//! the frontend never supplies an owner handle.
//!
//! The picker runs on a dedicated STA thread with a Windows message pump
//! (`GetMessageW`/`DispatchMessageW`), which the system picker UI requires.
//! The chosen `GraphicsCaptureItem` is returned to the caller; the COM guard
//! is balanced on the STA thread.

use std::sync::mpsc;

use windows::{
    core::Interface,
    Graphics::Capture::{GraphicsCaptureItem, GraphicsCapturePicker},
    Win32::UI::Shell::IInitializeWithWindow,
};

use super::target::NativeCaptureItem;
use super::{ComGuard, ComMode, ScreenCaptureError};

/// Runs the Windows system capture picker and returns the opaque
/// `GraphicsCaptureItem` chosen by the user, or a bounded cancellation result.
///
/// `owner_hwnd` is derived by the backend from the trusted Settings window;
/// it is never supplied by the frontend.
///
/// The picker is modal: it stays open until the user selects or cancels.
/// Forcibly tearing down the STA thread while the picker is open crashes the
/// WinRT runtime, so there is deliberately NO timeout on the picker itself.
/// The bounded `ScreenPerceptionCommandError` surface still applies to
/// picker *failures*; cancellation is the user's explicit "no selection".
#[cfg(windows)]
pub(crate) fn pick_capture_item(
    owner_hwnd: windows::Win32::Foundation::HWND,
) -> Result<PickOutcome, ScreenCaptureError> {
    let (sender, receiver) = mpsc::channel();
    // `HWND` is not `Send`; move the raw pointer as a `usize` into the STA
    // thread and rebuild the handle there.
    let owner_raw = owner_hwnd.0 as usize;

    // The picker is UI: run it on a dedicated STA thread with a message pump.
    let thread = std::thread::Builder::new()
        .name("d23-c1-picker".to_string())
        .spawn(move || {
            let outcome = run_picker_on_sta(windows::Win32::Foundation::HWND(
                owner_raw as *mut core::ffi::c_void,
            ));
            let _ = sender.send(outcome);
        })
        .map_err(|_| ScreenCaptureError::capture_failed())?;

    let outcome = receiver
        .recv()
        .map_err(|_| ScreenCaptureError::capture_failed())?;
    let _ = thread.join();
    outcome
}

/// Runs the picker on the current (STA) thread with a message pump.
#[cfg(windows)]
fn run_picker_on_sta(
    owner_hwnd: windows::Win32::Foundation::HWND,
) -> Result<PickOutcome, ScreenCaptureError> {
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    };

    let _com = ComGuard::acquire(ComMode::Sta)?;

    let picker = GraphicsCapturePicker::new().map_err(|_| ScreenCaptureError::capture_failed())?;

    // Parent the picker to the backend-derived owner window so the system UI
    // appears attached to our application.
    let initialize: IInitializeWithWindow = picker
        .cast()
        .map_err(|_| ScreenCaptureError::capture_failed())?;
    unsafe {
        initialize
            .Initialize(owner_hwnd)
            .map_err(|_| ScreenCaptureError::capture_failed())?;
    }

    let operation = picker
        .PickSingleItemAsync()
        .map_err(|_| ScreenCaptureError::capture_failed())?;

    // Non-blocking message pump: drain pending STA window messages (the
    // picker UI needs them) and poll the operation status.  This never
    // blocks on an empty queue and never tears the STA thread down while
    // the picker is open (that crashes the WinRT runtime).
    let mut message = std::mem::MaybeUninit::<MSG>::uninit();
    loop {
        let has_message = unsafe { PeekMessageW(message.as_mut_ptr(), None, 0, 0, PM_REMOVE) };
        if has_message.0 != 0 {
            unsafe {
                let _ = TranslateMessage(message.as_ptr());
                let _ = DispatchMessageW(message.as_ptr());
            }
            continue;
        }
        match poll_operation(&operation) {
            PollState::Pending => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            PollState::Done(outcome) => return outcome,
        }
    }
}

#[cfg(windows)]
enum PollState {
    Pending,
    Done(Result<PickOutcome, ScreenCaptureError>),
}

#[cfg(windows)]
fn poll_operation(operation: &windows_future::IAsyncOperation<GraphicsCaptureItem>) -> PollState {
    match picker_operation_state(operation.Status()) {
        PickerOperationState::Pending => PollState::Pending,
        PickerOperationState::Cancelled => PollState::Done(Ok(PickOutcome::Cancelled)),
        PickerOperationState::Failed => PollState::Done(Err(ScreenCaptureError::capture_failed())),
        PickerOperationState::Completed => map_completed_picker_result(operation.GetResults()),
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PickerOperationState {
    Pending,
    Completed,
    Cancelled,
    Failed,
}

#[cfg(windows)]
fn picker_operation_state(
    status: windows::core::Result<windows_future::AsyncStatus>,
) -> PickerOperationState {
    use windows_future::AsyncStatus;
    match status {
        Ok(AsyncStatus::Completed) => PickerOperationState::Completed,
        Ok(AsyncStatus::Canceled) => PickerOperationState::Cancelled,
        Ok(AsyncStatus::Error) | Err(_) => PickerOperationState::Failed,
        Ok(_) => PickerOperationState::Pending,
    }
}

#[cfg(windows)]
fn map_completed_picker_result(result: windows::core::Result<GraphicsCaptureItem>) -> PollState {
    match result {
        Ok(item) => PollState::Done(Ok(PickOutcome::Selected(item))),
        // Completed + GetResults failure is a runtime picker failure, not a
        // user cancellation.  Keep the bounded failure visible to the caller.
        Err(_) => PollState::Done(Err(ScreenCaptureError::capture_failed())),
    }
}

/// The bounded outcome of the native picker.  A cancelled picker does not
/// fabricate a target and must not silently change an existing valid one.
#[derive(Debug)]
pub(crate) enum PickOutcome {
    Selected(NativeCaptureItem),
    Cancelled,
}

/// Derives the trusted owner HWND for the Settings window from a Tauri
/// window handle.  Returns `None` when the handle is not a Win32 HWND (the
/// backend then fails closed rather than showing an unparented picker).
#[cfg(windows)]
pub(crate) fn settings_owner_hwnd(
    window: &tauri::WebviewWindow,
) -> Option<windows::Win32::Foundation::HWND> {
    use raw_window_handle::HasWindowHandle;
    let handle = window.window_handle().ok()?;
    match handle.as_raw() {
        raw_window_handle::RawWindowHandle::Win32(win32) => {
            Some(windows::Win32::Foundation::HWND(win32.hwnd.get() as *mut _))
        }
        _ => None,
    }
}

/// Test-only fake item used to exercise picker-install semantics without a
/// real Windows picker.  Only reachable on non-Windows test builds; Windows
/// tests exercise the fence-recheck denial directly via `fence_is_current`.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_pick_outcome_selected() -> PickOutcome {
    PickOutcome::Selected(test_native_item())
}

#[cfg(test)]
#[cfg(windows)]
#[allow(dead_code)]
fn test_native_item() -> NativeCaptureItem {
    // Windows unit tests never call this: the fence-recheck denial path is
    // tested through `fence_is_current` and the full install path only runs
    // on non-Windows builds where the native item is `()`.
    panic!("test_pick_outcome_selected is not supported on Windows")
}

#[cfg(test)]
#[cfg(not(windows))]
fn test_native_item() -> NativeCaptureItem {
    ()
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;

    #[test]
    fn async_error_is_failure_and_cancelled_is_not() {
        assert_eq!(
            picker_operation_state(Ok(windows_future::AsyncStatus::Error)),
            PickerOperationState::Failed
        );
        assert_eq!(
            picker_operation_state(Ok(windows_future::AsyncStatus::Canceled)),
            PickerOperationState::Cancelled
        );
        assert_eq!(
            picker_operation_state(Err(windows::core::Error::from_win32())),
            PickerOperationState::Failed
        );
    }

    #[test]
    fn completed_get_results_error_is_a_bounded_failure() {
        let state = map_completed_picker_result(Err(windows::core::Error::from_win32()));
        match state {
            PollState::Done(Err(error)) => {
                assert_eq!(
                    error.code,
                    crate::perception::screen_capture::ScreenCaptureErrorCode::CaptureFailed
                );
            }
            _ => panic!("completed picker result failure must not be cancellation"),
        }
    }
}
