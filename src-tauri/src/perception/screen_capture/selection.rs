//! Trusted Windows-native target enumeration and selection for D23-C1.
//!
//! Target selection originates entirely in the backend: monitors are
//! enumerated with `EnumDisplayMonitors` and windows with `EnumWindows`, and
//! the opaque `GraphicsCaptureItem` is created with the canonical
//! `IGraphicsCaptureItemInterop::CreateForWindow` / `CreateForMonitor` path.
//! The frontend only ever sees de-identified descriptors (index + bounded
//! label) and only ever sends back a selection index — never an HWND, PID,
//! title, process path, or monitor device path.

use windows::{
    core::HSTRING,
    Graphics::Capture::GraphicsCaptureItem,
    Win32::{
        Foundation::{HWND, LPARAM, RECT},
        Graphics::Gdi::{EnumDisplayMonitors, GetMonitorInfoW, HMONITOR, MONITORINFO},
        System::WinRT::{Graphics::Capture::IGraphicsCaptureItemInterop, RoGetActivationFactory},
        UI::WindowsAndMessaging::{EnumWindows, GetWindowTextW, IsWindowVisible},
    },
};

use super::target::{NativeCaptureItem, ScreenCaptureTargetBroker, ScreenCaptureTargetDescriptor};
use super::ScreenCaptureError;
use crate::perception::screen_policy::ScreenPerceptionSessionGate;

/// A single enumerated candidate.  The raw handle is kept only inside the
/// backend during one enumeration; only the de-identified descriptor escapes.
#[cfg(windows)]
struct Candidate {
    handle: CandidateHandle,
    descriptor: ScreenCaptureTargetDescriptor,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateHandle {
    Window(HWND),
    Monitor(HMONITOR),
}

#[cfg(windows)]
pub(crate) fn list_target_descriptors(
) -> Result<Vec<ScreenCaptureTargetDescriptor>, ScreenCaptureError> {
    let mut candidates = Vec::new();
    enumerate_monitors(&mut candidates)?;
    enumerate_windows(&mut candidates)?;
    Ok(candidates.into_iter().map(|c| c.descriptor).collect())
}

#[cfg(windows)]
fn enumerate_monitors(candidates: &mut Vec<Candidate>) -> Result<(), ScreenCaptureError> {
    unsafe extern "system" fn monitor_proc(
        hmonitor: HMONITOR,
        _hdc: windows::Win32::Graphics::Gdi::HDC,
        _rect: *mut RECT,
        data: LPARAM,
    ) -> windows::core::BOOL {
        let candidates = &mut *(data.0 as *mut Vec<Candidate>);
        let mut info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        let primary = unsafe { GetMonitorInfoW(hmonitor, &mut info) }.as_bool();
        let index = candidates.len() as u64;
        candidates.push(Candidate {
            handle: CandidateHandle::Monitor(hmonitor),
            descriptor: ScreenCaptureTargetDescriptor {
                index,
                kind: "monitor".to_string(),
                label: format!(
                    "Monitor {} ({})",
                    index + 1,
                    if primary { "primary" } else { "secondary" }
                ),
            },
        });
        windows::Win32::Foundation::TRUE
    }

    let _ = unsafe {
        EnumDisplayMonitors(
            None,
            None,
            Some(monitor_proc),
            LPARAM(candidates as *mut Vec<Candidate> as isize),
        )
    };
    Ok(())
}

#[cfg(windows)]
fn enumerate_windows(candidates: &mut Vec<Candidate>) -> Result<(), ScreenCaptureError> {
    unsafe extern "system" fn window_proc(hwnd: HWND, data: LPARAM) -> windows::core::BOOL {
        let candidates = &mut *(data.0 as *mut Vec<Candidate>);
        if unsafe { IsWindowVisible(hwnd) }.as_bool() {
            // A bounded window-title snapshot, used only to form a de-identified
            // display label; the title is never persisted or sent as authority.
            let mut buffer = [0u16; 256];
            let len = unsafe { GetWindowTextW(hwnd, &mut buffer) };
            let title = if len > 0 {
                String::from_utf16_lossy(&buffer[..len as usize])
            } else {
                String::new()
            };
            let label = if title.trim().is_empty() {
                format!("Window {}", candidates.len() + 1)
            } else {
                truncate_label(&title)
            };
            let index = candidates.len() as u64;
            candidates.push(Candidate {
                handle: CandidateHandle::Window(hwnd),
                descriptor: ScreenCaptureTargetDescriptor {
                    index,
                    kind: "window".to_string(),
                    label,
                },
            });
        }
        windows::Win32::Foundation::TRUE
    }

    let _ = unsafe {
        EnumWindows(
            Some(window_proc),
            LPARAM(candidates as *mut Vec<Candidate> as isize),
        )
    };
    Ok(())
}

#[cfg(windows)]
fn truncate_label(title: &str) -> String {
    const MAX_LABEL_CHARS: usize = 60;
    let mut chars = title.chars();
    let mut result: String = chars.by_ref().take(MAX_LABEL_CHARS).collect();
    if chars.next().is_some() {
        result.push('…');
    }
    result
}

/// Selects the candidate with the given index: re-enumerates, finds the
/// matching handle, creates the opaque `GraphicsCaptureItem` through the
/// canonical interop path, and installs it in the broker under the current
/// session fence.  The target is bound to the gate's life, so a rearmed
/// session invalidates it.
#[cfg(windows)]
pub(crate) fn select_target_service(
    gate: &ScreenPerceptionSessionGate,
    broker: &ScreenCaptureTargetBroker,
    life_id: &str,
    selection_index: u64,
) -> Result<ScreenCaptureTargetDescriptor, ScreenCaptureError> {
    let fence = gate
        .life_fence_for(life_id)
        .ok_or_else(ScreenCaptureError::session_denied)?;

    let mut candidates = Vec::new();
    enumerate_monitors(&mut candidates)?;
    enumerate_windows(&mut candidates)?;

    let candidate = candidates
        .iter()
        .find(|c| c.descriptor.index == selection_index)
        .ok_or_else(|| {
            ScreenCaptureError::invalid_argument("target selection index is invalid.")
        })?;

    let item = create_capture_item(candidate.handle)?;

    let descriptor = candidate.descriptor.clone();
    broker.select(fence, descriptor.clone(), item);
    Ok(descriptor)
}

#[cfg(windows)]
fn create_capture_item(handle: CandidateHandle) -> Result<NativeCaptureItem, ScreenCaptureError> {
    super::ensure_com_initialized()?;

    // The interop interface is exposed by the GraphicsCaptureItem class
    // factory.  Obtain it through the canonical activation-factory path and
    // create the opaque item from the backend-derived window/monitor handle.
    let interop: IGraphicsCaptureItemInterop = unsafe {
        RoGetActivationFactory(&HSTRING::from(
            "Windows.Graphics.Capture.GraphicsCaptureItem",
        ))
        .map_err(|_| ScreenCaptureError::target_unavailable())?
    };

    let item: GraphicsCaptureItem = match handle {
        CandidateHandle::Window(hwnd) => unsafe {
            interop
                .CreateForWindow(hwnd)
                .map_err(|_| ScreenCaptureError::target_unavailable())?
        },
        CandidateHandle::Monitor(hmonitor) => unsafe {
            interop
                .CreateForMonitor(hmonitor)
                .map_err(|_| ScreenCaptureError::target_unavailable())?
        },
    };
    Ok(item)
}

#[cfg(windows)]
#[cfg(test)]
pub(crate) fn diagnostic_create_for_index(index: u64) -> Result<(), String> {
    let mut candidates = Vec::new();
    enumerate_monitors(&mut candidates).map_err(|e| e.message)?;
    enumerate_windows(&mut candidates).map_err(|e| e.message)?;
    let candidate = candidates
        .into_iter()
        .find(|c| c.descriptor.index == index)
        .ok_or_else(|| format!("no candidate with index {index}"))?;
    let _ = create_capture_item_for_test(candidate.handle)?;
    Ok(())
}

#[cfg(windows)]
#[cfg(test)]
fn create_capture_item_for_test(handle: CandidateHandle) -> Result<NativeCaptureItem, String> {
    use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;
    super::ensure_com_initialized().map_err(|e| e.message)?;
    let interop: IGraphicsCaptureItemInterop = unsafe {
        RoGetActivationFactory(&HSTRING::from(
            "Windows.Graphics.Capture.GraphicsCaptureItem",
        ))
        .map_err(|e| format!("activation factory: {e:?}"))?
    };
    match handle {
        CandidateHandle::Window(hwnd) => unsafe {
            interop
                .CreateForWindow(hwnd)
                .map_err(|e| format!("create-for-window: {e:?}"))
        },
        CandidateHandle::Monitor(hmonitor) => unsafe {
            interop
                .CreateForMonitor(hmonitor)
                .map_err(|e| format!("create-for-monitor: {e:?}"))
        },
    }
}
