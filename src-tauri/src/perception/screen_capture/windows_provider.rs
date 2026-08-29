//! Windows Graphics Capture provider for D23-C1.
//!
//! This is the official Microsoft WGC backend.  It:
//!
//! 1. creates a D3D11 device (hardware, fallback to WARP),
//! 2. wraps it as a WinRT `IDirect3DDevice` via
//!    `CreateDirect3D11DeviceFromDXGIDevice`,
//! 3. uses the opaque `GraphicsCaptureItem` already created by the target
//!    broker,
//! 4. creates a `Direct3D11CaptureFramePool` (depth 1) and a capture session,
//! 5. on one explicit request, retrieves exactly one frame, copies its DXGI
//!    surface into a CPU-readable staging texture, maps it, and copies the
//!    bounded BGRA8 bytes into a [`super::ScreenFrame`],
//! 6. closes the session/frame-pool/frame and drops everything before
//!    returning.
//!
//! There is no polling, no background capture, no frame retention, no OCR,
//! and no pixel persistence.  All OS handles stay inside this module and are
//! never serialized.

use std::mem::MaybeUninit;

use windows::{
    core::Interface,
    Graphics::{
        Capture::{Direct3D11CaptureFrame, Direct3D11CaptureFramePool, GraphicsCaptureSession},
        DirectX::{
            Direct3D11::{IDirect3DDevice, IDirect3DSurface},
            DirectXPixelFormat,
        },
    },
    Win32::{
        Foundation::HMODULE,
        Graphics::{
            Direct3D::{
                D3D_DRIVER_TYPE, D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP,
                D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_11_0,
                D3D_FEATURE_LEVEL_11_1,
            },
            Direct3D11::{
                D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Resource,
                ID3D11Texture2D, D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_FLAG,
                D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_TEXTURE2D_DESC,
                D3D11_USAGE_STAGING,
            },
            Dxgi::{
                Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC},
                IDXGIDevice, IDXGISurface,
            },
        },
        System::WinRT::Direct3D11::{
            CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess,
        },
    },
};

use super::provider::ScreenCaptureProvider;
use super::target::ScreenCaptureTarget;
use super::{ScreenCaptureError, ScreenFrame, ScreenPixelFormat};

/// The D3D11 device is created lazily on first capture and retained for the
/// life of the provider.  Interior mutability keeps the provider usable
/// behind `&self` (the trait is `Send + Sync`).  The WinRT
/// `IDirect3DDevice` wrapper is created fresh per capture because it is not
/// `Send`; only the raw `ID3D11Device` (which is `Send + Sync`) is retained.
pub(crate) struct WindowsGraphicsCaptureProvider {
    device: std::sync::Mutex<Option<ID3D11Device>>,
}

impl WindowsGraphicsCaptureProvider {
    pub(crate) fn new() -> Self {
        Self {
            device: std::sync::Mutex::new(None),
        }
    }

    fn ensure_device(&self) -> Result<ID3D11Device, ScreenCaptureError> {
        let mut guard = self.device.lock().unwrap();
        if let Some(device) = &*guard {
            return Ok(device.clone());
        }
        let device = create_d3d11_device()?;
        *guard = Some(device.clone());
        Ok(device)
    }
}

impl ScreenCaptureProvider for WindowsGraphicsCaptureProvider {
    fn is_supported(&self) -> bool {
        GraphicsCaptureSession::IsSupported().unwrap_or(false)
    }

    fn capture_frame(
        &self,
        target: &ScreenCaptureTarget,
    ) -> Result<ScreenFrame, ScreenCaptureError> {
        super::ensure_com_initialized()?;
        let device = self.ensure_device()?;
        let winrt_device = wrap_device_as_winrt(&device)?;
        let item = target
            .native
            .clone()
            .ok_or_else(ScreenCaptureError::target_unavailable)?;

        // The frame pool must be created with the item's actual size; a
        // zero-size pool is rejected by WGC.
        let item_size = item
            .Size()
            .map_err(|_| ScreenCaptureError::capture_failed())?;

        // Frame pool with exactly one buffer: the one-shot semantics.
        let frame_pool = Direct3D11CaptureFramePool::Create(
            &winrt_device,
            DirectXPixelFormat::B8G8R8A8UIntNormalized,
            1,
            item_size,
        )
        .map_err(|_| ScreenCaptureError::capture_failed())?;

        let session = frame_pool
            .CreateCaptureSession(&item)
            .map_err(|_| ScreenCaptureError::capture_failed())?;
        session
            .StartCapture()
            .map_err(|_| ScreenCaptureError::capture_failed())?;

        // WGC frames arrive asynchronously; one-shot waits for the first
        // frame with a bounded timeout, then retires the session and pool
        // regardless of the outcome.
        let frame = wait_for_frame(&frame_pool)?;

        let result = copy_frame_to_cpu(&device, &frame);

        // Retire everything before returning.
        let _ = frame.Close();
        session.Close().ok();
        frame_pool.Close().ok();

        let (width, height, bytes) = result?;
        let screen_frame = ScreenFrame {
            width,
            height,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes,
        };
        screen_frame.validate()?;
        Ok(screen_frame)
    }
}

/// Waits (bounded) for the single next frame from the pool.  This is a
/// one-shot wait, never a capture loop.
fn wait_for_frame(
    frame_pool: &Direct3D11CaptureFramePool,
) -> Result<Direct3D11CaptureFrame, ScreenCaptureError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Ok(frame) = frame_pool.TryGetNextFrame() {
            return Ok(frame);
        }
        if std::time::Instant::now() >= deadline {
            return Err(ScreenCaptureError::capture_failed());
        }
        std::thread::sleep(std::time::Duration::from_millis(8));
    }
}

/// Wraps a raw D3D11 device as the WinRT `IDirect3DDevice` required by the
/// capture frame pool.
fn wrap_device_as_winrt(device: &ID3D11Device) -> Result<IDirect3DDevice, ScreenCaptureError> {
    let dxgi_device: IDXGIDevice = device
        .cast()
        .map_err(|_| ScreenCaptureError::not_supported())?;
    let inspectable = unsafe {
        CreateDirect3D11DeviceFromDXGIDevice(&dxgi_device)
            .map_err(|_| ScreenCaptureError::not_supported())?
    };
    inspectable
        .cast()
        .map_err(|_| ScreenCaptureError::not_supported())
}

/// Copies the capture frame's DXGI surface into a CPU-readable staging
/// texture and returns `(width, height, bgra8_bytes)`.
fn copy_frame_to_cpu(
    device: &ID3D11Device,
    frame: &Direct3D11CaptureFrame,
) -> Result<(u32, u32, Vec<u8>), ScreenCaptureError> {
    let content_size = frame
        .ContentSize()
        .map_err(|_| ScreenCaptureError::capture_failed())?;
    let width = content_size.Width as u32;
    let height = content_size.Height as u32;
    if width == 0 || height == 0 {
        return Err(ScreenCaptureError::frame_invalid());
    }

    // The frame's Surface is a WinRT IDirect3DSurface.  Cast it to the
    // interop access interface, then to the underlying DXGI surface.
    let surface: IDirect3DSurface = frame
        .Surface()
        .map_err(|_| ScreenCaptureError::capture_failed())?;
    let dxgi_interface_access: IDirect3DDxgiInterfaceAccess = surface
        .cast()
        .map_err(|_| ScreenCaptureError::capture_failed())?;
    let dxgi_surface: IDXGISurface = unsafe {
        dxgi_interface_access
            .GetInterface()
            .map_err(|_| ScreenCaptureError::capture_failed())?
    };

    let surface_desc = unsafe {
        dxgi_surface
            .GetDesc()
            .map_err(|_| ScreenCaptureError::capture_failed())?
    };
    let src_format = surface_desc.Format;
    if src_format != DXGI_FORMAT_B8G8R8A8_UNORM {
        // WGC produces B8G8R8A8 by default.  Any other format is rejected
        // rather than silently misinterpreted.
        return Err(ScreenCaptureError::frame_invalid());
    }

    let context = unsafe {
        device
            .GetImmediateContext()
            .map_err(|_| ScreenCaptureError::capture_failed())?
    };

    let staging_desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: src_format,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_STAGING,
        BindFlags: 0,
        CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
        MiscFlags: 0,
    };

    let mut staging: Option<ID3D11Texture2D> = None;
    unsafe {
        device
            .CreateTexture2D(&staging_desc, None, Some(&mut staging))
            .map_err(|_| ScreenCaptureError::capture_failed())?;
    }
    let staging = staging.ok_or_else(ScreenCaptureError::capture_failed)?;

    // Copy the DXGI surface (as an ID3D11Resource) into the staging texture.
    let src_resource: ID3D11Resource = dxgi_surface
        .cast()
        .map_err(|_| ScreenCaptureError::capture_failed())?;
    unsafe {
        context.CopyResource(&staging, &src_resource);
        context.Flush();
    }

    let mut mapped = MaybeUninit::<D3D11_MAPPED_SUBRESOURCE>::uninit();
    unsafe {
        context
            .Map(&staging, 0, D3D11_MAP_READ, 0, Some(mapped.as_mut_ptr()))
            .map_err(|_| ScreenCaptureError::capture_failed())?;
    }
    let mapped = unsafe { mapped.assume_init() };

    let row_pitch = mapped.RowPitch as usize;
    let row_bytes = width as usize * 4;
    let byte_count = row_bytes * height as usize;
    let mut bytes = Vec::with_capacity(byte_count);
    let src_ptr = mapped.pData as *const u8;
    unsafe {
        for row in 0..height as usize {
            let src_row = src_ptr.add(row * row_pitch);
            bytes.extend_from_slice(std::slice::from_raw_parts(src_row, row_bytes));
        }
    }
    unsafe {
        context.Unmap(&staging, 0);
    }

    Ok((width, height, bytes))
}

/// Creates the D3D11 device used for capture.  Prefers the hardware adapter;
/// falls back to WARP (software) only when no hardware device is available.
fn create_d3d11_device() -> Result<ID3D11Device, ScreenCaptureError> {
    let feature_levels = [
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0,
    ];

    let create = |driver_type: D3D_DRIVER_TYPE| {
        let mut device: Option<ID3D11Device> = None;
        let mut context: Option<ID3D11DeviceContext> = None;
        unsafe {
            D3D11CreateDevice(
                None,
                driver_type,
                HMODULE(std::ptr::null_mut()),
                D3D11_CREATE_DEVICE_FLAG(0),
                Some(&feature_levels),
                7,
                Some(&mut device),
                None,
                Some(&mut context),
            )
        }
        .map(|_| device)
    };

    let device = create(D3D_DRIVER_TYPE_HARDWARE)
        .ok()
        .flatten()
        .or_else(|| create(D3D_DRIVER_TYPE_WARP).ok().flatten())
        .ok_or_else(ScreenCaptureError::not_supported)?;
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::super::provider::ScreenCaptureProvider;
    use super::super::target::ScreenCaptureTargetBroker;
    use super::*;
    use crate::perception::screen_policy::ScreenPerceptionSessionGate;

    #[test]
    fn real_windows_wgc_captures_primary_monitor_one_shot() {
        // Real Windows smoke: enumerate monitors, select the primary monitor,
        // and capture exactly one bounded frame through the real WGC provider.
        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("smoke-life");
        let broker = ScreenCaptureTargetBroker::new();
        let _fence = gate.life_fence_for("smoke-life").unwrap();

        let descriptors = super::super::selection::list_target_descriptors().unwrap();
        assert!(
            !descriptors.is_empty(),
            "no capture targets enumerated; cannot smoke-test capture"
        );
        let primary = descriptors
            .iter()
            .find(|d| d.kind == "monitor" && d.label.contains("primary"));
        let Some(primary) = primary else {
            panic!("no primary monitor found; cannot smoke-test capture");
        };

        // Diagnostic path: surface the real interop error if item creation fails.
        super::super::selection::diagnostic_create_for_index(primary.index)
            .expect("the real GraphicsCaptureItem interop must create the primary-monitor item");

        let descriptor = super::super::selection::select_target_service(
            &gate,
            &broker,
            "smoke-life",
            primary.index,
        )
        .unwrap();
        assert_eq!(descriptor.index, primary.index);

        let provider = WindowsGraphicsCaptureProvider::new();
        assert!(provider.is_supported());
        let target = broker.current_target_for_life(&gate, "smoke-life").unwrap();
        let frame = provider.capture_frame(&target).unwrap();
        assert!(frame.width > 0);
        assert!(frame.height > 0);
        assert_eq!(frame.pixel_format, ScreenPixelFormat::Bgra8);
        assert_eq!(
            frame.bytes.len() as u64,
            frame.width as u64 * frame.height as u64 * 4
        );
        drop(frame);
    }
}
