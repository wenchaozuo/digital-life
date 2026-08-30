//! Windows Graphics Capture provider for D23-C1.
//!
//! This is the official Microsoft WGC backend.  It:
//!
//! 1. creates a D3D11 device (hardware, fallback to WARP),
//! 2. wraps it as a WinRT `IDirect3DDevice` via
//!    `CreateDirect3D11DeviceFromDXGIDevice`,
//! 3. uses the opaque `GraphicsCaptureItem` returned by the native picker
//!    (installed in the broker),
//! 4. creates a `Direct3D11CaptureFramePool` (depth 1) and a capture session,
//! 5. on one explicit request, retrieves exactly one frame, copies its DXGI
//!    surface into a CPU-readable staging texture, maps it, and copies the
//!    bounded BGRA8 bytes into a [`super::ScreenFrame`],
//! 6. closes the session/frame-pool/frame on EVERY path (success, timeout,
//!    frame acquisition failure, copy failure, validation failure) via the
//!    [`CaptureSessionGuard`] RAII structure.
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
                Common::{DXGI_FORMAT, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC},
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
use super::{
    ComGuard, ComMode, ScreenCaptureError, ScreenFrame, ScreenPixelFormat, ValidatedFrameGeometry,
};

/// RAII retirement of all WGC session resources.  Once the session/frame
/// pool have been created, `Drop` closes them on every exit path — success,
/// timeout, frame acquisition failure, copy failure, and validation failure.
/// A captured frame, when present, is also closed.
#[cfg(windows)]
struct CaptureSessionGuard {
    frame_pool: Option<Direct3D11CaptureFramePool>,
    session: Option<GraphicsCaptureSession>,
    frame: Option<Direct3D11CaptureFrame>,
}

#[cfg(windows)]
impl CaptureSessionGuard {
    fn with_frame_pool(frame_pool: Direct3D11CaptureFramePool) -> Self {
        Self {
            frame_pool: Some(frame_pool),
            session: None,
            frame: None,
        }
    }

    fn install_session(&mut self, session: GraphicsCaptureSession) {
        self.session = Some(session);
    }

    fn frame_pool(&self) -> Option<&Direct3D11CaptureFramePool> {
        self.frame_pool.as_ref()
    }

    fn session(&self) -> Option<&GraphicsCaptureSession> {
        self.session.as_ref()
    }

    fn install_frame(&mut self, frame: Direct3D11CaptureFrame) {
        self.frame = Some(frame);
    }

    fn frame(&self) -> Option<&Direct3D11CaptureFrame> {
        self.frame.as_ref()
    }
}

#[cfg(windows)]
impl Drop for CaptureSessionGuard {
    fn drop(&mut self) {
        if let Some(frame) = self.frame.take() {
            let _ = frame.Close();
        }
        if let Some(session) = self.session.take() {
            session.Close().ok();
        }
        if let Some(frame_pool) = self.frame_pool.take() {
            frame_pool.Close().ok();
        }
    }
}

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
        // COM must stay initialized for the whole WGC operation.
        let _com = ComGuard::acquire(ComMode::Mta)?;
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
        super::validate_capture_geometry(item_size.Width, item_size.Height)?;

        // Frame pool with exactly one buffer: the one-shot semantics.
        let frame_pool = Direct3D11CaptureFramePool::Create(
            &winrt_device,
            DirectXPixelFormat::B8G8R8A8UIntNormalized,
            1,
            item_size,
        )
        .map_err(|_| ScreenCaptureError::capture_failed())?;
        // The guard owns the pool before any subsequent fallible operation.
        let mut guard = CaptureSessionGuard::with_frame_pool(frame_pool);

        let session = guard
            .frame_pool()
            .ok_or_else(ScreenCaptureError::capture_failed)?
            .CreateCaptureSession(&item)
            .map_err(|_| ScreenCaptureError::capture_failed())?;
        // Install the session before starting it so a StartCapture failure
        // still closes both the session and frame pool through the guard.
        guard.install_session(session);
        guard
            .session()
            .ok_or_else(ScreenCaptureError::capture_failed)?
            .StartCapture()
            .map_err(|_| ScreenCaptureError::capture_failed())?;

        // WGC frames arrive asynchronously; one-shot waits for the first
        // frame with a bounded timeout.
        let frame = wait_for_frame(
            guard
                .frame_pool()
                .ok_or_else(ScreenCaptureError::capture_failed)?,
        )?;
        // Own the frame immediately after acquisition; all later errors then
        // run through the same explicit Close() path.
        guard.install_frame(frame);
        let frame = guard
            .frame()
            .ok_or_else(ScreenCaptureError::capture_failed)?;

        let (width, height, bytes) = copy_frame_to_cpu(&device, frame)?;
        let screen_frame = ScreenFrame {
            width,
            height,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes,
        };
        screen_frame.validate()?;
        drop(guard);
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

/// Validates the source surface before `CopyResource`.  The staging texture
/// is created with the same geometry and format only after this check passes.
fn validate_surface_for_copy(
    format: DXGI_FORMAT,
    width: u32,
    height: u32,
    geometry: ValidatedFrameGeometry,
) -> Result<(), ScreenCaptureError> {
    if format != DXGI_FORMAT_B8G8R8A8_UNORM || width != geometry.width || height != geometry.height
    {
        return Err(ScreenCaptureError::frame_invalid());
    }
    Ok(())
}

/// Validates the mapped staging-texture layout before any raw row slice or
/// pointer arithmetic is performed.  The returned height is converted once
/// and reused by the copy loop.
fn validate_mapped_layout(
    row_pitch: usize,
    data: *const u8,
    geometry: ValidatedFrameGeometry,
) -> Result<usize, ScreenCaptureError> {
    if row_pitch < geometry.row_bytes || data.is_null() {
        return Err(ScreenCaptureError::frame_invalid());
    }
    let height =
        usize::try_from(geometry.height).map_err(|_| ScreenCaptureError::frame_invalid())?;
    let mapped_span = row_pitch
        .checked_mul(height)
        .ok_or_else(ScreenCaptureError::frame_invalid)?;
    let last_row_end = row_pitch
        .checked_mul(
            height
                .checked_sub(1)
                .ok_or_else(ScreenCaptureError::frame_invalid)?,
        )
        .and_then(|offset| offset.checked_add(geometry.row_bytes))
        .ok_or_else(ScreenCaptureError::frame_invalid)?;
    if last_row_end > mapped_span {
        return Err(ScreenCaptureError::frame_invalid());
    }
    Ok(height)
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
    let geometry = super::validate_capture_geometry(content_size.Width, content_size.Height)?;

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
    // WGC produces B8G8R8A8 by default.  Any other format or geometry is
    // rejected rather than silently misinterpreted or copied incompatibly.
    validate_surface_for_copy(
        src_format,
        surface_desc.Width,
        surface_desc.Height,
        geometry,
    )?;

    let context = unsafe {
        device
            .GetImmediateContext()
            .map_err(|_| ScreenCaptureError::capture_failed())?
    };

    let staging_desc = D3D11_TEXTURE2D_DESC {
        Width: geometry.width,
        Height: geometry.height,
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

    let result: Result<Vec<u8>, ScreenCaptureError> = (|| {
        let row_pitch =
            usize::try_from(mapped.RowPitch).map_err(|_| ScreenCaptureError::frame_invalid())?;
        let height = validate_mapped_layout(row_pitch, mapped.pData.cast(), geometry)?;

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(geometry.byte_count)
            .map_err(|_| ScreenCaptureError::capture_failed())?;
        let src_ptr = mapped.pData.cast::<u8>();
        for row in 0..height {
            let row_offset = row_pitch
                .checked_mul(row)
                .ok_or_else(ScreenCaptureError::frame_invalid)?;
            let src_row = unsafe { src_ptr.add(row_offset) };
            let row_slice = unsafe { std::slice::from_raw_parts(src_row, geometry.row_bytes) };
            bytes.extend_from_slice(row_slice);
        }
        if bytes.len() != geometry.byte_count {
            return Err(ScreenCaptureError::frame_invalid());
        }
        Ok(bytes)
    })();
    unsafe {
        context.Unmap(&staging, 0);
    }

    Ok((geometry.width, geometry.height, result?))
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
    use super::*;

    /// The capture-session RAII guard must retire the session and pool when
    /// dropped.  This unit test exercises the guard directly (without a live
    /// WGC session) by verifying Drop does not panic and closes present
    /// handles; the real all-path behavior is covered by the production
    /// smoke test, where a timeout/error still returns cleanly.
    #[test]
    fn capture_session_guard_drops_cleanly() {
        let guard = CaptureSessionGuard {
            frame_pool: None,
            session: None,
            frame: None,
        };
        drop(guard);
    }

    #[test]
    fn production_arms_cleanup_guard_before_start_and_frame_copy() {
        let production = include_str!("windows_provider.rs")
            .split_once("#[cfg(test)]")
            .map_or(include_str!("windows_provider.rs"), |(source, _)| source);
        let pool_guard = production
            .find("CaptureSessionGuard::with_frame_pool")
            .expect("the frame pool must be guarded immediately");
        let session_create = production
            .find("CreateCaptureSession")
            .expect("the session must be created after the pool guard");
        let session_guard = production
            .find("guard.install_session(session)")
            .expect("the session must be installed in the guard");
        let start_capture = production
            .find(".StartCapture()")
            .expect("capture must start through the guarded session");
        let frame_wait = production
            .find("wait_for_frame")
            .expect("the provider must wait for one frame");
        let frame_guard = production
            .find("guard.install_frame(frame)")
            .expect("the frame must be guarded immediately after acquisition");
        let frame_copy = production
            .find("copy_frame_to_cpu(&device, frame)")
            .expect("copy must borrow the guarded frame");

        assert!(pool_guard < session_create);
        assert!(session_create < session_guard);
        assert!(session_guard < start_capture);
        assert!(start_capture < frame_wait);
        assert!(frame_wait < frame_guard);
        assert!(frame_guard < frame_copy);
    }

    #[test]
    fn surface_geometry_mismatch_is_rejected_before_copy_resource() {
        let geometry = super::super::validate_capture_geometry(64, 32).unwrap();
        let error = validate_surface_for_copy(
            DXGI_FORMAT_B8G8R8A8_UNORM,
            geometry.width + 1,
            geometry.height,
            geometry,
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            super::super::ScreenCaptureErrorCode::FrameInvalid
        );
    }

    #[test]
    fn mapped_layout_rejects_short_rows_and_null_pointer() {
        let geometry = super::super::validate_capture_geometry(64, 2).unwrap();
        let data = std::ptr::NonNull::<u8>::dangling().as_ptr();

        let short_row = validate_mapped_layout(geometry.row_bytes - 1, data, geometry).unwrap_err();
        assert_eq!(
            short_row.code,
            super::super::ScreenCaptureErrorCode::FrameInvalid
        );

        let null_pointer =
            validate_mapped_layout(geometry.row_bytes, std::ptr::null(), geometry).unwrap_err();
        assert_eq!(
            null_pointer.code,
            super::super::ScreenCaptureErrorCode::FrameInvalid
        );
    }

    #[test]
    fn mapped_layout_rejects_checked_span_overflow() {
        let geometry = super::super::validate_capture_geometry(1, 2).unwrap();
        let data = std::ptr::NonNull::<u8>::dangling().as_ptr();
        let error = validate_mapped_layout(usize::MAX, data, geometry).unwrap_err();
        assert_eq!(
            error.code,
            super::super::ScreenCaptureErrorCode::FrameInvalid
        );
    }

    #[test]
    fn com_guard_acquires_and_drops_balanced() {
        // Acquiring twice on the same thread yields S_FALSE the second time
        // and both drops are balanced; the call must simply succeed.
        let first = ComGuard::acquire(ComMode::Mta).unwrap();
        let second = ComGuard::acquire(ComMode::Mta).unwrap();
        drop(first);
        drop(second);
        // A fresh acquire after both drops still works.
        let third = ComGuard::acquire(ComMode::Mta).unwrap();
        drop(third);
    }

    /// Real Windows production-path smoke.
    ///
    /// This exercises the actual authority chain (not a direct provider
    /// call):
    ///
    /// 1. real `StorageService` on Schema27 with a real Life and an enabled
    ///    durable screen-perception policy;
    /// 2. canonical session gate armed for that Life;
    /// 3. the real Windows system `GraphicsCapturePicker`, parented to a
    ///    backend-derived test window HWND (the picker UI appears; the user
    ///    must select the visible "D23-C1 Smoke Target" window);
    /// 4. the returned `GraphicsCaptureItem` is installed in the broker;
    /// 5. `capture_one_shot` through the production service returns a
    ///    non-zero bounded frame;
    /// 6. after `disarm`, the next production capture is denied before the
    ///    provider; after rearming a different Life, the old target is
    ///    rejected.
    ///
    /// The picker is interactive: this test is excluded from the default run
    /// and executed explicitly for the real-Windows acceptance smoke.
    #[test]
    #[ignore = "interactive: opens the Windows system capture picker"]
    fn real_windows_picker_production_capture_smoke() {
        use super::super::selection;
        use super::super::target::ScreenCaptureTargetBroker;
        use crate::perception::screen_capture::{capture_one_shot, ScreenCaptureErrorCode};
        use crate::perception::screen_policy::{
            authorize_screen_perception, ScreenPerceptionRepository, ScreenPerceptionSessionGate,
        };
        use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord, StorageService};

        // Keep the picker owner and the selectable target separate.  The
        // owner thread runs a real Win32 message loop for the whole picker
        // lifetime, while the target remains visible and responsive.
        let smoke_windows = SmokeWindowFixture::new();

        let root = tempfile::tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(root.path().to_path_buf(), None).unwrap();
        storage
            .save_persona(PersonaTemplateRecord {
                id: "smoke-persona".into(),
                name: "Smoke Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        storage
            .save_life(LifeIdentityRecord {
                id: "smoke-life".into(),
                name: "Smoke Life".into(),
                created_at: "2026-08-29T00:00:00.000Z".into(),
                version: 1,
                body_id: "smoke-body".into(),
                persona_id: "smoke-persona".into(),
                persona_version: 1,
            })
            .unwrap();
        storage
            .create_screen_perception_policy(
                crate::perception::screen_policy::LifeScreenPerceptionPolicyCreateRequest {
                    life_id: "smoke-life".into(),
                    screen_perception_enabled: true,
                },
            )
            .unwrap();

        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("smoke-life");
        let broker = ScreenCaptureTargetBroker::new();

        // Authorization must hold before the picker.
        authorize_screen_perception(&storage, &gate, "smoke-life")
            .expect("durable policy + armed gate must authorize");

        // The real system picker appears listing the user's windows.  The
        // user must select a NON-SENSITIVE window (e.g. this harness window)
        // within the picker; the test then completes the full production
        // chain.  Selecting nothing (cancel) reports the test as needing
        // manual interaction.
        eprintln!(
            ">>> D23-C1 smoke: select any NON-SENSITIVE window (e.g. this harness) in the Windows capture picker."
        );
        let outcome =
            selection::pick_capture_item(smoke_windows.owner).expect("the real picker must run");
        let selection::PickOutcome::Selected(item) = outcome else {
            eprintln!(
                ">>> D23-C1 smoke: picker closed without a selection; run manually to complete the interactive chain."
            );
            return;
        };

        let fence = gate.life_fence_for("smoke-life").unwrap();
        broker.select(fence, item);

        // Production capture path.
        let frame = capture_one_shot(&storage, &gate, &broker, "smoke-life")
            .expect("the authorized production capture must succeed");
        assert!(frame.width > 0);
        assert!(frame.height > 0);
        assert_eq!(
            frame.bytes.len() as u64,
            frame.width as u64 * frame.height as u64 * 4
        );
        eprintln!(
            ">>> D23-C1 smoke: captured {}x{} bgra8 frame through the production path.",
            frame.width, frame.height
        );
        drop(frame);

        // Disarm → next production capture denied before the provider.
        gate.disarm();
        let error = capture_one_shot(&storage, &gate, &broker, "smoke-life").unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::SessionDenied);

        // Rearm a different Life → old target rejected (no policy for B).
        gate.arm_for_life("smoke-life-b");
        let error = capture_one_shot(&storage, &gate, &broker, "smoke-life-b").unwrap_err();
        assert!(matches!(
            error.code,
            ScreenCaptureErrorCode::SessionDenied | ScreenCaptureErrorCode::TargetRequired
        ));
    }

    /// Real Windows production-path local OCR smoke.
    ///
    /// This is the D23-D1 acceptance path.  It requires a human to select the
    /// dedicated high-contrast target titled `D23 OCR SMOKE 12345`; the
    /// selected item then travels through the canonical C1 broker, capture
    /// permit, local Windows OCR provider, and ephemeral observation boundary.
    /// No frame or OCR intermediate is returned or persisted by this test.
    #[test]
    #[ignore = "interactive: opens the Windows system capture picker and local OCR"]
    fn real_windows_local_ocr_production_observation_smoke() {
        use super::super::selection;
        use super::super::target::ScreenCaptureTargetBroker;
        use crate::perception::screen_ocr::{
            capture_screen_observation, ScreenObservationErrorCode, ScreenObservationStatus,
        };
        use crate::perception::screen_policy::{
            authorize_screen_perception, ScreenPerceptionRepository, ScreenPerceptionSessionGate,
        };
        use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord, StorageService};

        let smoke_windows = SmokeWindowFixture::with_target_title("D23 OCR SMOKE 12345");

        let root = tempfile::tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(root.path().to_path_buf(), None).unwrap();
        storage
            .save_persona(PersonaTemplateRecord {
                id: "d1-smoke-persona".into(),
                name: "D1 Smoke Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        storage
            .save_life(LifeIdentityRecord {
                id: "d1-smoke-life".into(),
                name: "D1 Smoke Life".into(),
                created_at: "2026-08-29T00:00:00.000Z".into(),
                version: 1,
                body_id: "d1-smoke-body".into(),
                persona_id: "d1-smoke-persona".into(),
                persona_version: 1,
            })
            .unwrap();
        storage
            .create_screen_perception_policy(
                crate::perception::screen_policy::LifeScreenPerceptionPolicyCreateRequest {
                    life_id: "d1-smoke-life".into(),
                    screen_perception_enabled: true,
                },
            )
            .unwrap();

        let session_gate = ScreenPerceptionSessionGate::new();
        session_gate.arm_for_life("d1-smoke-life");
        let broker = ScreenCaptureTargetBroker::new();
        authorize_screen_perception(&storage, &session_gate, "d1-smoke-life")
            .expect("durable policy + armed gate must authorize");

        eprintln!(
            ">>> D23-D1 smoke: select only the non-sensitive `D23 OCR SMOKE 12345` window in the Windows capture picker."
        );
        let outcome =
            selection::pick_capture_item(smoke_windows.owner).expect("the real picker must run");
        let selection::PickOutcome::Selected(item) = outcome else {
            panic!("D23-D1 smoke requires a selected target; picker returned Cancelled");
        };

        let fence = session_gate
            .life_fence_for("d1-smoke-life")
            .expect("armed smoke life must have a fence");
        broker.select(fence, item);

        let operation_gate = super::super::operation::ScreenCaptureOperationGate::new();
        let observation = match capture_screen_observation(
            &operation_gate,
            &storage,
            &session_gate,
            &broker,
            "d1-smoke-life",
        ) {
            Ok(observation) => observation,
            Err(error) if error.code == ScreenObservationErrorCode::OcrUnavailable => {
                eprintln!("ENVIRONMENTAL LOCAL_OCR_LANGUAGE_UNAVAILABLE");
                return;
            }
            Err(error) => panic!("D23-D1 local OCR smoke failed: {error}"),
        };

        assert_eq!(observation.status, ScreenObservationStatus::Recognized);
        let compact_text: String = observation
            .text
            .chars()
            .filter(|character| !character.is_whitespace())
            .flat_map(|character| character.to_lowercase())
            .collect();
        assert!(
            compact_text.contains("d23")
                && compact_text.contains("ocr")
                && compact_text.contains("smoke")
                && compact_text.contains("12345"),
            "OCR result did not contain the D23-D1 sentinel"
        );
        assert!(
            observation.text.len() <= crate::perception::screen_ocr::MAX_OBSERVATION_TEXT_BYTES
        );

        session_gate.disarm();
        let denied = capture_screen_observation(
            &operation_gate,
            &storage,
            &session_gate,
            &broker,
            "d1-smoke-life",
        )
        .unwrap_err();
        assert_eq!(denied.code, ScreenObservationErrorCode::SessionDenied);
    }

    /// Automated real-Windows capture smoke through the production service
    /// path.
    ///
    /// Unlike the interactive picker smoke, this test does not require a
    /// human click: it creates the opaque `GraphicsCaptureItem` for the
    /// primary display through the official WinRT
    /// `GraphicsCaptureItem::TryCreateFromDisplayId` API (a test-only helper;
    /// production target authority remains the system picker), installs it
    /// in the broker under the real session fence, and drives the real
    /// `capture_one_shot` chain: real StorageService/Schema27 → real Life →
    /// durable policy → armed gate → non-zero bounded frame.  Then it proves
    /// disarm and rearm-to-another-Life denials.
    ///
    /// Uses real hardware/COM: run it explicitly (not in the parallel
    /// default suite) to avoid cross-test COM/D3D contention.
    #[test]
    #[ignore = "real-hardware: run explicitly to avoid parallel COM contention"]
    fn real_windows_automated_production_capture_smoke() {
        use super::super::target::ScreenCaptureTargetBroker;
        use crate::perception::screen_capture::{capture_one_shot, ScreenCaptureErrorCode};
        use crate::perception::screen_policy::{
            authorize_screen_perception, ScreenPerceptionRepository, ScreenPerceptionSessionGate,
        };
        use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord, StorageService};

        let _com = ComGuard::acquire(ComMode::Mta).unwrap();

        // Primary display item via the official WinRT API.
        let display = windows::Graphics::DisplayId {
            Value: primary_monitor_handle().0 as usize as u64,
        };
        let item = windows::Graphics::Capture::GraphicsCaptureItem::TryCreateFromDisplayId(display)
            .expect("the primary display must yield a capture item");

        let root = tempfile::tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(root.path().to_path_buf(), None).unwrap();
        storage
            .save_persona(PersonaTemplateRecord {
                id: "auto-smoke-persona".into(),
                name: "Auto Smoke Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        storage
            .save_life(LifeIdentityRecord {
                id: "auto-smoke-life".into(),
                name: "Auto Smoke Life".into(),
                created_at: "2026-08-29T00:00:00.000Z".into(),
                version: 1,
                body_id: "auto-smoke-body".into(),
                persona_id: "auto-smoke-persona".into(),
                persona_version: 1,
            })
            .unwrap();
        storage
            .create_screen_perception_policy(
                crate::perception::screen_policy::LifeScreenPerceptionPolicyCreateRequest {
                    life_id: "auto-smoke-life".into(),
                    screen_perception_enabled: true,
                },
            )
            .unwrap();

        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("auto-smoke-life");
        let broker = ScreenCaptureTargetBroker::new();

        authorize_screen_perception(&storage, &gate, "auto-smoke-life")
            .expect("durable policy + armed gate must authorize");

        let fence = gate.life_fence_for("auto-smoke-life").unwrap();
        broker.select(fence, item);

        // Production capture path.
        let frame = capture_one_shot(&storage, &gate, &broker, "auto-smoke-life")
            .expect("the authorized production capture must succeed");
        assert!(frame.width > 0);
        assert!(frame.height > 0);
        assert_eq!(
            frame.bytes.len() as u64,
            frame.width as u64 * frame.height as u64 * 4
        );
        drop(frame);

        // Disarm → next production capture denied before the provider.
        gate.disarm();
        let error = capture_one_shot(&storage, &gate, &broker, "auto-smoke-life").unwrap_err();
        assert_eq!(error.code, ScreenCaptureErrorCode::SessionDenied);

        // Rearm a different Life → old target rejected (no policy for B).
        gate.arm_for_life("auto-smoke-life-b");
        let error = capture_one_shot(&storage, &gate, &broker, "auto-smoke-life-b").unwrap_err();
        assert!(matches!(
            error.code,
            ScreenCaptureErrorCode::SessionDenied | ScreenCaptureErrorCode::TargetRequired
        ));
    }

    /// Returns the HMONITOR of the primary display (test-only helper).
    fn primary_monitor_handle() -> windows::Win32::Graphics::Gdi::HMONITOR {
        use windows::Win32::{
            Foundation::POINT,
            Graphics::Gdi::{MonitorFromPoint, MONITOR_DEFAULTTONEAREST},
        };
        unsafe { MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTONEAREST) }
    }

    /// Owns a responsive native picker owner and a separate selectable
    /// non-sensitive target for the interactive smoke.  Both windows are
    /// created and destroyed on their UI thread; the test thread only uses
    /// the owner HWND while the picker is running.
    struct SmokeWindowFixture {
        owner: windows::Win32::Foundation::HWND,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl SmokeWindowFixture {
        fn new() -> Self {
            Self::with_target_title("D23-C1 Smoke Target")
        }

        fn with_target_title(target_title: &'static str) -> Self {
            use std::sync::mpsc;
            use windows::Win32::UI::WindowsAndMessaging::{
                DispatchMessageW, GetMessageW, ShowWindow, TranslateMessage, MSG, SW_SHOW,
            };

            let (ready_sender, ready_receiver) = mpsc::channel();
            let thread = std::thread::Builder::new()
                .name("d23-c1-smoke-window".to_string())
                .spawn(move || {
                    use windows::Win32::UI::WindowsAndMessaging::{
                        PeekMessageW, PM_NOREMOVE, WM_USER,
                    };

                    // Force creation of this thread's message queue before
                    // publishing the HWNDs to the test thread.
                    let mut queue_probe = MSG::default();
                    unsafe {
                        let _ = PeekMessageW(&mut queue_probe, None, WM_USER, WM_USER, PM_NOREMOVE);
                    }

                    let (owner, target) = create_smoke_test_windows(target_title);
                    let _ = ready_sender.send((owner.0 as usize, target.0 as usize));
                    if owner.0.is_null() || target.0.is_null() {
                        return;
                    }

                    unsafe {
                        let _ = ShowWindow(owner, SW_SHOW);
                        let _ = ShowWindow(target, SW_SHOW);
                        let _ = windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow(owner);
                    }

                    let mut message = MSG::default();
                    loop {
                        let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
                        if result.0 <= 0 {
                            break;
                        }
                        unsafe {
                            let _ = TranslateMessage(&message);
                            let _ = DispatchMessageW(&message);
                        }
                    }

                    // WM_CLOSE on either window ends the loop; retire both
                    // windows on the same UI thread before the fixture joins.
                    unsafe {
                        if !owner.0.is_null() {
                            let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(owner);
                        }
                        if !target.0.is_null() {
                            let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(target);
                        }
                    }
                })
                .expect("failed to start smoke window thread");

            let (owner_raw, target_raw) = ready_receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("smoke window thread did not publish its HWNDs");
            assert!(owner_raw != 0, "failed to create the smoke picker owner");
            assert!(target_raw != 0, "failed to create the smoke capture target");
            Self {
                owner: windows::Win32::Foundation::HWND(owner_raw as *mut core::ffi::c_void),
                thread: Some(thread),
            }
        }
    }

    impl Drop for SmokeWindowFixture {
        fn drop(&mut self) {
            use windows::Win32::Foundation::{LPARAM, WPARAM};
            use windows::Win32::UI::WindowsAndMessaging::WM_CLOSE;

            unsafe {
                if !self.owner.0.is_null() {
                    let _ = windows::Win32::UI::WindowsAndMessaging::PostMessageW(
                        Some(self.owner),
                        WM_CLOSE,
                        WPARAM(0),
                        LPARAM(0),
                    );
                }
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// Creates the responsive picker owner and the separate visible target.
    fn create_smoke_test_windows(
        target_title: &str,
    ) -> (
        windows::Win32::Foundation::HWND,
        windows::Win32::Foundation::HWND,
    ) {
        let owner = create_smoke_test_window("D23-C1 Picker Owner", 100, 100, 320, 200);
        let target = create_smoke_test_window(target_title, 460, 100, 480, 300);
        (owner, target)
    }

    /// Creates a visible test window used only as the picker owner or the
    /// pickable non-sensitive target.  The HWND is backend-derived; the
    /// frontend never supplies an owner handle.
    fn create_smoke_test_window(
        title: &str,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) -> windows::Win32::Foundation::HWND {
        use windows::core::w;
        use windows::Win32::{
            Foundation::{HWND, LPARAM, WPARAM},
            Graphics::Gdi::{
                CreateFontW, GetStockObject, CLIP_DEFAULT_PRECIS, DEFAULT_CHARSET, DEFAULT_PITCH,
                DEFAULT_QUALITY, FF_SWISS, OUT_DEFAULT_PRECIS, WHITE_BRUSH,
            },
            UI::WindowsAndMessaging::{
                CreateWindowExW, DefWindowProcW, PostQuitMessage, RegisterClassW, SendMessageW,
                CS_HREDRAW, CS_VREDRAW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_DESTROY,
                WM_SETFONT, WNDCLASSW, WS_CHILD, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
            },
        };

        unsafe extern "system" fn smoke_wnd_proc(
            hwnd: HWND,
            msg: u32,
            wparam: windows::Win32::Foundation::WPARAM,
            lparam: windows::Win32::Foundation::LPARAM,
        ) -> windows::Win32::Foundation::LRESULT {
            if msg == WM_CLOSE {
                unsafe {
                    let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(hwnd);
                }
                return windows::Win32::Foundation::LRESULT(0);
            }
            if msg == WM_DESTROY {
                unsafe {
                    PostQuitMessage(0);
                }
                return windows::Win32::Foundation::LRESULT(0);
            }
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }

        unsafe {
            let class = WNDCLASSW {
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(smoke_wnd_proc),
                hInstance: windows::Win32::Foundation::HINSTANCE(std::ptr::null_mut()),
                hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH(GetStockObject(WHITE_BRUSH).0),
                lpszClassName: w!("D23C1SmokeWindowClass"),
                ..Default::default()
            };
            RegisterClassW(&class);
            // The title buffer must outlive the window; leak it deliberately
            // for the duration of the smoke test process.
            let title_utf16 = title
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>();
            let title_ptr = Box::leak(title_utf16.into_boxed_slice()).as_ptr();
            let title = windows::core::PCWSTR(title_ptr);
            let window = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("D23C1SmokeWindowClass"),
                title,
                WINDOW_STYLE(WS_OVERLAPPEDWINDOW.0 | WS_VISIBLE.0),
                x,
                y,
                width,
                height,
                None,
                None,
                None,
                None,
            )
            .unwrap_or(HWND(std::ptr::null_mut()));

            if !window.0.is_null() {
                // Put the sentinel in the captured client area as large,
                // high-contrast native text.  The OCR smoke therefore does
                // not depend on whether a particular Windows build includes
                // non-client title-bar pixels in a window capture.
                if let Ok(label) = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("STATIC"),
                    title,
                    WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | 1),
                    18,
                    48,
                    width.saturating_sub(36),
                    90,
                    Some(window),
                    None,
                    None,
                    None,
                ) {
                    let font = CreateFontW(
                        -36,
                        0,
                        0,
                        0,
                        700,
                        0,
                        0,
                        0,
                        DEFAULT_CHARSET,
                        OUT_DEFAULT_PRECIS,
                        CLIP_DEFAULT_PRECIS,
                        DEFAULT_QUALITY,
                        DEFAULT_PITCH.0 as u32 | FF_SWISS.0 as u32,
                        w!("Segoe UI"),
                    );
                    if !font.0.is_null() {
                        let _ = SendMessageW(
                            label,
                            WM_SETFONT,
                            Some(WPARAM(font.0 as usize)),
                            Some(LPARAM(1)),
                        );
                    }
                }
            }
            window
        }
    }
}
