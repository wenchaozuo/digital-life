//! Capability-safe workspace path preparation.
//!
//! The H2 boundary is deliberately narrower than an executor.  It acquires
//! one trusted directory handle and can prepare a relative resource by
//! walking from that handle.  The result contains identity and lifetime
//! information only; it has no read, write, execute, or authorization API.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::{contains_stock_codex_state, VitaAgentError};

const TARGET_FIELD: &str = "workspace_target";
const ROOT_FIELD: &str = "workspace_root";
const MAX_COMPONENTS: usize = 256;
const MAX_UTF16_UNITS: usize = 32_767;

/// A validated, relative workspace name.
///
/// This type intentionally does not expose a filesystem operation.  It only
/// carries the component sequence that the capability walker is allowed to
/// resolve beneath an already acquired root handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceRelativePath {
    path: PathBuf,
    components: Vec<OsString>,
}

impl WorkspaceRelativePath {
    pub fn parse(path: &Path) -> Result<Self, VitaAgentError> {
        let raw = path.to_string_lossy();
        if raw.is_empty() {
            return Err(unsafe_relative_path(path, "empty path is ambiguous"));
        }

        let mut previous_was_separator = false;
        let mut saw_separator = false;
        for character in raw.chars() {
            if character == '/' || character == '\\' {
                if previous_was_separator {
                    return Err(unsafe_relative_path(
                        path,
                        "repeated separators are ambiguous",
                    ));
                }
                previous_was_separator = true;
                saw_separator = true;
                continue;
            }
            previous_was_separator = false;
            if character == ':' {
                return Err(unsafe_relative_path(
                    path,
                    "alternate data streams and qualified paths are forbidden",
                ));
            }
            if character.is_control() || character == '\0' {
                return Err(unsafe_relative_path(
                    path,
                    "control characters are forbidden",
                ));
            }
            #[cfg(windows)]
            if matches!(character, '<' | '>' | '"' | '|' | '?' | '*') {
                return Err(unsafe_relative_path(
                    path,
                    "Windows-invalid filename characters are forbidden",
                ));
            }
        }

        if raw.starts_with('/') || raw.starts_with('\\') {
            return Err(unsafe_relative_path(
                path,
                "rooted, UNC, or device paths are forbidden",
            ));
        }
        if raw.ends_with('/') || raw.ends_with('\\') {
            return Err(unsafe_relative_path(
                path,
                "trailing separators are ambiguous",
            ));
        }

        let components = path
            .components()
            .map(|component| match component {
                Component::Normal(value) => Ok(value.to_os_string()),
                Component::Prefix(_) => Err(unsafe_relative_path(
                    path,
                    "drive-qualified, UNC, or device paths are forbidden",
                )),
                Component::RootDir => Err(unsafe_relative_path(
                    path,
                    "rooted, UNC, or device paths are forbidden",
                )),
                Component::CurDir => Err(unsafe_relative_path(
                    path,
                    "current-directory components are ambiguous",
                )),
                Component::ParentDir => {
                    Err(unsafe_relative_path(path, "parent traversal is forbidden"))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        if components.is_empty() {
            return Err(unsafe_relative_path(path, "path has no usable components"));
        }
        if components.len() > MAX_COMPONENTS {
            return Err(unsafe_relative_path(path, "too many path components"));
        }
        if !saw_separator && components.len() != 1 {
            return Err(unsafe_relative_path(
                path,
                "path component parsing is ambiguous",
            ));
        }

        for component in &components {
            validate_component(path, component)?;
        }

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;

            let utf16_units = path.as_os_str().encode_wide().count();
            if utf16_units > MAX_UTF16_UNITS {
                return Err(unsafe_relative_path(path, "path is too long"));
            }
        }

        Ok(Self {
            path: path.to_path_buf(),
            components,
        })
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }

    pub fn to_path_buf(&self) -> PathBuf {
        self.path.clone()
    }

    pub fn components(&self) -> impl ExactSizeIterator<Item = &OsStr> {
        self.components.iter().map(OsString::as_os_str)
    }
}

fn validate_component(path: &Path, component: &OsStr) -> Result<(), VitaAgentError> {
    if component.is_empty() {
        return Err(unsafe_relative_path(
            path,
            "empty path component is ambiguous",
        ));
    }

    let text = component.to_string_lossy();
    if text.ends_with('.') || text.ends_with(' ') {
        return Err(unsafe_relative_path(
            path,
            "trailing dots and spaces are forbidden",
        ));
    }

    let device_name = text
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(
        device_name.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        return Err(unsafe_relative_path(
            path,
            "reserved Windows device names are forbidden",
        ));
    }

    Ok(())
}

fn unsafe_relative_path(path: &Path, reason: &'static str) -> VitaAgentError {
    VitaAgentError::UnsafePath {
        field: TARGET_FIELD,
        path: path.to_path_buf(),
        reason,
    }
}

/// Stable file identity captured from a verified handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WorkspaceRootIdentity {
    #[cfg(windows)]
    volume_serial_number: u64,
    #[cfg(windows)]
    file_id: [u8; 16],
    #[cfg(not(windows))]
    unavailable: (),
}

impl WorkspaceRootIdentity {
    #[cfg(windows)]
    fn windows(volume_serial_number: u64, file_id: [u8; 16]) -> Self {
        Self {
            volume_serial_number,
            file_id,
        }
    }

    #[cfg(not(windows))]
    fn unavailable() -> Self {
        Self { unavailable: () }
    }

    pub fn volume_serial_number(&self) -> Option<u64> {
        #[cfg(windows)]
        {
            Some(self.volume_serial_number)
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    pub fn file_id(&self) -> Option<[u8; 16]> {
        #[cfg(windows)]
        {
            Some(self.file_id)
        }
        #[cfg(not(windows))]
        {
            None
        }
    }
}

/// Classification of a prepared resource.  `Missing` is identity-only and
/// does not mean that any creation or mutation occurred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedWorkspaceTargetKind {
    ExistingFile,
    ExistingDirectory,
    Missing,
}

/// A process-lifetime, OS-backed capability to one trusted workspace root.
#[derive(Clone)]
pub struct TrustedWorkspaceRoot {
    inner: Arc<TrustedWorkspaceRootInner>,
}

struct TrustedWorkspaceRootInner {
    requested_path: PathBuf,
    final_path: PathBuf,
    identity: WorkspaceRootIdentity,
    #[cfg(windows)]
    handle: Arc<platform::OwnedHandle>,
}

impl fmt::Debug for TrustedWorkspaceRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedWorkspaceRoot")
            .field("requested_path", &self.inner.requested_path)
            .field("final_path", &self.inner.final_path)
            .field("identity", &self.inner.identity)
            .finish_non_exhaustive()
    }
}

impl PartialEq for TrustedWorkspaceRoot {
    fn eq(&self, other: &Self) -> bool {
        self.inner.identity == other.inner.identity
            && normalize_path_for_comparison(&self.inner.final_path)
                == normalize_path_for_comparison(&other.inner.final_path)
    }
}

impl Eq for TrustedWorkspaceRoot {}

impl TrustedWorkspaceRoot {
    pub fn acquire(requested_path: &Path) -> Result<Self, VitaAgentError> {
        validate_explicit_root_path(requested_path)?;

        #[cfg(windows)]
        {
            return platform::acquire_root(requested_path);
        }
        #[cfg(not(windows))]
        {
            let _ = requested_path;
            Err(VitaAgentError::KernelInvariant(
                "workspace capability is unavailable on this platform",
            ))
        }
    }

    pub fn requested_path(&self) -> &Path {
        &self.inner.requested_path
    }

    pub fn final_path(&self) -> &Path {
        &self.inner.final_path
    }

    pub fn identity(&self) -> WorkspaceRootIdentity {
        self.inner.identity
    }

    /// Re-checks that the configured root name still denotes the originally
    /// acquired directory identity.  This catches rename/replacement of the
    /// root name without replacing the already-held capability.
    pub fn verify_named_path_current(&self) -> Result<(), VitaAgentError> {
        #[cfg(windows)]
        {
            platform::verify_root_name(self)
        }
        #[cfg(not(windows))]
        {
            Err(VitaAgentError::KernelInvariant(
                "workspace capability is unavailable on this platform",
            ))
        }
    }

    /// Resolves one relative target from the root handle and returns only
    /// resource identity and classification.  No later pathname reopen is
    /// implied by this API.
    pub fn prepare_target(
        &self,
        requested: &Path,
    ) -> Result<PreparedWorkspaceTarget, VitaAgentError> {
        let relative = WorkspaceRelativePath::parse(requested)?;

        #[cfg(windows)]
        {
            return platform::prepare_target(self, relative);
        }
        #[cfg(not(windows))]
        {
            let _ = relative;
            Err(VitaAgentError::KernelInvariant(
                "workspace capability is unavailable on this platform",
            ))
        }
    }

    #[cfg(windows)]
    fn from_platform(
        requested_path: PathBuf,
        final_path: PathBuf,
        identity: WorkspaceRootIdentity,
        handle: Arc<platform::OwnedHandle>,
    ) -> Self {
        Self {
            inner: Arc::new(TrustedWorkspaceRootInner {
                requested_path,
                final_path,
                identity,
                handle,
            }),
        }
    }
}

/// Identity-only preparation result.  Parent and target handles are retained
/// privately so a future creation primitive can remain anchored to the same
/// capability; no handle is exposed as an executable or readable object.
///
/// H3 existing-target operations must rebind the relative leaf through
/// `parent_handle` with `NtCreateFile(RootDirectory = parent_handle)` and
/// `OBJ_DONT_REPARSE`, request only the operation's access, inspect that same
/// returned handle, and compare its identity and kind with this preparation.
/// A mismatch or missing target must deny the operation.  The operation must
/// then use that inspected handle directly; it must never validate a pathname,
/// close the validation handle, and reopen the target by pathname before a
/// side effect.
pub struct PreparedWorkspaceTarget {
    root: TrustedWorkspaceRoot,
    relative_path: WorkspaceRelativePath,
    parent_identity: WorkspaceRootIdentity,
    target_identity: Option<WorkspaceRootIdentity>,
    final_path: Option<PathBuf>,
    kind: PreparedWorkspaceTargetKind,
    #[cfg(windows)]
    #[allow(dead_code)]
    parent_handle: Arc<platform::OwnedHandle>,
    #[cfg(windows)]
    #[allow(dead_code)]
    target_handle: Option<Arc<platform::OwnedHandle>>,
}

impl fmt::Debug for PreparedWorkspaceTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedWorkspaceTarget")
            .field("relative_path", &self.relative_path)
            .field("parent_identity", &self.parent_identity)
            .field("target_identity", &self.target_identity)
            .field("final_path", &self.final_path)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl PreparedWorkspaceTarget {
    pub fn root(&self) -> &TrustedWorkspaceRoot {
        &self.root
    }

    pub fn relative_path(&self) -> &WorkspaceRelativePath {
        &self.relative_path
    }

    pub fn parent_identity(&self) -> WorkspaceRootIdentity {
        self.parent_identity
    }

    pub fn target_identity(&self) -> Option<WorkspaceRootIdentity> {
        self.target_identity
    }

    pub fn final_path(&self) -> Option<&Path> {
        self.final_path.as_deref()
    }

    pub fn kind(&self) -> PreparedWorkspaceTargetKind {
        self.kind
    }
}

fn validate_explicit_root_path(path: &Path) -> Result<(), VitaAgentError> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(VitaAgentError::InvalidPath {
            field: ROOT_FIELD,
            path: path.to_path_buf(),
        });
    }
    if contains_stock_codex_state(path) {
        return Err(VitaAgentError::ForbiddenStockPath {
            field: ROOT_FIELD,
            path: path.to_path_buf(),
        });
    }
    for component in path.components() {
        if matches!(component, Component::CurDir | Component::ParentDir) {
            return Err(VitaAgentError::UnsafePath {
                field: ROOT_FIELD,
                path: path.to_path_buf(),
                reason: "dot path components are ambiguous",
            });
        }
    }

    #[cfg(windows)]
    {
        use std::path::Prefix;

        match path.components().next() {
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)) => {}
            _ => {
                return Err(VitaAgentError::UnsafePath {
                    field: ROOT_FIELD,
                    path: path.to_path_buf(),
                    reason: "only an explicit local drive directory is allowed",
                })
            }
        }
        if path
            .to_string_lossy()
            .chars()
            .any(|character| character.is_control() || character == '\0')
        {
            return Err(VitaAgentError::UnsafePath {
                field: ROOT_FIELD,
                path: path.to_path_buf(),
                reason: "control characters are forbidden",
            });
        }
        for component in path.components() {
            if let Component::Normal(value) = component {
                if value.to_string_lossy().contains(':') {
                    return Err(VitaAgentError::UnsafePath {
                        field: ROOT_FIELD,
                        path: path.to_path_buf(),
                        reason: "alternate data streams are forbidden",
                    });
                }
            }
        }
    }

    Ok(())
}

fn normalize_path_for_comparison(path: &Path) -> String {
    let mut value = path.to_string_lossy().replace('/', "\\");
    if value.starts_with("\\\\?\\") {
        value.drain(..4);
    }
    while value.ends_with('\\') && value.len() > 3 {
        value.pop();
    }
    value.to_ascii_lowercase()
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        NtCreateFile, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, OBJ_CASE_INSENSITIVE,
        OBJ_DONT_REPARSE, STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_NOT_FOUND,
        STATUS_OBJECT_PATH_NOT_FOUND, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FileIdInfo, GetDriveTypeW, GetFileInformationByHandle,
        GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
        FILE_INFO_BY_HANDLE_CLASS, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_TYPE_DISK, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::WindowsProgramming::{
        DRIVE_FIXED, DRIVE_NO_ROOT_DIR, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE, DRIVE_UNKNOWN,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    // FILE_TRAVERSE is retained only for directory RootDirectory traversal.
    // A regular target never receives FILE_TRAVERSE/FILE_EXECUTE.
    const OPEN_DIRECTORY_ACCESS: u32 = FILE_READ_ATTRIBUTES | FILE_TRAVERSE;
    const OPEN_TARGET_ACCESS: u32 = FILE_READ_ATTRIBUTES;

    pub(super) struct OwnedHandle(pub(super) HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    // A Windows kernel handle is process-local and is closed exactly once by
    // OwnedHandle.  Arc ensures all cloned capabilities share its lifetime.
    unsafe impl Send for OwnedHandle {}
    unsafe impl Sync for OwnedHandle {}

    impl fmt::Debug for OwnedHandle {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("OwnedHandle(<redacted>)")
        }
    }

    struct HandleDetails {
        identity: WorkspaceRootIdentity,
        final_path: PathBuf,
        is_directory: bool,
    }

    pub(super) fn acquire_root(
        requested_path: &Path,
    ) -> Result<TrustedWorkspaceRoot, VitaAgentError> {
        acquire_root_impl(requested_path, || {})
    }

    #[cfg(test)]
    pub(super) fn acquire_root_with_hook<F>(
        requested_path: &Path,
        hook: F,
    ) -> Result<TrustedWorkspaceRoot, VitaAgentError>
    where
        F: FnMut(),
    {
        acquire_root_impl(requested_path, hook)
    }

    fn acquire_root_impl<F>(
        requested_path: &Path,
        mut after_drive_anchor: F,
    ) -> Result<TrustedWorkspaceRoot, VitaAgentError>
    where
        F: FnMut(),
    {
        // This is input validation only.  The authority decision below is
        // made by walking from the local-drive anchor, never by canonicalizing
        // and reopening the full user pathname.
        validate_explicit_root_path(requested_path)?;
        let components = root_components(requested_path)?;
        let (drive_anchor, anchor_details) = open_drive_anchor(requested_path)?;
        ensure_allowed_local_final_path(&anchor_details.final_path, requested_path)?;
        reject_resolved_stock_state(&anchor_details.final_path)?;

        // The drive root is the only full-name open in the authority path.  It
        // is derived from the validated local drive prefix and is itself the
        // trusted parent for every user-selected component below.
        after_drive_anchor();

        let anchor_final_path = anchor_details.final_path.clone();
        let mut parent_handle = Arc::new(drive_anchor);
        let mut final_details = anchor_details;
        for component in &components {
            let child = match open_relative(&parent_handle, component, true) {
                Ok(child) => child,
                Err(error) => return Err(relative_open_error(requested_path, error)),
            };
            let details = inspect_handle(&child, true)?;
            ensure_allowed_local_final_path(&details.final_path, requested_path)?;
            if !is_same_or_descendant_path(&anchor_final_path, &details.final_path) {
                return Err(unsafe_root_path(
                    &details.final_path,
                    "root component escaped the local drive anchor",
                ));
            }
            final_details = details;
            parent_handle = Arc::new(child);
        }

        if !is_same_or_descendant_path(&anchor_final_path, &final_details.final_path) {
            return Err(unsafe_root_path(
                &final_details.final_path,
                "resolved root is outside the local drive anchor",
            ));
        }
        reject_resolved_stock_state(&final_details.final_path)?;

        Ok(TrustedWorkspaceRoot::from_platform(
            requested_path.to_path_buf(),
            final_details.final_path,
            final_details.identity,
            parent_handle,
        ))
    }

    pub(super) fn verify_root_name(root: &TrustedWorkspaceRoot) -> Result<(), VitaAgentError> {
        // Revalidation uses the same handle-relative, no-reparse acquisition
        // path as initial acquisition.  It never treats a full pathname open
        // or canonicalize result as the authority.
        let rebound = acquire_root(root.requested_path())?;
        if rebound.identity() != root.identity()
            || !same_path(root.final_path(), rebound.final_path())
        {
            return Err(unsafe_root_path(
                root.requested_path(),
                "root name no longer denotes the acquired directory",
            ));
        }
        Ok(())
    }

    pub(super) fn prepare_target(
        root: &TrustedWorkspaceRoot,
        relative: WorkspaceRelativePath,
    ) -> Result<PreparedWorkspaceTarget, VitaAgentError> {
        prepare_target_impl(root, relative, || {})
    }

    fn prepare_target_impl<F>(
        root: &TrustedWorkspaceRoot,
        relative: WorkspaceRelativePath,
        mut after_parent: F,
    ) -> Result<PreparedWorkspaceTarget, VitaAgentError>
    where
        F: FnMut(),
    {
        verify_root_name(root)?;

        let components = relative.components().collect::<Vec<_>>();
        let mut parent_handle = Arc::clone(&root.inner.handle);
        let mut parent_identity = root.identity();
        let mut parent_identities = vec![parent_identity];

        for component in components.iter().take(components.len().saturating_sub(1)) {
            let child = match open_relative(&parent_handle, component, true) {
                Ok(child) => child,
                Err(error) => return Err(relative_open_error(relative.as_path(), error)),
            };
            let details = inspect_handle(&child, true)?;
            ensure_descendant(root, &details.final_path)?;
            parent_identity = details.identity;
            parent_identities.push(parent_identity);
            parent_handle = Arc::new(child);
        }

        // Test-only race injection point: the parent capability has already
        // been acquired, so replacing its old pathname cannot redirect the
        // handle-relative final open.
        after_parent();

        let leaf = components
            .last()
            .expect("WorkspaceRelativePath always has one component");
        let target = match open_relative(&parent_handle, leaf, false) {
            Ok(handle) => {
                let details = inspect_handle(&handle, false)?;
                ensure_descendant(root, &details.final_path)?;
                let kind = if details.is_directory {
                    PreparedWorkspaceTargetKind::ExistingDirectory
                } else {
                    PreparedWorkspaceTargetKind::ExistingFile
                };
                (
                    kind,
                    Some(details.identity),
                    Some(details.final_path),
                    Some(Arc::new(handle)),
                )
            }
            Err(RelativeOpenError::Missing(status)) if is_missing_status(status) => {
                (PreparedWorkspaceTargetKind::Missing, None, None, None)
            }
            Err(RelativeOpenError::Missing(status)) => {
                return Err(relative_open_error(
                    relative.as_path(),
                    RelativeOpenError::Missing(status),
                ));
            }
            Err(RelativeOpenError::Status(status)) => {
                return Err(relative_open_error(
                    relative.as_path(),
                    RelativeOpenError::Status(status),
                ));
            }
        };

        verify_relative_parents(root, &components, &parent_identities, relative.as_path())?;
        verify_target_name_current(
            root,
            &parent_handle,
            leaf,
            target.1,
            target.0,
            relative.as_path(),
        )?;

        // The root name is checked again after all handle-relative stages.  A
        // root rename/replacement therefore fails closed even though the
        // original root handle remains stable and is never silently rebound.
        verify_root_name(root)?;

        Ok(PreparedWorkspaceTarget {
            root: root.clone(),
            relative_path: relative,
            parent_identity,
            target_identity: target.1,
            final_path: target.2,
            kind: target.0,
            parent_handle,
            target_handle: target.3,
        })
    }

    fn open_drive_anchor(
        requested_path: &Path,
    ) -> Result<(OwnedHandle, HandleDetails), VitaAgentError> {
        let drive_root = drive_root_path(requested_path)?;
        let drive_type = unsafe { GetDriveTypeW(nul_terminated(&drive_root).as_ptr()) };
        validate_drive_type(&drive_root, drive_type)?;

        let wide = nul_terminated(&drive_root);
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                OPEN_DIRECTORY_ACCESS,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if is_invalid_handle(handle) {
            return Err(VitaAgentError::KernelConfig(io::Error::last_os_error()));
        }
        let handle = OwnedHandle(handle);
        let details = inspect_handle(&handle, true)?;
        Ok((handle, details))
    }

    fn drive_root_path(path: &Path) -> Result<PathBuf, VitaAgentError> {
        use std::path::Prefix;

        match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) => Ok(PathBuf::from(format!("{}:\\", letter as char))),
                _ => Err(unsafe_root_path(
                    path,
                    "only a local disk drive can provide a workspace anchor",
                )),
            },
            _ => Err(unsafe_root_path(
                path,
                "workspace root has no explicit local drive anchor",
            )),
        }
    }

    fn root_components(path: &Path) -> Result<Vec<OsString>, VitaAgentError> {
        let mut components = Vec::new();
        for component in path.components() {
            if let Component::Normal(value) = component {
                components.push(value.to_os_string());
            }
        }
        Ok(components)
    }

    fn validate_drive_type(path: &Path, drive_type: u32) -> Result<(), VitaAgentError> {
        match drive_type {
            DRIVE_REMOTE => Err(unsafe_root_path(
                path,
                "mapped or remote drives are not allowed as workspace roots",
            )),
            DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_RAMDISK => Ok(()),
            DRIVE_UNKNOWN | DRIVE_NO_ROOT_DIR => {
                Err(unsafe_root_path(path, "drive type is indeterminate"))
            }
            _ => Err(unsafe_root_path(
                path,
                "drive type is not an allowed local filesystem",
            )),
        }
    }

    fn ensure_allowed_local_final_path(
        path: &Path,
        requested_path: &Path,
    ) -> Result<(), VitaAgentError> {
        let raw = path
            .to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase();
        let is_verbatim = raw.starts_with("\\\\?\\");
        let without_verbatim = raw.strip_prefix("\\\\?\\").unwrap_or(&raw);
        let is_unc = raw.starts_with("\\\\?\\unc\\") || (!is_verbatim && raw.starts_with("\\\\"));
        let is_device = raw.starts_with("\\device\\")
            || raw.starts_with("\\\\device\\")
            || raw.starts_with("\\\\.\\")
            || without_verbatim.starts_with("device\\")
            || without_verbatim.starts_with("globalroot\\device\\");
        if is_unc || is_device {
            return Err(unsafe_root_path(
                requested_path,
                "resolved workspace path is UNC or device namespace",
            ));
        }

        match without_verbatim.as_bytes() {
            [drive, b':', ..] if drive.is_ascii_alphabetic() => Ok(()),
            _ => Err(unsafe_root_path(
                requested_path,
                "resolved workspace path is not an allowed local drive path",
            )),
        }
    }

    fn reject_resolved_stock_state(path: &Path) -> Result<(), VitaAgentError> {
        if contains_stock_codex_state(path) {
            return Err(VitaAgentError::ForbiddenStockPath {
                field: ROOT_FIELD,
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    fn open_relative(
        parent: &Arc<OwnedHandle>,
        component: &OsStr,
        directory: bool,
    ) -> Result<OwnedHandle, RelativeOpenError> {
        let mut name = component.encode_wide().collect::<Vec<_>>();
        let byte_length = name
            .len()
            .checked_mul(2)
            .ok_or_else(|| RelativeOpenError::Status(STATUS_OBJECT_NAME_NOT_FOUND))?;
        if byte_length > u16::MAX as usize {
            return Err(RelativeOpenError::Status(STATUS_OBJECT_NAME_NOT_FOUND));
        }
        let unicode_name = UNICODE_STRING {
            Length: byte_length as u16,
            MaximumLength: byte_length as u16,
            Buffer: name.as_mut_ptr(),
        };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.0,
            ObjectName: &unicode_name,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let mut handle: HANDLE = std::ptr::null_mut();
        let create_options =
            FILE_OPEN_REPARSE_POINT | if directory { FILE_DIRECTORY_FILE } else { 0 };
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                if directory {
                    OPEN_DIRECTORY_ACCESS
                } else {
                    OPEN_TARGET_ACCESS
                },
                &object_attributes,
                &mut status_block,
                std::ptr::null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                create_options,
                std::ptr::null(),
                0,
            )
        };
        if status < 0 {
            if !is_invalid_handle(handle) {
                unsafe {
                    let _ = CloseHandle(handle);
                }
            }
            return Err(if is_missing_status(status) {
                RelativeOpenError::Missing(status)
            } else {
                RelativeOpenError::Status(status)
            });
        }
        if is_invalid_handle(handle) {
            return Err(RelativeOpenError::Status(status));
        }
        Ok(OwnedHandle(handle))
    }

    fn inspect_handle(
        handle: &OwnedHandle,
        require_directory: bool,
    ) -> Result<HandleDetails, VitaAgentError> {
        let mut legacy = BY_HANDLE_FILE_INFORMATION::default();
        let ok = unsafe { GetFileInformationByHandle(handle.0, &mut legacy) } != 0;
        if !ok {
            return Err(VitaAgentError::KernelConfig(io::Error::last_os_error()));
        }
        let is_directory = legacy.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let is_reparse = legacy.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        if unsafe { GetFileType(handle.0) } != FILE_TYPE_DISK {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: PathBuf::new(),
                reason: "workspace handle is not a disk object",
            });
        }
        if is_reparse {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: PathBuf::new(),
                reason: "reparse points are forbidden",
            });
        }
        if require_directory && !is_directory {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: PathBuf::new(),
                reason: "workspace path component is not a directory",
            });
        }

        let identity = file_identity(handle, &legacy)?;
        let final_path = final_path_from_handle(handle)?;
        Ok(HandleDetails {
            identity,
            final_path,
            is_directory,
        })
    }

    fn file_identity(
        handle: &OwnedHandle,
        legacy: &BY_HANDLE_FILE_INFORMATION,
    ) -> Result<WorkspaceRootIdentity, VitaAgentError> {
        let mut info = FILE_ID_INFO::default();
        let modern = unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                FileIdInfo as FILE_INFO_BY_HANDLE_CLASS,
                (&mut info as *mut FILE_ID_INFO).cast::<c_void>(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } != 0;
        if modern {
            return Ok(WorkspaceRootIdentity::windows(
                info.VolumeSerialNumber,
                info.FileId.Identifier,
            ));
        }

        let mut file_id = [0_u8; 16];
        file_id[..4].copy_from_slice(&legacy.nFileIndexLow.to_le_bytes());
        file_id[4..8].copy_from_slice(&legacy.nFileIndexHigh.to_le_bytes());
        Ok(WorkspaceRootIdentity::windows(
            legacy.dwVolumeSerialNumber as u64,
            file_id,
        ))
    }

    fn final_path_from_handle(handle: &OwnedHandle) -> Result<PathBuf, VitaAgentError> {
        let mut buffer = vec![0_u16; 32_768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle.0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED,
            )
        };
        if length == 0 || length >= buffer.len() as u32 {
            return Err(VitaAgentError::KernelConfig(io::Error::last_os_error()));
        }
        String::from_utf16(&buffer[..length as usize])
            .map(PathBuf::from)
            .map_err(|_| {
                VitaAgentError::KernelInvariant("Windows returned a non-UTF-16 final path")
            })
    }

    fn ensure_descendant(root: &TrustedWorkspaceRoot, path: &Path) -> Result<(), VitaAgentError> {
        let root_path = normalize_path_for_comparison(root.final_path());
        let child_path = normalize_path_for_comparison(path);
        let root_prefix = if root_path.ends_with('\\') {
            root_path.clone()
        } else {
            format!("{root_path}\\")
        };
        if child_path == root_path || child_path.starts_with(&root_prefix) {
            Ok(())
        } else {
            Err(unsafe_root_path(
                path,
                "handle-relative resolution escaped the trusted root",
            ))
        }
    }

    fn same_path(left: &Path, right: &Path) -> bool {
        normalize_path_for_comparison(left) == normalize_path_for_comparison(right)
    }

    fn is_same_or_descendant_path(parent: &Path, child: &Path) -> bool {
        let parent = normalize_path_for_comparison(parent);
        let child = normalize_path_for_comparison(child);
        let prefix = if parent.ends_with('\\') {
            parent.clone()
        } else {
            format!("{parent}\\")
        };
        child == parent || child.starts_with(&prefix)
    }

    fn verify_relative_parents(
        root: &TrustedWorkspaceRoot,
        components: &[&OsStr],
        expected_identities: &[WorkspaceRootIdentity],
        requested: &Path,
    ) -> Result<(), VitaAgentError> {
        let mut handle = Arc::clone(&root.inner.handle);
        for (index, component) in components
            .iter()
            .take(components.len().saturating_sub(1))
            .enumerate()
        {
            let child = match open_relative(&handle, component, true) {
                Ok(child) => child,
                Err(error) => return Err(relative_open_error(requested, error)),
            };
            let details = inspect_handle(&child, true)?;
            ensure_descendant(root, &details.final_path)?;
            if expected_identities.get(index + 1).copied() != Some(details.identity) {
                return Err(VitaAgentError::UnsafePath {
                    field: TARGET_FIELD,
                    path: requested.to_path_buf(),
                    reason: "workspace parent identity changed during preparation",
                });
            }
            handle = Arc::new(child);
        }
        Ok(())
    }

    #[cfg(test)]
    fn open_and_verify_existing_target(
        root: &TrustedWorkspaceRoot,
        parent: &Arc<OwnedHandle>,
        leaf: &OsStr,
        expected_identity: WorkspaceRootIdentity,
        expected_kind: PreparedWorkspaceTargetKind,
        requested: &Path,
    ) -> Result<(OwnedHandle, HandleDetails), VitaAgentError> {
        let handle = match open_relative(parent, leaf, false) {
            Ok(handle) => handle,
            Err(RelativeOpenError::Missing(_)) => {
                return Err(VitaAgentError::UnsafePath {
                    field: TARGET_FIELD,
                    path: requested.to_path_buf(),
                    reason: "workspace target disappeared during same-handle rebind",
                })
            }
            Err(error) => return Err(relative_open_error(requested, error)),
        };
        let details = inspect_handle(&handle, false)?;
        ensure_descendant(root, &details.final_path)?;
        let actual_kind = if details.is_directory {
            PreparedWorkspaceTargetKind::ExistingDirectory
        } else {
            PreparedWorkspaceTargetKind::ExistingFile
        };
        if details.identity != expected_identity || actual_kind != expected_kind {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: requested.to_path_buf(),
                reason: "workspace target identity or kind changed during same-handle rebind",
            });
        }
        Ok((handle, details))
    }

    fn verify_target_name_current(
        root: &TrustedWorkspaceRoot,
        parent: &Arc<OwnedHandle>,
        leaf: &OsStr,
        expected_identity: Option<WorkspaceRootIdentity>,
        expected_kind: PreparedWorkspaceTargetKind,
        requested: &Path,
    ) -> Result<(), VitaAgentError> {
        match open_relative(parent, leaf, false) {
            Ok(handle) => {
                let details = inspect_handle(&handle, false)?;
                ensure_descendant(root, &details.final_path)?;
                let actual_kind = if details.is_directory {
                    PreparedWorkspaceTargetKind::ExistingDirectory
                } else {
                    PreparedWorkspaceTargetKind::ExistingFile
                };
                if expected_identity != Some(details.identity) || expected_kind != actual_kind {
                    return Err(VitaAgentError::UnsafePath {
                        field: TARGET_FIELD,
                        path: requested.to_path_buf(),
                        reason: "workspace target identity changed during preparation",
                    });
                }
            }
            Err(RelativeOpenError::Missing(status)) if is_missing_status(status) => {
                if expected_kind != PreparedWorkspaceTargetKind::Missing {
                    return Err(VitaAgentError::UnsafePath {
                        field: TARGET_FIELD,
                        path: requested.to_path_buf(),
                        reason: "workspace target disappeared during preparation",
                    });
                }
            }
            Err(error) => return Err(relative_open_error(requested, error)),
        }
        Ok(())
    }

    fn nul_terminated(path: &Path) -> Vec<u16> {
        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        wide.push(0);
        wide
    }

    fn is_invalid_handle(handle: HANDLE) -> bool {
        handle.is_null() || handle == INVALID_HANDLE_VALUE
    }

    fn is_missing_status(status: NTSTATUS) -> bool {
        matches!(
            status,
            STATUS_NO_SUCH_FILE | STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND
        )
    }

    enum RelativeOpenError {
        Missing(NTSTATUS),
        Status(NTSTATUS),
    }

    fn relative_open_error(path: &Path, error: RelativeOpenError) -> VitaAgentError {
        let reason = match error {
            RelativeOpenError::Missing(_) => "required directory component is missing",
            RelativeOpenError::Status(_) => "handle-relative workspace open failed closed",
        };
        VitaAgentError::UnsafePath {
            field: TARGET_FIELD,
            path: path.to_path_buf(),
            reason,
        }
    }

    fn unsafe_root_path(path: &Path, reason: &'static str) -> VitaAgentError {
        VitaAgentError::UnsafePath {
            field: ROOT_FIELD,
            path: path.to_path_buf(),
            reason,
        }
    }

    #[cfg(test)]
    pub(super) fn prepare_target_with_hook<F>(
        root: &TrustedWorkspaceRoot,
        relative: WorkspaceRelativePath,
        hook: F,
    ) -> Result<PreparedWorkspaceTarget, VitaAgentError>
    where
        F: FnMut(),
    {
        prepare_target_impl(root, relative, hook)
    }

    #[cfg(test)]
    pub(super) fn root_with_requested_path_for_test(
        root: &TrustedWorkspaceRoot,
        requested_path: PathBuf,
    ) -> TrustedWorkspaceRoot {
        TrustedWorkspaceRoot {
            inner: Arc::new(TrustedWorkspaceRootInner {
                requested_path,
                final_path: root.inner.final_path.clone(),
                identity: root.inner.identity,
                handle: Arc::clone(&root.inner.handle),
            }),
        }
    }

    #[cfg(test)]
    pub(super) fn verify_parent_identities_for_test(
        root: &TrustedWorkspaceRoot,
        relative: &WorkspaceRelativePath,
        expected_identities: &[WorkspaceRootIdentity],
    ) -> Result<(), VitaAgentError> {
        let components = relative.components().collect::<Vec<_>>();
        verify_relative_parents(root, &components, expected_identities, relative.as_path())
    }

    #[cfg(test)]
    pub(super) fn verify_target_identity_for_test(
        root: &TrustedWorkspaceRoot,
        relative: &WorkspaceRelativePath,
        expected_identity: WorkspaceRootIdentity,
    ) -> Result<(), VitaAgentError> {
        let components = relative.components().collect::<Vec<_>>();
        let leaf = components
            .last()
            .expect("WorkspaceRelativePath always has one component");
        let mut parent_handle = Arc::clone(&root.inner.handle);
        for component in components.iter().take(components.len().saturating_sub(1)) {
            let child = match open_relative(&parent_handle, component, true) {
                Ok(child) => child,
                Err(error) => return Err(relative_open_error(relative.as_path(), error)),
            };
            let details = inspect_handle(&child, true)?;
            ensure_descendant(root, &details.final_path)?;
            parent_handle = Arc::new(child);
        }

        let handle = match open_relative(&parent_handle, leaf, false) {
            Ok(handle) => handle,
            Err(error) => return Err(relative_open_error(relative.as_path(), error)),
        };
        let details = inspect_handle(&handle, false)?;
        let kind = if details.is_directory {
            PreparedWorkspaceTargetKind::ExistingDirectory
        } else {
            PreparedWorkspaceTargetKind::ExistingFile
        };
        drop(handle);
        verify_target_name_current(
            root,
            &parent_handle,
            leaf,
            Some(expected_identity),
            kind,
            relative.as_path(),
        )
    }

    #[cfg(test)]
    pub(super) fn rebind_existing_target_for_test(
        prepared: &PreparedWorkspaceTarget,
    ) -> Result<WorkspaceRootIdentity, VitaAgentError> {
        let expected_identity = prepared.target_identity.ok_or(VitaAgentError::UnsafePath {
            field: TARGET_FIELD,
            path: prepared.relative_path.to_path_buf(),
            reason: "missing target has no existing identity to rebind",
        })?;
        if prepared.kind == PreparedWorkspaceTargetKind::Missing {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: prepared.relative_path.to_path_buf(),
                reason: "missing target has no existing kind to rebind",
            });
        }

        let parent_details = inspect_handle(&prepared.parent_handle, true)?;
        ensure_descendant(&prepared.root, &parent_details.final_path)?;
        if parent_details.identity != prepared.parent_identity {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: prepared.relative_path.to_path_buf(),
                reason: "workspace parent identity changed before same-handle rebind",
            });
        }
        let leaf = prepared
            .relative_path
            .components()
            .last()
            .expect("WorkspaceRelativePath always has one component");

        // This H2 test helper intentionally requests only the metadata access
        // available to H2.  A future H3 operation must replace this with the
        // exact access mask for its operation and continue using the returned
        // handle after these checks, without reopening the pathname.
        let (handle, details) = open_and_verify_existing_target(
            &prepared.root,
            &prepared.parent_handle,
            leaf,
            expected_identity,
            prepared.kind,
            prepared.relative_path.as_path(),
        )?;
        prepared.root.verify_named_path_current()?;
        let identity = details.identity;
        drop(handle);
        Ok(identity)
    }

    #[cfg(test)]
    pub(super) fn access_masks_for_test() -> (u32, u32) {
        (OPEN_DIRECTORY_ACCESS, OPEN_TARGET_ACCESS)
    }

    #[cfg(test)]
    pub(super) fn validate_drive_type_for_test(drive_type: u32) -> Result<(), VitaAgentError> {
        validate_drive_type(Path::new("C:\\"), drive_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn relative_path_rejects_ambiguous_and_dangerous_forms() {
        for path in [
            "",
            "..",
            "../outside",
            "safe/../outside",
            "/absolute",
            "\\absolute",
            "C:\\absolute",
            "C:relative",
            "\\\\server\\share",
            "\\\\?\\C:\\device",
            "safe:file",
            "safe\\\\file",
            "safe//file",
            "safe/",
            ".\\file",
            "CON",
            "LPT1.txt",
            "safe.",
            "safe ",
        ] {
            let result = WorkspaceRelativePath::parse(Path::new(path));
            #[cfg(windows)]
            assert!(result.is_err(), "accepted unsafe relative path {path:?}");
            #[cfg(not(windows))]
            if path != "C:\\absolute" && path != "C:relative" && path != "LPT1.txt" {
                assert!(result.is_err(), "accepted unsafe relative path {path:?}");
            }
        }
        assert!(WorkspaceRelativePath::parse(Path::new("safe/file.txt")).is_ok());
    }

    #[cfg(windows)]
    fn native_symlink(link: &Path, target: &Path, directory: bool) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateSymbolicLinkW, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
            SYMBOLIC_LINK_FLAG_DIRECTORY,
        };

        let mut link_wide = link.as_os_str().encode_wide().collect::<Vec<_>>();
        let mut target_wide = target.as_os_str().encode_wide().collect::<Vec<_>>();
        link_wide.push(0);
        target_wide.push(0);
        let created = unsafe {
            CreateSymbolicLinkW(
                link_wide.as_ptr(),
                target_wide.as_ptr(),
                SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
                    | if directory {
                        SYMBOLIC_LINK_FLAG_DIRECTORY
                    } else {
                        0
                    },
            )
        };
        assert!(created, "native symlink creation failed");
    }

    #[cfg(windows)]
    fn native_dir_symlink(link: &Path, target: &Path) {
        native_symlink(link, target, true);
    }

    #[cfg(windows)]
    fn native_file_symlink(link: &Path, target: &Path) {
        native_symlink(link, target, false);
    }

    #[cfg(windows)]
    #[test]
    fn directory_and_target_access_masks_are_identity_only() {
        use windows_sys::Win32::Storage::FileSystem::{FILE_READ_ATTRIBUTES, FILE_TRAVERSE};

        let (directory_access, target_access) = platform::access_masks_for_test();
        assert_eq!(
            directory_access,
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
            "directory handles may only inspect and traverse"
        );
        assert_eq!(
            target_access, FILE_READ_ATTRIBUTES,
            "regular targets must not receive traversal or execution access"
        );
    }

    #[cfg(windows)]
    #[test]
    fn indeterminate_and_remote_drive_types_fail_closed() {
        use windows_sys::Win32::System::WindowsProgramming::{
            DRIVE_FIXED, DRIVE_NO_ROOT_DIR, DRIVE_REMOTE, DRIVE_UNKNOWN,
        };

        assert!(platform::validate_drive_type_for_test(DRIVE_FIXED).is_ok());
        assert!(platform::validate_drive_type_for_test(DRIVE_REMOTE).is_err());
        assert!(platform::validate_drive_type_for_test(DRIVE_UNKNOWN).is_err());
        assert!(platform::validate_drive_type_for_test(DRIVE_NO_ROOT_DIR).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn fresh_root_has_stable_identity_and_prepares_missing_without_creation() {
        let directory = tempdir().expect("tempdir");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let identity = root.identity();
        assert!(identity.volume_serial_number().is_some());
        assert!(identity.file_id().is_some());
        let target = root
            .prepare_target(Path::new("new.txt"))
            .expect("missing target preparation");
        assert_eq!(target.kind(), PreparedWorkspaceTargetKind::Missing);
        assert_eq!(target.parent_identity(), identity);
        assert!(target.target_identity().is_none());
        assert!(!directory.path().join("new.txt").exists());
    }

    #[cfg(windows)]
    #[test]
    fn existing_file_and_directory_are_classified_by_handle() {
        let directory = tempdir().expect("tempdir");
        fs::create_dir(directory.path().join("nested")).expect("nested");
        fs::write(directory.path().join("file.txt"), b"fixture").expect("file");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let file = root
            .prepare_target(Path::new("file.txt"))
            .expect("file prepare");
        let nested = root
            .prepare_target(Path::new("nested"))
            .expect("directory prepare");
        assert_eq!(file.kind(), PreparedWorkspaceTargetKind::ExistingFile);
        assert_eq!(
            nested.kind(),
            PreparedWorkspaceTargetKind::ExistingDirectory
        );
        assert!(file.target_identity().is_some());
        assert!(nested.target_identity().is_some());
    }

    #[cfg(windows)]
    #[test]
    fn repeated_successful_preparations_do_not_report_spurious_busy_or_change_identity() {
        let directory = tempdir().expect("tempdir");
        fs::write(directory.path().join("file.txt"), b"fixture").expect("file");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let first = root
            .prepare_target(Path::new("file.txt"))
            .expect("first preparation");
        let identity = first.target_identity();
        for _ in 0..64 {
            let next = root
                .prepare_target(Path::new("file.txt"))
                .expect("back-to-back preparation");
            assert_eq!(next.kind(), PreparedWorkspaceTargetKind::ExistingFile);
            assert_eq!(next.target_identity(), identity);
        }
    }

    #[cfg(windows)]
    #[test]
    fn root_reparse_point_is_rejected() {
        let directory = tempdir().expect("tempdir");
        let outside = tempdir().expect("outside");
        let link = directory.path().join("root-link");
        native_dir_symlink(&link, outside.path());
        assert!(TrustedWorkspaceRoot::acquire(&link).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn acquisition_ancestor_replacement_race_fails_closed() {
        let directory = tempdir().expect("directory");
        let outside = tempdir().expect("outside");
        let parent = directory.path().join("parent");
        let requested = parent.join("workspace");
        let moved_parent = directory.path().join("parent-old");
        fs::create_dir(&parent).expect("parent");
        fs::create_dir(&requested).expect("workspace");

        let result = platform::acquire_root_with_hook(&requested, || {
            fs::rename(&parent, &moved_parent).expect("rename ancestor");
            native_dir_symlink(&parent, outside.path());
        });

        assert!(
            result.is_err(),
            "an ancestor replaced after anchor acquisition must not redirect the walk"
        );
    }

    #[cfg(windows)]
    #[test]
    fn intermediate_and_final_reparse_points_are_rejected() {
        let directory = tempdir().expect("tempdir");
        let outside = tempdir().expect("outside");
        fs::create_dir(directory.path().join("real")).expect("real");
        let intermediate = directory.path().join("intermediate-link");
        native_dir_symlink(&intermediate, outside.path());
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        assert!(root
            .prepare_target(Path::new("intermediate-link\\file.txt"))
            .is_err());

        let final_link = directory.path().join("final-link");
        native_dir_symlink(&final_link, outside.path());
        assert!(root.prepare_target(Path::new("final-link")).is_err());

        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, b"outside fixture").expect("outside file");
        let final_file_link = directory.path().join("final-file-link");
        native_file_symlink(&final_file_link, &outside_file);
        assert!(root.prepare_target(Path::new("final-file-link")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn case_normalization_is_allowed_for_same_identity() {
        let directory = tempdir().expect("tempdir");
        fs::write(directory.path().join("Case.txt"), b"fixture").expect("file");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let target = root
            .prepare_target(Path::new("case.TXT"))
            .expect("case-insensitive target");
        assert_eq!(target.kind(), PreparedWorkspaceTargetKind::ExistingFile);
    }

    #[cfg(windows)]
    #[test]
    fn root_rename_is_denied_until_root_capability_drops() {
        let directory = tempdir().expect("tempdir");
        let requested = directory.path().join("root");
        let replacement = directory.path().join("replacement");
        fs::create_dir(&requested).expect("root");
        let root = TrustedWorkspaceRoot::acquire(&requested).expect("acquire root");
        let identity = root.identity();
        let final_path = root.final_path().to_path_buf();
        assert!(
            fs::rename(&requested, &replacement).is_err(),
            "the retained root capability must block rename while alive"
        );
        assert!(root.verify_named_path_current().is_ok());
        assert_eq!(root.identity(), identity);
        assert_eq!(root.final_path(), final_path.as_path());

        drop(root);
        fs::rename(&requested, &replacement).expect("rename after root capability drop");
    }

    #[cfg(windows)]
    #[test]
    fn root_identity_mismatch_fails_closed() {
        let directory = tempdir().expect("directory");
        let requested = directory.path().join("root");
        let other = directory.path().join("other");
        fs::create_dir(&requested).expect("root");
        fs::create_dir(&other).expect("other");
        let root = TrustedWorkspaceRoot::acquire(&requested).expect("acquire root");
        let rebound = platform::root_with_requested_path_for_test(&root, other);

        assert!(
            rebound.verify_named_path_current().is_err(),
            "a different current name must not validate against the held identity"
        );
    }

    #[cfg(windows)]
    #[test]
    fn intermediate_replacement_cannot_escape_handle_walk() {
        let directory = tempdir().expect("tempdir");
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).expect("nested");
        fs::write(nested.join("secret.txt"), b"nested fixture").expect("nested fixture");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");

        let replacement = directory.path().join("nested-old");
        let prepared = platform::prepare_target_with_hook(
            &root,
            WorkspaceRelativePath::parse(Path::new("nested\\secret.txt")).expect("relative"),
            || {
                assert!(
                    fs::rename(&nested, &replacement).is_err(),
                    "the retained parent capability must block intermediate rename"
                );
            },
        )
        .expect("handle-relative preparation");
        assert_eq!(prepared.kind(), PreparedWorkspaceTargetKind::ExistingFile);

        drop(prepared);
        fs::rename(&nested, &replacement).expect("rename after parent capability drop");
        assert!(!directory.path().join("secret.txt").exists());
    }

    #[cfg(windows)]
    #[test]
    fn prepared_parent_rename_is_denied_until_preparation_drops() {
        let directory = tempdir().expect("directory");
        let nested = directory.path().join("nested");
        let moved = directory.path().join("nested-moved");
        fs::create_dir(&nested).expect("nested");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("nested\\new.txt"))
            .expect("missing target preparation");

        assert!(
            fs::rename(&nested, &moved).is_err(),
            "the retained prepared parent must block rename while alive"
        );
        drop(prepared);
        fs::rename(&nested, &moved).expect("rename after prepared parent drop");
    }

    #[cfg(windows)]
    #[test]
    fn existing_target_metadata_capability_allows_external_rename() {
        let directory = tempdir().expect("directory");
        let target = directory.path().join("target.txt");
        let moved = directory.path().join("target-moved.txt");
        fs::write(&target, b"fixture").expect("target");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("target.txt"))
            .expect("target preparation");

        fs::rename(&target, &moved).expect("metadata-only H2 handle permits rename");
        assert_eq!(prepared.kind(), PreparedWorkspaceTargetKind::ExistingFile);
        assert!(prepared.target_identity().is_some());
        drop(prepared);
        assert!(moved.exists());
    }

    #[cfg(windows)]
    #[test]
    fn existing_target_rebind_rejects_replacement_identity() {
        let directory = tempdir().expect("directory");
        let target = directory.path().join("a.txt");
        let moved = directory.path().join("old.txt");
        fs::write(&target, b"original").expect("original target");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("a.txt"))
            .expect("target preparation");
        assert!(prepared.target_identity().is_some());

        fs::rename(&target, &moved).expect("rename original target");
        fs::write(&target, b"replacement").expect("replacement target");

        assert!(
            platform::rebind_existing_target_for_test(&prepared).is_err(),
            "a replacement at the same relative name must fail identity rebind"
        );
    }

    #[cfg(windows)]
    #[test]
    fn existing_target_rebind_rejects_renamed_away_name() {
        let directory = tempdir().expect("directory");
        let target = directory.path().join("a.txt");
        let moved = directory.path().join("old.txt");
        fs::write(&target, b"original").expect("original target");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("a.txt"))
            .expect("target preparation");

        fs::rename(&target, &moved).expect("rename original target");

        assert!(
            platform::rebind_existing_target_for_test(&prepared).is_err(),
            "a renamed-away target must fail identity rebind as missing"
        );
    }

    #[cfg(windows)]
    #[test]
    fn existing_target_rebind_accepts_unchanged_identity() {
        let directory = tempdir().expect("directory");
        let target = directory.path().join("a.txt");
        fs::write(&target, b"original").expect("original target");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("a.txt"))
            .expect("target preparation");
        let expected_identity = prepared.target_identity().expect("target identity");

        let rebound_identity =
            platform::rebind_existing_target_for_test(&prepared).expect("unchanged target rebind");
        assert_eq!(rebound_identity, expected_identity);
    }

    #[cfg(windows)]
    #[test]
    fn parent_identity_mismatch_fails_closed() {
        let directory = tempdir().expect("directory");
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).expect("nested");
        fs::write(nested.join("file.txt"), b"fixture").expect("file");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let relative =
            WorkspaceRelativePath::parse(Path::new("nested\\file.txt")).expect("relative");

        assert!(
            platform::verify_parent_identities_for_test(
                &root,
                &relative,
                &[root.identity(), root.identity()]
            )
            .is_err(),
            "a changed parent identity must fail closed"
        );
    }

    #[cfg(windows)]
    #[test]
    fn target_identity_mismatch_fails_closed() {
        let directory = tempdir().expect("directory");
        let target = directory.path().join("target.txt");
        fs::write(&target, b"fixture").expect("target");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let relative = WorkspaceRelativePath::parse(Path::new("target.txt")).expect("relative");

        assert!(
            platform::verify_target_identity_for_test(&root, &relative, root.identity()).is_err(),
            "a changed target identity must fail closed"
        );
    }

    #[cfg(windows)]
    #[test]
    fn hard_link_identity_is_explicitly_shared_inode_semantics() {
        let directory = tempdir().expect("tempdir");
        let inside = directory.path().join("inside.txt");
        let alias = directory.path().join("alias.txt");
        fs::write(&inside, b"fixture").expect("inside fixture");
        fs::hard_link(&inside, &alias).expect("hard link");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("inside.txt"))
            .expect("prepare");
        assert_eq!(prepared.kind(), PreparedWorkspaceTargetKind::ExistingFile);
        assert!(prepared.target_identity().is_some());
        // H2 prevents reparse traversal, not a second hard-link pathname for
        // the same inode.  A future creation policy must address that alias
        // explicitly when it needs a new object rather than an identity.
    }
}
