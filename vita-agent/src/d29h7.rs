//! D29-H7-A governed no-shell process supervisor.
//!
//! The module is deliberately test/integration-only. The only model-visible
//! process is a Host-catalogued fixture. It compiles a strict logical request,
//! obtains a non-serializable ProcessGrant through the independent D28 Host
//! fixture, and launches the retained executable image directly with the
//! Windows process API.

#![allow(dead_code, private_interfaces)]

use codex_extension_api::{
    parse_tool_input_schema, JsonToolOutput, ResponsesApiTool, ToolCall, ToolContributor,
    ToolExecutor, ToolExecutorFuture, ToolName, ToolOutput, ToolSpec,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::sync::Notify;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetHandleInformation, GetLastError, SetHandleInformation,
    DUPLICATE_SAME_ACCESS, ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING,
    ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, FALSE, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE,
    UNICODE_STRING, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, GetFileInformationByHandle, ReadFile, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, OPEN_EXISTING, PIPE_ACCESS_INBOUND,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
    GetExitCodeProcess, InitializeProcThreadAttributeList, ResetEvent, ResumeThread,
    TerminateProcess, UpdateProcThreadAttribute, WaitForMultipleObjects, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_REMOTE;
use windows_sys::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, IO_STATUS_BLOCK, OVERLAPPED,
};

use crate::{sha256_hex, TrustedWorkspaceRoot, VitaExecutionContext, WorkspaceRootIdentity};

pub(crate) const VITA_PROCESS_RUN_TOOL_NAME: &str = "vita_run_process";
const H7_CAPABILITY_ID: &str = "vita.process.run";
const H7B_CAPABILITY_ID: &str = "vita.process.workspace.run";
const H7C_CAPABILITY_ID: &str = "vita.process.workspace.git_status";
const H7_PROGRAM_ID: &str = "d29h7_fixture";
const H7B_TOOL_NAME: &str = "vita_workspace_process_probe";
const H7C_TOOL_NAME: &str = "vita_workspace_git_status";
const H7C_PROFILE_ID: &str = "d29h7c.git.status.v1";
const H7_MAX_ARGS: usize = 16;
const H7_MAX_ARG_BYTES: usize = 1024;
const H7_STDOUT_BOUND: usize = 65_536;
const H7_STDERR_BOUND: usize = 65_536;
const H7_MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const H7_TIMEOUT: Duration = Duration::from_millis(500);
const H7_CONFIRMATION_TIMEOUT: Duration = Duration::from_millis(300);
const H7_HOST_IPC_TIMEOUT: Duration = Duration::from_secs(2);
const H7_HOST_MAX_FRAME_BYTES: usize = 64 * 1024;
const H7_TURN_TIMEOUT: Duration = Duration::from_secs(30);
const H7_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const H7_MAX_QUARANTINED_OUTPUT: usize = 2;
const H7_MAX_QUARANTINED_CONNECT: usize = 1;
const H7_MAX_QUARANTINED_IO: usize = H7_MAX_QUARANTINED_OUTPUT + H7_MAX_QUARANTINED_CONNECT;
const H7_HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const H7_HTTP_MAX_BODY: usize = 2 * 1024 * 1024;
const H7_TEST_STACK_SIZE: usize = 32 * 1024 * 1024;
const H7_LIFE_ID: &str = "life-d29h7-a";
const H7_TASK_ID: &str = "task-d29h7-a";
const H7_MODEL: &str = "d29h7-local-responses-model";
const H7_PROVIDER_ID: &str = "d29h7-loopback-responses";
const H7_PROMPT: &str = "Run the bounded fixture process.";
const H7_REPLY: &str = "D29-H7 process completed";
const H7_ENV_ALLOWLIST_KEY: &str = "D29H7_FIXTURE_ALLOWLIST";
const H7_ENV_ALLOWLIST_VALUE: &str = "fixture-v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct H7ProcessArguments {
    program: String,
    args: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H7ProcessRequest {
    tool_call_id: String,
    turn_id: String,
    program: String,
    args: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H7RequestError {
    InvalidRequest,
}

impl H7ProcessRequest {
    fn from_codex_call(call: &ToolCall<'_>) -> Result<Self, H7RequestError> {
        if call.tool_name.name != VITA_PROCESS_RUN_TOOL_NAME
            || !call.tool_name.is_default_namespace()
        {
            return Err(H7RequestError::InvalidRequest);
        }
        let tool_call_id = bounded_id(&call.call_id).ok_or(H7RequestError::InvalidRequest)?;
        let turn_id = bounded_id(&call.turn_id).ok_or(H7RequestError::InvalidRequest)?;
        let arguments = call
            .function_arguments()
            .map_err(|_| H7RequestError::InvalidRequest)?;
        let arguments: H7ProcessArguments =
            serde_json::from_str(arguments).map_err(|_| H7RequestError::InvalidRequest)?;
        Self::from_arguments(tool_call_id, turn_id, arguments)
    }

    fn from_arguments(
        tool_call_id: String,
        turn_id: String,
        arguments: H7ProcessArguments,
    ) -> Result<Self, H7RequestError> {
        if arguments.program != H7_PROGRAM_ID
            || arguments.args.len() > H7_MAX_ARGS
            || arguments
                .args
                .iter()
                .any(|arg| arg.as_bytes().len() > H7_MAX_ARG_BYTES || arg.contains('\0'))
        {
            return Err(H7RequestError::InvalidRequest);
        }
        Ok(Self {
            tool_call_id,
            turn_id,
            program: arguments.program,
            args: arguments.args,
        })
    }

    fn synthetic(call_id: &str, turn_id: &str, args: &[&str]) -> Self {
        Self {
            tool_call_id: call_id.to_string(),
            turn_id: turn_id.to_string(),
            program: H7_PROGRAM_ID.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
        }
    }
}

fn bounded_id(value: &str) -> Option<String> {
    (!value.is_empty() && value.chars().count() <= 256 && !value.chars().any(char::is_control))
        .then(|| value.to_string())
}

fn h7_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u64::MAX as u128) as u64
        })
}

fn h7_workspace_identity_wire(identity: WorkspaceRootIdentity) -> String {
    let volume = identity.volume_serial_number().unwrap_or_default();
    let file_id = identity
        .file_id()
        .map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .unwrap_or_else(|| "none".to_string());
    format!("v{volume:x}f{file_id}")
}

fn h7_workspace_path_key(path: &Path) -> String {
    let path = path.to_string_lossy();
    let path = path.strip_prefix("\\\\?\\").unwrap_or(&path);
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn h7_workspace_paths_equal(left: &Path, right: &Path) -> bool {
    h7_workspace_path_key(left) == h7_workspace_path_key(right)
}

fn h7_process_schema_contract() -> Value {
    json!({
        "type": "object",
        "properties": {
            "program": {"type": "string", "enum": [H7_PROGRAM_ID]},
            "args": {
                "type": "array",
                "maxItems": H7_MAX_ARGS,
                "items": {"type": "string", "maxLength": H7_MAX_ARG_BYTES}
            }
        },
        "required": ["program", "args"],
        "additionalProperties": false
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct H7ImageIdentity {
    volume_serial: u32,
    file_index: u64,
    file_size: u64,
}

impl H7ImageIdentity {
    fn wire(self) -> String {
        format!(
            "{:08x}-{:016x}-{:016x}",
            self.volume_serial, self.file_index, self.file_size
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct H7NamespaceIdentity {
    volume_serial: u32,
    file_index: u64,
    directory: bool,
    reparse: bool,
}

impl H7NamespaceIdentity {
    fn wire(self) -> String {
        format!(
            "{}-{:08x}-{:016x}",
            if self.directory { "directory" } else { "file" },
            self.volume_serial,
            self.file_index
        )
    }
}

struct H7PreparedNamespace {
    path: PathBuf,
    parent: Arc<H7Handle>,
    leaf: Arc<H7Handle>,
    leaf_name: OsString,
    identity: H7NamespaceIdentity,
    chain: Vec<Arc<H7Handle>>,
}

impl H7PreparedNamespace {
    fn prepare(path: &Path, directory: bool) -> Result<Self, String> {
        if !path.is_absolute() || path.to_string_lossy().starts_with("\\\\") {
            return Err("H7 namespace path was not an absolute local path".to_string());
        }
        let mut normal_components = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) if matches!(prefix.kind(), Prefix::Disk(_)) => {}
                Component::RootDir => {}
                Component::Normal(value) => normal_components.push(value.to_os_string()),
                _ => return Err("H7 namespace path contained an unsafe component".to_string()),
            }
        }
        let drive_letter = match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) => letter,
                _ => return Err("H7 namespace path had no local drive anchor".to_string()),
            },
            _ => return Err("H7 namespace path had no explicit local drive anchor".to_string()),
        };
        if normal_components.is_empty() {
            return Err("H7 namespace path had no leaf component".to_string());
        }
        let drive_root = PathBuf::from(format!("{}:\\", drive_letter as char));
        let drive_type = unsafe { GetDriveTypeW(wide_null(drive_root.as_os_str()).as_ptr()) };
        if drive_type == DRIVE_REMOTE {
            return Err("H7 namespace path was on a remote drive".to_string());
        }
        let root = open_namespace_drive_anchor(&drive_root)?;
        let mut chain = vec![Arc::new(root)];
        let mut parent = Arc::clone(chain.last().expect("H7 drive anchor"));
        let leaf_name = normal_components
            .last()
            .cloned()
            .expect("H7 namespace leaf");
        for (index, component) in normal_components.iter().enumerate() {
            let is_leaf = index + 1 == normal_components.len();
            let handle = Arc::new(if is_leaf && !directory {
                open_namespace_relative_executable_leaf(&parent, component)?
            } else {
                open_namespace_relative_directory(&parent, component)?
            });
            let identity = namespace_identity(handle.raw())?;
            if identity.reparse || identity.directory != (if is_leaf { directory } else { true }) {
                return Err("H7 namespace component was reparse or wrong kind".to_string());
            }
            if is_leaf {
                return Ok(Self {
                    path: path.to_path_buf(),
                    parent,
                    leaf: handle,
                    leaf_name,
                    identity,
                    chain,
                });
            }
            chain.push(Arc::clone(&handle));
            parent = handle;
        }
        Err("H7 namespace leaf acquisition failed".to_string())
    }

    fn rebind_leaf(&self) -> Result<Arc<H7Handle>, String> {
        let handle = Arc::new(if self.identity.directory {
            open_namespace_relative_directory(&self.parent, &self.leaf_name)?
        } else {
            open_namespace_relative_executable_leaf(&self.parent, &self.leaf_name)?
        });
        let identity = namespace_identity(handle.raw())?;
        if identity != self.identity || identity.reparse {
            return Err("H7 namespace leaf identity changed".to_string());
        }
        Ok(handle)
    }

    fn identity(&self) -> H7NamespaceIdentity {
        self.identity
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

struct PreparedExecutableNamespace(H7PreparedNamespace);

impl PreparedExecutableNamespace {
    fn prepare(path: &Path) -> Result<Self, String> {
        Ok(Self(H7PreparedNamespace::prepare(path, false)?))
    }

    fn rebind_leaf(&self) -> Result<Arc<H7Handle>, String> {
        self.0.rebind_leaf()
    }

    fn identity(&self) -> H7NamespaceIdentity {
        self.0.identity()
    }
}

struct PreparedWorkingDirectory(H7PreparedNamespace);

impl PreparedWorkingDirectory {
    fn prepare(path: &Path) -> Result<Self, String> {
        Ok(Self(H7PreparedNamespace::prepare(path, true)?))
    }

    fn rebind_leaf(&self) -> Result<Arc<H7Handle>, String> {
        self.0.rebind_leaf()
    }

    fn identity(&self) -> H7NamespaceIdentity {
        self.0.identity()
    }

    fn path(&self) -> &Path {
        self.0.path()
    }
}

struct PreparedExecutableImage {
    file: File,
    path: PathBuf,
    namespace: Arc<PreparedExecutableNamespace>,
    identity: H7ImageIdentity,
    sha256: String,
}

impl PreparedExecutableImage {
    fn prepare(path: &Path) -> Result<Self, String> {
        let namespace = Arc::new(PreparedExecutableNamespace::prepare(path)?);
        let file = duplicate_file_handle(namespace.0.leaf.raw())?;
        let identity = file_identity(&file)?;
        if identity.file_size == 0 {
            return Err("H7 executable image was empty".to_string());
        }
        let sha256 = hash_file(&file)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            namespace,
            identity,
            sha256,
        })
    }

    fn reverify(&mut self, expected: H7ImageIdentity, expected_sha256: &str) -> Result<(), String> {
        let identity = file_identity(&self.file)?;
        let sha256 = hash_file(&self.file)?;
        if identity != expected
            || sha256 != expected_sha256
            || self.namespace.rebind_leaf().is_err()
        {
            return Err("H7 retained executable image evidence changed".to_string());
        }
        Ok(())
    }

    fn reverify_identity(
        &self,
        expected: H7ImageIdentity,
        expected_namespace: H7NamespaceIdentity,
    ) -> Result<Arc<H7Handle>, String> {
        let identity = file_identity(&self.file)?;
        if identity != expected || self.namespace.identity() != expected_namespace {
            return Err("H7 retained executable identity changed".to_string());
        }
        self.namespace.rebind_leaf()
    }
}

fn duplicate_file_handle(handle: HANDLE) -> Result<File, String> {
    let mut duplicate = std::ptr::null_mut();
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 || duplicate.is_null() || duplicate == INVALID_HANDLE_VALUE {
        return Err(format!(
            "H7 executable handle duplication failed: {}",
            unsafe { GetLastError() }
        ));
    }
    Ok(unsafe { File::from_raw_handle(duplicate as RawHandle) })
}

fn open_namespace_drive_anchor(path: &Path) -> Result<H7Handle, String> {
    let handle = unsafe {
        CreateFileW(
            wide_null(path.as_os_str()).as_ptr(),
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    let handle = H7Handle::new(handle)?;
    let identity = namespace_identity(handle.raw())?;
    if !identity.directory || identity.reparse {
        return Err("H7 local drive anchor was not a non-reparse directory".to_string());
    }
    Ok(handle)
}

fn open_namespace_relative_directory(
    parent: &Arc<H7Handle>,
    component: &OsStr,
) -> Result<H7Handle, String> {
    open_namespace_relative_with_share(parent, component, true, FILE_SHARE_READ | FILE_SHARE_WRITE)
}

fn open_namespace_relative_executable_leaf(
    parent: &Arc<H7Handle>,
    component: &OsStr,
) -> Result<H7Handle, String> {
    open_namespace_relative_with_share(parent, component, false, FILE_SHARE_READ)
}

fn open_namespace_relative_with_share(
    parent: &Arc<H7Handle>,
    component: &OsStr,
    directory: bool,
    share_access: u32,
) -> Result<H7Handle, String> {
    let mut name = component.encode_wide().collect::<Vec<_>>();
    let byte_length = name
        .len()
        .checked_mul(2)
        .ok_or_else(|| "H7 namespace component was too long".to_string())?;
    if byte_length > u16::MAX as usize {
        return Err("H7 namespace component was too long".to_string());
    }
    let unicode_name = UNICODE_STRING {
        Length: byte_length as u16,
        MaximumLength: byte_length as u16,
        Buffer: name.as_mut_ptr(),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.raw(),
        ObjectName: &unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let desired_access = if directory {
        FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE
    } else {
        FILE_GENERIC_READ | SYNCHRONIZE
    };
    let create_options = if directory {
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
    } else {
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut raw = std::ptr::null_mut();
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            desired_access,
            &object_attributes,
            &mut status_block,
            std::ptr::null(),
            0,
            share_access,
            FILE_OPEN,
            create_options,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 || raw.is_null() || raw == INVALID_HANDLE_VALUE {
        if !raw.is_null() && raw != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(raw);
            }
        }
        return Err(format!(
            "H7 handle-relative namespace open failed: {status}"
        ));
    }
    let handle = H7Handle::new(raw)?;
    let _ = namespace_identity(handle.raw())?;
    Ok(handle)
}

fn namespace_identity(handle: HANDLE) -> Result<H7NamespaceIdentity, String> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        return Err(format!("H7 namespace identity read failed: {}", unsafe {
            GetLastError()
        }));
    }
    Ok(H7NamespaceIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        directory: information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        reparse: information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
    })
}

fn file_identity(file: &File) -> Result<H7ImageIdentity, String> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let ok =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) };
    if ok == 0 {
        return Err(format!("H7 executable identity read failed: {}", unsafe {
            GetLastError()
        }));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err("H7 executable image was not a non-reparse regular file".to_string());
    }
    Ok(H7ImageIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        file_size: (u64::from(information.nFileSizeHigh) << 32)
            | u64::from(information.nFileSizeLow),
    })
}

fn hash_file(file: &File) -> Result<String, String> {
    let mut file = file
        .try_clone()
        .map_err(|_| "H7 executable hash handle clone failed".to_string())?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "H7 executable hash seek failed".to_string())?;
    let mut total = 0_u64;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|_| "H7 executable hash read failed".to_string())?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > H7_MAX_EXECUTABLE_BYTES {
            return Err("H7 executable image exceeded its hard hash bound".to_string());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(sha256_hex(&bytes))
}

struct H7CatalogEntry {
    program_id: String,
    image_path: PathBuf,
    expected_image_identity: H7ImageIdentity,
    expected_image_namespace: H7NamespaceIdentity,
    expected_image_sha256: String,
    working_directory: Arc<PreparedWorkingDirectory>,
    working_directory_identity: String,
    environment: BTreeMap<String, String>,
    environment_policy_hash: String,
    timeout: Duration,
    stdout_bound: usize,
    stderr_bound: usize,
}

struct H7ExecutableCatalog {
    entry: H7CatalogEntry,
}

impl H7ExecutableCatalog {
    fn fixture(image_path: PathBuf, working_directory: PathBuf) -> Result<Self, String> {
        if !image_path.is_absolute() || !working_directory.is_absolute() {
            return Err("H7 catalog paths must be absolute".to_string());
        }
        let working_directory = Arc::new(PreparedWorkingDirectory::prepare(&working_directory)?);
        let mut image = PreparedExecutableImage::prepare(&image_path)?;
        let expected_image_identity = image.identity;
        let expected_image_namespace = image.namespace.identity();
        let expected_image_sha256 = image.sha256.clone();
        let expected_working_directory_identity = working_directory.0.identity();
        let environment = BTreeMap::from([(
            H7_ENV_ALLOWLIST_KEY.to_string(),
            H7_ENV_ALLOWLIST_VALUE.to_string(),
        )]);
        let environment_policy_hash = sha256_hex(&environment_policy_bytes(&environment));
        image
            .reverify(expected_image_identity, &expected_image_sha256)
            .map_err(|error| format!("H7 catalog image proof failed: {error}"))?;
        Ok(Self {
            entry: H7CatalogEntry {
                program_id: H7_PROGRAM_ID.to_string(),
                image_path,
                expected_image_identity,
                expected_image_namespace,
                expected_image_sha256,
                working_directory_identity: expected_working_directory_identity.wire(),
                working_directory,
                environment,
                environment_policy_hash,
                timeout: H7_TIMEOUT,
                stdout_bound: H7_STDOUT_BOUND,
                stderr_bound: H7_STDERR_BOUND,
            },
        })
    }

    fn prepare_action(
        &self,
        context: VitaExecutionContext,
        request: H7ProcessRequest,
    ) -> Result<Arc<PreparedProcessAction>, String> {
        self.prepare_action_with_metadata(context, request, H7_CAPABILITY_ID, None)
    }

    fn prepare_workspace_action(
        &self,
        context: VitaExecutionContext,
        request: H7ProcessRequest,
        workspace_root: TrustedWorkspaceRoot,
    ) -> Result<Arc<PreparedProcessAction>, String> {
        if !h7_workspace_paths_equal(
            self.entry.working_directory.path(),
            workspace_root.final_path(),
        ) {
            return Err(
                "H7-B catalog working directory was not the Host workspace root".to_string(),
            );
        }
        self.prepare_action_with_metadata(context, request, H7B_CAPABILITY_ID, Some(workspace_root))
    }

    fn prepare_action_without_workspace_scope_for_test(
        &self,
        context: VitaExecutionContext,
        request: H7ProcessRequest,
    ) -> Result<Arc<PreparedProcessAction>, String> {
        self.prepare_action_with_metadata(context, request, H7B_CAPABILITY_ID, None)
    }

    fn prepare_action_with_metadata(
        &self,
        context: VitaExecutionContext,
        request: H7ProcessRequest,
        capability_id: &str,
        workspace_root: Option<TrustedWorkspaceRoot>,
    ) -> Result<Arc<PreparedProcessAction>, String> {
        if request.program != self.entry.program_id {
            return Err("H7 program was not in the Host-owned catalog".to_string());
        }
        let image = PreparedExecutableImage::prepare(&self.entry.image_path)?;
        if image.identity != self.entry.expected_image_identity
            || image.namespace.identity() != self.entry.expected_image_namespace
            || image.sha256 != self.entry.expected_image_sha256
        {
            return Err("H7 executable image did not match the immutable catalog".to_string());
        }
        let mut argv = Vec::with_capacity(request.args.len() + 1);
        argv.push(self.entry.image_path.to_string_lossy().into_owned());
        argv.extend(request.args.iter().cloned());
        let argv_hash = sha256_hex(
            &serde_json::to_vec(&request.args)
                .map_err(|_| "H7 argv binding serialization failed".to_string())?,
        );
        let workspace_root_identity = workspace_root.as_ref().map(|root| root.identity());
        Ok(Arc::new(PreparedProcessAction {
            context,
            tool_call_id: request.tool_call_id,
            turn_id: request.turn_id,
            capability_id: capability_id.to_string(),
            program_id: request.program,
            image: Mutex::new(image),
            executable_namespace_identity: self.entry.expected_image_namespace,
            argv,
            argv_hash,
            argv_count: request.args.len(),
            working_directory: self.entry.working_directory.clone(),
            working_directory_identity: self.entry.working_directory_identity.clone(),
            environment: self.entry.environment.clone(),
            environment_policy_hash: self.entry.environment_policy_hash.clone(),
            timeout: self.entry.timeout,
            stdout_bound: self.entry.stdout_bound,
            stderr_bound: self.entry.stderr_bound,
            workspace_root,
            workspace_root_identity,
            profile_id: None,
        }))
    }
}

struct PreparedProcessAction {
    context: VitaExecutionContext,
    tool_call_id: String,
    turn_id: String,
    capability_id: String,
    program_id: String,
    image: Mutex<PreparedExecutableImage>,
    executable_namespace_identity: H7NamespaceIdentity,
    argv: Vec<String>,
    argv_hash: String,
    argv_count: usize,
    working_directory: Arc<PreparedWorkingDirectory>,
    working_directory_identity: String,
    environment: BTreeMap<String, String>,
    environment_policy_hash: String,
    timeout: Duration,
    stdout_bound: usize,
    stderr_bound: usize,
    workspace_root: Option<TrustedWorkspaceRoot>,
    workspace_root_identity: Option<WorkspaceRootIdentity>,
    profile_id: Option<String>,
}

impl PreparedProcessAction {
    fn binding(&self) -> H7ProcessBinding {
        let image = self
            .image
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        H7ProcessBinding {
            life_id: self.context.life_id().to_string(),
            task_id: self.context.task_id().to_string(),
            capability_id: self.capability_id.clone(),
            program_id: self.program_id.clone(),
            executable_identity: image.identity.wire(),
            executable_sha256: image.sha256.clone(),
            argv_hash: self.argv_hash.clone(),
            argv_count: self.argv_count,
            working_directory_identity: self.working_directory_identity.clone(),
            environment_policy_hash: self.environment_policy_hash.clone(),
            stdout_bound: self.stdout_bound,
            stderr_bound: self.stderr_bound,
            timeout_ms: self.timeout.as_millis().min(u64::MAX as u128) as u64,
            tool_call_id: self.tool_call_id.clone(),
            turn_id: self.turn_id.clone(),
            workspace_root_identity: self.workspace_root_identity.map(h7_workspace_identity_wire),
            profile_id: self.profile_id.clone(),
        }
    }
}

fn verify_workspace_root_binding(action: &PreparedProcessAction) -> Result<(), String> {
    let workspace_capability = matches!(
        action.capability_id.as_str(),
        H7B_CAPABILITY_ID | H7C_CAPABILITY_ID
    );
    if !workspace_capability {
        if action.workspace_root.is_some() || action.workspace_root_identity.is_some() {
            return Err(
                "H7 workspace root evidence appeared on a non-workspace action".to_string(),
            );
        }
        return Ok(());
    }

    let root = action
        .workspace_root
        .as_ref()
        .ok_or_else(|| "H7-B workspace scope was not Host-owned".to_string())?;
    let root_identity = root.identity();
    if action.workspace_root_identity != Some(root_identity)
        || !h7_workspace_paths_equal(action.working_directory.path(), root.final_path())
    {
        return Err("H7-B workspace root and cwd binding did not match".to_string());
    }
    root.verify_named_path_current()
        .map_err(|_| "H7-B workspace root named path changed".to_string())
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn environment_block(environment: &BTreeMap<String, String>) -> Vec<u16> {
    let mut block = Vec::new();
    for (key, value) in environment {
        block.extend(OsStr::new(&format!("{key}={value}")).encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

fn environment_policy_bytes(environment: &BTreeMap<String, String>) -> Vec<u8> {
    environment_block(environment)
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn quote_windows_arg(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character == ' ' || character == '\t' || character == '"')
    {
        return argument.to_string();
    }
    let mut output = String::from("\"");
    let mut backslashes = 0usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            output.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            output.push('"');
            backslashes = 0;
        } else {
            output.extend(std::iter::repeat_n('\\', backslashes));
            output.push(character);
            backslashes = 0;
        }
    }
    output.extend(std::iter::repeat_n('\\', backslashes * 2));
    output.push('"');
    output
}

fn argv_to_command_line(argv: &[String]) -> Vec<u16> {
    let command_line = argv
        .iter()
        .map(|argument| quote_windows_arg(argument))
        .collect::<Vec<_>>()
        .join(" ");
    wide_null(OsStr::new(&command_line))
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct H7ProcessBinding {
    life_id: String,
    task_id: String,
    capability_id: String,
    program_id: String,
    executable_identity: String,
    executable_sha256: String,
    argv_hash: String,
    argv_count: usize,
    working_directory_identity: String,
    environment_policy_hash: String,
    stdout_bound: usize,
    stderr_bound: usize,
    timeout_ms: u64,
    tool_call_id: String,
    turn_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workspace_root_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_id: Option<String>,
}

impl H7ProcessBinding {
    fn from_action(action: &PreparedProcessAction) -> Self {
        action.binding()
    }
}

struct H7Handle(HANDLE);

impl H7Handle {
    fn new(handle: HANDLE) -> Result<Self, String> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(format!("H7 native handle creation failed: {}", unsafe {
                GetLastError()
            }))
        } else {
            Ok(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }

    fn into_raw(self) -> HANDLE {
        let handle = self.0;
        std::mem::forget(self);
        handle
    }
}

impl Drop for H7Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

// A H7 handle is an owned process-local kernel reference.  It is moved, never
// cloned, across the bounded blocking launch fence; Arc is used only for the
// retained namespace chain and closes the handle exactly once.
unsafe impl Send for H7Handle {}
unsafe impl Sync for H7Handle {}

struct H7ProcThreadAttributes {
    buffer: Vec<u8>,
    handles: Vec<HANDLE>,
}

impl H7ProcThreadAttributes {
    fn new(attribute_count: u32) -> Result<Self, String> {
        let mut size = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), attribute_count, 0, &mut size);
        }
        if size == 0 {
            return Err(format!(
                "H7 process attribute list size failed: {}",
                unsafe { GetLastError() }
            ));
        }
        let mut buffer = vec![0_u8; size];
        let result = unsafe {
            InitializeProcThreadAttributeList(
                buffer.as_mut_ptr().cast(),
                attribute_count,
                0,
                &mut size,
            )
        };
        if result == 0 {
            return Err(format!(
                "H7 process attribute list initialization failed: {}",
                unsafe { GetLastError() }
            ));
        }
        Ok(Self {
            buffer,
            handles: Vec::new(),
        })
    }

    fn pointer(&mut self) -> *mut c_void {
        self.buffer.as_mut_ptr().cast()
    }

    fn set_handle_list(&mut self, handles: Vec<HANDLE>) -> Result<(), String> {
        self.handles = handles;
        let result = unsafe {
            UpdateProcThreadAttribute(
                self.pointer().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                self.handles.as_ptr().cast(),
                std::mem::size_of_val(self.handles.as_slice()),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if result == 0 {
            return Err(format!(
                "H7 explicit handle-list attribute failed: {}",
                unsafe { GetLastError() }
            ));
        }
        Ok(())
    }
}

impl Drop for H7ProcThreadAttributes {
    fn drop(&mut self) {
        if !self.buffer.is_empty() {
            unsafe {
                DeleteProcThreadAttributeList(self.pointer().cast());
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H7LaunchPhase {
    NotStarted = 0,
    CreatedSuspended = 1,
    AssignedJob = 2,
    Resumed = 3,
    Exited = 4,
}

fn phase_at_least(phase: &AtomicU8, target: H7LaunchPhase) -> bool {
    phase.load(Ordering::Acquire) >= target as u8
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H7NativeLaunchFault {
    None,
    PanicBeforeCreateProcess,
    PanicAfterCreateProcess,
    ForceAssignmentFailure,
    ForceThreadHandleFailure,
}

#[derive(Default)]
struct H7SupervisorMetrics {
    process_created: AtomicUsize,
    job_assigned: AtomicUsize,
    thread_resumed: AtomicUsize,
    process_exited: AtomicUsize,
    process_exit_verified: AtomicUsize,
    jobs_terminated: AtomicUsize,
    job_termination_failures: AtomicUsize,
    direct_termination_attempted: AtomicUsize,
    direct_termination_verified: AtomicUsize,
    automatic_retries: AtomicUsize,
    process_tree_remaining: AtomicUsize,
    process_tree_observations: AtomicUsize,
    reader_threads_remaining: AtomicUsize,
    native_workers_active: AtomicUsize,
    native_workers_started: AtomicUsize,
    native_workers_finished: AtomicUsize,
    active_processes_peak: AtomicUsize,
    pending_output_reads: AtomicUsize,
    output_handles_active: AtomicUsize,
    created_notify: Notify,
    native_worker_finished_notify: Notify,
}

struct H7NativeWorkerGuard {
    metrics: Arc<H7SupervisorMetrics>,
}

impl H7NativeWorkerGuard {
    fn new(metrics: Arc<H7SupervisorMetrics>) -> Self {
        metrics
            .native_workers_started
            .fetch_add(1, Ordering::AcqRel);
        metrics.native_workers_active.fetch_add(1, Ordering::AcqRel);
        Self { metrics }
    }
}

impl Drop for H7NativeWorkerGuard {
    fn drop(&mut self) {
        self.metrics
            .native_workers_active
            .fetch_sub(1, Ordering::AcqRel);
        self.metrics
            .native_workers_finished
            .fetch_add(1, Ordering::AcqRel);
        self.metrics.native_worker_finished_notify.notify_waiters();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum H7NativeOutcomeKind {
    LaunchFailed,
    StartedAndExited,
    StartedAndTimedOut,
    StartedAndCancelled,
    StartedAndOutputLimited,
    StartedOutcomeUnknown,
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H7NativeResult {
    kind: H7NativeOutcomeKind,
    process_created: bool,
    user_code_started: bool,
    exit_code: Option<u32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    job_terminated: bool,
    process_tree_observed: bool,
    process_tree_remaining: usize,
    automatic_retry: bool,
    direct_termination_attempted: bool,
    direct_termination_verified: bool,
    process_exit_verified: bool,
    stdout_reader_joined: bool,
    stderr_reader_joined: bool,
    pending_stdout_reads: usize,
    pending_stderr_reads: usize,
    stdout_retained_bytes: usize,
    stderr_retained_bytes: usize,
}

const H7_OUTPUT_SCRATCH_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H7OverlappedState {
    Idle,
    Pending,
    CancelRequested,
    TerminalCompleted,
    TerminalCancelled,
    TerminalEof,
    TerminalError(u32),
}

impl H7OverlappedState {
    fn is_pending(self) -> bool {
        matches!(self, Self::Pending | Self::CancelRequested)
    }

    fn is_terminal(self) -> bool {
        !self.is_pending() && !matches!(self, Self::Idle)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H7OverlappedPoll {
    Pending,
    TerminalSuccess { transferred: u32 },
    TerminalCancelled,
    TerminalEof,
    Indeterminate(u32),
}

// ERROR_IO_PENDING is the successful return-side status for initiating an
// asynchronous ReadFile/ConnectNamedPipe operation.  Once the operation has
// been initiated, GetOverlappedResult(FALSE) uses ERROR_IO_INCOMPLETE to say
// that the kernel still owns the OVERLAPPED.  Keep this interpretation in one
// helper so no completion path can accidentally reuse the initiation status.
fn poll_h7_overlapped(handle: HANDLE, operation: &OVERLAPPED, pipe_read: bool) -> H7OverlappedPoll {
    let mut transferred = 0_u32;
    if unsafe { GetOverlappedResult(handle, operation, &mut transferred, FALSE) } != 0 {
        return H7OverlappedPoll::TerminalSuccess { transferred };
    }
    classify_h7_overlapped_error(unsafe { GetLastError() }, pipe_read)
}

fn classify_h7_overlapped_error(error: u32, pipe_read: bool) -> H7OverlappedPoll {
    match error {
        ERROR_IO_INCOMPLETE => H7OverlappedPoll::Pending,
        ERROR_OPERATION_ABORTED => H7OverlappedPoll::TerminalCancelled,
        ERROR_BROKEN_PIPE if pipe_read => H7OverlappedPoll::TerminalEof,
        error => H7OverlappedPoll::Indeterminate(error),
    }
}

#[derive(Default)]
struct H7TerminalityGate {
    cancel_requested: AtomicBool,
    allow_terminal: AtomicBool,
    cleanup_timeout_ms: AtomicUsize,
}

#[derive(Default)]
struct H7TerminalityProbe {
    drop_started: AtomicBool,
    drop_finished: AtomicBool,
    terminal_observed: AtomicBool,
}

#[derive(Default)]
struct H7ConnectTerminalityProbe {
    terminal_observed: AtomicBool,
    dropped: AtomicBool,
}

struct H7ConnectOperationOwner {
    read: H7Handle,
    event: H7Handle,
    operation: Box<OVERLAPPED>,
    state: H7OverlappedState,
    terminality_gate: Option<Arc<H7TerminalityGate>>,
    probe: Option<Arc<H7ConnectTerminalityProbe>>,
}

unsafe impl Send for H7ConnectOperationOwner {}

struct H7OverlappedConnect {
    owner: Option<H7ConnectOperationOwner>,
}

impl H7OverlappedConnect {
    fn new(read: H7Handle) -> Result<Self, String> {
        let event =
            H7Handle::new(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })?;
        if unsafe { SetHandleInformation(event.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(format!(
                "H7 overlapped connect event inheritance restriction failed: {}",
                unsafe { GetLastError() }
            ));
        }
        Ok(Self {
            owner: Some(H7ConnectOperationOwner {
                read,
                event,
                operation: Box::new(OVERLAPPED::default()),
                state: H7OverlappedState::Idle,
                terminality_gate: None,
                probe: None,
            }),
        })
    }

    #[cfg(test)]
    fn with_terminality_test_hooks(
        mut self,
        gate: Arc<H7TerminalityGate>,
        probe: Arc<H7ConnectTerminalityProbe>,
    ) -> Self {
        let owner = self.owner.as_mut().expect("H7 connect owner");
        owner.terminality_gate = Some(gate);
        owner.probe = Some(probe);
        self
    }

    fn owner(&self) -> &H7ConnectOperationOwner {
        self.owner.as_ref().expect("H7 connect owner exists")
    }

    fn owner_mut(&mut self) -> &mut H7ConnectOperationOwner {
        self.owner.as_mut().expect("H7 connect owner exists")
    }

    fn start(&mut self) -> Result<(), u32> {
        let owner = self.owner_mut();
        owner.operation = Box::new(OVERLAPPED {
            hEvent: owner.event.raw(),
            ..Default::default()
        });
        let connected =
            unsafe { ConnectNamedPipe(owner.read.raw(), owner.operation.as_mut()) } != 0;
        if connected {
            self.mark_terminal(H7OverlappedState::TerminalCompleted);
            return Ok(());
        }
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => {
                self.mark_terminal(H7OverlappedState::TerminalCompleted);
                Ok(())
            }
            ERROR_IO_PENDING => {
                self.owner_mut().state = H7OverlappedState::Pending;
                Ok(())
            }
            error => {
                self.mark_terminal(H7OverlappedState::TerminalError(error));
                Err(error)
            }
        }
    }

    fn pending(&self) -> bool {
        self.owner().state.is_pending()
    }

    fn error(&self) -> Option<u32> {
        match self.owner().state {
            H7OverlappedState::TerminalError(error) => Some(error),
            _ => None,
        }
    }

    fn cleanup_timeout(&self) -> Duration {
        self.owner()
            .terminality_gate
            .as_ref()
            .and_then(|gate| {
                let millis = gate.cleanup_timeout_ms.load(Ordering::Acquire);
                (millis != 0).then_some(Duration::from_millis(millis as u64))
            })
            .unwrap_or(H7_CLEANUP_TIMEOUT)
    }

    fn mark_terminal(&mut self, state: H7OverlappedState) {
        let owner = self.owner_mut();
        owner.state = state;
        if let Some(probe) = owner.probe.as_ref() {
            probe.terminal_observed.store(true, Ordering::Release);
        }
    }

    fn request_cancel(&mut self) {
        if self.owner().state != H7OverlappedState::Pending {
            return;
        }
        let owner = self.owner_mut();
        owner.state = H7OverlappedState::CancelRequested;
        if let Some(gate) = owner.terminality_gate.as_ref() {
            gate.cancel_requested.store(true, Ordering::Release);
        }
        if unsafe { CancelIoEx(owner.read.raw(), owner.operation.as_ref()) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_NOT_FOUND {
                // Cancellation is only a request. The event plus an actual
                // GetOverlappedResult(FALSE) terminal result remain required.
            }
        }
    }

    fn observe_terminal(&mut self) -> bool {
        if !self.pending() {
            return self.owner().state.is_terminal();
        }
        let poll = {
            let owner = self.owner();
            poll_h7_overlapped(owner.read.raw(), owner.operation.as_ref(), false)
        };
        if matches!(
            poll,
            H7OverlappedPoll::Pending | H7OverlappedPoll::Indeterminate(_)
        ) {
            unsafe {
                let _ = ResetEvent(self.owner().event.raw());
            }
            return false;
        }
        if let Some(gate) = self.owner().terminality_gate.as_ref() {
            if gate.cancel_requested.load(Ordering::Acquire)
                && !gate.allow_terminal.load(Ordering::Acquire)
            {
                return false;
            }
        }
        let owner = self.owner_mut();
        owner.state = match poll {
            H7OverlappedPoll::TerminalSuccess { .. } => H7OverlappedState::TerminalCompleted,
            H7OverlappedPoll::TerminalCancelled => H7OverlappedState::TerminalCancelled,
            H7OverlappedPoll::TerminalEof => {
                unreachable!("H7 connect poll cannot report EOF")
            }
            H7OverlappedPoll::Pending | H7OverlappedPoll::Indeterminate(_) => {
                unreachable!("H7 connect terminal poll was filtered above")
            }
        };
        if let Some(probe) = owner.probe.as_ref() {
            probe.terminal_observed.store(true, Ordering::Release);
        }
        true
    }

    fn wait_for_terminal_until(&mut self, deadline: Instant) -> bool {
        while self.pending() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.request_cancel();
                let _ = self.observe_terminal();
                return !self.pending();
            }
            let wait_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
            match unsafe { WaitForSingleObject(self.owner().event.raw(), wait_ms) } {
                WAIT_OBJECT_0 => {
                    let _ = self.observe_terminal();
                }
                WAIT_TIMEOUT => {
                    self.request_cancel();
                    let _ = self.observe_terminal();
                    return !self.pending();
                }
                _ => {
                    self.request_cancel();
                    let _ = self.observe_terminal();
                    return !self.pending();
                }
            }
        }
        true
    }

    fn take_read(mut self) -> Result<H7Handle, Self> {
        if self.pending() {
            return Err(self);
        }
        let owner = self.owner.take().expect("H7 connect owner exists");
        owner.mark_released();
        let H7ConnectOperationOwner {
            read,
            event,
            operation,
            terminality_gate: _,
            probe: _,
            state: _,
        } = owner;
        drop(event);
        drop(operation);
        Ok(read)
    }

    fn quarantine(self) {
        let mut this = self;
        if let Some(owner) = this.owner.take() {
            h7_quarantine_insert(H7QuarantineEntry::Connect(owner));
        }
    }
}

impl Drop for H7OverlappedConnect {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            if owner.state.is_pending() {
                h7_quarantine_insert(H7QuarantineEntry::Connect(owner));
            } else {
                owner.mark_released();
            }
        }
    }
}

struct H7OutputReadOperation {
    overlapped: OVERLAPPED,
    scratch: [u8; H7_OUTPUT_SCRATCH_BYTES],
    state: H7OverlappedState,
}

struct H7OutputIoOwner {
    read: H7Handle,
    child_write: H7Handle,
    event: H7Handle,
    operation: Box<H7OutputReadOperation>,
    terminality_gate: Option<Arc<H7TerminalityGate>>,
    terminality_probe: Option<Arc<H7TerminalityProbe>>,
}

unsafe impl Send for H7OutputIoOwner {}

impl H7OutputIoOwner {
    fn pending(&self) -> bool {
        self.operation.state.is_pending()
    }

    fn mark_released(&self) {
        if let Some(probe) = self.terminality_probe.as_ref() {
            probe.drop_finished.store(true, Ordering::Release);
        }
    }

    fn observe_terminal_poll(&mut self, poll: H7OverlappedPoll) -> bool {
        if matches!(
            poll,
            H7OverlappedPoll::Pending | H7OverlappedPoll::Indeterminate(_)
        ) {
            unsafe {
                let _ = ResetEvent(self.event.raw());
            }
            return false;
        }
        if let Some(gate) = self.terminality_gate.as_ref() {
            if gate.cancel_requested.load(Ordering::Acquire)
                && !gate.allow_terminal.load(Ordering::Acquire)
            {
                return false;
            }
        }
        self.operation.state = match poll {
            H7OverlappedPoll::TerminalSuccess { .. } => H7OverlappedState::TerminalCompleted,
            H7OverlappedPoll::TerminalCancelled => H7OverlappedState::TerminalCancelled,
            H7OverlappedPoll::TerminalEof => H7OverlappedState::TerminalEof,
            H7OverlappedPoll::Pending | H7OverlappedPoll::Indeterminate(_) => {
                unreachable!("H7 output terminal poll was filtered above")
            }
        };
        unsafe {
            let _ = ResetEvent(self.event.raw());
        }
        self.mark_terminal_observed();
        true
    }

    fn observe_terminal_nonblocking(&mut self) -> bool {
        if !self.pending() {
            return self.operation.state.is_terminal();
        }
        let _ = unsafe { WaitForSingleObject(self.event.raw(), 0) };
        let poll = poll_h7_overlapped(self.read.raw(), &self.operation.overlapped, true);
        self.observe_terminal_poll(poll)
    }

    fn mark_terminal_observed(&self) {
        if let Some(probe) = self.terminality_probe.as_ref() {
            probe.terminal_observed.store(true, Ordering::Release);
        }
    }
}

struct H7OverlappedOutputCapture {
    owner: Option<H7OutputIoOwner>,
    bytes: Vec<u8>,
    bound: usize,
    stream_complete: bool,
    overflow: bool,
}

unsafe impl Send for H7OverlappedOutputCapture {}

impl H7OverlappedOutputCapture {
    fn new(bound: usize, stream: &str) -> Result<Self, String> {
        Self::new_inner(bound, stream, false, None, None)
    }

    fn new_inner(
        bound: usize,
        stream: &str,
        force_connect_error: bool,
        connect_probe: Option<Arc<H7ConnectTerminalityProbe>>,
        connect_gate: Option<Arc<H7TerminalityGate>>,
    ) -> Result<Self, String> {
        let pipe_name = h7_output_pipe_name(stream)?;
        let read = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                H7_OUTPUT_SCRATCH_BYTES as u32,
                H7_OUTPUT_SCRATCH_BYTES as u32,
                1_000,
                std::ptr::null(),
            )
        };
        let read = H7Handle::new(read)?;
        if unsafe { SetHandleInformation(read.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(format!(
                "H7 overlapped {} read handle inheritance restriction failed: {}",
                stream,
                unsafe { GetLastError() }
            ));
        }

        let mut connect = H7OverlappedConnect::new(read)?;
        if let Some(probe) = connect_probe {
            connect.owner_mut().probe = Some(probe);
        }
        if let Some(gate) = connect_gate {
            connect.owner_mut().terminality_gate = Some(gate);
        }
        connect.start().map_err(|error| {
            format!(
                "H7 overlapped {} named-pipe connect failed: {}",
                stream, error
            )
        })?;

        if force_connect_error && connect.owner().terminality_gate.is_some() {
            connect.request_cancel();
            let _ = connect.wait_for_terminal_until(Instant::now() + connect.cleanup_timeout());
            return Err(format!(
                "D29-H7 injected pending named-pipe connect constructor failure for {}",
                stream
            ));
        }

        let child_write = H7Handle::new(unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                FILE_GENERIC_WRITE,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        })?;
        if unsafe {
            SetHandleInformation(child_write.raw(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
        } == 0
        {
            return Err(format!(
                "H7 overlapped {} child handle inheritance setup failed: {}",
                stream,
                unsafe { GetLastError() }
            ));
        }
        if force_connect_error {
            connect.request_cancel();
            let _ = connect.wait_for_terminal_until(Instant::now() + connect.cleanup_timeout());
            return Err(format!(
                "D29-H7 injected named-pipe connect constructor failure for {}",
                stream
            ));
        }
        if connect.pending()
            && !connect.wait_for_terminal_until(Instant::now() + Duration::from_secs(2))
        {
            connect.quarantine();
            return Err(format!(
                "H7 overlapped {} named-pipe connect timed out",
                stream
            ));
        }
        if let Some(error) = connect.error() {
            return Err(format!(
                "H7 overlapped {} named-pipe connect completion failed: {}",
                stream, error
            ));
        }
        let read = match connect.take_read() {
            Ok(read) => read,
            Err(connect) => {
                connect.quarantine();
                return Err(format!(
                    "H7 overlapped {} named-pipe connect remained pending",
                    stream
                ));
            }
        };

        let event =
            H7Handle::new(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })?;
        if unsafe { SetHandleInformation(event.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(format!(
                "H7 overlapped {} completion event inheritance restriction failed: {}",
                stream,
                unsafe { GetLastError() }
            ));
        }
        let overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..Default::default()
        };
        Ok(Self {
            owner: Some(H7OutputIoOwner {
                read,
                child_write,
                event,
                operation: Box::new(H7OutputReadOperation {
                    overlapped,
                    scratch: [0_u8; H7_OUTPUT_SCRATCH_BYTES],
                    state: H7OverlappedState::Idle,
                }),
                terminality_gate: None,
                terminality_probe: None,
            }),
            bytes: Vec::with_capacity(bound.min(H7_OUTPUT_SCRATCH_BYTES)),
            bound,
            stream_complete: false,
            overflow: false,
        })
    }

    #[cfg(test)]
    fn new_for_connect_terminality_test(
        bound: usize,
        stream: &str,
        probe: Arc<H7ConnectTerminalityProbe>,
    ) -> Result<Self, String> {
        Self::new_inner(bound, stream, true, Some(probe), None)
    }

    #[cfg(test)]
    fn new_for_connect_quarantine_test(
        bound: usize,
        stream: &str,
        gate: Arc<H7TerminalityGate>,
        probe: Arc<H7ConnectTerminalityProbe>,
    ) -> Result<Self, String> {
        Self::new_inner(bound, stream, true, Some(probe), Some(gate))
    }

    #[cfg(test)]
    fn with_terminality_test_hooks(
        mut self,
        gate: Arc<H7TerminalityGate>,
        probe: Arc<H7TerminalityProbe>,
    ) -> Self {
        self = self.with_terminality_gate(gate);
        self.owner_mut().terminality_probe = Some(probe);
        self
    }

    fn with_terminality_gate(mut self, gate: Arc<H7TerminalityGate>) -> Self {
        self.owner_mut().terminality_gate = Some(gate);
        self
    }

    fn cleanup_timeout(&self) -> Duration {
        self.owner
            .as_ref()
            .and_then(|owner| owner.terminality_gate.as_ref())
            .and_then(|gate| {
                let millis = gate.cleanup_timeout_ms.load(Ordering::Acquire);
                (millis != 0).then_some(Duration::from_millis(millis as u64))
            })
            .unwrap_or(H7_CLEANUP_TIMEOUT)
    }

    #[cfg(test)]
    fn with_cleanup_timeout(self, timeout: Duration) -> Self {
        if let Some(gate) = self
            .owner
            .as_ref()
            .and_then(|owner| owner.terminality_gate.as_ref())
        {
            gate.cleanup_timeout_ms.store(
                timeout.as_millis().max(1).min(usize::MAX as u128) as usize,
                Ordering::Release,
            );
        }
        self
    }

    #[cfg(test)]
    fn with_terminality_test_hooks_and_cleanup_timeout(
        self,
        gate: Arc<H7TerminalityGate>,
        timeout: Duration,
    ) -> Self {
        self.with_terminality_gate(gate)
            .with_cleanup_timeout(timeout)
    }

    fn owner(&self) -> &H7OutputIoOwner {
        self.owner.as_ref().expect("H7 output owner exists")
    }

    fn owner_mut(&mut self) -> &mut H7OutputIoOwner {
        self.owner.as_mut().expect("H7 output owner exists")
    }

    fn child_handle(&self) -> HANDLE {
        self.owner().child_write.raw()
    }

    fn close_child_endpoint(&mut self) {
        let child_write = std::mem::replace(
            &mut self.owner_mut().child_write,
            H7Handle(std::ptr::null_mut()),
        );
        drop(child_write);
    }

    fn event_handle(&self) -> HANDLE {
        self.owner().event.raw()
    }

    fn pending(&self) -> bool {
        self.owner.as_ref().is_some_and(H7OutputIoOwner::pending)
    }

    fn is_complete(&self) -> bool {
        self.stream_complete
    }

    fn overflowed(&self) -> bool {
        self.overflow
    }

    fn failed(&self) -> bool {
        self.owner.as_ref().is_some_and(|owner| {
            matches!(owner.operation.state, H7OverlappedState::TerminalError(_))
        })
    }

    fn retained_len(&self) -> usize {
        self.bytes.len()
    }

    fn arm_read(&mut self) {
        if self.pending() || self.stream_complete {
            return;
        }
        let remaining = self.bound.saturating_sub(self.bytes.len());
        let requested = remaining
            .saturating_add(1)
            .min(H7_OUTPUT_SCRATCH_BYTES)
            .max(1);
        let owner = self.owner_mut();
        debug_assert!(
            owner.operation.state == H7OverlappedState::Idle || owner.operation.state.is_terminal()
        );
        unsafe {
            let _ = ResetEvent(owner.event.raw());
        }
        owner.operation.overlapped = OVERLAPPED {
            hEvent: owner.event.raw(),
            ..Default::default()
        };
        owner.operation.state = H7OverlappedState::Pending;
        let started = unsafe {
            ReadFile(
                owner.read.raw(),
                owner.operation.scratch.as_mut_ptr().cast(),
                requested as u32,
                std::ptr::null_mut(),
                &mut owner.operation.overlapped,
            )
        } != 0;
        if started {
            let _ = self.complete_pending();
            return;
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            self.mark_read_terminal(error, 0);
        }
    }

    fn complete_pending(&mut self) -> bool {
        if !self.pending() {
            return self
                .owner
                .as_ref()
                .is_some_and(|owner| owner.operation.state.is_terminal());
        }
        let poll = {
            let owner = self.owner();
            poll_h7_overlapped(owner.read.raw(), &owner.operation.overlapped, true)
        };
        if matches!(
            poll,
            H7OverlappedPoll::Pending | H7OverlappedPoll::Indeterminate(_)
        ) {
            unsafe {
                let _ = ResetEvent(self.owner().event.raw());
            }
            return false;
        }
        if let Some(gate) = self
            .owner
            .as_ref()
            .and_then(|owner| owner.terminality_gate.as_ref())
        {
            if gate.cancel_requested.load(Ordering::Acquire)
                && !gate.allow_terminal.load(Ordering::Acquire)
            {
                thread::yield_now();
                return false;
            }
        }
        let remaining = self.bound.saturating_sub(self.bytes.len());
        let mut completed_bytes = Vec::new();
        let mut transferred = 0_u32;
        {
            let owner = self.owner_mut();
            match poll {
                H7OverlappedPoll::TerminalSuccess { transferred: bytes } => {
                    transferred = bytes;
                    owner.operation.state = if bytes == 0 {
                        H7OverlappedState::TerminalEof
                    } else {
                        H7OverlappedState::TerminalCompleted
                    };
                    if bytes != 0 {
                        let take = remaining.min(bytes as usize);
                        completed_bytes.extend_from_slice(&owner.operation.scratch[..take]);
                    }
                }
                H7OverlappedPoll::TerminalCancelled => {
                    owner.operation.state = H7OverlappedState::TerminalCancelled;
                }
                H7OverlappedPoll::TerminalEof => {
                    owner.operation.state = H7OverlappedState::TerminalEof;
                }
                H7OverlappedPoll::Pending | H7OverlappedPoll::Indeterminate(_) => {
                    unreachable!("H7 output completion poll was filtered above")
                }
            }
            unsafe {
                let _ = ResetEvent(owner.event.raw());
            }
        }
        if matches!(
            poll,
            H7OverlappedPoll::TerminalCancelled | H7OverlappedPoll::TerminalEof
        ) || transferred == 0
        {
            if matches!(poll, H7OverlappedPoll::TerminalEof) || transferred == 0 {
                self.stream_complete = true;
            }
            self.mark_read_terminal_observed();
            return true;
        }
        let take = completed_bytes.len();
        self.bytes.extend_from_slice(&completed_bytes);
        if take < transferred as usize {
            self.overflow = true;
            self.stream_complete = true;
        }
        self.mark_read_terminal_observed();
        true
    }

    fn mark_read_terminal_observed(&self) {
        if let Some(probe) = self
            .owner
            .as_ref()
            .and_then(|owner| owner.terminality_probe.as_ref())
        {
            probe.terminal_observed.store(true, Ordering::Release);
        }
    }

    fn mark_read_terminal(&mut self, error: u32, transferred: u32) {
        let end_of_stream = error == ERROR_BROKEN_PIPE;
        let state = if end_of_stream {
            H7OverlappedState::TerminalEof
        } else if error == ERROR_OPERATION_ABORTED {
            H7OverlappedState::TerminalCancelled
        } else {
            H7OverlappedState::TerminalError(error)
        };
        {
            let owner = self.owner_mut();
            owner.operation.state = state;
            if transferred == 0 {
                unsafe {
                    let _ = ResetEvent(owner.event.raw());
                }
            }
        }
        if end_of_stream {
            self.stream_complete = true;
        }
        self.mark_read_terminal_observed();
    }

    fn request_cancel(&mut self) {
        if !self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.operation.state == H7OverlappedState::Pending)
        {
            return;
        }
        let owner = self.owner_mut();
        owner.operation.state = H7OverlappedState::CancelRequested;
        if let Some(gate) = owner.terminality_gate.as_ref() {
            gate.cancel_requested.store(true, Ordering::Release);
        }
        if unsafe { CancelIoEx(owner.read.raw(), &owner.operation.overlapped) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_NOT_FOUND {
                // ERROR_NOT_FOUND and every other failure still require the
                // event plus GetOverlappedResult terminality proof.
            }
        }
    }

    fn cancel_pending(&mut self) {
        self.request_cancel();
    }

    fn drain_until_terminal(&mut self, deadline: Instant) -> bool {
        while self.pending() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let wait_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
            if unsafe { WaitForSingleObject(self.event_handle(), wait_ms) } != WAIT_OBJECT_0 {
                return false;
            }
            let _ = self.complete_pending();
        }
        true
    }

    fn quarantine_if_pending(&mut self) -> bool {
        if !self.pending() {
            return false;
        }
        let owner = self.owner.take().expect("H7 output owner exists");
        h7_quarantine_insert(H7QuarantineEntry::Output(owner));
        true
    }
}

impl Drop for H7OverlappedOutputCapture {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            if owner.pending() {
                if let Some(probe) = owner.terminality_probe.as_ref() {
                    probe.drop_started.store(true, Ordering::Release);
                }
                h7_quarantine_insert(H7QuarantineEntry::Output(owner));
            } else {
                owner.mark_released();
            }
        }
    }
}

enum H7QuarantineEntry {
    Connect(H7ConnectOperationOwner),
    Output(H7OutputIoOwner),
}

unsafe impl Send for H7QuarantineEntry {}

impl H7QuarantineEntry {
    fn is_output(&self) -> bool {
        matches!(self, Self::Output(_))
    }

    fn is_connect(&self) -> bool {
        matches!(self, Self::Connect(_))
    }

    fn observe_terminal_nonblocking(&mut self) -> bool {
        match self {
            Self::Connect(owner) => {
                if !owner.state.is_pending() {
                    return owner.state.is_terminal();
                }
                let poll = poll_h7_overlapped(owner.read.raw(), owner.operation.as_ref(), false);
                if matches!(
                    poll,
                    H7OverlappedPoll::Pending | H7OverlappedPoll::Indeterminate(_)
                ) {
                    unsafe {
                        let _ = ResetEvent(owner.event.raw());
                    }
                    return false;
                }
                if let Some(gate) = owner.terminality_gate.as_ref() {
                    if gate.cancel_requested.load(Ordering::Acquire)
                        && !gate.allow_terminal.load(Ordering::Acquire)
                    {
                        return false;
                    }
                }
                let _ = unsafe { WaitForSingleObject(owner.event.raw(), 0) };
                owner.state = match poll {
                    H7OverlappedPoll::TerminalSuccess { .. } => {
                        H7OverlappedState::TerminalCompleted
                    }
                    H7OverlappedPoll::TerminalCancelled => H7OverlappedState::TerminalCancelled,
                    H7OverlappedPoll::TerminalEof => {
                        unreachable!("H7 connect poll cannot report EOF")
                    }
                    H7OverlappedPoll::Pending | H7OverlappedPoll::Indeterminate(_) => {
                        unreachable!("H7 connect completion poll was filtered above")
                    }
                };
                unsafe {
                    let _ = ResetEvent(owner.event.raw());
                }
                if let Some(probe) = owner.probe.as_ref() {
                    probe.terminal_observed.store(true, Ordering::Release);
                }
                true
            }
            Self::Output(owner) => owner.observe_terminal_nonblocking(),
        }
    }

    fn mark_released(&self) {
        match self {
            Self::Connect(owner) => owner.mark_released(),
            Self::Output(owner) => owner.mark_released(),
        }
    }
}

impl H7ConnectOperationOwner {
    fn mark_released(&self) {
        if let Some(probe) = self.probe.as_ref() {
            probe.dropped.store(true, Ordering::Release);
        }
    }
}

struct H7PendingIoQuarantine {
    entries: Mutex<[Option<H7QuarantineEntry>; H7_MAX_QUARANTINED_IO]>,
}

unsafe impl Sync for H7PendingIoQuarantine {}

impl Default for H7PendingIoQuarantine {
    fn default() -> Self {
        Self {
            entries: Mutex::new(std::array::from_fn(|_| None)),
        }
    }
}

impl H7PendingIoQuarantine {
    fn try_insert(&self, entry: H7QuarantineEntry) -> Result<(), H7QuarantineEntry> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let output_count = entries
            .iter()
            .flatten()
            .filter(|entry| entry.is_output())
            .count();
        let connect_count = entries
            .iter()
            .flatten()
            .filter(|entry| entry.is_connect())
            .count();
        let allowed = match &entry {
            H7QuarantineEntry::Output(_) => output_count < H7_MAX_QUARANTINED_OUTPUT,
            H7QuarantineEntry::Connect(_) => connect_count < H7_MAX_QUARANTINED_CONNECT,
        };
        if !allowed {
            return Err(entry);
        }
        let slot = entries
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("H7 quarantine capacity accounting");
        *slot = Some(entry);
        Ok(())
    }

    fn reap_nonblocking(&self) -> usize {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut released = 0;
        for slot in entries.iter_mut() {
            let terminal = slot
                .as_mut()
                .is_some_and(H7QuarantineEntry::observe_terminal_nonblocking);
            if terminal {
                if let Some(entry) = slot.take() {
                    entry.mark_released();
                    released += 1;
                }
            }
        }
        released
    }

    fn count(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|entry| entry.is_some())
            .count()
    }
}

static H7_PENDING_IO_QUARANTINE: OnceLock<Arc<H7PendingIoQuarantine>> = OnceLock::new();

fn h7_pending_io_quarantine() -> Arc<H7PendingIoQuarantine> {
    Arc::clone(H7_PENDING_IO_QUARANTINE.get_or_init(|| Arc::new(H7PendingIoQuarantine::default())))
}

fn h7_quarantine_insert(entry: H7QuarantineEntry) {
    let quarantine = h7_pending_io_quarantine();
    match quarantine.try_insert(entry) {
        Ok(()) => {}
        Err(_entry) => {
            // The single-active admission invariant makes this unreachable:
            // at most one connect and two output operations can be pending.
            // The process must not continue with an owner that has no fixed
            // slot; abort before Rust can drop the kernel-referenced owner.
            std::process::abort();
        }
    }
}

fn h7_reap_pending_io_nonblocking() -> usize {
    h7_pending_io_quarantine().reap_nonblocking();
    h7_pending_io_quarantine().count()
}

fn update_h7_pending_output_metric(
    metrics: &H7SupervisorMetrics,
    stdout: &H7OverlappedOutputCapture,
    stderr: &H7OverlappedOutputCapture,
) {
    metrics.pending_output_reads.store(
        usize::from(stdout.pending()) + usize::from(stderr.pending()),
        Ordering::Release,
    );
}

fn service_h7_ready_output_events(
    stdout: &mut H7OverlappedOutputCapture,
    stderr: &mut H7OverlappedOutputCapture,
) {
    if stdout.pending() && unsafe { WaitForSingleObject(stdout.event_handle(), 0) } == WAIT_OBJECT_0
    {
        let _ = stdout.complete_pending();
    }
    if stderr.pending() && unsafe { WaitForSingleObject(stderr.event_handle(), 0) } == WAIT_OBJECT_0
    {
        let _ = stderr.complete_pending();
    }
}

fn cancel_and_drain_h7_output(
    metrics: &H7SupervisorMetrics,
    stdout: &mut H7OverlappedOutputCapture,
    stderr: &mut H7OverlappedOutputCapture,
) -> bool {
    stdout.cancel_pending();
    stderr.cancel_pending();
    let deadline = Instant::now() + stdout.cleanup_timeout().min(stderr.cleanup_timeout());
    let stdout_done = stdout.drain_until_terminal(deadline);
    let stderr_done = stderr.drain_until_terminal(deadline);
    update_h7_pending_output_metric(metrics, stdout, stderr);
    stdout_done && stderr_done
}

struct H7OutputHandleGuard {
    metrics: Arc<H7SupervisorMetrics>,
    count: usize,
}

impl H7OutputHandleGuard {
    fn new(metrics: Arc<H7SupervisorMetrics>, count: usize) -> Self {
        metrics
            .output_handles_active
            .fetch_add(count, Ordering::AcqRel);
        Self { metrics, count }
    }
}

impl Drop for H7OutputHandleGuard {
    fn drop(&mut self) {
        self.metrics
            .output_handles_active
            .fetch_sub(self.count, Ordering::AcqRel);
    }
}

fn h7_output_pipe_name(stream: &str) -> Result<Vec<u16>, String> {
    let mut nonce = [0_u8; 16];
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            nonce.as_mut_ptr(),
            nonce.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(format!(
            "H7 {} output pipe nonce generation failed: {}",
            stream, status
        ));
    }
    let nonce = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let name = format!(r"\\.\pipe\vita-h7-{stream}-{nonce}");
    Ok(wide_null(OsStr::new(&name)))
}

#[derive(Default)]
struct H7CleanupEvidence {
    direct_termination_attempted: AtomicBool,
    direct_termination_verified: AtomicBool,
    job_termination_attempted: AtomicBool,
    job_termination_succeeded: AtomicBool,
    job_termination_proven: AtomicBool,
    process_exit_verified: AtomicBool,
    process_tree_observed: AtomicBool,
    process_tree_remaining: AtomicUsize,
    stdout_reader_joined: AtomicBool,
    stderr_reader_joined: AtomicBool,
    user_code_started: AtomicBool,
}

struct H7NativeResources {
    job: H7Handle,
    process: H7Handle,
    thread: H7Handle,
    phase: Arc<AtomicU8>,
    metrics: Arc<H7SupervisorMetrics>,
    cleanup: Arc<H7CleanupEvidence>,
    job_assigned: bool,
    job_terminated: bool,
}

impl H7NativeResources {
    fn close_process_handle(&mut self) {
        let process = std::mem::replace(&mut self.process, H7Handle(std::ptr::null_mut()));
        drop(process);
    }

    fn close_thread_handle(&mut self) {
        let thread = std::mem::replace(&mut self.thread, H7Handle(std::ptr::null_mut()));
        drop(thread);
    }

    fn observe_process_exit(&self, milliseconds: u32) -> bool {
        let signaled =
            unsafe { WaitForSingleObject(self.process.raw(), milliseconds) } == WAIT_OBJECT_0;
        if signaled {
            if self
                .cleanup
                .process_exit_verified
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.metrics
                    .process_exit_verified
                    .fetch_add(1, Ordering::AcqRel);
            }
        }
        signaled
    }

    fn observe_process_tree(&self) -> Option<usize> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut returned_length = 0_u32;
        let ok = unsafe {
            QueryInformationJobObject(
                self.job.raw(),
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                &mut returned_length,
            )
        } != 0;
        if !ok {
            return None;
        }
        let remaining = accounting.ActiveProcesses as usize;
        self.cleanup
            .process_tree_remaining
            .store(remaining, Ordering::Release);
        self.cleanup
            .process_tree_observed
            .store(true, Ordering::Release);
        self.metrics
            .process_tree_remaining
            .store(remaining, Ordering::Release);
        self.metrics
            .process_tree_observations
            .fetch_add(1, Ordering::AcqRel);
        Some(remaining)
    }

    fn observe_process_tree_until_quiescent(&self, timeout: Duration) -> Option<usize> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = self.observe_process_tree()?;
            if remaining == 0 || Instant::now() >= deadline {
                return Some(remaining);
            }
            thread::yield_now();
        }
    }

    fn terminate_primary_process(&mut self) -> bool {
        let verified = terminate_process_and_verify_exit(
            self.process.raw(),
            &self.phase,
            &self.metrics,
            &self.cleanup,
        );
        if verified {
            let _ = self.observe_process_tree_until_quiescent(Duration::from_millis(100));
        }
        verified
    }

    fn terminate_assigned_job(&mut self) -> bool {
        if !self.job_assigned || self.job_terminated {
            return self.job_terminated;
        }
        let job_call_succeeded = if self
            .cleanup
            .job_termination_attempted
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let succeeded = unsafe { TerminateJobObject(self.job.raw(), 1) } != 0;
            if succeeded {
                self.cleanup
                    .job_termination_succeeded
                    .store(true, Ordering::Release);
                self.metrics.jobs_terminated.fetch_add(1, Ordering::AcqRel);
            } else {
                self.metrics
                    .job_termination_failures
                    .fetch_add(1, Ordering::AcqRel);
            }
            succeeded
        } else {
            self.cleanup
                .job_termination_succeeded
                .load(Ordering::Acquire)
        };
        let mut process_closed = self.observe_process_exit(1_000);
        let mut tree_closed =
            self.observe_process_tree_until_quiescent(H7_CLEANUP_TIMEOUT) == Some(0);
        if (!process_closed || !tree_closed) && !self.job_terminated {
            // A failed or unproven Job operation gets a bounded primary-process
            // fallback.  Its proof remains separate from job_termination_succeeded.
            let _ = self.terminate_primary_process();
            process_closed = self.observe_process_exit(1_000);
            tree_closed = self.observe_process_tree_until_quiescent(H7_CLEANUP_TIMEOUT) == Some(0);
        }
        if process_closed && !phase_at_least(&self.phase, H7LaunchPhase::Exited) {
            self.phase
                .store(H7LaunchPhase::Exited as u8, Ordering::Release);
            self.metrics.process_exited.fetch_add(1, Ordering::AcqRel);
        }
        self.job_terminated = job_call_succeeded && process_closed && tree_closed;
        if self.job_terminated {
            self.cleanup
                .job_termination_proven
                .store(true, Ordering::Release);
        }
        self.job_terminated
    }

    fn terminate_for_cleanup(&mut self) -> bool {
        if self.job_assigned {
            self.terminate_assigned_job()
        } else {
            self.terminate_primary_process()
        }
    }
}

fn terminate_process_and_verify_exit(
    process: HANDLE,
    phase: &AtomicU8,
    metrics: &H7SupervisorMetrics,
    cleanup: &H7CleanupEvidence,
) -> bool {
    if cleanup
        .direct_termination_attempted
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return cleanup.direct_termination_verified.load(Ordering::Acquire);
    }
    metrics
        .direct_termination_attempted
        .fetch_add(1, Ordering::AcqRel);
    let _requested = unsafe { TerminateProcess(process, 1) } != 0;
    let observed_exit = unsafe { WaitForSingleObject(process, 1_000) } == WAIT_OBJECT_0;
    if !observed_exit {
        return false;
    }
    cleanup.process_exit_verified.store(true, Ordering::Release);
    if cleanup
        .direct_termination_verified
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        metrics
            .direct_termination_verified
            .fetch_add(1, Ordering::AcqRel);
    }
    if !phase_at_least(phase, H7LaunchPhase::Exited) {
        phase.store(H7LaunchPhase::Exited as u8, Ordering::Release);
        metrics.process_exited.fetch_add(1, Ordering::AcqRel);
    }
    true
}

impl Drop for H7NativeResources {
    fn drop(&mut self) {
        if !phase_at_least(&self.phase, H7LaunchPhase::Exited) {
            let _ = self.terminate_for_cleanup();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H7PostHostMutation {
    None,
    ArgvHash,
    CwdIdentity,
    EnvironmentHash,
    ExecutableIdentity,
}

struct H7LaunchPreparation {
    job: H7Handle,
    stdin_read: H7Handle,
    stdin_write: H7Handle,
    stdout_capture: H7OverlappedOutputCapture,
    stderr_capture: H7OverlappedOutputCapture,
    attributes: H7ProcThreadAttributes,
    application_name: Vec<u16>,
    command_line: Vec<u16>,
    current_directory: Vec<u16>,
    environment: Vec<u16>,
    executable_probe: Arc<H7Handle>,
    working_directory_probe: Arc<H7Handle>,
    binding: H7ProcessBinding,
    expected_image_identity: H7ImageIdentity,
    expected_image_namespace: H7NamespaceIdentity,
    expected_working_directory: H7NamespaceIdentity,
}

// The preparation owns unique native handles and is transferred once to the
// bounded blocking launch closure.  No handle is shared through this value.
unsafe impl Send for H7LaunchPreparation {}

impl H7LaunchPreparation {
    fn prepare(
        action: &PreparedProcessAction,
        unlisted_inheritable_handle: Option<usize>,
        output_terminality_gate: Option<Arc<H7TerminalityGate>>,
    ) -> Result<Self, String> {
        let (expected_image_identity, expected_image_namespace, executable_probe) = {
            let mut image = action
                .image
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let expected_identity = image.identity;
            let expected_sha256 = image.sha256.clone();
            image.reverify(expected_identity, &expected_sha256)?;
            let namespace = image.namespace.identity();
            let probe = image.namespace.rebind_leaf()?;
            (expected_identity, namespace, probe)
        };
        let expected_working_directory = action.working_directory.0.identity();
        let working_directory_probe = action.working_directory.rebind_leaf()?;
        if expected_working_directory.wire() != action.working_directory_identity {
            return Err("H7 working-directory binding was not host-owned".to_string());
        }
        verify_workspace_root_binding(action)?;
        let job = create_job_object()?;
        let (stdin_read, stdin_write) = create_stdin_pipe()?;
        let stdout_capture = H7OverlappedOutputCapture::new(action.stdout_bound, "stdout")?;
        let stdout_capture = match output_terminality_gate.as_ref() {
            Some(gate) => stdout_capture.with_terminality_gate(Arc::clone(gate)),
            None => stdout_capture,
        };
        let stderr_capture = H7OverlappedOutputCapture::new(action.stderr_bound, "stderr")?;
        let stderr_capture = match output_terminality_gate {
            Some(gate) => stderr_capture.with_terminality_gate(gate),
            None => stderr_capture,
        };
        let mut attributes = H7ProcThreadAttributes::new(1)?;
        attributes.set_handle_list(vec![
            stdin_read.raw(),
            stdout_capture.child_handle(),
            stderr_capture.child_handle(),
        ])?;
        if let Some(raw) = unlisted_inheritable_handle {
            unsafe {
                if SetHandleInformation(raw as HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
                    == 0
                {
                    return Err("H7 unlisted handle inheritance seam failed".to_string());
                }
            }
        }
        let application_name = {
            let image = action
                .image
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            wide_null(image.path.as_os_str())
        };
        let binding = action.binding();
        Ok(Self {
            job,
            stdin_read,
            stdin_write,
            stdout_capture,
            stderr_capture,
            attributes,
            application_name,
            command_line: argv_to_command_line(&action.argv),
            current_directory: wide_null(action.working_directory.path().as_os_str()),
            environment: environment_block(&action.environment),
            executable_probe,
            working_directory_probe,
            binding,
            expected_image_identity,
            expected_image_namespace,
            expected_working_directory,
        })
    }

    fn final_local_fence(
        &mut self,
        action: &PreparedProcessAction,
        grant: &H7ProcessGrant,
        cancellation: &AtomicBool,
        mutation: H7PostHostMutation,
    ) -> Result<(), String> {
        if cancellation.load(Ordering::Acquire) {
            return Err("H7 cancellation won the final launch fence".to_string());
        }
        let mut expected_binding = self.binding.clone();
        match mutation {
            H7PostHostMutation::None => {}
            H7PostHostMutation::ArgvHash => expected_binding.argv_hash = "0".repeat(64),
            H7PostHostMutation::CwdIdentity => {
                expected_binding.working_directory_identity = "0".repeat(64)
            }
            H7PostHostMutation::EnvironmentHash => {
                expected_binding.environment_policy_hash = "0".repeat(64)
            }
            H7PostHostMutation::ExecutableIdentity => {
                expected_binding.executable_identity = "0".repeat(64)
            }
        }
        let current_binding = action.binding();
        if current_binding != expected_binding
            || grant.binding != current_binding
            || grant.authorization_revision <= 0
            || !grant.used
        {
            return Err("H7 local final binding fence rejected the ProcessGrant".to_string());
        }
        self.final_native_fence(action, cancellation, mutation)
    }

    fn final_native_fence(
        &mut self,
        action: &PreparedProcessAction,
        cancellation: &AtomicBool,
        mutation: H7PostHostMutation,
    ) -> Result<(), String> {
        if cancellation.load(Ordering::Acquire) {
            return Err("H7 cancellation won the final launch fence".to_string());
        }
        verify_workspace_root_binding(action)?;
        let (image_identity, image_namespace_identity, probe) = {
            let image = action
                .image
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let probe = image.namespace.rebind_leaf()?;
            let duplicate = duplicate_file_handle(probe.raw())?;
            (
                file_identity(&duplicate)?,
                image.namespace.identity(),
                probe,
            )
        };
        let working_directory_identity = namespace_identity(self.working_directory_probe.raw())?;
        let cwd_probe = action.working_directory.rebind_leaf()?;
        let cwd_identity = namespace_identity(cwd_probe.raw())?;
        if image_identity != self.expected_image_identity
            || image_namespace_identity != self.expected_image_namespace
            || working_directory_identity != self.expected_working_directory
            || cwd_identity != self.expected_working_directory
        {
            return Err("H7 final executable or cwd identity fence failed".to_string());
        }
        self.executable_probe = probe;
        self.working_directory_probe = cwd_probe;
        if action.argv_count != self.binding.argv_count
            || action.argv_hash != self.binding.argv_hash
            || action.environment_policy_hash != self.binding.environment_policy_hash
            || action.stdout_bound != self.binding.stdout_bound
            || action.stderr_bound != self.binding.stderr_bound
            || action.timeout.as_millis() as u64 != self.binding.timeout_ms
        {
            return Err("H7 final argv/environment/bounds fence failed".to_string());
        }
        if cancellation.load(Ordering::Acquire) {
            return Err("H7 cancellation won the final launch fence".to_string());
        }
        if mutation != H7PostHostMutation::None {
            return Err("H7 post-Host local binding mutation was detected".to_string());
        }
        Ok(())
    }
}

#[derive(Clone)]
struct H7NativeOptions {
    cancellation: Arc<AtomicBool>,
    metrics: Arc<H7SupervisorMetrics>,
    fault: H7NativeLaunchFault,
    unlisted_inheritable_handle: Option<usize>,
    post_host_mutation: H7PostHostMutation,
    pre_create_process_gate: Option<Arc<H7PostHostFenceGate>>,
    output_terminality_gate: Option<Arc<H7TerminalityGate>>,
}

fn supervise_native(action: &PreparedProcessAction, options: H7NativeOptions) -> H7NativeResult {
    let preparation = match H7LaunchPreparation::prepare(
        action,
        options.unlisted_inheritable_handle,
        options.output_terminality_gate.clone(),
    ) {
        Ok(preparation) => preparation,
        Err(_) => return launch_failed(false, false, None),
    };
    supervise_native_prepared(action, options, preparation, None)
}

fn supervise_native_prepared(
    action: &PreparedProcessAction,
    options: H7NativeOptions,
    preparation: H7LaunchPreparation,
    grant: Option<H7ProcessGrant>,
) -> H7NativeResult {
    let phase = Arc::new(AtomicU8::new(H7LaunchPhase::NotStarted as u8));
    let cleanup = Arc::new(H7CleanupEvidence::default());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        supervise_native_inner(
            action,
            &options,
            Arc::clone(&phase),
            Arc::clone(&cleanup),
            preparation,
            grant.as_ref(),
        )
    }));
    match result {
        Ok(result) => result,
        Err(_) => H7NativeResult {
            kind: if phase_at_least(&phase, H7LaunchPhase::CreatedSuspended) {
                H7NativeOutcomeKind::StartedOutcomeUnknown
            } else {
                H7NativeOutcomeKind::Denied
            },
            process_created: phase_at_least(&phase, H7LaunchPhase::CreatedSuspended),
            user_code_started: cleanup.user_code_started.load(Ordering::Acquire),
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            job_terminated: cleanup.job_termination_proven.load(Ordering::Acquire),
            process_tree_remaining: if cleanup.process_tree_observed.load(Ordering::Acquire) {
                cleanup.process_tree_remaining.load(Ordering::Acquire)
            } else if phase_at_least(&phase, H7LaunchPhase::CreatedSuspended) {
                usize::MAX
            } else {
                0
            },
            process_tree_observed: cleanup.process_tree_observed.load(Ordering::Acquire),
            automatic_retry: false,
            direct_termination_attempted: cleanup
                .direct_termination_attempted
                .load(Ordering::Acquire),
            direct_termination_verified: cleanup
                .direct_termination_verified
                .load(Ordering::Acquire),
            process_exit_verified: cleanup.process_exit_verified.load(Ordering::Acquire),
            stdout_reader_joined: cleanup.stdout_reader_joined.load(Ordering::Acquire),
            stderr_reader_joined: cleanup.stderr_reader_joined.load(Ordering::Acquire),
            pending_stdout_reads: 0,
            pending_stderr_reads: 0,
            stdout_retained_bytes: 0,
            stderr_retained_bytes: 0,
        },
    }
}

fn supervise_native_inner(
    action: &PreparedProcessAction,
    options: &H7NativeOptions,
    phase: Arc<AtomicU8>,
    cleanup: Arc<H7CleanupEvidence>,
    mut preparation: H7LaunchPreparation,
    grant: Option<&H7ProcessGrant>,
) -> H7NativeResult {
    if options.cancellation.load(Ordering::Acquire) {
        return launch_failed(false, false, None).with_kind(H7NativeOutcomeKind::Denied);
    }
    if options.fault == H7NativeLaunchFault::PanicBeforeCreateProcess {
        panic!("D29-H7 injected panic before CreateProcessW");
    }
    let final_fence = if let Some(grant) = grant {
        preparation.final_local_fence(
            action,
            grant,
            options.cancellation.as_ref(),
            options.post_host_mutation,
        )
    } else {
        preparation.final_native_fence(
            action,
            options.cancellation.as_ref(),
            H7PostHostMutation::None,
        )
    };
    if final_fence.is_err() {
        return launch_failed(false, false, None).with_kind(H7NativeOutcomeKind::Denied);
    }
    let H7LaunchPreparation {
        job,
        stdin_read,
        stdin_write,
        mut stdout_capture,
        mut stderr_capture,
        mut attributes,
        application_name,
        mut command_line,
        current_directory,
        environment,
        executable_probe: _executable_probe,
        working_directory_probe: _working_directory_probe,
        binding: _binding,
        expected_image_identity: _expected_image_identity,
        expected_image_namespace: _expected_image_namespace,
        expected_working_directory: _expected_working_directory,
    } = preparation;
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin_read.raw();
    startup.StartupInfo.hStdOutput = stdout_capture.child_handle();
    startup.StartupInfo.hStdError = stderr_capture.child_handle();
    startup.lpAttributeList = attributes.pointer().cast();
    let mut process_information: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    if let Some(gate) = options.pre_create_process_gate.as_ref() {
        gate.wait_if_armed_blocking();
    }
    // This is the final cancellation load.  Keep it immediately adjacent to
    // CreateProcessW: no hash, IPC, allocation, wait, or other meaningful
    // work may occur between the load and the syscall.
    if options.cancellation.load(Ordering::Acquire) {
        return launch_failed(false, false, None).with_kind(H7NativeOutcomeKind::Denied);
    }
    let created = unsafe {
        CreateProcessW(
            application_name.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            1,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT
                | CREATE_NO_WINDOW,
            environment.as_ptr().cast::<c_void>(),
            current_directory.as_ptr(),
            &mut startup.StartupInfo,
            &mut process_information,
        )
    };
    if created == 0 {
        return launch_failed(false, false, None);
    }
    phase.store(H7LaunchPhase::CreatedSuspended as u8, Ordering::Release);
    options
        .metrics
        .process_created
        .fetch_add(1, Ordering::AcqRel);
    options.metrics.created_notify.notify_waiters();
    drop(stdin_read);
    drop(stdin_write);
    stdout_capture.close_child_endpoint();
    stderr_capture.close_child_endpoint();
    let process = match H7Handle::new(process_information.hProcess) {
        Ok(handle) => handle,
        Err(_) => {
            return launch_failed(true, false, None);
        }
    };
    let thread = match if options.fault == H7NativeLaunchFault::ForceThreadHandleFailure {
        Err("D29-H7 injected process-thread handle failure".to_string())
    } else {
        H7Handle::new(process_information.hThread)
    } {
        Ok(handle) => handle,
        Err(_) => {
            let _ = terminate_process_and_verify_exit(
                process.raw(),
                &phase,
                &options.metrics,
                &cleanup,
            );
            return launch_failed(true, false, Some(&cleanup));
        }
    };
    let mut resources = H7NativeResources {
        job,
        process,
        thread,
        phase: Arc::clone(&phase),
        metrics: Arc::clone(&options.metrics),
        cleanup: Arc::clone(&cleanup),
        job_assigned: false,
        job_terminated: false,
    };
    cleanup.stdout_reader_joined.store(true, Ordering::Release);
    cleanup.stderr_reader_joined.store(true, Ordering::Release);
    if options.fault == H7NativeLaunchFault::PanicAfterCreateProcess {
        panic!("D29-H7 injected panic after CreateProcessW");
    }
    let assignment_ok = options.fault != H7NativeLaunchFault::ForceAssignmentFailure
        && unsafe { AssignProcessToJobObject(resources.job.raw(), resources.process.raw()) != 0 };
    if !assignment_ok {
        let _ = resources.terminate_for_cleanup();
        return launch_failed(true, false, Some(&cleanup));
    }
    let mut in_job = FALSE;
    let verified = unsafe {
        IsProcessInJob(resources.process.raw(), resources.job.raw(), &mut in_job) != 0
            && in_job != FALSE
    };
    if !verified {
        let _ = resources.terminate_for_cleanup();
        return launch_failed(true, false, Some(&cleanup));
    }
    resources.job_assigned = true;
    options.metrics.job_assigned.fetch_add(1, Ordering::AcqRel);
    phase.store(H7LaunchPhase::AssignedJob as u8, Ordering::Release);
    let resumed = unsafe { ResumeThread(resources.thread.raw()) } != u32::MAX;
    if !resumed {
        let _ = resources.terminate_for_cleanup();
        return launch_failed(true, false, Some(&cleanup));
    }
    options
        .metrics
        .thread_resumed
        .fetch_add(1, Ordering::AcqRel);
    cleanup.user_code_started.store(true, Ordering::Release);
    phase.store(H7LaunchPhase::Resumed as u8, Ordering::Release);
    let _output_handle_guard = H7OutputHandleGuard::new(Arc::clone(&options.metrics), 4);
    let mut stdout_capture = stdout_capture;
    let mut stderr_capture = stderr_capture;
    let deadline = Instant::now() + action.timeout;
    let mut output_drain_deadline = None;
    let mut timed_out = false;
    let mut cancelled = false;
    let mut output_failure = false;
    let mut output_cleanup_bounded = true;
    let mut process_signaled = false;

    loop {
        if options.cancellation.load(Ordering::Acquire) {
            cancelled = true;
            if !process_signaled {
                let _ = resources.terminate_assigned_job();
            }
            output_cleanup_bounded = cancel_and_drain_h7_output(
                &options.metrics,
                &mut stdout_capture,
                &mut stderr_capture,
            );
            break;
        }
        stdout_capture.arm_read();
        stderr_capture.arm_read();
        service_h7_ready_output_events(&mut stdout_capture, &mut stderr_capture);
        update_h7_pending_output_metric(&options.metrics, &stdout_capture, &stderr_capture);
        if stdout_capture.overflowed() || stderr_capture.overflowed() {
            if !process_signaled {
                let _ = resources.terminate_assigned_job();
            }
            output_cleanup_bounded = cancel_and_drain_h7_output(
                &options.metrics,
                &mut stdout_capture,
                &mut stderr_capture,
            );
            break;
        }
        if stdout_capture.failed() || stderr_capture.failed() {
            output_failure = true;
            if !process_signaled {
                let _ = resources.terminate_assigned_job();
            }
            output_cleanup_bounded = cancel_and_drain_h7_output(
                &options.metrics,
                &mut stdout_capture,
                &mut stderr_capture,
            );
            break;
        }
        if process_signaled && stdout_capture.is_complete() && stderr_capture.is_complete() {
            break;
        }

        let wait_deadline = if process_signaled {
            output_drain_deadline.expect("D29-H7 output drain deadline")
        } else {
            deadline
        };
        let remaining = wait_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if process_signaled {
                output_failure = true;
                output_cleanup_bounded = cancel_and_drain_h7_output(
                    &options.metrics,
                    &mut stdout_capture,
                    &mut stderr_capture,
                );
            } else {
                timed_out = true;
                let _ = resources.terminate_assigned_job();
                output_cleanup_bounded = cancel_and_drain_h7_output(
                    &options.metrics,
                    &mut stdout_capture,
                    &mut stderr_capture,
                );
            }
            break;
        }
        let wait_ms = remaining.as_millis().min(20).max(1) as u32;
        if process_signaled {
            let handles = [stdout_capture.event_handle(), stderr_capture.event_handle()];
            let wait = unsafe {
                WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, wait_ms)
            };
            if wait == WAIT_OBJECT_0 {
                let _ = stdout_capture.complete_pending();
            } else if wait == WAIT_OBJECT_0 + 1 {
                let _ = stderr_capture.complete_pending();
            } else if wait != WAIT_TIMEOUT {
                output_failure = true;
                output_cleanup_bounded = cancel_and_drain_h7_output(
                    &options.metrics,
                    &mut stdout_capture,
                    &mut stderr_capture,
                );
                break;
            }
        } else {
            let handles = [
                resources.process.raw(),
                stdout_capture.event_handle(),
                stderr_capture.event_handle(),
            ];
            let wait = unsafe {
                WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, wait_ms)
            };
            if wait == WAIT_OBJECT_0 {
                process_signaled = true;
                output_drain_deadline = Some(Instant::now() + H7_CLEANUP_TIMEOUT);
                phase.store(H7LaunchPhase::Exited as u8, Ordering::Release);
                options
                    .metrics
                    .process_exited
                    .fetch_add(1, Ordering::AcqRel);
                // The process HANDLE is removed from all subsequent waits.
                // Consume both already-signaled output events before entering
                // the output-only drain phase.
                service_h7_ready_output_events(&mut stdout_capture, &mut stderr_capture);
                update_h7_pending_output_metric(&options.metrics, &stdout_capture, &stderr_capture);
            } else if wait == WAIT_OBJECT_0 + 1 {
                let _ = stdout_capture.complete_pending();
            } else if wait == WAIT_OBJECT_0 + 2 {
                let _ = stderr_capture.complete_pending();
            } else if wait != WAIT_TIMEOUT {
                output_failure = true;
                let _ = resources.terminate_assigned_job();
                output_cleanup_bounded = cancel_and_drain_h7_output(
                    &options.metrics,
                    &mut stdout_capture,
                    &mut stderr_capture,
                );
                break;
            }
        }
        update_h7_pending_output_metric(&options.metrics, &stdout_capture, &stderr_capture);
    }
    if !phase_at_least(&phase, H7LaunchPhase::Exited) && !resources.job_terminated {
        let _ = resources.terminate_for_cleanup();
    }
    if stdout_capture.pending() || stderr_capture.pending() {
        output_cleanup_bounded =
            cancel_and_drain_h7_output(&options.metrics, &mut stdout_capture, &mut stderr_capture)
                && output_cleanup_bounded;
    }
    // A bounded drain is only an observation deadline. If the kernel has not
    // reported terminality by then, transfer the exact operation owner to the
    // process-lifetime quarantine. The active worker never frees a
    // kernel-referenced OVERLAPPED, buffer, event, or pipe handle.
    let stdout_quarantined = stdout_capture.quarantine_if_pending();
    let stderr_quarantined = stderr_capture.quarantine_if_pending();
    output_cleanup_bounded &= !stdout_quarantined && !stderr_quarantined;
    update_h7_pending_output_metric(&options.metrics, &stdout_capture, &stderr_capture);
    // Compatibility fields retained from the R2 result shape.  R3 has no
    // reader threads to join; a stream is cleanup-complete once it has no
    // outstanding overlapped read, including the pre-arm cancellation race.
    let stdout_reader_joined = !stdout_quarantined && !stdout_capture.pending();
    let stderr_reader_joined = !stderr_quarantined && !stderr_capture.pending();
    cleanup
        .stdout_reader_joined
        .store(stdout_reader_joined, Ordering::Release);
    cleanup
        .stderr_reader_joined
        .store(stderr_reader_joined, Ordering::Release);
    let output_limited = stdout_capture.overflowed() || stderr_capture.overflowed();
    if output_limited && !phase_at_least(&phase, H7LaunchPhase::Exited) && !resources.job_terminated
    {
        let _ = resources.terminate_for_cleanup();
    }
    let mut process_exit_verified = cleanup.process_exit_verified.load(Ordering::Acquire);
    if phase_at_least(&phase, H7LaunchPhase::Exited) && !process_exit_verified {
        let _ = resources.observe_process_exit(0);
        process_exit_verified = cleanup.process_exit_verified.load(Ordering::Acquire);
    }
    let exit_code = if process_exit_verified {
        let mut code = 0_u32;
        (unsafe { GetExitCodeProcess(resources.process.raw(), &mut code) } != 0).then_some(code)
    } else {
        None
    };
    if process_exit_verified {
        resources.close_process_handle();
        resources.close_thread_handle();
    }
    if !cleanup.process_tree_observed.load(Ordering::Acquire) {
        let _ = resources.observe_process_tree_until_quiescent(Duration::from_millis(100));
    }
    let process_tree_remaining = if cleanup.process_tree_observed.load(Ordering::Acquire) {
        cleanup.process_tree_remaining.load(Ordering::Acquire)
    } else {
        usize::MAX
    };
    let pending_stdout_reads = usize::from(stdout_capture.pending());
    let pending_stderr_reads = usize::from(stderr_capture.pending());
    let stdout_retained_bytes = stdout_capture.retained_len();
    let stderr_retained_bytes = stderr_capture.retained_len();
    let stdout = std::mem::take(&mut stdout_capture.bytes);
    let stderr = std::mem::take(&mut stderr_capture.bytes);
    drop(stdout_capture);
    drop(stderr_capture);
    drop(_output_handle_guard);
    let termination_unproven = ((cancelled || timed_out || (output_limited && !process_signaled))
        && !resources.job_terminated)
        || output_failure
        || !output_cleanup_bounded;
    let kind = if termination_unproven {
        H7NativeOutcomeKind::StartedOutcomeUnknown
    } else if output_limited {
        H7NativeOutcomeKind::StartedAndOutputLimited
    } else if cancelled {
        H7NativeOutcomeKind::StartedAndCancelled
    } else if timed_out {
        H7NativeOutcomeKind::StartedAndTimedOut
    } else if phase_at_least(&phase, H7LaunchPhase::Exited) {
        H7NativeOutcomeKind::StartedAndExited
    } else {
        H7NativeOutcomeKind::StartedOutcomeUnknown
    };
    H7NativeResult {
        kind,
        process_created: true,
        user_code_started: true,
        exit_code,
        stdout,
        stderr,
        job_terminated: resources.job_terminated,
        process_tree_observed: cleanup.process_tree_observed.load(Ordering::Acquire),
        process_tree_remaining,
        automatic_retry: false,
        direct_termination_attempted: cleanup.direct_termination_attempted.load(Ordering::Acquire),
        direct_termination_verified: cleanup.direct_termination_verified.load(Ordering::Acquire),
        process_exit_verified,
        stdout_reader_joined,
        stderr_reader_joined,
        pending_stdout_reads,
        pending_stderr_reads,
        stdout_retained_bytes,
        stderr_retained_bytes,
    }
}

trait H7NativeResultExt {
    fn with_kind(self, kind: H7NativeOutcomeKind) -> Self;
}

impl H7NativeResultExt for H7NativeResult {
    fn with_kind(mut self, kind: H7NativeOutcomeKind) -> Self {
        self.kind = kind;
        self
    }
}

fn launch_failed(
    process_created: bool,
    user_code_started: bool,
    cleanup: Option<&H7CleanupEvidence>,
) -> H7NativeResult {
    let (
        job_terminated,
        process_tree_observed,
        process_tree_remaining,
        direct_termination_attempted,
        direct_termination_verified,
        process_exit_verified,
        stdout_reader_joined,
        stderr_reader_joined,
    ) = cleanup.map_or(
        (false, false, 0, false, false, false, true, true),
        |cleanup| {
            (
                cleanup.job_termination_proven.load(Ordering::Acquire),
                cleanup.process_tree_observed.load(Ordering::Acquire),
                if cleanup.process_tree_observed.load(Ordering::Acquire) {
                    cleanup.process_tree_remaining.load(Ordering::Acquire)
                } else if process_created {
                    usize::MAX
                } else {
                    0
                },
                cleanup.direct_termination_attempted.load(Ordering::Acquire),
                cleanup.direct_termination_verified.load(Ordering::Acquire),
                cleanup.process_exit_verified.load(Ordering::Acquire),
                cleanup.stdout_reader_joined.load(Ordering::Acquire),
                cleanup.stderr_reader_joined.load(Ordering::Acquire),
            )
        },
    );
    H7NativeResult {
        kind: H7NativeOutcomeKind::LaunchFailed,
        process_created,
        user_code_started,
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        job_terminated,
        process_tree_observed,
        process_tree_remaining,
        automatic_retry: false,
        direct_termination_attempted,
        direct_termination_verified,
        process_exit_verified,
        stdout_reader_joined,
        stderr_reader_joined,
        pending_stdout_reads: 0,
        pending_stderr_reads: 0,
        stdout_retained_bytes: 0,
        stderr_retained_bytes: 0,
    }
}

fn create_job_object() -> Result<H7Handle, String> {
    let job =
        unsafe { CreateJobObjectW(std::ptr::null::<SECURITY_ATTRIBUTES>(), std::ptr::null()) };
    let job = H7Handle::new(job)?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
            LimitFlags: JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            ActiveProcessLimit: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let ok = unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        return Err("H7 Job Object limit configuration failed".to_string());
    }
    Ok(job)
}

fn create_stdin_pipe() -> Result<(H7Handle, H7Handle), String> {
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    if unsafe {
        windows_sys::Win32::System::Pipes::CreatePipe(
            &mut read,
            &mut write,
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            0,
        )
    } == 0
    {
        return Err("H7 stdin pipe creation failed".to_string());
    }
    let stdin_read = H7Handle::new(read)?;
    let stdin_write = H7Handle::new(write)?;
    if unsafe { SetHandleInformation(stdin_write.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err("H7 parent stdin handle inheritance restriction failed".to_string());
    }
    if unsafe { SetHandleInformation(stdin_read.raw(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }
        == 0
    {
        return Err("H7 child stdin handle inheritance setup failed".to_string());
    }
    Ok((stdin_read, stdin_write))
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum H7HostRequest {
    Initialize {
        protocol_version: u8,
        life_id: String,
        task_id: String,
        capability_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        workspace_root_identity: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        profile_id: Option<String>,
    },
    EvaluateWorkspaceScope {
        binding: H7ProcessBinding,
    },
    ProvisionProcessConfirmation {
        binding: H7ProcessBinding,
    },
    IssueProcessGrant {
        binding: H7ProcessBinding,
        authorization_revision: i64,
    },
    RevalidateProcessGrant {
        grant_id: String,
        binding: H7ProcessBinding,
        authorization_revision: i64,
    },
    DisableAuthorizationForTest {
        life_id: String,
        capability_id: String,
        expected_revision: i64,
    },
    HoldForTest {
        milliseconds: u64,
    },
    Shutdown {},
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct H7HostResponse {
    operation: String,
    status: String,
    canonical: Option<H7CanonicalWire>,
    confirmation: Option<H7ConfirmationWire>,
    process_grant: Option<H7GrantWire>,
    confirmation_consumed: bool,
    denial: Option<String>,
    authorization_revision: Option<i64>,
    error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct H7CanonicalWire {
    canonical_evaluations: usize,
    production_registry_size: usize,
    test_registry_size: usize,
    authorization_row_reads: usize,
    life_id: String,
    capability_id: String,
    outcome: String,
    decision_code: String,
    risk_class: String,
    approval_floor: String,
    scope_requirement: String,
    authorization_revision: Option<i64>,
    #[serde(default)]
    host_scope_authority_present: Option<bool>,
    #[serde(default)]
    requested_root_matched_authorized_root: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct H7ConfirmationWire {
    confirmation_id: String,
    binding: H7ProcessBinding,
    authorization_revision: i64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct H7GrantWire {
    grant_id: String,
    confirmation_id: String,
    binding: H7ProcessBinding,
    authorization_revision: i64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    single_use: bool,
    used: bool,
}

struct H7HostProcessIo {
    stdin: ChildStdin,
    stdout: ChildStdout,
}

struct H7PersistentHostProcess {
    io: Mutex<Option<H7HostProcessIo>>,
    child: Arc<Mutex<Child>>,
    in_flight: AtomicBool,
}

impl H7PersistentHostProcess {
    fn start(
        repo_root: &Path,
        capability_id: &str,
        workspace_root_identity: Option<String>,
        profile_id: Option<String>,
    ) -> Result<Arc<Self>, String> {
        let executable = h7_authority_fixture_executable(repo_root)?;
        let mut child = Command::new(executable)
            .current_dir(repo_root)
            .env("CARGO_TERM_COLOR", "never")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("spawn D29-H7 Host fixture: {error}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "D29-H7 Host fixture stdin unavailable".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "D29-H7 Host fixture stdout unavailable".to_string())?;
        let process = Arc::new(Self {
            io: Mutex::new(Some(H7HostProcessIo { stdin, stdout })),
            child: Arc::new(Mutex::new(child)),
            in_flight: AtomicBool::new(false),
        });
        let response = process.roundtrip_bounded(&H7HostRequest::Initialize {
            protocol_version: 1,
            life_id: H7_LIFE_ID.to_string(),
            task_id: H7_TASK_ID.to_string(),
            capability_id: capability_id.to_string(),
            workspace_root_identity,
            profile_id,
        });
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                process.abort();
                return Err(error);
            }
        };
        let response: H7HostResponse = serde_json::from_slice(&response)
            .map_err(|_| "D29-H7 Host initialize response malformed".to_string())?;
        if response.operation != "initialize"
            || response.status != "ok"
            || response.authorization_revision != Some(2)
            || response.canonical.is_some()
            || response.confirmation.is_some()
            || response.process_grant.is_some()
            || response.confirmation_consumed
            || response.denial.is_some()
            || response.error_code.is_some()
        {
            process.abort();
            return Err("D29-H7 Host initialize response invalid".to_string());
        }
        Ok(process)
    }

    fn roundtrip_bounded(self: &Arc<Self>, request: &H7HostRequest) -> Result<Vec<u8>, String> {
        if self
            .in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("D29-H7 Host IPC already has an outstanding request".to_string());
        }
        let request = request.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let process = Arc::clone(self);
        let join = thread::spawn(move || {
            let result = process.roundtrip_raw(&request);
            let _ = sender.send(result);
        });
        match receiver.recv_timeout(H7_HOST_IPC_TIMEOUT) {
            Ok(result) => {
                let _ = join.join();
                self.in_flight.store(false, Ordering::Release);
                result
            }
            Err(_) => {
                self.abort();
                let _ = join.join();
                self.in_flight.store(false, Ordering::Release);
                Err("D29-H7 Host IPC timed out".to_string())
            }
        }
    }

    fn roundtrip_raw(&self, request: &H7HostRequest) -> Result<Vec<u8>, String> {
        let body = serde_json::to_vec(request)
            .map_err(|_| "D29-H7 Host request serialization failed".to_string())?;
        if body.is_empty() || body.len() > H7_HOST_MAX_FRAME_BYTES {
            return Err("D29-H7 Host request exceeded bounded frame size".to_string());
        }
        let mut io = self
            .io
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let io = io
            .as_mut()
            .ok_or_else(|| "D29-H7 Host process is closed".to_string())?;
        io.stdin
            .write_all(&(body.len() as u32).to_be_bytes())
            .and_then(|_| io.stdin.write_all(&body))
            .and_then(|_| io.stdin.flush())
            .map_err(|_| "D29-H7 Host request write failed".to_string())?;
        let mut length = [0_u8; 4];
        io.stdout
            .read_exact(&mut length)
            .map_err(|_| "D29-H7 Host response frame length read failed".to_string())?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > H7_HOST_MAX_FRAME_BYTES {
            return Err("D29-H7 Host response exceeded its bound".to_string());
        }
        let mut response = vec![0_u8; length];
        io.stdout
            .read_exact(&mut response)
            .map_err(|_| "D29-H7 Host response frame body read failed".to_string())?;
        Ok(response)
    }

    fn abort(&self) {
        {
            let mut child = self
                .child
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        *self
            .io
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    fn shutdown(self: &Arc<Self>) -> bool {
        let response = self
            .roundtrip_bounded(&H7HostRequest::Shutdown {})
            .ok()
            .and_then(|body| serde_json::from_slice::<H7HostResponse>(&body).ok());
        let valid = response.as_ref().is_some_and(|response| {
            response.operation == "shutdown"
                && response.status == "ok"
                && response.canonical.is_none()
                && response.confirmation.is_none()
                && response.process_grant.is_none()
                && !response.confirmation_consumed
                && response.denial.is_none()
                && response.authorization_revision.is_none()
                && response.error_code.is_none()
        });
        let mut child = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let exited = match child.try_wait() {
            Ok(Some(status)) => status.success(),
            Ok(None) if valid => child.wait().map(|status| status.success()).unwrap_or(false),
            Ok(None) => {
                let _ = child.kill();
                child.wait().map(|status| status.success()).unwrap_or(false)
            }
            Err(_) => false,
        };
        *self
            .io
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        valid && exited
    }
}

impl Drop for H7PersistentHostProcess {
    fn drop(&mut self) {
        self.abort();
    }
}

fn h7_authority_fixture_executable(repo_root: &Path) -> Result<PathBuf, String> {
    let executable = repo_root
        .join("src-tauri")
        .join("target")
        .join("debug")
        .join("d29h7-authority-fixture.exe");
    let source = repo_root
        .join("src-tauri")
        .join("src")
        .join("capability")
        .join("d29h7_host_fixture.rs");
    let executable_is_fresh = executable
        .metadata()
        .and_then(|binary| binary.modified())
        .and_then(|binary_time| {
            source.metadata().and_then(|source| {
                source
                    .modified()
                    .map(|source_time| (binary_time, source_time))
            })
        })
        .is_ok_and(|(binary_time, source_time)| binary_time >= source_time);
    if executable.is_file() && executable_is_fresh {
        return Ok(executable);
    }
    let status = Command::new("cargo")
        .current_dir(repo_root)
        .args(["build", "--quiet", "--locked", "--manifest-path"])
        .arg(repo_root.join("src-tauri").join("Cargo.toml"))
        .args([
            "--bin",
            "d29h7-authority-fixture",
            "--features",
            "d29-h7-host-fixture",
        ])
        .env("CARGO_BUILD_JOBS", "1")
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_TERM_COLOR", "never")
        .status()
        .map_err(|error| format!("build D29-H7 Host fixture: {error}"))?;
    if !status.success() || !executable.is_file() {
        return Err("D29-H7 Host fixture executable was not produced".to_string());
    }
    Ok(executable)
}

fn h7_process_fixture_executable(repo_root: &Path) -> Result<PathBuf, String> {
    let executable = repo_root
        .join("vita-agent")
        .join("target")
        .join("debug")
        .join("d29h7-process-fixture.exe");
    let source = repo_root
        .join("vita-agent")
        .join("src")
        .join("bin")
        .join("d29h7-process-fixture.rs");
    let executable_is_fresh = executable
        .metadata()
        .and_then(|binary| binary.modified())
        .and_then(|binary_time| {
            source.metadata().and_then(|source| {
                source
                    .modified()
                    .map(|source_time| (binary_time, source_time))
            })
        })
        .is_ok_and(|(binary_time, source_time)| binary_time >= source_time);
    if executable.is_file() && executable_is_fresh {
        return Ok(executable);
    }
    let status = Command::new("cargo")
        .current_dir(repo_root)
        .args(["build", "--quiet", "--locked", "--manifest-path"])
        .arg(repo_root.join("vita-agent").join("Cargo.toml"))
        .args(["--bin", "d29h7-process-fixture"])
        .env("CARGO_BUILD_JOBS", "1")
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_TERM_COLOR", "never")
        .status()
        .map_err(|error| format!("build D29-H7 process fixture: {error}"))?;
    if !status.success() || !executable.is_file() {
        return Err("D29-H7 process fixture executable was not produced".to_string());
    }
    Ok(executable)
}

struct H7ProcessGrant {
    grant_id: String,
    confirmation_id: String,
    binding: H7ProcessBinding,
    authorization_revision: i64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    single_use: bool,
    used: bool,
}

#[derive(Default)]
struct H7AuthorityMetrics {
    trusted_confirmations: AtomicUsize,
    request_derived_confirmations: AtomicUsize,
    trusted_workspace_scopes: AtomicUsize,
    request_derived_workspace_scopes: AtomicUsize,
    grants_issued: AtomicUsize,
    final_revalidations: AtomicUsize,
    canonical_evaluations: AtomicUsize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H7HostResponseFault {
    IssueWrongBinding,
    IssueWrongRevision,
    IssueWrongConfirmation,
    IssueSingleUseFalse,
    FinalWrongBinding,
    FinalWrongRevision,
    FinalWrongConfirmation,
    FinalSingleUseFalse,
    FinalUsedFalse,
    FinalContradictory,
    FinalExtraConfirmation,
    FinalMalformed,
    FinalTruncated,
}

impl H7HostResponseFault {
    fn is_final(self) -> bool {
        matches!(
            self,
            Self::FinalWrongBinding
                | Self::FinalWrongRevision
                | Self::FinalWrongConfirmation
                | Self::FinalSingleUseFalse
                | Self::FinalUsedFalse
                | Self::FinalContradictory
                | Self::FinalExtraConfirmation
                | Self::FinalMalformed
                | Self::FinalTruncated
        )
    }
}

fn apply_h7_host_response_fault(response: &mut H7HostResponse, fault: H7HostResponseFault) {
    match fault {
        H7HostResponseFault::IssueWrongBinding | H7HostResponseFault::FinalWrongBinding => {
            if let Some(grant) = response.process_grant.as_mut() {
                grant.binding.program_id = "wrong-program".to_string();
            }
        }
        H7HostResponseFault::IssueWrongRevision | H7HostResponseFault::FinalWrongRevision => {
            response.authorization_revision =
                response.authorization_revision.map(|value| value + 1);
            if let Some(grant) = response.process_grant.as_mut() {
                grant.authorization_revision += 1;
            }
        }
        H7HostResponseFault::IssueWrongConfirmation => {
            if let Some(grant) = response.process_grant.as_mut() {
                grant.confirmation_id.clear();
            }
        }
        H7HostResponseFault::FinalWrongConfirmation => {
            if let Some(grant) = response.process_grant.as_mut() {
                grant.confirmation_id = "wrong-confirmation".to_string();
            }
        }
        H7HostResponseFault::IssueSingleUseFalse | H7HostResponseFault::FinalSingleUseFalse => {
            if let Some(grant) = response.process_grant.as_mut() {
                grant.single_use = false;
            }
        }
        H7HostResponseFault::FinalUsedFalse => {
            if let Some(grant) = response.process_grant.as_mut() {
                grant.used = false;
            }
        }
        H7HostResponseFault::FinalContradictory => {
            response.confirmation_consumed = true;
        }
        H7HostResponseFault::FinalExtraConfirmation => {
            if let Some(grant) = response.process_grant.as_ref() {
                response.confirmation = Some(H7ConfirmationWire {
                    confirmation_id: grant.confirmation_id.clone(),
                    binding: grant.binding.clone(),
                    authorization_revision: grant.authorization_revision,
                    issued_at_unix_ms: grant.issued_at_unix_ms,
                    expires_at_unix_ms: grant.expires_at_unix_ms,
                });
            }
        }
        H7HostResponseFault::FinalMalformed | H7HostResponseFault::FinalTruncated => {}
    }
}

struct H7Authority {
    process: Arc<H7PersistentHostProcess>,
    metrics: Arc<H7AuthorityMetrics>,
    response_fault: Mutex<Option<H7HostResponseFault>>,
    capability_id: String,
    workspace_root_identity: Option<String>,
    profile_id: Option<String>,
}

impl H7Authority {
    fn new() -> Result<Arc<Self>, String> {
        Self::new_with_binding(H7_CAPABILITY_ID, None, None)
    }

    fn new_workspace(workspace_root: &TrustedWorkspaceRoot) -> Result<Arc<Self>, String> {
        workspace_root
            .verify_named_path_current()
            .map_err(|_| "D29-H7-B workspace root was not current at Host setup".to_string())?;
        Self::new_with_binding(
            H7B_CAPABILITY_ID,
            Some(h7_workspace_identity_wire(workspace_root.identity())),
            None,
        )
    }

    fn new_git_workspace(workspace_root: &TrustedWorkspaceRoot) -> Result<Arc<Self>, String> {
        workspace_root
            .verify_named_path_current()
            .map_err(|_| "D29-H7-C workspace root was not current at Host setup".to_string())?;
        Self::new_with_binding(
            H7C_CAPABILITY_ID,
            Some(h7_workspace_identity_wire(workspace_root.identity())),
            Some(H7C_PROFILE_ID.to_string()),
        )
    }

    fn new_with_binding(
        capability_id: &str,
        workspace_root_identity: Option<String>,
        profile_id: Option<String>,
    ) -> Result<Arc<Self>, String> {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| "D29-H7 manifest has no repository parent".to_string())?
            .to_path_buf();
        Ok(Arc::new(Self {
            process: H7PersistentHostProcess::start(
                &repo_root,
                capability_id,
                workspace_root_identity.clone(),
                profile_id.clone(),
            )?,
            metrics: Arc::new(H7AuthorityMetrics::default()),
            response_fault: Mutex::new(None),
            capability_id: capability_id.to_string(),
            workspace_root_identity,
            profile_id,
        }))
    }

    fn inject_response_fault(&self, fault: H7HostResponseFault) {
        *self
            .response_fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fault);
    }

    fn take_response_fault(&self, final_response: bool) -> Option<H7HostResponseFault> {
        let mut fault = self
            .response_fault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if fault.is_some_and(|value| value.is_final() == final_response) {
            fault.take()
        } else {
            None
        }
    }

    fn provenance(&self) -> (usize, usize) {
        (
            self.metrics.trusted_confirmations.load(Ordering::Acquire),
            self.metrics
                .request_derived_confirmations
                .load(Ordering::Acquire),
        )
    }

    fn workspace_scope_provenance(&self) -> (usize, usize) {
        (
            self.metrics
                .trusted_workspace_scopes
                .load(Ordering::Acquire),
            self.metrics
                .request_derived_workspace_scopes
                .load(Ordering::Acquire),
        )
    }

    fn evaluate_workspace_scope(&self, action: &PreparedProcessAction) -> Result<i64, String> {
        let action_root_identity = action
            .workspace_root_identity
            .map(h7_workspace_identity_wire);
        if !matches!(
            action.capability_id.as_str(),
            H7B_CAPABILITY_ID | H7C_CAPABILITY_ID
        ) || !matches!(
            self.capability_id.as_str(),
            H7B_CAPABILITY_ID | H7C_CAPABILITY_ID
        ) || self.workspace_root_identity.as_deref() != action_root_identity.as_deref()
            || self.profile_id.as_deref() != action.profile_id.as_deref()
        {
            return Err("D29-H7-B Host workspace scope binding was not exact".to_string());
        }
        let response = self
            .process
            .roundtrip_bounded(&H7HostRequest::EvaluateWorkspaceScope {
                binding: H7ProcessBinding::from_action(action),
            })?;
        let response: H7HostResponse = serde_json::from_slice(&response)
            .map_err(|_| "D29-H7-B workspace scope response malformed".to_string())?;
        if response.operation != "evaluate_workspace_scope"
            || response.status != "ok"
            || response.canonical.is_none()
            || response.confirmation.is_some()
            || response.process_grant.is_some()
            || response.confirmation_consumed
            || response.denial.is_some()
            || response.error_code.is_some()
        {
            return Err(response
                .denial
                .unwrap_or_else(|| "D29-H7-B workspace scope response invalid".to_string()));
        }
        let canonical = response.canonical.as_ref().expect("checked canonical");
        validate_h7_canonical(
            canonical,
            action,
            response.authorization_revision.unwrap_or(0),
        )?;
        self.metrics
            .trusted_workspace_scopes
            .fetch_add(1, Ordering::AcqRel);
        response
            .authorization_revision
            .ok_or_else(|| "D29-H7-B workspace scope omitted authorization revision".to_string())
    }

    fn provision_workspace_confirmation(
        &self,
        action: &PreparedProcessAction,
    ) -> Result<i64, String> {
        if !matches!(
            action.capability_id.as_str(),
            H7B_CAPABILITY_ID | H7C_CAPABILITY_ID
        ) {
            return Err("D29-H7-B confirmation received a non-workspace action".to_string());
        }
        self.provision_confirmation(action)
    }

    fn provision_confirmation(&self, action: &PreparedProcessAction) -> Result<i64, String> {
        let response =
            self.process
                .roundtrip_bounded(&H7HostRequest::ProvisionProcessConfirmation {
                    binding: H7ProcessBinding::from_action(action),
                })?;
        let response: H7HostResponse = serde_json::from_slice(&response)
            .map_err(|_| "D29-H7 confirmation response malformed".to_string())?;
        if response.operation != "provision_process_confirmation"
            || response.status != "ok"
            || response.canonical.is_some()
            || response.confirmation.is_some()
            || response.process_grant.is_some()
            || response.confirmation_consumed
            || response.denial.is_some()
            || response.error_code.is_some()
        {
            return Err("D29-H7 confirmation response invalid".to_string());
        }
        self.metrics
            .trusted_confirmations
            .fetch_add(1, Ordering::AcqRel);
        response
            .authorization_revision
            .ok_or_else(|| "D29-H7 confirmation omitted authorization revision".to_string())
    }

    fn issue_process_grant(
        &self,
        action: &PreparedProcessAction,
        authorization_revision: i64,
    ) -> Result<H7ProcessGrant, String> {
        let response = self
            .process
            .roundtrip_bounded(&H7HostRequest::IssueProcessGrant {
                binding: H7ProcessBinding::from_action(action),
                authorization_revision,
            })?;
        let mut response: H7HostResponse = serde_json::from_slice(&response)
            .map_err(|_| "D29-H7 ProcessGrant response malformed".to_string())?;
        if let Some(fault) = self.take_response_fault(false) {
            apply_h7_host_response_fault(&mut response, fault);
        }
        if response.operation != "issue_process_grant"
            || response.status != "ok"
            || response.canonical.is_none()
            || response.confirmation.is_some()
            || response.process_grant.is_none()
            || !response.confirmation_consumed
            || response.authorization_revision != Some(authorization_revision)
            || response.denial.is_some()
            || response.error_code.is_some()
        {
            return Err(response
                .denial
                .unwrap_or_else(|| "D29-H7 ProcessGrant issuance was invalid".to_string()));
        }
        let canonical = response.canonical.as_ref().expect("checked canonical");
        validate_h7_canonical(canonical, action, authorization_revision)?;
        let grant = response.process_grant.expect("checked ProcessGrant");
        validate_h7_grant_binding(&grant, action, authorization_revision)?;
        self.metrics.grants_issued.fetch_add(1, Ordering::AcqRel);
        Ok(H7ProcessGrant {
            grant_id: grant.grant_id,
            confirmation_id: grant.confirmation_id,
            binding: grant.binding,
            authorization_revision: grant.authorization_revision,
            issued_at_unix_ms: grant.issued_at_unix_ms,
            expires_at_unix_ms: grant.expires_at_unix_ms,
            single_use: grant.single_use,
            used: grant.used,
        })
    }

    fn revalidate_process_grant(
        &self,
        action: &PreparedProcessAction,
        grant: &mut H7ProcessGrant,
    ) -> Result<(), String> {
        if grant.used || grant.binding != H7ProcessBinding::from_action(action) {
            return Err(
                "D29-H7 local ProcessGrant binding was already used or changed".to_string(),
            );
        }
        let response = self
            .process
            .roundtrip_bounded(&H7HostRequest::RevalidateProcessGrant {
                grant_id: grant.grant_id.clone(),
                binding: H7ProcessBinding::from_action(action),
                authorization_revision: grant.authorization_revision,
            })?;
        let final_fault = self.take_response_fault(true);
        let response = match final_fault {
            Some(H7HostResponseFault::FinalMalformed) => b"not-json".to_vec(),
            Some(H7HostResponseFault::FinalTruncated) => {
                response[..response.len().saturating_sub(1)].to_vec()
            }
            _ => response,
        };
        let mut response: H7HostResponse = serde_json::from_slice(&response)
            .map_err(|_| "D29-H7 final Host response malformed".to_string())?;
        if let Some(fault) = final_fault {
            apply_h7_host_response_fault(&mut response, fault);
        }
        if response.operation != "revalidate_process_grant"
            || response.status != "ok"
            || response.canonical.is_none()
            || response.confirmation.is_some()
            || response.process_grant.is_none()
            || response.confirmation_consumed
            || response.authorization_revision != Some(grant.authorization_revision)
            || response.denial.is_some()
            || response.error_code.is_some()
        {
            return Err(response
                .denial
                .unwrap_or_else(|| "D29-H7 final Host revalidation denied".to_string()));
        }
        let canonical = response.canonical.as_ref().expect("checked canonical");
        validate_h7_canonical(canonical, action, grant.authorization_revision)?;
        let returned = response.process_grant.expect("checked final grant");
        if returned.grant_id != grant.grant_id
            || returned.confirmation_id != grant.confirmation_id
            || returned.binding != grant.binding
            || returned.authorization_revision != grant.authorization_revision
            || returned.issued_at_unix_ms != grant.issued_at_unix_ms
            || returned.expires_at_unix_ms != grant.expires_at_unix_ms
            || !returned.single_use
            || !returned.used
            || returned.expires_at_unix_ms <= h7_unix_millis()
        {
            return Err("D29-H7 final Host grant evidence was invalid".to_string());
        }
        grant.used = true;
        self.metrics
            .final_revalidations
            .fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn disable_authorization_for_test(&self, expected_revision: i64) -> Result<(), String> {
        let response =
            self.process
                .roundtrip_bounded(&H7HostRequest::DisableAuthorizationForTest {
                    life_id: H7_LIFE_ID.to_string(),
                    capability_id: self.capability_id.clone(),
                    expected_revision,
                })?;
        let response: H7HostResponse = serde_json::from_slice(&response)
            .map_err(|_| "D29-H7 disable response malformed".to_string())?;
        if response.operation != "disable_authorization_for_test"
            || response.status != "ok"
            || response.authorization_revision != Some(expected_revision + 1)
        {
            return Err("D29-H7 disable response invalid".to_string());
        }
        Ok(())
    }

    fn hold_for_test(&self, milliseconds: u64) -> Result<(), String> {
        let _ = self
            .process
            .roundtrip_bounded(&H7HostRequest::HoldForTest { milliseconds })?;
        Ok(())
    }

    fn shutdown(&self) -> bool {
        self.process.shutdown()
    }
}

fn validate_h7_canonical(
    canonical: &H7CanonicalWire,
    action: &PreparedProcessAction,
    revision: i64,
) -> Result<(), String> {
    let binding = H7ProcessBinding::from_action(action);
    let workspace = matches!(
        action.capability_id.as_str(),
        H7B_CAPABILITY_ID | H7C_CAPABILITY_ID
    );
    let expected_scope_requirement = if workspace {
        "WorkspaceRequired"
    } else {
        "None"
    };
    let expected_outcome = if workspace {
        "scope_required"
    } else {
        "explicit_confirmation_required"
    };
    let expected_decision_code = if workspace {
        "CAPABILITY_SCOPE_NOT_AVAILABLE"
    } else {
        "CAPABILITY_CONFIRMATION_REQUIRED"
    };
    if canonical.canonical_evaluations != 1
        || canonical.production_registry_size != 0
        || canonical.test_registry_size != 1
        || canonical.authorization_row_reads != 1
        || canonical.life_id != binding.life_id
        || canonical.capability_id != binding.capability_id
        || canonical.outcome != expected_outcome
        || canonical.decision_code != expected_decision_code
        || canonical.risk_class != "Critical"
        || canonical.approval_floor != "ExplicitPerAction"
        || canonical.scope_requirement != expected_scope_requirement
        || canonical.authorization_revision != Some(revision)
    {
        return Err("D29-H7 canonical D28 evidence was invalid".to_string());
    }
    if workspace
        && (canonical.host_scope_authority_present != Some(true)
            || canonical.requested_root_matched_authorized_root != Some(true))
    {
        return Err("D29-H7-B trusted workspace scope evidence was invalid".to_string());
    }
    if !workspace
        && (canonical.host_scope_authority_present.is_some()
            || canonical.requested_root_matched_authorized_root.is_some())
    {
        return Err("D29-H7 canonical unexpectedly exposed workspace scope evidence".to_string());
    }
    Ok(())
}

fn validate_h7_grant_binding(
    grant: &H7GrantWire,
    action: &PreparedProcessAction,
    revision: i64,
) -> Result<(), String> {
    let now = h7_unix_millis();
    if bounded_id(&grant.grant_id).is_none()
        || bounded_id(&grant.confirmation_id).is_none()
        || grant.issued_at_unix_ms > grant.expires_at_unix_ms
        || grant.issued_at_unix_ms > now
        || grant.expires_at_unix_ms <= now
        || grant.binding != H7ProcessBinding::from_action(action)
        || grant.authorization_revision != revision
        || !grant.single_use
        || grant.used
    {
        return Err("D29-H7 ProcessGrant binding was invalid".to_string());
    }
    Ok(())
}

struct H7PendingProcessAction {
    action: Arc<PreparedProcessAction>,
    response: tokio::sync::oneshot::Sender<i64>,
}

#[derive(Clone)]
struct H7PendingConfirmationBridge {
    sender: tokio::sync::mpsc::Sender<H7PendingProcessAction>,
    cancelled: Arc<AtomicBool>,
    cancelled_notify: Arc<Notify>,
}

impl H7PendingConfirmationBridge {
    fn new() -> (
        Arc<Self>,
        tokio::sync::mpsc::Receiver<H7PendingProcessAction>,
    ) {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        (
            Arc::new(Self {
                sender,
                cancelled: Arc::new(AtomicBool::new(false)),
                cancelled_notify: Arc::new(Notify::new()),
            }),
            receiver,
        )
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.cancelled_notify.notify_waiters();
    }

    async fn await_confirmation(
        &self,
        action: Arc<PreparedProcessAction>,
        cancellation: &AtomicBool,
        cancellation_notify: &Notify,
    ) -> Result<i64, String> {
        if cancellation.load(Ordering::Acquire) || self.cancelled.load(Ordering::Acquire) {
            return Err("D29-H7 process action was cancelled before confirmation".to_string());
        }
        let (response, receiver) = tokio::sync::oneshot::channel();
        let send = self
            .sender
            .send(H7PendingProcessAction { action, response });
        tokio::pin!(send);
        tokio::select! {
            result = &mut send => result.map_err(|_| "D29-H7 confirmation bridge closed".to_string())?,
            _ = cancellation_notify.notified() => return Err("D29-H7 process action cancelled".to_string()),
            _ = self.cancelled_notify.notified() => return Err("D29-H7 process action cancelled".to_string()),
            _ = tokio::time::sleep(H7_CONFIRMATION_TIMEOUT) => return Err("D29-H7 confirmation timed out".to_string()),
        }
        tokio::select! {
            result = tokio::time::timeout(H7_CONFIRMATION_TIMEOUT, receiver) => {
                result.map_err(|_| "D29-H7 confirmation timed out".to_string())?
                    .map_err(|_| "D29-H7 confirmation response closed".to_string())
            }
            _ = cancellation_notify.notified() => Err("D29-H7 process action cancelled".to_string()),
            _ = self.cancelled_notify.notified() => Err("D29-H7 process action cancelled".to_string()),
        }
    }
}

struct H7FinalFenceGate {
    armed: AtomicBool,
    entered: AtomicBool,
    released: AtomicBool,
    entered_notify: Notify,
    release_notify: Notify,
}

struct H7PostHostFenceGate {
    armed: AtomicBool,
    entered: AtomicBool,
    released: AtomicBool,
    entered_notify: Notify,
}

impl H7PostHostFenceGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            armed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
            entered_notify: Notify::new(),
        })
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }

    async fn wait_until_entered(&self) {
        if self.entered.load(Ordering::Acquire) {
            return;
        }
        self.entered_notify.notified().await;
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
    }

    fn wait_if_armed_blocking(&self) {
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        self.entered.store(true, Ordering::Release);
        self.entered_notify.notify_waiters();
        while !self.released.load(Ordering::Acquire) {
            thread::yield_now();
        }
    }
}

impl H7FinalFenceGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            armed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
            entered_notify: Notify::new(),
            release_notify: Notify::new(),
        })
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }

    async fn wait_until_entered(&self) {
        if self.entered.load(Ordering::Acquire) {
            return;
        }
        self.entered_notify.notified().await;
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.release_notify.notify_waiters();
    }

    async fn wait_if_armed(&self) {
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        self.entered.store(true, Ordering::Release);
        self.entered_notify.notify_waiters();
        if !self.released.load(Ordering::Acquire) {
            self.release_notify.notified().await;
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H7ToolResult {
    status: &'static str,
    process_created: bool,
    side_effect_count: usize,
    exit_code: Option<u32>,
    stdout: String,
    stderr: String,
    timed_out: bool,
    cancelled: bool,
    job_terminated: bool,
    process_tree_observed: bool,
    process_tree_remaining: usize,
    direct_termination_attempted: bool,
    direct_termination_verified: bool,
    process_exit_verified: bool,
    stdout_reader_joined: bool,
    stderr_reader_joined: bool,
    pending_stdout_reads: usize,
    pending_stderr_reads: usize,
    stdout_retained_bytes: usize,
    stderr_retained_bytes: usize,
}

impl H7ToolResult {
    fn denied() -> Self {
        Self {
            status: "denied",
            process_created: false,
            side_effect_count: 0,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            cancelled: false,
            job_terminated: false,
            process_tree_observed: false,
            process_tree_remaining: 0,
            direct_termination_attempted: false,
            direct_termination_verified: false,
            process_exit_verified: false,
            stdout_reader_joined: true,
            stderr_reader_joined: true,
            pending_stdout_reads: 0,
            pending_stderr_reads: 0,
            stdout_retained_bytes: 0,
            stderr_retained_bytes: 0,
        }
    }

    fn from_native(native: H7NativeResult) -> Self {
        let status = match native.kind {
            H7NativeOutcomeKind::LaunchFailed => "launch_failed",
            H7NativeOutcomeKind::StartedAndExited => "started_and_exited",
            H7NativeOutcomeKind::StartedAndTimedOut => "started_and_timed_out",
            H7NativeOutcomeKind::StartedAndCancelled => "started_and_cancelled",
            H7NativeOutcomeKind::StartedAndOutputLimited => "started_and_output_limited",
            H7NativeOutcomeKind::StartedOutcomeUnknown => "started_outcome_unknown",
            H7NativeOutcomeKind::Denied => "denied",
        };
        Self {
            status,
            process_created: native.process_created,
            side_effect_count: usize::from(native.process_created),
            exit_code: native.exit_code,
            stdout: String::from_utf8_lossy(&native.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&native.stderr).into_owned(),
            timed_out: native.kind == H7NativeOutcomeKind::StartedAndTimedOut,
            cancelled: native.kind == H7NativeOutcomeKind::StartedAndCancelled,
            job_terminated: native.job_terminated,
            process_tree_observed: native.process_tree_observed,
            process_tree_remaining: native.process_tree_remaining,
            direct_termination_attempted: native.direct_termination_attempted,
            direct_termination_verified: native.direct_termination_verified,
            process_exit_verified: native.process_exit_verified,
            stdout_reader_joined: native.stdout_reader_joined,
            stderr_reader_joined: native.stderr_reader_joined,
            pending_stdout_reads: native.pending_stdout_reads,
            pending_stderr_reads: native.pending_stderr_reads,
            stdout_retained_bytes: native.stdout_retained_bytes,
            stderr_retained_bytes: native.stderr_retained_bytes,
        }
    }

    fn value(&self) -> Value {
        json!({
            "status": self.status,
            "process_created": self.process_created,
            "side_effect_count": self.side_effect_count,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
        })
    }
}

struct H7ActiveCancellation {
    token: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

struct H7ProcessAdmission {
    active: AtomicBool,
}

struct H7ProcessAdmissionLeaseState {
    admission: Arc<H7ProcessAdmission>,
}

#[derive(Clone)]
struct H7ProcessAdmissionLease {
    state: Arc<H7ProcessAdmissionLeaseState>,
}

impl Drop for H7ProcessAdmissionLeaseState {
    fn drop(&mut self) {
        self.admission.active.store(false, Ordering::Release);
    }
}

impl H7ProcessAdmission {
    fn try_acquire(self: &Arc<Self>) -> Option<H7ProcessAdmissionLease> {
        if h7_reap_pending_io_nonblocking() != 0 {
            return None;
        }
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(H7ProcessAdmissionLease {
            state: Arc::new(H7ProcessAdmissionLeaseState {
                admission: Arc::clone(self),
            }),
        })
    }
}

static H7_PROCESS_ADMISSION: OnceLock<Arc<H7ProcessAdmission>> = OnceLock::new();

fn h7_process_admission() -> Arc<H7ProcessAdmission> {
    Arc::clone(H7_PROCESS_ADMISSION.get_or_init(|| {
        Arc::new(H7ProcessAdmission {
            active: AtomicBool::new(false),
        })
    }))
}

struct H7ActionCancellationGuard {
    token: Arc<AtomicBool>,
    notify: Arc<Notify>,
    active: Arc<Mutex<Option<H7ActiveCancellation>>>,
    armed: bool,
}

impl H7ActionCancellationGuard {
    fn new(
        active: Arc<Mutex<Option<H7ActiveCancellation>>>,
        token: Arc<AtomicBool>,
        notify: Arc<Notify>,
    ) -> Self {
        *active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(H7ActiveCancellation {
            token: Arc::clone(&token),
            notify: Arc::clone(&notify),
        });
        Self {
            token,
            notify,
            active,
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
        self.clear_active();
    }

    fn clear_active(&self) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(&current.token, &self.token))
        {
            *active = None;
        }
    }
}

impl Drop for H7ActionCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.token.store(true, Ordering::Release);
            self.notify.notify_waiters();
            self.clear_active();
        }
    }
}

struct H7ProcessBroker {
    context: VitaExecutionContext,
    catalog: Arc<H7ExecutableCatalog>,
    authority: Arc<H7Authority>,
    bridge: Arc<H7PendingConfirmationBridge>,
    admission: Arc<H7ProcessAdmission>,
    active_cancellation: Arc<Mutex<Option<H7ActiveCancellation>>>,
    metrics: Arc<H7SupervisorMetrics>,
    final_fence_gate: Option<Arc<H7FinalFenceGate>>,
    post_host_gate: Option<Arc<H7PostHostFenceGate>>,
    native_fault: H7NativeLaunchFault,
    unlisted_inheritable_handle: Option<usize>,
    post_host_mutation: H7PostHostMutation,
    output_terminality_gate: Option<Arc<H7TerminalityGate>>,
}

impl H7ProcessBroker {
    fn new(
        context: VitaExecutionContext,
        catalog: Arc<H7ExecutableCatalog>,
        authority: Arc<H7Authority>,
        bridge: Arc<H7PendingConfirmationBridge>,
    ) -> Arc<Self> {
        Arc::new(Self {
            context,
            catalog,
            authority,
            bridge,
            admission: h7_process_admission(),
            active_cancellation: Arc::new(Mutex::new(None)),
            metrics: Arc::new(H7SupervisorMetrics::default()),
            final_fence_gate: None,
            post_host_gate: None,
            native_fault: H7NativeLaunchFault::None,
            unlisted_inheritable_handle: None,
            post_host_mutation: H7PostHostMutation::None,
            output_terminality_gate: None,
        })
    }

    fn with_final_fence_gate(mut self: Arc<Self>, gate: Arc<H7FinalFenceGate>) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("H7 final fence gate must be installed before sharing broker")
            .final_fence_gate = Some(gate);
        self
    }

    fn with_native_fault(mut self: Arc<Self>, fault: H7NativeLaunchFault) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("H7 native fault must be installed before sharing broker")
            .native_fault = fault;
        self
    }

    fn with_post_host_gate(mut self: Arc<Self>, gate: Arc<H7PostHostFenceGate>) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("H7 post-Host gate must be installed before sharing broker")
            .post_host_gate = Some(gate);
        self
    }

    fn with_post_host_mutation(mut self: Arc<Self>, mutation: H7PostHostMutation) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("H7 post-Host mutation must be installed before sharing broker")
            .post_host_mutation = mutation;
        self
    }

    #[cfg(test)]
    fn with_output_terminality_gate(
        mut self: Arc<Self>,
        gate: Arc<H7TerminalityGate>,
        cleanup_timeout: Duration,
    ) -> Arc<Self> {
        gate.cleanup_timeout_ms.store(
            cleanup_timeout.as_millis().max(1).min(usize::MAX as u128) as usize,
            Ordering::Release,
        );
        Arc::get_mut(&mut self)
            .expect("H7 output terminality gate must be installed before sharing broker")
            .output_terminality_gate = Some(gate);
        self
    }

    fn cancel(&self) {
        if let Some(active) = self
            .active_cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            active.token.store(true, Ordering::Release);
            active.notify.notify_waiters();
        }
        self.bridge.cancel();
    }

    fn metrics(&self) -> Arc<H7SupervisorMetrics> {
        Arc::clone(&self.metrics)
    }

    async fn execute(self: &Arc<Self>, action: Arc<PreparedProcessAction>) -> H7ToolResult {
        self.execute_tool_action(action).await
    }

    async fn execute_tool_action(
        self: &Arc<Self>,
        action: Arc<PreparedProcessAction>,
    ) -> H7ToolResult {
        let admission = match self.admission.try_acquire() {
            Some(admission) => admission,
            None => return H7ToolResult::denied(),
        };
        let cancellation = Arc::new(AtomicBool::new(false));
        let cancellation_notify = Arc::new(Notify::new());
        let guard = H7ActionCancellationGuard::new(
            Arc::clone(&self.active_cancellation),
            Arc::clone(&cancellation),
            Arc::clone(&cancellation_notify),
        );
        let result = self
            .execute_with_cancellation(action, cancellation, cancellation_notify, admission)
            .await;
        guard.disarm();
        result
    }

    async fn execute_with_cancellation(
        self: &Arc<Self>,
        action: Arc<PreparedProcessAction>,
        cancellation: Arc<AtomicBool>,
        cancellation_notify: Arc<Notify>,
        admission: H7ProcessAdmissionLease,
    ) -> H7ToolResult {
        let authorization_revision = match self
            .bridge
            .await_confirmation(
                Arc::clone(&action),
                cancellation.as_ref(),
                cancellation_notify.as_ref(),
            )
            .await
        {
            Ok(revision) => revision,
            Err(_) => return H7ToolResult::denied(),
        };
        if cancellation.load(Ordering::Acquire) {
            return H7ToolResult::denied();
        }
        let authority = Arc::clone(&self.authority);
        let action_for_grant = Arc::clone(&action);
        let grant_admission = admission.clone();
        let grant = match tokio::task::spawn_blocking(move || {
            let _admission = grant_admission;
            authority.issue_process_grant(&action_for_grant, authorization_revision)
        })
        .await
        {
            Ok(Ok(grant)) => grant,
            _ => return H7ToolResult::denied(),
        };
        let preparation_action = Arc::clone(&action);
        let unlisted_inheritable_handle = self.unlisted_inheritable_handle;
        let output_terminality_gate = self.output_terminality_gate.clone();
        let preparation_admission = admission.clone();
        let preparation = match tokio::task::spawn_blocking(move || {
            let _admission = preparation_admission;
            H7LaunchPreparation::prepare(
                &preparation_action,
                unlisted_inheritable_handle,
                output_terminality_gate,
            )
        })
        .await
        {
            Ok(Ok(preparation)) => preparation,
            _ => return H7ToolResult::denied(),
        };
        if let Some(gate) = &self.final_fence_gate {
            gate.wait_if_armed().await;
        }
        let authority = Arc::clone(&self.authority);
        let action_for_launch = Arc::clone(&action);
        let cancellation = Arc::clone(&cancellation);
        let metrics = Arc::clone(&self.metrics);
        let fault = self.native_fault;
        let pre_create_process_gate = self.post_host_gate.clone();
        let post_host_mutation = self.post_host_mutation;
        let output_terminality_gate = self.output_terminality_gate.clone();
        let worker_metrics = Arc::clone(&metrics);
        let worker_admission = admission.clone();
        match tokio::task::spawn_blocking(move || {
            let _admission = worker_admission;
            let _worker = H7NativeWorkerGuard::new(worker_metrics);
            if cancellation.load(Ordering::Acquire) {
                return H7ToolResult::denied();
            }
            let mut grant = grant;
            if authority
                .revalidate_process_grant(&action_for_launch, &mut grant)
                .is_err()
            {
                return H7ToolResult::denied();
            }
            H7ToolResult::from_native(supervise_native_prepared(
                &action_for_launch,
                H7NativeOptions {
                    cancellation,
                    metrics,
                    fault,
                    unlisted_inheritable_handle,
                    post_host_mutation,
                    pre_create_process_gate,
                    output_terminality_gate,
                },
                preparation,
                Some(grant),
            ))
        })
        .await
        {
            Ok(result) => result,
            Err(_) => H7ToolResult::denied(),
        }
    }
}

pub(crate) struct VitaProcessToolContributor {
    broker: Arc<H7ProcessBroker>,
    tool_call_count: Arc<AtomicUsize>,
}

impl VitaProcessToolContributor {
    fn new(broker: Arc<H7ProcessBroker>) -> Self {
        Self {
            broker,
            tool_call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn with_tool_call_count(mut self, count: Arc<AtomicUsize>) -> Self {
        self.tool_call_count = count;
        self
    }
}

impl ToolContributor for VitaProcessToolContributor {
    fn tools(
        &self,
        _session_store: &codex_extension_api::ExtensionData,
        _thread_store: &codex_extension_api::ExtensionData,
    ) -> Vec<Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>> {
        vec![Arc::new(VitaProcessTool {
            broker: Arc::clone(&self.broker),
            tool_call_count: Arc::clone(&self.tool_call_count),
        })]
    }
}

struct VitaProcessTool {
    broker: Arc<H7ProcessBroker>,
    tool_call_count: Arc<AtomicUsize>,
}

impl VitaProcessTool {
    async fn execute_prepared_action(&self, action: Arc<PreparedProcessAction>) -> H7ToolResult {
        let admission = match self.broker.admission.try_acquire() {
            Some(admission) => admission,
            None => return H7ToolResult::denied(),
        };
        let cancellation = Arc::new(AtomicBool::new(false));
        let cancellation_notify = Arc::new(Notify::new());
        let guard = H7ActionCancellationGuard::new(
            Arc::clone(&self.broker.active_cancellation),
            Arc::clone(&cancellation),
            Arc::clone(&cancellation_notify),
        );
        let result = self
            .broker
            .execute_with_cancellation(action, cancellation, cancellation_notify, admission)
            .await;
        // This disarm is reached only after the action and its blocking worker
        // have completed; dropping the ToolExecutorFuture earlier runs Drop.
        guard.disarm();
        result
    }
}

impl<'call> ToolExecutor<ToolCall<'call>> for VitaProcessTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(VITA_PROCESS_RUN_TOOL_NAME)
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::Function(ResponsesApiTool {
            name: VITA_PROCESS_RUN_TOOL_NAME.to_string(),
            description: "Run the one Host-catalogued no-shell D29-H7 fixture process.".to_string(),
            strict: true,
            defer_loading: None,
            parameters: parse_tool_input_schema(&h7_process_schema_contract())
                .expect("D29-H7 process schema is static and valid"),
            output_schema: None,
        })
    }

    fn supports_parallel_tool_calls(&self) -> bool {
        false
    }

    fn handle<'a>(&'a self, call: ToolCall<'call>) -> ToolExecutorFuture<'a>
    where
        'call: 'a,
    {
        self.tool_call_count.fetch_add(1, Ordering::AcqRel);
        let broker = Arc::clone(&self.broker);
        let tool = self;
        Box::pin(async move {
            let result = match H7ProcessRequest::from_codex_call(&call).and_then(|request| {
                broker
                    .catalog
                    .prepare_action(broker.context.clone(), request)
                    .map_err(|_| H7RequestError::InvalidRequest)
            }) {
                Ok(action) => tool.execute_prepared_action(action).await,
                Err(_) => H7ToolResult::denied(),
            };
            Ok(
                Box::new(JsonToolOutput::with_success(result.value(), Some(false)))
                    as Box<dyn ToolOutput>,
            )
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct H7BWorkspaceProcessArguments {
    operation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H7BWorkspaceProcessRequest {
    tool_call_id: String,
    turn_id: String,
}

impl H7BWorkspaceProcessRequest {
    fn from_codex_call(call: &ToolCall<'_>) -> Result<Self, H7RequestError> {
        if call.tool_name.name != H7B_TOOL_NAME || !call.tool_name.is_default_namespace() {
            return Err(H7RequestError::InvalidRequest);
        }
        let tool_call_id = bounded_id(&call.call_id).ok_or(H7RequestError::InvalidRequest)?;
        let turn_id = bounded_id(&call.turn_id).ok_or(H7RequestError::InvalidRequest)?;
        let arguments = call
            .function_arguments()
            .map_err(|_| H7RequestError::InvalidRequest)?;
        let arguments: H7BWorkspaceProcessArguments =
            serde_json::from_str(arguments).map_err(|_| H7RequestError::InvalidRequest)?;
        if arguments.operation != "report_workspace" {
            return Err(H7RequestError::InvalidRequest);
        }
        Ok(Self {
            tool_call_id,
            turn_id,
        })
    }
}

fn h7b_workspace_process_schema_contract() -> Value {
    json!({
        "type": "object",
        "properties": {
            "operation": {"type": "string", "enum": ["report_workspace"]}
        },
        "required": ["operation"],
        "additionalProperties": false
    })
}

struct H7BToolResult {
    status: &'static str,
    process_created: bool,
    side_effect_count: usize,
}

impl H7BToolResult {
    fn denied() -> Self {
        Self {
            status: "denied",
            process_created: false,
            side_effect_count: 0,
        }
    }

    fn from_native(native: &H7NativeResult) -> Self {
        let status = match native.kind {
            H7NativeOutcomeKind::StartedAndExited => "workspace_process_completed",
            H7NativeOutcomeKind::StartedAndTimedOut => "timed_out",
            H7NativeOutcomeKind::StartedAndCancelled => "cancelled",
            H7NativeOutcomeKind::StartedAndOutputLimited => "output_limited",
            H7NativeOutcomeKind::StartedOutcomeUnknown => "outcome_unknown",
            H7NativeOutcomeKind::LaunchFailed | H7NativeOutcomeKind::Denied => "denied",
        };
        Self {
            status,
            process_created: native.process_created,
            side_effect_count: usize::from(native.process_created),
        }
    }

    fn value(&self) -> Value {
        json!({
            "status": self.status,
            "process_created": self.process_created,
            "side_effect_count": self.side_effect_count,
        })
    }
}

struct H7BWorkspaceProcessBroker {
    context: VitaExecutionContext,
    catalog: Arc<H7ExecutableCatalog>,
    authority: Arc<H7Authority>,
    bridge: Arc<H7PendingConfirmationBridge>,
    workspace_root: Option<TrustedWorkspaceRoot>,
    admission: Arc<H7ProcessAdmission>,
    active_cancellation: Arc<Mutex<Option<H7ActiveCancellation>>>,
    metrics: Arc<H7SupervisorMetrics>,
    last_fixture_stdout: Arc<Mutex<Option<Vec<u8>>>>,
    final_fence_gate: Option<Arc<H7FinalFenceGate>>,
}

impl H7BWorkspaceProcessBroker {
    fn new(
        context: VitaExecutionContext,
        catalog: Arc<H7ExecutableCatalog>,
        authority: Arc<H7Authority>,
        bridge: Arc<H7PendingConfirmationBridge>,
        workspace_root: Option<TrustedWorkspaceRoot>,
    ) -> Arc<Self> {
        Arc::new(Self {
            context,
            catalog,
            authority,
            bridge,
            workspace_root,
            admission: h7_process_admission(),
            active_cancellation: Arc::new(Mutex::new(None)),
            metrics: Arc::new(H7SupervisorMetrics::default()),
            last_fixture_stdout: Arc::new(Mutex::new(None)),
            final_fence_gate: None,
        })
    }

    fn with_final_fence_gate(mut self: Arc<Self>, gate: Arc<H7FinalFenceGate>) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("D29-H7-B final fence gate must be installed before sharing broker")
            .final_fence_gate = Some(gate);
        self
    }

    fn prepare_model_action(
        &self,
        request: H7BWorkspaceProcessRequest,
    ) -> Result<Arc<PreparedProcessAction>, String> {
        let workspace_root = self
            .workspace_root
            .clone()
            .ok_or_else(|| "D29-H7-B workspace scope was absent from Host context".to_string())?;
        self.catalog.prepare_workspace_action(
            self.context.clone(),
            H7ProcessRequest {
                tool_call_id: request.tool_call_id,
                turn_id: request.turn_id,
                program: H7_PROGRAM_ID.to_string(),
                args: vec!["report-cwd".to_string()],
            },
            workspace_root,
        )
    }

    fn cancel(&self) {
        if let Some(active) = self
            .active_cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            active.token.store(true, Ordering::Release);
            active.notify.notify_waiters();
        }
        self.bridge.cancel();
    }

    fn metrics(&self) -> Arc<H7SupervisorMetrics> {
        Arc::clone(&self.metrics)
    }

    fn last_fixture_stdout(&self) -> Option<Vec<u8>> {
        self.last_fixture_stdout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    async fn execute(self: &Arc<Self>, action: Arc<PreparedProcessAction>) -> H7BToolResult {
        let admission = match self.admission.try_acquire() {
            Some(admission) => admission,
            None => return H7BToolResult::denied(),
        };
        let cancellation = Arc::new(AtomicBool::new(false));
        let cancellation_notify = Arc::new(Notify::new());
        let guard = H7ActionCancellationGuard::new(
            Arc::clone(&self.active_cancellation),
            Arc::clone(&cancellation),
            Arc::clone(&cancellation_notify),
        );
        let result = self
            .execute_with_cancellation(action, cancellation, cancellation_notify, admission)
            .await;
        guard.disarm();
        result
    }

    async fn execute_with_cancellation(
        self: &Arc<Self>,
        action: Arc<PreparedProcessAction>,
        cancellation: Arc<AtomicBool>,
        cancellation_notify: Arc<Notify>,
        admission: H7ProcessAdmissionLease,
    ) -> H7BToolResult {
        if action.capability_id != H7B_CAPABILITY_ID
            || action.workspace_root.is_none()
            || self.authority.evaluate_workspace_scope(&action).is_err()
        {
            return H7BToolResult::denied();
        }
        let authorization_revision = match self
            .bridge
            .await_confirmation(
                Arc::clone(&action),
                cancellation.as_ref(),
                cancellation_notify.as_ref(),
            )
            .await
        {
            Ok(revision) => revision,
            Err(_) => return H7BToolResult::denied(),
        };
        if cancellation.load(Ordering::Acquire) {
            return H7BToolResult::denied();
        }
        let authority = Arc::clone(&self.authority);
        let action_for_grant = Arc::clone(&action);
        let grant_admission = admission.clone();
        let grant = match tokio::task::spawn_blocking(move || {
            let _admission = grant_admission;
            authority.issue_process_grant(&action_for_grant, authorization_revision)
        })
        .await
        {
            Ok(Ok(grant)) => grant,
            _ => return H7BToolResult::denied(),
        };
        let preparation_action = Arc::clone(&action);
        let preparation_admission = admission.clone();
        let preparation = match tokio::task::spawn_blocking(move || {
            let _admission = preparation_admission;
            H7LaunchPreparation::prepare(&preparation_action, None, None)
        })
        .await
        {
            Ok(Ok(preparation)) => preparation,
            _ => return H7BToolResult::denied(),
        };
        if let Some(gate) = &self.final_fence_gate {
            gate.wait_if_armed().await;
        }
        let authority = Arc::clone(&self.authority);
        let action_for_launch = Arc::clone(&action);
        let cancellation_for_launch = Arc::clone(&cancellation);
        let metrics = Arc::clone(&self.metrics);
        let output = Arc::clone(&self.last_fixture_stdout);
        let worker_admission = admission.clone();
        match tokio::task::spawn_blocking(move || {
            let _admission = worker_admission;
            let _worker = H7NativeWorkerGuard::new(Arc::clone(&metrics));
            if cancellation_for_launch.load(Ordering::Acquire) {
                return H7BToolResult::denied();
            }
            let mut grant = grant;
            if authority
                .revalidate_process_grant(&action_for_launch, &mut grant)
                .is_err()
            {
                return H7BToolResult::denied();
            }
            let native = supervise_native_prepared(
                &action_for_launch,
                H7NativeOptions {
                    cancellation: cancellation_for_launch,
                    metrics: Arc::clone(&metrics),
                    fault: H7NativeLaunchFault::None,
                    unlisted_inheritable_handle: None,
                    post_host_mutation: H7PostHostMutation::None,
                    pre_create_process_gate: None,
                    output_terminality_gate: None,
                },
                preparation,
                Some(grant),
            );
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(native.stdout.clone());
            H7BToolResult::from_native(&native)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => H7BToolResult::denied(),
        }
    }
}

pub(crate) struct VitaWorkspaceProcessToolContributor {
    broker: Arc<H7BWorkspaceProcessBroker>,
    tool_call_count: Arc<AtomicUsize>,
}

impl VitaWorkspaceProcessToolContributor {
    fn new(broker: Arc<H7BWorkspaceProcessBroker>) -> Self {
        Self {
            broker,
            tool_call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn with_tool_call_count(mut self, count: Arc<AtomicUsize>) -> Self {
        self.tool_call_count = count;
        self
    }
}

impl ToolContributor for VitaWorkspaceProcessToolContributor {
    fn tools(
        &self,
        _session_store: &codex_extension_api::ExtensionData,
        _thread_store: &codex_extension_api::ExtensionData,
    ) -> Vec<Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>> {
        vec![Arc::new(VitaWorkspaceProcessTool {
            broker: Arc::clone(&self.broker),
            tool_call_count: Arc::clone(&self.tool_call_count),
        })]
    }
}

struct VitaWorkspaceProcessTool {
    broker: Arc<H7BWorkspaceProcessBroker>,
    tool_call_count: Arc<AtomicUsize>,
}

impl<'call> ToolExecutor<ToolCall<'call>> for VitaWorkspaceProcessTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(H7B_TOOL_NAME)
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::Function(ResponsesApiTool {
            name: H7B_TOOL_NAME.to_string(),
            description: "Report the workspace cwd through the Host-governed fixture process."
                .to_string(),
            strict: true,
            defer_loading: None,
            parameters: parse_tool_input_schema(&h7b_workspace_process_schema_contract())
                .expect("D29-H7-B workspace process schema is static and valid"),
            output_schema: None,
        })
    }

    fn supports_parallel_tool_calls(&self) -> bool {
        false
    }

    fn handle<'a>(&'a self, call: ToolCall<'call>) -> ToolExecutorFuture<'a>
    where
        'call: 'a,
    {
        self.tool_call_count.fetch_add(1, Ordering::AcqRel);
        let broker = Arc::clone(&self.broker);
        Box::pin(async move {
            let result =
                match H7BWorkspaceProcessRequest::from_codex_call(&call).and_then(|request| {
                    broker
                        .prepare_model_action(request)
                        .map_err(|_| H7RequestError::InvalidRequest)
                }) {
                    Ok(action) => broker.execute(action).await,
                    Err(_) => H7BToolResult::denied(),
                };
            Ok(
                Box::new(JsonToolOutput::with_success(result.value(), Some(false)))
                    as Box<dyn ToolOutput>,
            )
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct H7CGitStatusArguments {
    operation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H7CGitStatusRequest {
    tool_call_id: String,
    turn_id: String,
}

impl H7CGitStatusRequest {
    fn from_codex_call(call: &ToolCall<'_>) -> Result<Self, H7RequestError> {
        if call.tool_name.name != H7C_TOOL_NAME || !call.tool_name.is_default_namespace() {
            return Err(H7RequestError::InvalidRequest);
        }
        let tool_call_id = bounded_id(&call.call_id).ok_or(H7RequestError::InvalidRequest)?;
        let turn_id = bounded_id(&call.turn_id).ok_or(H7RequestError::InvalidRequest)?;
        let arguments = call
            .function_arguments()
            .map_err(|_| H7RequestError::InvalidRequest)?;
        let arguments: H7CGitStatusArguments =
            serde_json::from_str(arguments).map_err(|_| H7RequestError::InvalidRequest)?;
        if arguments.operation != "status" {
            return Err(H7RequestError::InvalidRequest);
        }
        Ok(Self {
            tool_call_id,
            turn_id,
        })
    }
}

fn h7c_git_status_schema_contract() -> Value {
    json!({
        "type": "object",
        "properties": {
            "operation": {"type": "string", "enum": ["status"]}
        },
        "required": ["operation"],
        "additionalProperties": false
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct H7CGitStatusEntry {
    index: String,
    worktree: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H7CPathError {
    Invalid,
    Limited,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum H7CParseOutcome {
    Complete(Vec<H7CGitStatusEntry>),
    Limited,
    Invalid,
}

fn h7c_relative_path(value: &[u8]) -> Result<String, H7CPathError> {
    if value.len() > 1024 {
        return Err(H7CPathError::Limited);
    }
    if value.is_empty() || value.contains(&0) {
        return Err(H7CPathError::Invalid);
    }
    let value = std::str::from_utf8(value).map_err(|_| H7CPathError::Invalid)?;
    let path = Path::new(value);
    if path.is_absolute()
        || value.starts_with('\\')
        || value.starts_with('/')
        || value.starts_with("\\\\")
        || value.starts_with("//")
        || value.starts_with(r"\\?\")
        || value.starts_with(r"\\.\")
    {
        return Err(H7CPathError::Invalid);
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(H7CPathError::Invalid);
        }
    }
    Ok(value.to_string())
}

fn h7c_parse_porcelain_z(output: &[u8]) -> H7CParseOutcome {
    if output.len() > H7_STDOUT_BOUND {
        return H7CParseOutcome::Limited;
    }
    let mut entries = Vec::new();
    let mut records = output.split(|byte| *byte == 0).peekable();
    while let Some(record) = records.next() {
        if record.is_empty() {
            continue;
        }
        if record.len() < 4 || record[2] != b' ' {
            return H7CParseOutcome::Invalid;
        }
        let index = record[0] as char;
        let worktree = record[1] as char;
        if !index.is_ascii() || !worktree.is_ascii() {
            return H7CParseOutcome::Invalid;
        }
        let path = match h7c_relative_path(&record[3..]) {
            Ok(path) => path,
            Err(H7CPathError::Invalid) => return H7CParseOutcome::Invalid,
            Err(H7CPathError::Limited) => return H7CParseOutcome::Limited,
        };
        let rename_or_copy = matches!(index, 'R' | 'C') || matches!(worktree, 'R' | 'C');
        let from = if rename_or_copy {
            let Some(source) = records.next() else {
                return H7CParseOutcome::Invalid;
            };
            match h7c_relative_path(source) {
                Ok(source) => Some(source),
                Err(H7CPathError::Invalid) => return H7CParseOutcome::Invalid,
                Err(H7CPathError::Limited) => return H7CParseOutcome::Limited,
            }
        } else {
            None
        };
        entries.push(H7CGitStatusEntry {
            index: index.to_string(),
            worktree: worktree.to_string(),
            path,
            from,
        });
        if entries.len() > 256 {
            return H7CParseOutcome::Limited;
        }
    }
    H7CParseOutcome::Complete(entries)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct H7CGitStatusResult {
    status: &'static str,
    entries: Vec<H7CGitStatusEntry>,
}

impl H7CGitStatusResult {
    fn denied() -> Self {
        Self {
            status: "denied",
            entries: Vec::new(),
        }
    }

    fn from_native(native: &H7NativeResult) -> Self {
        if native.kind == H7NativeOutcomeKind::StartedAndOutputLimited {
            return Self {
                status: "inspection_output_limited",
                entries: Vec::new(),
            };
        }
        if native.kind != H7NativeOutcomeKind::StartedAndExited || native.exit_code != Some(0) {
            return Self {
                status: "inspection_failed",
                entries: Vec::new(),
            };
        }
        match h7c_parse_porcelain_z(&native.stdout) {
            H7CParseOutcome::Complete(entries) => Self {
                status: "completed",
                entries,
            },
            H7CParseOutcome::Limited => Self {
                status: "inspection_output_limited",
                entries: Vec::new(),
            },
            H7CParseOutcome::Invalid => Self {
                status: "inspection_failed",
                entries: Vec::new(),
            },
        }
    }

    fn value(&self) -> Value {
        serde_json::to_value(self).expect("D29-H7-C status result is serializable")
    }
}

struct H7CGitStatusProfile {
    profile_id: String,
    git_path: PathBuf,
    expected_image_identity: H7ImageIdentity,
    expected_image_namespace: H7NamespaceIdentity,
    expected_image_sha256: String,
    working_directory: Arc<PreparedWorkingDirectory>,
    working_directory_identity: String,
    workspace_root_identity: WorkspaceRootIdentity,
    argv: Vec<String>,
    argv_hash: String,
    environment: BTreeMap<String, String>,
    environment_policy_hash: String,
    timeout: Duration,
    stdout_bound: usize,
    stderr_bound: usize,
    _git_home: TempDir,
}

impl H7CGitStatusProfile {
    fn new(root: &TrustedWorkspaceRoot, git_path: PathBuf) -> Result<Self, String> {
        root.verify_named_path_current()
            .map_err(|_| "D29-H7-C workspace root was not current".to_string())?;
        h7c_validate_git_metadata(root)?;
        if !git_path.is_absolute() {
            return Err("D29-H7-C Git image path was not absolute".to_string());
        }
        let mut image = PreparedExecutableImage::prepare(&git_path)?;
        let expected_image_identity = image.identity;
        let expected_image_namespace = image.namespace.identity();
        let expected_image_sha256 = image.sha256.clone();
        let working_directory = Arc::new(PreparedWorkingDirectory::prepare(root.requested_path())?);
        let working_directory_identity = working_directory.0.identity().wire();
        let git_home = tempfile::tempdir()
            .map_err(|_| "D29-H7-C could not create the owned Git home".to_string())?;
        let mut argv = vec![git_path.to_string_lossy().into_owned()];
        argv.extend(
            [
                "--no-pager",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "submodule.recurse=false",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=all",
            ]
            .into_iter()
            .map(str::to_string),
        );
        let argv_hash = sha256_hex(
            &serde_json::to_vec(&argv)
                .map_err(|_| "D29-H7-C Git argv binding serialization failed".to_string())?,
        );
        let ceiling = root
            .requested_path()
            .parent()
            .ok_or_else(|| "D29-H7-C workspace root had no ceiling directory".to_string())?;
        let environment = BTreeMap::from([
            ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
            ("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string()),
            ("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()),
            ("GCM_INTERACTIVE".to_string(), "Never".to_string()),
            (
                "GIT_CEILING_DIRECTORIES".to_string(),
                ceiling.to_string_lossy().into_owned(),
            ),
            (
                "HOME".to_string(),
                git_home.path().to_string_lossy().into_owned(),
            ),
        ]);
        let environment_policy_hash = sha256_hex(&environment_policy_bytes(&environment));
        image.reverify(expected_image_identity, &expected_image_sha256)?;
        Ok(Self {
            profile_id: H7C_PROFILE_ID.to_string(),
            git_path,
            expected_image_identity,
            expected_image_namespace,
            expected_image_sha256,
            working_directory,
            working_directory_identity,
            workspace_root_identity: root.identity(),
            argv,
            argv_hash,
            environment,
            environment_policy_hash,
            timeout: Duration::from_secs(2),
            stdout_bound: H7_STDOUT_BOUND,
            stderr_bound: H7_STDERR_BOUND,
            _git_home: git_home,
        })
    }

    fn prepare_action(
        &self,
        context: VitaExecutionContext,
        request: H7CGitStatusRequest,
        workspace_root: Option<TrustedWorkspaceRoot>,
    ) -> Result<Arc<PreparedProcessAction>, String> {
        if let Some(root) = workspace_root.as_ref() {
            if root.identity() != self.workspace_root_identity
                || !h7_workspace_paths_equal(self.working_directory.path(), root.final_path())
            {
                return Err(
                    "D29-H7-C Host workspace root was not the fixed profile root".to_string(),
                );
            }
            root.verify_named_path_current()
                .map_err(|_| "D29-H7-C workspace root was not current".to_string())?;
        }
        let image = PreparedExecutableImage::prepare(&self.git_path)?;
        if image.identity != self.expected_image_identity
            || image.namespace.identity() != self.expected_image_namespace
            || image.sha256 != self.expected_image_sha256
        {
            return Err("D29-H7-C Git image did not match the fixed profile".to_string());
        }
        let workspace_root_identity = workspace_root.as_ref().map(|root| root.identity());
        Ok(Arc::new(PreparedProcessAction {
            context,
            tool_call_id: request.tool_call_id,
            turn_id: request.turn_id,
            capability_id: H7C_CAPABILITY_ID.to_string(),
            program_id: H7C_PROFILE_ID.to_string(),
            image: Mutex::new(image),
            executable_namespace_identity: self.expected_image_namespace,
            argv: self.argv.clone(),
            argv_hash: self.argv_hash.clone(),
            argv_count: self.argv.len(),
            working_directory: Arc::clone(&self.working_directory),
            working_directory_identity: self.working_directory_identity.clone(),
            environment: self.environment.clone(),
            environment_policy_hash: self.environment_policy_hash.clone(),
            timeout: self.timeout,
            stdout_bound: self.stdout_bound,
            stderr_bound: self.stderr_bound,
            workspace_root,
            workspace_root_identity,
            profile_id: Some(self.profile_id.clone()),
        }))
    }

    fn action_is_exact(&self, action: &PreparedProcessAction) -> bool {
        action.capability_id == H7C_CAPABILITY_ID
            && action.program_id == H7C_PROFILE_ID
            && action.profile_id.as_deref() == Some(self.profile_id.as_str())
            && action.argv == self.argv
            && action.argv_hash == self.argv_hash
            && action.argv_count == self.argv.len()
            && action.environment == self.environment
            && action.environment_policy_hash == self.environment_policy_hash
            && action.working_directory_identity == self.working_directory_identity
            && action.workspace_root_identity == Some(self.workspace_root_identity)
            && action.timeout == self.timeout
            && action.stdout_bound == self.stdout_bound
            && action.stderr_bound == self.stderr_bound
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H7CWorkspaceSnapshot {
    workspace_files: BTreeMap<String, String>,
    git_files: BTreeMap<String, String>,
}

fn h7c_validate_git_metadata(root: &TrustedWorkspaceRoot) -> Result<(), String> {
    let git_target = root
        .prepare_target(Path::new(".git"))
        .map_err(|_| "D29-H7-C Git metadata target could not be prepared".to_string())?;
    if git_target.kind() != crate::PreparedWorkspaceTargetKind::ExistingDirectory {
        return Err("D29-H7-C external or file-form Git metadata was rejected".to_string());
    }
    let snapshot = h7c_snapshot_workspace(root.requested_path())?;
    if snapshot.git_files.is_empty() {
        return Err("D29-H7-C Git metadata directory was empty".to_string());
    }
    for redirect in [
        ".git/gitdir",
        ".git/commondir",
        ".git/objects/info/alternates",
    ] {
        if snapshot.git_files.contains_key(redirect) {
            return Err("D29-H7-C external Git metadata redirect was rejected".to_string());
        }
    }
    if root.requested_path().join(".git/worktrees").exists() {
        return Err("D29-H7-C linked Git worktree metadata was rejected".to_string());
    }
    Ok(())
}

fn h7c_snapshot_workspace(root: &Path) -> Result<H7CWorkspaceSnapshot, String> {
    let mut workspace_files = BTreeMap::new();
    h7c_snapshot_directory(root, root, &mut workspace_files)?;
    let git_files = workspace_files
        .iter()
        .filter(|(path, _)| path.as_str() == ".git" || path.starts_with(".git/"))
        .map(|(path, digest)| (path.clone(), digest.clone()))
        .collect();
    Ok(H7CWorkspaceSnapshot {
        workspace_files,
        git_files,
    })
}

fn h7c_snapshot_directory(
    root: &Path,
    current: &Path,
    files: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(current)
        .map_err(|_| "D29-H7-C workspace snapshot metadata failed".to_string())?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.file_type().is_symlink()
    {
        return Err("D29-H7-C workspace snapshot encountered a reparse point".to_string());
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(current)
            .map_err(|_| "D29-H7-C workspace snapshot enumeration failed".to_string())?
        {
            let entry =
                entry.map_err(|_| "D29-H7-C workspace snapshot entry failed".to_string())?;
            h7c_snapshot_directory(root, &entry.path(), files)?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err("D29-H7-C workspace snapshot encountered a non-file".to_string());
    }
    let relative = current
        .strip_prefix(root)
        .map_err(|_| "D29-H7-C workspace snapshot escaped its root".to_string())?;
    if relative.as_os_str().is_empty() {
        return Ok(());
    }
    let relative = relative.to_string_lossy().replace('\\', "/");
    let bytes =
        fs::read(current).map_err(|_| "D29-H7-C workspace snapshot read failed".to_string())?;
    files.insert(relative, format!("{}:{}", bytes.len(), sha256_hex(&bytes)));
    Ok(())
}

fn h7c_index_lock_present(root: &Path) -> bool {
    fs::symlink_metadata(root.join(".git/index.lock")).is_ok()
}

struct H7CGitStatusBroker {
    context: VitaExecutionContext,
    profile: Arc<H7CGitStatusProfile>,
    authority: Arc<H7Authority>,
    bridge: Arc<H7PendingConfirmationBridge>,
    workspace_root: Option<TrustedWorkspaceRoot>,
    admission: Arc<H7ProcessAdmission>,
    active_cancellation: Arc<Mutex<Option<H7ActiveCancellation>>>,
    metrics: Arc<H7SupervisorMetrics>,
    last_native: Arc<Mutex<Option<H7NativeResult>>>,
    final_fence_gate: Option<Arc<H7FinalFenceGate>>,
}

impl H7CGitStatusBroker {
    fn new(
        context: VitaExecutionContext,
        profile: Arc<H7CGitStatusProfile>,
        authority: Arc<H7Authority>,
        bridge: Arc<H7PendingConfirmationBridge>,
        workspace_root: Option<TrustedWorkspaceRoot>,
    ) -> Arc<Self> {
        Arc::new(Self {
            context,
            profile,
            authority,
            bridge,
            workspace_root,
            admission: h7_process_admission(),
            active_cancellation: Arc::new(Mutex::new(None)),
            metrics: Arc::new(H7SupervisorMetrics::default()),
            last_native: Arc::new(Mutex::new(None)),
            final_fence_gate: None,
        })
    }

    fn with_final_fence_gate(mut self: Arc<Self>, gate: Arc<H7FinalFenceGate>) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("D29-H7-C final fence gate must be installed before sharing broker")
            .final_fence_gate = Some(gate);
        self
    }

    fn prepare_model_action(
        &self,
        request: H7CGitStatusRequest,
    ) -> Result<Arc<PreparedProcessAction>, String> {
        let root = self
            .workspace_root
            .clone()
            .ok_or_else(|| "D29-H7-C workspace scope was absent from Host context".to_string())?;
        self.profile
            .prepare_action(self.context.clone(), request, Some(root))
    }

    fn cancel(&self) {
        if let Some(active) = self
            .active_cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            active.token.store(true, Ordering::Release);
            active.notify.notify_waiters();
        }
        self.bridge.cancel();
    }

    fn metrics(&self) -> Arc<H7SupervisorMetrics> {
        Arc::clone(&self.metrics)
    }

    fn last_native(&self) -> Option<H7NativeResult> {
        self.last_native
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    async fn execute(self: &Arc<Self>, action: Arc<PreparedProcessAction>) -> H7CGitStatusResult {
        let admission = match self.admission.try_acquire() {
            Some(admission) => admission,
            None => return H7CGitStatusResult::denied(),
        };
        let cancellation = Arc::new(AtomicBool::new(false));
        let cancellation_notify = Arc::new(Notify::new());
        let guard = H7ActionCancellationGuard::new(
            Arc::clone(&self.active_cancellation),
            Arc::clone(&cancellation),
            Arc::clone(&cancellation_notify),
        );
        let result = self
            .execute_with_cancellation(action, cancellation, cancellation_notify, admission)
            .await;
        guard.disarm();
        result
    }

    async fn execute_with_cancellation(
        self: &Arc<Self>,
        action: Arc<PreparedProcessAction>,
        cancellation: Arc<AtomicBool>,
        cancellation_notify: Arc<Notify>,
        admission: H7ProcessAdmissionLease,
    ) -> H7CGitStatusResult {
        if !self.profile.action_is_exact(&action)
            || action.workspace_root.is_none()
            || self.authority.evaluate_workspace_scope(&action).is_err()
        {
            return H7CGitStatusResult::denied();
        }
        let authorization_revision = match self
            .bridge
            .await_confirmation(
                Arc::clone(&action),
                cancellation.as_ref(),
                cancellation_notify.as_ref(),
            )
            .await
        {
            Ok(revision) => revision,
            Err(_) => return H7CGitStatusResult::denied(),
        };
        if cancellation.load(Ordering::Acquire) {
            return H7CGitStatusResult::denied();
        }
        let authority = Arc::clone(&self.authority);
        let action_for_grant = Arc::clone(&action);
        let grant_admission = admission.clone();
        let grant = match tokio::task::spawn_blocking(move || {
            let _admission = grant_admission;
            authority.issue_process_grant(&action_for_grant, authorization_revision)
        })
        .await
        {
            Ok(Ok(grant)) => grant,
            _ => return H7CGitStatusResult::denied(),
        };
        let preparation_action = Arc::clone(&action);
        let preparation_admission = admission.clone();
        let preparation = match tokio::task::spawn_blocking(move || {
            let _admission = preparation_admission;
            H7LaunchPreparation::prepare(&preparation_action, None, None)
        })
        .await
        {
            Ok(Ok(preparation)) => preparation,
            _ => return H7CGitStatusResult::denied(),
        };
        if let Some(gate) = &self.final_fence_gate {
            gate.wait_if_armed().await;
        }
        let authority = Arc::clone(&self.authority);
        let action_for_launch = Arc::clone(&action);
        let cancellation_for_launch = Arc::clone(&cancellation);
        let metrics = Arc::clone(&self.metrics);
        let last_native = Arc::clone(&self.last_native);
        let worker_admission = admission.clone();
        match tokio::task::spawn_blocking(move || {
            let _admission = worker_admission;
            let _worker = H7NativeWorkerGuard::new(Arc::clone(&metrics));
            if cancellation_for_launch.load(Ordering::Acquire) {
                return H7CGitStatusResult::denied();
            }
            let mut grant = grant;
            if authority
                .revalidate_process_grant(&action_for_launch, &mut grant)
                .is_err()
            {
                return H7CGitStatusResult::denied();
            }
            let native = supervise_native_prepared(
                &action_for_launch,
                H7NativeOptions {
                    cancellation: cancellation_for_launch,
                    metrics,
                    fault: H7NativeLaunchFault::None,
                    unlisted_inheritable_handle: None,
                    post_host_mutation: H7PostHostMutation::None,
                    pre_create_process_gate: None,
                    output_terminality_gate: None,
                },
                preparation,
                Some(grant),
            );
            *last_native
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(native.clone());
            H7CGitStatusResult::from_native(&native)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => H7CGitStatusResult::denied(),
        }
    }
}

struct VitaGitStatusToolContributor {
    broker: Arc<H7CGitStatusBroker>,
    tool_call_count: Arc<AtomicUsize>,
}

impl VitaGitStatusToolContributor {
    fn new(broker: Arc<H7CGitStatusBroker>) -> Self {
        Self {
            broker,
            tool_call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn with_tool_call_count(mut self, count: Arc<AtomicUsize>) -> Self {
        self.tool_call_count = count;
        self
    }
}

impl ToolContributor for VitaGitStatusToolContributor {
    fn tools(
        &self,
        _session_store: &codex_extension_api::ExtensionData,
        _thread_store: &codex_extension_api::ExtensionData,
    ) -> Vec<Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>> {
        vec![Arc::new(VitaGitStatusTool {
            broker: Arc::clone(&self.broker),
            tool_call_count: Arc::clone(&self.tool_call_count),
        })]
    }
}

struct VitaGitStatusTool {
    broker: Arc<H7CGitStatusBroker>,
    tool_call_count: Arc<AtomicUsize>,
}

impl<'call> ToolExecutor<ToolCall<'call>> for VitaGitStatusTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(H7C_TOOL_NAME)
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::Function(ResponsesApiTool {
            name: H7C_TOOL_NAME.to_string(),
            description: "Inspect the fixed Host-owned Git workspace status.".to_string(),
            strict: true,
            defer_loading: None,
            parameters: parse_tool_input_schema(&h7c_git_status_schema_contract())
                .expect("D29-H7-C Git status schema is static and valid"),
            output_schema: None,
        })
    }

    fn supports_parallel_tool_calls(&self) -> bool {
        false
    }

    fn handle<'a>(&'a self, call: ToolCall<'call>) -> ToolExecutorFuture<'a>
    where
        'call: 'a,
    {
        self.tool_call_count.fetch_add(1, Ordering::AcqRel);
        let broker = Arc::clone(&self.broker);
        Box::pin(async move {
            let result = match H7CGitStatusRequest::from_codex_call(&call).and_then(|request| {
                broker
                    .prepare_model_action(request)
                    .map_err(|_| H7RequestError::InvalidRequest)
            }) {
                Ok(action) => broker.execute(action).await,
                Err(_) => H7CGitStatusResult::denied(),
            };
            Ok(
                Box::new(JsonToolOutput::with_success(result.value(), Some(false)))
                    as Box<dyn ToolOutput>,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_gateway::{VitaGatewayBinding, VitaProviderAuthority};
    use crate::{
        ProviderCapabilities, ProviderProfile, ProviderProtocol, ProviderRetryPolicy,
        VitaAgentEntrypoint, VitaAgentRuntimeProfile,
    };
    use codex_core_api::{
        CodexAppsToolsCache, CodexAuth, EnvironmentManager, EventMsg, Op, SessionSource,
        StartThreadOptions, ThreadId, ThreadManager, TurnInputRequest, TurnInputSubmission,
        UserInput,
    };
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
    use tempfile::{tempdir, TempDir};

    static H7_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn lock_h7_tests() -> MutexGuard<'static, ()> {
        H7_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    struct H7EnvironmentGuard {
        previous: Vec<(String, Option<OsString>)>,
    }

    impl H7EnvironmentGuard {
        fn install(entries: &[(&str, &str)]) -> Self {
            let previous = entries
                .iter()
                .map(|(key, value)| {
                    let previous = std::env::var_os(key);
                    std::env::set_var(key, value);
                    ((*key).to_string(), previous)
                })
                .collect();
            Self { previous }
        }
    }

    impl Drop for H7EnvironmentGuard {
        fn drop(&mut self) {
            for (key, value) in &self.previous {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    struct H7DirectHarness {
        _working_directory: TempDir,
        catalog: Arc<H7ExecutableCatalog>,
        authority: Arc<H7Authority>,
        bridge: Arc<H7PendingConfirmationBridge>,
        receiver: Option<tokio::sync::mpsc::Receiver<H7PendingProcessAction>>,
        broker: Arc<H7ProcessBroker>,
    }

    impl H7DirectHarness {
        fn new() -> Self {
            let working_directory = tempdir().expect("D29-H7 working directory");
            Self::with_working_directory(working_directory)
        }

        fn with_working_directory(working_directory: TempDir) -> Self {
            let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("D29-H7 repository root")
                .to_path_buf();
            let image_path = h7_process_fixture_executable(&repo_root)
                .expect("D29-H7 process fixture executable");
            let catalog = Arc::new(
                H7ExecutableCatalog::fixture(image_path, working_directory.path().to_path_buf())
                    .expect("D29-H7 executable catalog"),
            );
            let authority = H7Authority::new().expect("D29-H7 Host authority");
            let (bridge, receiver) = H7PendingConfirmationBridge::new();
            let context = VitaExecutionContext::try_new(H7_LIFE_ID, H7_TASK_ID)
                .expect("D29-H7 execution context");
            let broker = H7ProcessBroker::new(
                context,
                Arc::clone(&catalog),
                Arc::clone(&authority),
                Arc::clone(&bridge),
            );
            Self {
                _working_directory: working_directory,
                catalog,
                authority,
                bridge,
                receiver: Some(receiver),
                broker,
            }
        }

        fn action(&self, args: &[&str]) -> Arc<PreparedProcessAction> {
            let request = H7ProcessRequest::synthetic("call-d29h7-test", "turn-d29h7-test", args);
            self.catalog
                .prepare_action(self.broker.context.clone(), request)
                .expect("D29-H7 prepared action")
        }

        fn broker_with_final_fence(&self, gate: Arc<H7FinalFenceGate>) -> Arc<H7ProcessBroker> {
            H7ProcessBroker::new(
                self.broker.context.clone(),
                Arc::clone(&self.catalog),
                Arc::clone(&self.authority),
                Arc::clone(&self.bridge),
            )
            .with_final_fence_gate(gate)
        }

        fn broker_with_post_host_gate(
            &self,
            gate: Arc<H7PostHostFenceGate>,
        ) -> Arc<H7ProcessBroker> {
            H7ProcessBroker::new(
                self.broker.context.clone(),
                Arc::clone(&self.catalog),
                Arc::clone(&self.authority),
                Arc::clone(&self.bridge),
            )
            .with_post_host_gate(gate)
        }

        fn broker_with_post_host_mutation(
            &self,
            mutation: H7PostHostMutation,
        ) -> Arc<H7ProcessBroker> {
            H7ProcessBroker::new(
                self.broker.context.clone(),
                Arc::clone(&self.catalog),
                Arc::clone(&self.authority),
                Arc::clone(&self.bridge),
            )
            .with_post_host_mutation(mutation)
        }

        fn broker_with_output_terminality_gate(
            &self,
            gate: Arc<H7TerminalityGate>,
            cleanup_timeout: Duration,
        ) -> Arc<H7ProcessBroker> {
            H7ProcessBroker::new(
                self.broker.context.clone(),
                Arc::clone(&self.catalog),
                Arc::clone(&self.authority),
                Arc::clone(&self.bridge),
            )
            .with_output_terminality_gate(gate, cleanup_timeout)
        }
    }

    struct H7BDirectHarness {
        _workspace: TempDir,
        root: TrustedWorkspaceRoot,
        catalog: Arc<H7ExecutableCatalog>,
        authority: Arc<H7Authority>,
        bridge: Arc<H7PendingConfirmationBridge>,
        receiver: Option<tokio::sync::mpsc::Receiver<H7PendingProcessAction>>,
        broker: Arc<H7BWorkspaceProcessBroker>,
    }

    impl H7BDirectHarness {
        fn new() -> Self {
            let workspace = tempdir().expect("D29-H7-B workspace directory");
            let root = TrustedWorkspaceRoot::acquire(workspace.path())
                .expect("D29-H7-B trusted workspace root");
            let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("D29-H7-B repository root")
                .to_path_buf();
            let image_path = h7_process_fixture_executable(&repo_root)
                .expect("D29-H7-B process fixture executable");
            let catalog = Arc::new(
                H7ExecutableCatalog::fixture(image_path, root.requested_path().to_path_buf())
                    .expect("D29-H7-B executable catalog"),
            );
            let authority = H7Authority::new_workspace(&root).expect("D29-H7-B Host authority");
            let (bridge, receiver) = H7PendingConfirmationBridge::new();
            let context = VitaExecutionContext::try_new(H7_LIFE_ID, H7_TASK_ID)
                .expect("D29-H7-B execution context");
            let broker = H7BWorkspaceProcessBroker::new(
                context,
                Arc::clone(&catalog),
                Arc::clone(&authority),
                Arc::clone(&bridge),
                Some(root.clone()),
            );
            Self {
                _workspace: workspace,
                root,
                catalog,
                authority,
                bridge,
                receiver: Some(receiver),
                broker,
            }
        }

        fn action(&self) -> Arc<PreparedProcessAction> {
            self.action_with_args(&["report-cwd"])
        }

        fn action_with_args(&self, args: &[&str]) -> Arc<PreparedProcessAction> {
            let request = H7ProcessRequest::synthetic("call-d29h7b-test", "turn-d29h7b-test", args);
            self.catalog
                .prepare_workspace_action(self.broker.context.clone(), request, self.root.clone())
                .expect("D29-H7-B prepared action")
        }

        fn action_without_scope(&self) -> Arc<PreparedProcessAction> {
            let request = H7ProcessRequest::synthetic(
                "call-d29h7b-noscope",
                "turn-d29h7b-noscope",
                &["report-cwd"],
            );
            self.catalog
                .prepare_action_without_workspace_scope_for_test(
                    self.broker.context.clone(),
                    request,
                )
                .expect("D29-H7-B scope-free test action")
        }

        fn broker_with_final_fence(
            &self,
            gate: Arc<H7FinalFenceGate>,
        ) -> Arc<H7BWorkspaceProcessBroker> {
            H7BWorkspaceProcessBroker::new(
                self.broker.context.clone(),
                Arc::clone(&self.catalog),
                Arc::clone(&self.authority),
                Arc::clone(&self.bridge),
                Some(self.root.clone()),
            )
            .with_final_fence_gate(gate)
        }
    }

    fn h7c_installed_git_path() -> PathBuf {
        [
            PathBuf::from(r"E:\Program Files\Git\mingw64\bin\git.exe"),
            PathBuf::from(r"C:\Program Files\Git\mingw64\bin\git.exe"),
            PathBuf::from(r"E:\Program Files\Git\cmd\git.exe"),
            PathBuf::from(r"C:\Program Files\Git\cmd\git.exe"),
            PathBuf::from(r"C:\Program Files\Git\bin\git.exe"),
        ]
        .into_iter()
        .find(|path| path.is_file())
        .expect("D29-H7-C installed Git image")
    }

    fn h7c_run_git(git_path: &Path, cwd: &Path, args: &[&str]) {
        let output = Command::new(git_path)
            .current_dir(cwd)
            .args(args)
            .output()
            .expect("D29-H7-C local Git setup process");
        assert!(
            output.status.success(),
            "D29-H7-C local Git setup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn h7c_initialize_repo(workspace: &Path, git_path: &Path) {
        fs::write(workspace.join("unchanged.txt"), b"unchanged\n")
            .expect("D29-H7-C unchanged file");
        fs::write(workspace.join("modified.txt"), b"before\n").expect("D29-H7-C modified file");
        h7c_run_git(git_path, workspace, &["init", "--quiet"]);
        h7c_run_git(git_path, workspace, &["config", "user.name", "D29-H7-C"]);
        h7c_run_git(
            git_path,
            workspace,
            &["config", "user.email", "d29h7c@example.invalid"],
        );
        h7c_run_git(
            git_path,
            workspace,
            &["add", "--", "unchanged.txt", "modified.txt"],
        );
        h7c_run_git(git_path, workspace, &["commit", "--quiet", "-m", "initial"]);
    }

    fn h7c_helper_fixture_executable(repo_root: &Path) -> PathBuf {
        let executable = repo_root
            .join("vita-agent")
            .join("target")
            .join("debug")
            .join("d29h7-git-helper-fixture.exe");
        if executable.is_file() {
            return executable;
        }
        let status = Command::new("cargo")
            .current_dir(repo_root)
            .args([
                "build",
                "--manifest-path",
                "vita-agent/Cargo.toml",
                "--bin",
                "d29h7-git-helper-fixture",
                "--features",
                "d29-h7-test-helper",
            ])
            .env("CARGO_BUILD_JOBS", "1")
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_TERM_COLOR", "never")
            .status()
            .expect("D29-H7-C helper fixture build");
        assert!(status.success() && executable.is_file());
        executable
    }

    struct H7CDirectHarness {
        _workspace: TempDir,
        root: TrustedWorkspaceRoot,
        profile: Arc<H7CGitStatusProfile>,
        authority: Arc<H7Authority>,
        bridge: Arc<H7PendingConfirmationBridge>,
        receiver: Option<tokio::sync::mpsc::Receiver<H7PendingProcessAction>>,
        broker: Arc<H7CGitStatusBroker>,
        git_path: PathBuf,
    }

    impl H7CDirectHarness {
        fn new() -> Self {
            let workspace = tempdir().expect("D29-H7-C workspace directory");
            let git_path = h7c_installed_git_path();
            h7c_initialize_repo(workspace.path(), &git_path);
            let root = TrustedWorkspaceRoot::acquire(workspace.path())
                .expect("D29-H7-C trusted workspace root");
            let profile = Arc::new(
                H7CGitStatusProfile::new(&root, git_path.clone())
                    .expect("D29-H7-C fixed Git profile"),
            );
            let authority = H7Authority::new_git_workspace(&root).expect("D29-H7-C Host authority");
            let (bridge, receiver) = H7PendingConfirmationBridge::new();
            let context = VitaExecutionContext::try_new(H7_LIFE_ID, H7_TASK_ID)
                .expect("D29-H7-C execution context");
            let broker = H7CGitStatusBroker::new(
                context,
                Arc::clone(&profile),
                Arc::clone(&authority),
                Arc::clone(&bridge),
                Some(root.clone()),
            );
            Self {
                _workspace: workspace,
                root,
                profile,
                authority,
                bridge,
                receiver: Some(receiver),
                broker,
                git_path,
            }
        }

        fn action(&self) -> Arc<PreparedProcessAction> {
            self.profile
                .prepare_action(
                    self.broker.context.clone(),
                    H7CGitStatusRequest {
                        tool_call_id: "call-d29h7c-test".to_string(),
                        turn_id: "turn-d29h7c-test".to_string(),
                    },
                    Some(self.root.clone()),
                )
                .expect("D29-H7-C prepared Git status action")
        }

        fn action_without_scope(&self) -> Arc<PreparedProcessAction> {
            self.profile
                .prepare_action(
                    self.broker.context.clone(),
                    H7CGitStatusRequest {
                        tool_call_id: "call-d29h7c-noscope".to_string(),
                        turn_id: "turn-d29h7c-noscope".to_string(),
                    },
                    None,
                )
                .expect("D29-H7-C scope-free test action")
        }

        fn broker_with_final_fence(&self, gate: Arc<H7FinalFenceGate>) -> Arc<H7CGitStatusBroker> {
            H7CGitStatusBroker::new(
                self.broker.context.clone(),
                Arc::clone(&self.profile),
                Arc::clone(&self.authority),
                Arc::clone(&self.bridge),
                Some(self.root.clone()),
            )
            .with_final_fence_gate(gate)
        }

        fn snapshot(&self) -> H7CWorkspaceSnapshot {
            h7c_snapshot_workspace(self.root.requested_path()).expect("D29-H7-C snapshot")
        }
    }

    async fn run_h7c_approved(
        broker: Arc<H7CGitStatusBroker>,
        authority: Arc<H7Authority>,
        receiver: &mut tokio::sync::mpsc::Receiver<H7PendingProcessAction>,
        action: Arc<PreparedProcessAction>,
    ) -> H7CGitStatusResult {
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.execute(action).await }
        });
        let pending = tokio::time::timeout(H7_TURN_TIMEOUT, receiver.recv())
            .await
            .expect("D29-H7-C confirmation request wait")
            .expect("D29-H7-C confirmation request");
        let revision = authority
            .provision_workspace_confirmation(&pending.action)
            .expect("D29-H7-C trusted confirmation");
        pending
            .response
            .send(revision)
            .expect("D29-H7-C confirmation response");
        task.await.expect("D29-H7-C broker task")
    }

    fn h7c_append_malicious_core_config(root: &TrustedWorkspaceRoot, key: &str, sentinel: &Path) {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("D29-H7-C repository root")
            .to_path_buf();
        let helper = h7c_helper_fixture_executable(&repo_root);
        let helper = helper.to_string_lossy().replace('\\', "/");
        let sentinel = sentinel.to_string_lossy().replace('\\', "/");
        let mut config = OpenOptions::new()
            .append(true)
            .open(root.requested_path().join(".git/config"))
            .expect("D29-H7-C malicious Git config");
        writeln!(
            config,
            "\n[core]\n\t{key} = \"{helper} write-sentinel {sentinel}\""
        )
        .expect("D29-H7-C malicious Git config write");
    }

    fn assert_h7c_denied(result: &H7CGitStatusResult, broker: &H7CGitStatusBroker) {
        assert_eq!(result.status, "denied");
        assert_eq!(broker.metrics().process_created.load(Ordering::Acquire), 0);
    }

    #[test]
    fn h7c_git_status_schema_is_fixed() {
        let schema = h7c_git_status_schema_contract();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"], json!(["operation"]));
        assert_eq!(schema["properties"]["operation"]["type"], "string");
        assert_eq!(schema["properties"]["operation"]["enum"], json!(["status"]));
        assert_eq!(
            schema["properties"]["operation"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["enum".to_string(), "type".to_string()])
        );
    }

    #[test]
    fn h7c_model_cannot_supply_git_args() {
        assert!(serde_json::from_str::<H7CGitStatusArguments>(
            r#"{"operation":"status","args":["--porcelain=v2"]}"#
        )
        .is_err());
    }

    #[test]
    fn h7c_model_cannot_supply_executable() {
        assert!(serde_json::from_str::<H7CGitStatusArguments>(
            r#"{"operation":"status","executable":"cmd.exe"}"#
        )
        .is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_real_git_executable_is_exact_bound() {
        let _lock = lock_h7_tests();
        let harness = H7CDirectHarness::new();
        let action = harness.action();
        let image = action
            .image
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(harness.git_path, harness.profile.git_path);
        assert!(harness.git_path.is_absolute());
        assert!(harness.git_path.is_file());
        assert_eq!(image.identity, harness.profile.expected_image_identity);
        assert_eq!(
            image.namespace.identity(),
            harness.profile.expected_image_namespace
        );
        assert_eq!(image.sha256, harness.profile.expected_image_sha256);
        assert_eq!(action.profile_id.as_deref(), Some(H7C_PROFILE_ID));
        assert!(action
            .argv
            .windows(2)
            .any(|args| args == ["--no-pager".to_string(), "--no-optional-locks".to_string()]));
        assert!(!action.environment.contains_key("PATH"));
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_workspace_scope_required() {
        let _lock = lock_h7_tests();
        let harness = H7CDirectHarness::new();
        let revision = harness
            .authority
            .evaluate_workspace_scope(&harness.action())
            .expect("D29-H7-C workspace scope");
        assert_eq!(revision, 2);
        assert_eq!(harness.authority.workspace_scope_provenance(), (1, 0));
        assert_eq!(harness.authority.provenance(), (0, 0));
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_no_scope_createprocess_zero() {
        let _lock = lock_h7_tests();
        let harness = H7CDirectHarness::new();
        let action = harness.action_without_scope();
        let result = harness.broker.execute(action).await;
        assert_h7c_denied(&result, &harness.broker);
        assert_eq!(harness.authority.workspace_scope_provenance(), (0, 0));
        assert_eq!(harness.authority.provenance(), (0, 0));
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_no_confirmation_createprocess_zero() {
        let _lock = lock_h7_tests();
        let mut harness = H7CDirectHarness::new();
        let action = harness.action();
        let receiver = harness.receiver.as_mut().expect("D29-H7-C receiver");
        let task = tokio::spawn({
            let broker = Arc::clone(&harness.broker);
            async move { broker.execute(action).await }
        });
        let pending = tokio::time::timeout(H7_TURN_TIMEOUT, receiver.recv())
            .await
            .expect("D29-H7-C no-confirmation wait")
            .expect("D29-H7-C no-confirmation action");
        drop(pending);
        let result = task.await.expect("D29-H7-C no-confirmation task");
        assert_h7c_denied(&result, &harness.broker);
        assert_eq!(harness.authority.workspace_scope_provenance(), (1, 0));
        assert_eq!(harness.authority.provenance(), (0, 0));
        assert_eq!(
            harness
                .authority
                .metrics
                .grants_issued
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_wrong_workspace_createprocess_zero() {
        let _lock = lock_h7_tests();
        let harness = H7CDirectHarness::new();
        let wrong_workspace = tempdir().expect("D29-H7-C wrong workspace");
        let wrong_root = TrustedWorkspaceRoot::acquire(wrong_workspace.path())
            .expect("D29-H7-C wrong trusted root");
        let action = harness.profile.prepare_action(
            harness.broker.context.clone(),
            H7CGitStatusRequest {
                tool_call_id: "call-d29h7c-wrong-root".to_string(),
                turn_id: "turn-d29h7c-wrong-root".to_string(),
            },
            Some(wrong_root),
        );
        assert!(action.is_err());
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_root_rebind_createprocess_zero() {
        let _lock = lock_h7_tests();
        let mut harness = H7CDirectHarness::new();
        let action = harness.action();
        let rebound_path = harness
            ._workspace
            .path()
            .join("rebound-name-that-does-not-exist");
        let rebound_root = crate::workspace_capability::root_with_requested_path_for_test(
            &harness.root,
            rebound_path,
        );
        let mut rebound_action = action;
        let rebound_action_mut = Arc::get_mut(&mut rebound_action).expect("D29-H7-C unique action");
        rebound_action_mut.workspace_root = Some(rebound_root.clone());
        rebound_action_mut.workspace_root_identity = Some(rebound_root.identity());
        let result = run_h7c_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            rebound_action,
        )
        .await;
        assert_h7c_denied(&result, &harness.broker);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_same_sqlite_rev2_to_rev3_createprocess_zero() {
        let _lock = lock_h7_tests();
        let mut harness = H7CDirectHarness::new();
        let gate = H7FinalFenceGate::new();
        gate.arm();
        let broker = harness.broker_with_final_fence(Arc::clone(&gate));
        let action = harness.action();
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.execute(action).await }
        });
        let pending = harness.receiver.as_mut().unwrap().recv().await.unwrap();
        let revision = harness
            .authority
            .provision_workspace_confirmation(&pending.action)
            .unwrap();
        pending.response.send(revision).unwrap();
        gate.wait_until_entered().await;
        harness
            .authority
            .disable_authorization_for_test(2)
            .expect("D29-H7-C SQLite rev2 to rev3 disable");
        gate.release();
        let result = task.await.unwrap();
        assert_h7c_denied(&result, &broker);
        assert_eq!(
            harness
                .authority
                .metrics
                .grants_issued
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(
            harness
                .authority
                .metrics
                .final_revalidations
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_git_status_workspace_bytes_unchanged() {
        let _lock = lock_h7_tests();
        let mut harness = H7CDirectHarness::new();
        let before = harness.snapshot();
        let action = harness.action();
        let result = run_h7c_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        assert_eq!(result.status, "completed");
        assert_eq!(before.workspace_files, harness.snapshot().workspace_files);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_git_status_git_metadata_bytes_unchanged() {
        let _lock = lock_h7_tests();
        let mut harness = H7CDirectHarness::new();
        let before = harness.snapshot();
        let action = harness.action();
        let result = run_h7c_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        assert_eq!(result.status, "completed");
        assert_eq!(before.git_files, harness.snapshot().git_files);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_git_status_creates_no_index_lock() {
        let _lock = lock_h7_tests();
        let mut harness = H7CDirectHarness::new();
        assert!(!h7c_index_lock_present(harness.root.requested_path()));
        let action = harness.action();
        let result = run_h7c_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        assert_eq!(result.status, "completed");
        assert!(!h7c_index_lock_present(harness.root.requested_path()));
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_git_status_spawns_no_descendant() {
        let _lock = lock_h7_tests();
        let mut harness = H7CDirectHarness::new();
        let action = harness.action();
        let result = run_h7c_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        assert_eq!(result.status, "completed");
        let native = harness
            .broker
            .last_native()
            .expect("D29-H7-C native result");
        assert!(native.process_tree_observed);
        assert_eq!(native.process_tree_remaining, 0);
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            1
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_malicious_fsmonitor_helper_never_executes() {
        let _lock = lock_h7_tests();
        let mut harness = H7CDirectHarness::new();
        let sentinel = harness.root.requested_path().join("fsmonitor-sentinel.txt");
        h7c_append_malicious_core_config(&harness.root, "fsmonitor", &sentinel);
        let action = harness.action();
        let result = run_h7c_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        assert_eq!(result.status, "completed");
        assert!(!sentinel.exists());
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_tree_remaining
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_malicious_pager_never_executes() {
        let _lock = lock_h7_tests();
        let mut harness = H7CDirectHarness::new();
        let sentinel = harness.root.requested_path().join("pager-sentinel.txt");
        h7c_append_malicious_core_config(&harness.root, "pager", &sentinel);
        let action = harness.action();
        let result = run_h7c_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        assert_eq!(result.status, "completed");
        assert!(!sentinel.exists());
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_tree_remaining
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7c_gitfile_outside_workspace_is_rejected() {
        let _lock = lock_h7_tests();
        let workspace = tempdir().expect("D29-H7-C gitfile workspace");
        fs::write(
            workspace.path().join(".git"),
            b"gitdir: C:/outside/repository\n",
        )
        .expect("D29-H7-C external gitfile");
        let root = TrustedWorkspaceRoot::acquire(workspace.path()).expect("D29-H7-C gitfile root");
        assert!(H7CGitStatusProfile::new(&root, h7c_installed_git_path()).is_err());
    }

    #[test]
    fn h7c_status_parser_rejects_absolute_path() {
        assert_eq!(
            h7c_parse_porcelain_z(b" M C:\\outside\\file.txt\0"),
            H7CParseOutcome::Invalid
        );
    }

    #[test]
    fn h7c_status_parser_rejects_parent_escape() {
        assert_eq!(
            h7c_parse_porcelain_z(b" M ../outside.txt\0"),
            H7CParseOutcome::Invalid
        );
    }

    #[test]
    fn h7c_status_parser_is_bounded() {
        let mut output = Vec::new();
        for index in 0..257 {
            output.extend_from_slice(format!(" M file-{index}\0").as_bytes());
        }
        assert_eq!(h7c_parse_porcelain_z(&output), H7CParseOutcome::Limited);
        let long_path = format!(" M {}\0", "x".repeat(1025));
        assert_eq!(
            h7c_parse_porcelain_z(long_path.as_bytes()),
            H7CParseOutcome::Limited
        );
    }

    #[test]
    fn h7c_model_output_has_no_absolute_paths() {
        let result = H7CGitStatusResult {
            status: "completed",
            entries: vec![H7CGitStatusEntry {
                index: " ".to_string(),
                worktree: "M".to_string(),
                path: "modified.txt".to_string(),
                from: None,
            }],
        };
        let output = result.value().to_string();
        assert!(!output.contains("C:\\"));
        assert!(!output.contains("\\\\"));
        assert!(!h7_output_has_authority_facts(&result.value()));
    }

    #[test]
    fn h7c_uses_global_h7_admission() {
        let _lock = lock_h7_tests();
        let harness = H7CDirectHarness::new();
        assert!(Arc::ptr_eq(
            &harness.broker.admission,
            &h7_process_admission()
        ));
        let lease = h7_process_admission()
            .try_acquire()
            .expect("D29-H7-C global admission");
        drop(lease);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_global_quarantine_blocks_git_before_confirmation() {
        let _lock = lock_h7_tests();
        let (gate, probe, before) = install_h7_pending_output_quarantine("h7c-quarantine");
        let harness = H7CDirectHarness::new();
        let result = harness.broker.execute(harness.action()).await;
        assert_h7c_denied(&result, &harness.broker);
        assert_eq!(harness.authority.workspace_scope_provenance(), (0, 0));
        assert_eq!(harness.authority.provenance(), (0, 0));
        gate.allow_terminal.store(true, Ordering::Release);
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert!(probe.terminal_observed.load(Ordering::Acquire));
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7c_outer_abort_preserves_h7_cleanup() {
        let _lock = lock_h7_tests();
        let mut harness = H7CDirectHarness::new();
        let gate = H7FinalFenceGate::new();
        gate.arm();
        let broker = harness.broker_with_final_fence(Arc::clone(&gate));
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            let action = harness.action();
            async move { broker.execute(action).await }
        });
        let pending = harness.receiver.as_mut().unwrap().recv().await.unwrap();
        let revision = harness
            .authority
            .provision_workspace_confirmation(&pending.action)
            .unwrap();
        pending.response.send(revision).unwrap();
        gate.wait_until_entered().await;
        task.abort();
        assert!(task.await.is_err());
        gate.release();
        tokio::task::yield_now().await;
        assert_eq!(broker.metrics().process_created.load(Ordering::Acquire), 0);
        assert_eq!(
            broker
                .metrics()
                .output_handles_active
                .load(Ordering::Acquire),
            0
        );
        assert!(!h7_process_admission().active.load(Ordering::Acquire));
        assert!(harness.authority.shutdown());
    }

    async fn run_h7b_approved(
        broker: Arc<H7BWorkspaceProcessBroker>,
        authority: Arc<H7Authority>,
        receiver: &mut tokio::sync::mpsc::Receiver<H7PendingProcessAction>,
        action: Arc<PreparedProcessAction>,
    ) -> H7BToolResult {
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.execute(action).await }
        });
        let pending = tokio::time::timeout(H7_TURN_TIMEOUT, receiver.recv())
            .await
            .expect("D29-H7-B confirmation request wait")
            .expect("D29-H7-B confirmation request");
        let revision = authority
            .provision_workspace_confirmation(&pending.action)
            .expect("D29-H7-B trusted confirmation");
        pending
            .response
            .send(revision)
            .expect("D29-H7-B confirmation response");
        task.await.expect("D29-H7-B broker task")
    }

    fn assert_h7b_zero_process_result(result: &H7BToolResult) {
        assert_eq!(result.status, "denied");
        assert!(!result.process_created);
        assert_eq!(result.side_effect_count, 0);
    }

    #[test]
    fn h7b_d28_workspace_scope_required() {
        let _lock = lock_h7_tests();
        let harness = H7BDirectHarness::new();
        let action = harness.action();
        let revision = harness
            .authority
            .evaluate_workspace_scope(&action)
            .expect("D29-H7-B canonical workspace scope");
        assert_eq!(revision, 2);
        assert_eq!(harness.authority.workspace_scope_provenance(), (1, 0));
        assert_eq!(harness.authority.provenance(), (0, 0));
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_no_scope_confirmation_zero() {
        let _lock = lock_h7_tests();
        let mut harness = H7BDirectHarness::new();
        let action = harness.action_without_scope();
        let result = harness.broker.execute(action).await;
        assert_h7b_zero_process_result(&result);
        assert_eq!(harness.authority.workspace_scope_provenance(), (0, 0));
        assert_eq!(harness.authority.provenance(), (0, 0));
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.receiver.take().is_some());
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_no_confirmation_createprocess_zero() {
        let _lock = lock_h7_tests();
        let mut harness = H7BDirectHarness::new();
        let action = harness.action();
        let receiver = harness.receiver.as_mut().expect("D29-H7-B receiver");
        let task = tokio::spawn({
            let broker = Arc::clone(&harness.broker);
            async move { broker.execute(action).await }
        });
        let pending = tokio::time::timeout(H7_TURN_TIMEOUT, receiver.recv())
            .await
            .expect("D29-H7-B no-confirmation pending wait")
            .expect("D29-H7-B no-confirmation pending action");
        drop(pending);
        let result = task.await.expect("D29-H7-B no-confirmation broker task");
        assert_h7b_zero_process_result(&result);
        assert_eq!(harness.authority.workspace_scope_provenance(), (1, 0));
        assert_eq!(harness.authority.provenance(), (0, 0));
        assert_eq!(
            harness
                .authority
                .metrics
                .grants_issued
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_workspace_grant_binds_exact_root() {
        let _lock = lock_h7_tests();
        let mut harness = H7BDirectHarness::new();
        let action = harness.action();
        let binding = action.binding();
        assert_eq!(binding.capability_id, H7B_CAPABILITY_ID);
        assert_eq!(
            binding.workspace_root_identity.as_deref(),
            Some(h7_workspace_identity_wire(harness.root.identity()).as_str())
        );
        assert_eq!(
            binding.working_directory_identity,
            action.working_directory_identity
        );
        let result = run_h7b_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        assert_eq!(result.status, "workspace_process_completed");
        assert!(result.process_created);
        assert_eq!(harness.authority.workspace_scope_provenance(), (1, 0));
        assert_eq!(harness.authority.provenance(), (1, 0));
        assert_eq!(
            harness
                .authority
                .metrics
                .grants_issued
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(
            harness
                .authority
                .metrics
                .final_revalidations
                .load(Ordering::Acquire),
            1
        );
        let raw = harness
            .broker
            .last_fixture_stdout()
            .expect("D29-H7-B fixture cwd output");
        let observation: Value = serde_json::from_slice(&raw).expect("D29-H7-B cwd JSON");
        let actual = PathBuf::from(
            observation["cwd"]
                .as_str()
                .expect("D29-H7-B fixture cwd field"),
        );
        assert_eq!(
            fs::canonicalize(actual).unwrap(),
            fs::canonicalize(harness.root.requested_path()).unwrap()
        );
        assert_eq!(
            harness
                .broker
                .metrics()
                .job_assigned
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(
            harness
                .broker
                .metrics()
                .thread_resumed
                .load(Ordering::Acquire),
            1
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_wrong_workspace_root_createprocess_zero() {
        let _lock = lock_h7_tests();
        let harness = H7BDirectHarness::new();
        let wrong_workspace = tempdir().expect("D29-H7-B wrong workspace");
        let wrong_root = TrustedWorkspaceRoot::acquire(wrong_workspace.path())
            .expect("D29-H7-B wrong trusted root");
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("D29-H7-B repository root")
            .to_path_buf();
        let image = h7_process_fixture_executable(&repo_root).expect("D29-H7-B fixture image");
        let wrong_catalog =
            H7ExecutableCatalog::fixture(image, wrong_root.requested_path().to_path_buf())
                .expect("D29-H7-B wrong catalog");
        let action = wrong_catalog
            .prepare_workspace_action(
                harness.broker.context.clone(),
                H7ProcessRequest::synthetic(
                    "call-d29h7b-wrong-root",
                    "turn-d29h7b-wrong-root",
                    &["report-cwd"],
                ),
                wrong_root,
            )
            .expect("D29-H7-B wrong-root action");
        let result = harness.broker.execute(action).await;
        assert_h7b_zero_process_result(&result);
        assert_eq!(harness.authority.workspace_scope_provenance(), (0, 0));
        assert_eq!(harness.authority.provenance(), (0, 0));
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_workspace_root_rebind_createprocess_zero() {
        let _lock = lock_h7_tests();
        let mut harness = H7BDirectHarness::new();
        let rebound_path = harness
            ._workspace
            .path()
            .join("rebound-name-that-does-not-exist");
        let rebound_root = crate::workspace_capability::root_with_requested_path_for_test(
            &harness.root,
            rebound_path,
        );
        let action = harness
            .catalog
            .prepare_workspace_action(
                harness.broker.context.clone(),
                H7ProcessRequest::synthetic(
                    "call-d29h7b-root-rebind",
                    "turn-d29h7b-root-rebind",
                    &["report-cwd"],
                ),
                rebound_root,
            )
            .expect("D29-H7-B rebound action");
        let result = run_h7b_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        assert_h7b_zero_process_result(&result);
        assert_eq!(
            harness
                .authority
                .metrics
                .grants_issued
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_workspace_root_rename_cannot_redirect_process() {
        let _lock = lock_h7_tests();
        let mut harness = H7BDirectHarness::new();
        let original = harness.root.requested_path().to_path_buf();
        let moved = harness
            ._workspace
            .path()
            .parent()
            .expect("D29-H7-B workspace parent")
            .join("d29h7b-renamed-root");
        let renamed = fs::rename(&original, &moved).is_ok();
        let action = harness.action();
        let result = run_h7b_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        if renamed {
            assert_h7b_zero_process_result(&result);
            assert!(harness.root.verify_named_path_current().is_err());
            let _ = fs::rename(&moved, &original);
        } else {
            assert_eq!(result.status, "workspace_process_completed");
            assert!(harness.root.verify_named_path_current().is_ok());
            let raw = harness.broker.last_fixture_stdout().unwrap();
            let observation: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(
                fs::canonicalize(observation["cwd"].as_str().unwrap()).unwrap(),
                fs::canonicalize(&original).unwrap()
            );
        }
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_same_sqlite_rev2_to_rev3_createprocess_zero() {
        let _lock = lock_h7_tests();
        let mut harness = H7BDirectHarness::new();
        let gate = H7FinalFenceGate::new();
        gate.arm();
        let broker = harness.broker_with_final_fence(Arc::clone(&gate));
        let action = harness.action();
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.execute(action).await }
        });
        let pending = harness.receiver.as_mut().unwrap().recv().await.unwrap();
        let revision = harness
            .authority
            .provision_workspace_confirmation(&pending.action)
            .unwrap();
        pending.response.send(revision).unwrap();
        gate.wait_until_entered().await;
        harness
            .authority
            .disable_authorization_for_test(2)
            .expect("D29-H7-B SQLite rev2 to rev3 disable");
        gate.release();
        let result = task.await.unwrap();
        assert_h7b_zero_process_result(&result);
        assert_eq!(
            harness
                .authority
                .metrics
                .grants_issued
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(
            harness
                .authority
                .metrics
                .final_revalidations
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(broker.metrics().process_created.load(Ordering::Acquire), 0);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_fixture_cwd_equals_authorized_workspace() {
        let _lock = lock_h7_tests();
        let mut harness = H7BDirectHarness::new();
        let action = harness.action();
        let result = run_h7b_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        assert_eq!(result.status, "workspace_process_completed");
        let raw = harness.broker.last_fixture_stdout().unwrap();
        let observation: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            fs::canonicalize(observation["cwd"].as_str().unwrap()).unwrap(),
            fs::canonicalize(harness.root.requested_path()).unwrap()
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_fixture_mutates_workspace_zero() {
        let _lock = lock_h7_tests();
        let mut harness = H7BDirectHarness::new();
        let sentinel = harness.root.requested_path().join("d29h7b-sentinel.txt");
        fs::write(&sentinel, b"unchanged").expect("D29-H7-B sentinel");
        let before = fs::read(&sentinel).unwrap();
        let action = harness.action();
        let result = run_h7b_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        assert_eq!(result.status, "workspace_process_completed");
        assert_eq!(fs::read(&sentinel).unwrap(), before);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_model_output_hides_absolute_workspace_path() {
        let _lock = lock_h7_tests();
        let mut harness = H7BDirectHarness::new();
        let action = harness.action();
        let result = run_h7b_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            harness.receiver.as_mut().unwrap(),
            action,
        )
        .await;
        let serialized = result.value().to_string();
        assert!(!serialized.contains(harness.root.final_path().to_string_lossy().as_ref()));
        assert!(!serialized.contains("grant_id"));
        assert!(!serialized.contains("confirmation_id"));
        assert!(!serialized.contains("authorization_revision"));
        assert!(!serialized.contains("workspace_root_identity"));
        assert!(!serialized.contains("working_directory_identity"));
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7b_uses_h7a_global_admission() {
        let _lock = lock_h7_tests();
        let harness = H7BDirectHarness::new();
        assert!(Arc::ptr_eq(
            &harness.broker.admission,
            &h7_process_admission()
        ));
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_h7a_active_blocks_h7b_before_confirmation() {
        let _lock = lock_h7_tests();
        let mut h7a = H7DirectHarness::new();
        let h7b = H7BDirectHarness::new();
        let first = tokio::spawn({
            let broker = Arc::clone(&h7a.broker);
            let action = h7a.action(&["sleep", "500"]);
            async move { broker.execute(action).await }
        });
        let pending = h7a.receiver.as_mut().unwrap().recv().await.unwrap();
        let second = h7b.broker.execute(h7b.action()).await;
        assert_h7b_zero_process_result(&second);
        assert_eq!(h7b.authority.workspace_scope_provenance(), (0, 0));
        drop(pending);
        let first_result = first.await.unwrap();
        assert_h7_zero_process_result(&first_result);
        assert!(h7a.authority.shutdown());
        assert!(h7b.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_active_blocks_h7a_before_confirmation() {
        let _lock = lock_h7_tests();
        let mut h7b = H7BDirectHarness::new();
        let h7a = H7DirectHarness::new();
        let first = tokio::spawn({
            let broker = Arc::clone(&h7b.broker);
            let action = h7b.action();
            async move { broker.execute(action).await }
        });
        let pending = h7b.receiver.as_mut().unwrap().recv().await.unwrap();
        let second = h7a
            .broker
            .execute(h7a.action(&["echo-argv", "blocked"]))
            .await;
        assert_h7_zero_process_result(&second);
        assert_eq!(h7a.authority.provenance(), (0, 0));
        drop(pending);
        let first_result = first.await.unwrap();
        assert_h7b_zero_process_result(&first_result);
        assert!(h7a.authority.shutdown());
        assert!(h7b.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_global_quarantine_blocks_workspace_process() {
        let _lock = lock_h7_tests();
        let (gate, probe, before) = install_h7_pending_output_quarantine("h7b-quarantine");
        let harness = H7BDirectHarness::new();
        let result = harness.broker.execute(harness.action()).await;
        assert_h7b_zero_process_result(&result);
        assert_eq!(harness.authority.workspace_scope_provenance(), (0, 0));
        assert_eq!(harness.authority.provenance(), (0, 0));
        gate.allow_terminal.store(true, Ordering::Release);
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert!(probe.terminal_observed.load(Ordering::Acquire));
        assert!(probe.drop_finished.load(Ordering::Acquire));
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7b_outer_abort_preserves_h7a_cleanup() {
        let _lock = lock_h7_tests();
        let harness = H7BDirectHarness::new();
        let metrics = harness.broker.metrics();
        let action = harness.action_with_args(&["sleep", "2_000"]);
        let mut receiver = harness.receiver.expect("D29-H7-B outer-abort receiver");
        let task = tokio::spawn({
            let broker = Arc::clone(&harness.broker);
            async move { broker.execute(action).await }
        });
        let pending = receiver.recv().await.unwrap();
        let revision = harness
            .authority
            .provision_workspace_confirmation(&pending.action)
            .unwrap();
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), metrics.created_notify.notified())
            .await
            .expect("D29-H7-B outer-abort process creation");
        task.abort();
        assert!(task.await.is_err());
        wait_h7_native_workers_quiet(metrics.clone()).await;
        assert_eq!(metrics.jobs_terminated.load(Ordering::Acquire), 1);
        assert_eq!(metrics.process_tree_remaining.load(Ordering::Acquire), 0);
        assert_eq!(metrics.output_handles_active.load(Ordering::Acquire), 0);
        assert!(!h7_process_admission().active.load(Ordering::Acquire));
        assert!(harness.authority.shutdown());
    }

    async fn run_approved(
        broker: Arc<H7ProcessBroker>,
        authority: Arc<H7Authority>,
        receiver: &mut tokio::sync::mpsc::Receiver<H7PendingProcessAction>,
        action: Arc<PreparedProcessAction>,
    ) -> H7ToolResult {
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.execute(action).await }
        });
        let pending = tokio::time::timeout(H7_TURN_TIMEOUT, receiver.recv())
            .await
            .expect("D29-H7 confirmation request wait")
            .expect("D29-H7 confirmation request");
        let revision = authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 trusted confirmation");
        pending
            .response
            .send(revision)
            .expect("D29-H7 confirmation response");
        task.await.expect("D29-H7 broker task")
    }

    async fn run_h7_approved_fixture(args: &[&str]) -> H7ToolResult {
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(args),
        )
        .await;
        assert!(harness.authority.shutdown());
        result
    }

    async fn run_with_final_host_fault(fault: H7HostResponseFault) -> H7ToolResult {
        let mut harness = H7DirectHarness::new();
        harness.authority.inject_response_fault(fault);
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["echo-argv", "final-fault"]),
        )
        .await;
        assert!(harness.authority.shutdown());
        result
    }

    async fn run_with_post_host_mutation(mutation: H7PostHostMutation) -> H7ToolResult {
        let mut harness = H7DirectHarness::new();
        let broker = harness.broker_with_post_host_mutation(mutation);
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            broker,
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["echo-argv", "post-host-fault"]),
        )
        .await;
        assert!(harness.authority.shutdown());
        result
    }

    async fn run_cancelled(
        broker: Arc<H7ProcessBroker>,
        authority: Arc<H7Authority>,
        receiver: &mut tokio::sync::mpsc::Receiver<H7PendingProcessAction>,
        action: Arc<PreparedProcessAction>,
    ) -> H7ToolResult {
        let metrics = broker.metrics();
        let created = metrics.created_notify.notified();
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.execute(action).await }
        });
        let pending = tokio::time::timeout(H7_TURN_TIMEOUT, receiver.recv())
            .await
            .expect("D29-H7 cancellation confirmation wait")
            .expect("D29-H7 cancellation confirmation");
        let revision = authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 cancellation confirmation");
        pending
            .response
            .send(revision)
            .expect("D29-H7 cancellation response");
        tokio::time::timeout(Duration::from_secs(2), created)
            .await
            .expect("D29-H7 cancellation process creation");
        broker.cancel();
        task.await.expect("D29-H7 cancelled broker task")
    }

    async fn wait_h7_native_workers_quiet(metrics: Arc<H7SupervisorMetrics>) {
        let deadline = Instant::now() + H7_CLEANUP_TIMEOUT;
        while metrics.native_workers_active.load(Ordering::Acquire) != 0 {
            let notified = metrics.native_worker_finished_notify.notified();
            if metrics.native_workers_active.load(Ordering::Acquire) == 0 {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "D29-H7 native worker did not exit");
            tokio::time::timeout(remaining, notified)
                .await
                .expect("D29-H7 native worker exit wait");
        }
        assert_eq!(metrics.native_workers_active.load(Ordering::Acquire), 0);
        assert_eq!(
            metrics.native_workers_started.load(Ordering::Acquire),
            metrics.native_workers_finished.load(Ordering::Acquire)
        );
    }

    fn cleanup_h7_test_output_capture(
        mut capture: H7OverlappedOutputCapture,
        quarantine_before: usize,
    ) {
        capture.cancel_pending();
        if !capture.drain_until_terminal(Instant::now() + H7_CLEANUP_TIMEOUT) {
            assert!(capture.quarantine_if_pending());
        }
        drop(capture);
        reap_h7_quarantine_until(quarantine_before, Instant::now() + Duration::from_secs(1));
        assert_eq!(h7_pending_io_quarantine().count(), quarantine_before);
    }

    fn h7_pending_connect_for_test(stream: &str) -> H7OverlappedConnect {
        let pipe_name = h7_output_pipe_name(stream).expect("D29-H7 pending connect pipe name");
        let read = H7Handle::new(unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                H7_OUTPUT_SCRATCH_BYTES as u32,
                H7_OUTPUT_SCRATCH_BYTES as u32,
                1_000,
                std::ptr::null(),
            )
        })
        .expect("D29-H7 pending connect server handle");
        assert_ne!(
            unsafe { SetHandleInformation(read.raw(), HANDLE_FLAG_INHERIT, 0) },
            0,
            "D29-H7 pending connect server inheritance"
        );
        let mut connect = H7OverlappedConnect::new(read).expect("D29-H7 pending connect owner");
        connect.start().expect("D29-H7 pending ConnectNamedPipe");
        assert!(connect.pending(), "D29-H7 ConnectNamedPipe must be pending");
        connect
    }

    fn cleanup_h7_test_connect(mut connect: H7OverlappedConnect, quarantine_before: usize) {
        connect.request_cancel();
        if !connect.wait_for_terminal_until(Instant::now() + H7_CLEANUP_TIMEOUT) {
            connect.quarantine();
        } else {
            drop(connect);
        }
        reap_h7_quarantine_until(quarantine_before, Instant::now() + Duration::from_secs(1));
        assert_eq!(h7_pending_io_quarantine().count(), quarantine_before);
    }

    async fn assert_h7_cross_broker_second_action_is_denied() {
        let mut broker_a_harness = H7DirectHarness::new();
        let mut broker_b_harness = H7DirectHarness::new();
        let gate = H7FinalFenceGate::new();
        gate.arm();
        let broker_a = broker_a_harness.broker_with_final_fence(Arc::clone(&gate));
        assert!(Arc::ptr_eq(
            &broker_a.admission,
            &broker_b_harness.broker.admission
        ));
        let mut receiver_a = broker_a_harness.receiver.take().unwrap();
        let mut receiver_b = broker_b_harness.receiver.take().unwrap();
        let first_task = tokio::spawn({
            let broker = Arc::clone(&broker_a);
            let action = broker_a_harness.action(&["echo-argv", "cross-broker-first"]);
            async move { broker.execute(action).await }
        });
        let pending = receiver_a
            .recv()
            .await
            .expect("D29-H7 cross-broker first confirmation");
        let revision = broker_a_harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 cross-broker first confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), gate.wait_until_entered())
            .await
            .expect("D29-H7 cross-broker final fence entry");

        let second = broker_b_harness
            .broker
            .execute(broker_b_harness.action(&["echo-argv", "cross-broker-second"]))
            .await;
        assert_eq!(second.status, "denied");
        assert_h7_zero_process_result(&second);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), receiver_b.recv())
                .await
                .is_err()
        );
        assert_eq!(
            broker_b_harness
                .authority
                .metrics
                .trusted_confirmations
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            broker_b_harness
                .authority
                .metrics
                .grants_issued
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            broker_b_harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );

        gate.release();
        let first = first_task.await.expect("D29-H7 cross-broker first task");
        assert_completed(&first);
        assert_eq!(
            broker_a.metrics().process_created.load(Ordering::Acquire),
            1
        );
        assert!(broker_a_harness.authority.shutdown());
        assert!(broker_b_harness.authority.shutdown());
    }

    async fn assert_h7_cross_broker_quarantine_is_safe() {
        let mut broker_a_harness = H7DirectHarness::new();
        let mut broker_b_harness = H7DirectHarness::new();
        let gate = Arc::new(H7TerminalityGate::default());
        let broker_a = broker_a_harness
            .broker_with_output_terminality_gate(Arc::clone(&gate), Duration::from_millis(50));
        let metrics = broker_a.metrics();
        let quarantine = h7_pending_io_quarantine();
        let before = quarantine.count();
        let mut receiver_a = broker_a_harness.receiver.take().unwrap();
        let mut receiver_b = broker_b_harness.receiver.take().unwrap();
        let task = tokio::spawn({
            let broker = Arc::clone(&broker_a);
            let action = broker_a_harness.action(&["sleep", "2000"]);
            async move { broker.execute(action).await }
        });
        let pending = receiver_a
            .recv()
            .await
            .expect("D29-H7 cross-broker quarantine confirmation");
        let revision = broker_a_harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 cross-broker quarantine confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), metrics.created_notify.notified())
            .await
            .expect("D29-H7 cross-broker quarantine process creation");
        wait_h7_pending_output_reads(&metrics).await;
        broker_a.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("D29-H7 cross-broker quarantine worker exit")
            .expect("D29-H7 cross-broker quarantine worker join");
        assert_eq!(result.status, "started_outcome_unknown");
        assert!(!broker_a.admission.active.load(Ordering::Acquire));
        assert!(quarantine.count() > before);
        assert!(quarantine.count() <= before + H7_MAX_QUARANTINED_OUTPUT);

        let second = broker_b_harness
            .broker
            .execute(broker_b_harness.action(&["echo-argv", "cross-broker-quarantine-second"]))
            .await;
        assert_eq!(second.status, "denied");
        assert_h7_zero_process_result(&second);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), receiver_b.recv())
                .await
                .is_err()
        );
        assert_eq!(
            broker_b_harness
                .authority
                .metrics
                .trusted_confirmations
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            broker_b_harness
                .authority
                .metrics
                .grants_issued
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            broker_b_harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );

        gate.allow_terminal.store(true, Ordering::Release);
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert_eq!(quarantine.count(), before);
        assert!(broker_a_harness.authority.shutdown());
        assert!(broker_b_harness.authority.shutdown());
    }

    fn assert_h7_zero_process_result(result: &H7ToolResult) {
        assert!(!result.process_created);
        assert_eq!(result.side_effect_count, 0);
    }

    #[test]
    fn h7_issue_host_grant_binding_faults_are_denied() {
        let _lock = lock_h7_tests();
        for fault in [
            H7HostResponseFault::IssueWrongBinding,
            H7HostResponseFault::IssueWrongRevision,
            H7HostResponseFault::IssueWrongConfirmation,
            H7HostResponseFault::IssueSingleUseFalse,
        ] {
            let harness = H7DirectHarness::new();
            let action = harness.action(&["echo-argv", "issue-fault"]);
            let revision = harness
                .authority
                .provision_confirmation(&action)
                .expect("D29-H7 issue-fault confirmation");
            harness.authority.inject_response_fault(fault);
            assert!(harness
                .authority
                .issue_process_grant(&action, revision)
                .is_err());
            assert!(harness.authority.shutdown());
        }
    }

    #[test]
    fn h7_host_response_parser_rejects_malformed_and_truncated() {
        let malformed = br#"{"operation":"revalidate_process_grant""#;
        let truncated = br#"{"operation":"revalidate_process_grant","status":"ok"}"#;
        assert!(serde_json::from_slice::<H7HostResponse>(malformed).is_err());
        assert!(serde_json::from_slice::<H7HostResponse>(truncated).is_err());
    }

    fn native_options(
        metrics: Arc<H7SupervisorMetrics>,
        fault: H7NativeLaunchFault,
    ) -> H7NativeOptions {
        H7NativeOptions {
            cancellation: Arc::new(AtomicBool::new(false)),
            metrics,
            fault,
            unlisted_inheritable_handle: None,
            post_host_mutation: H7PostHostMutation::None,
            pre_create_process_gate: None,
            output_terminality_gate: None,
        }
    }

    fn h7_prepared_tool(broker: Arc<H7ProcessBroker>) -> Arc<VitaProcessTool> {
        Arc::new(VitaProcessTool {
            broker,
            tool_call_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn parse_stdout(result: &H7ToolResult) -> Value {
        serde_json::from_str(&result.stdout).expect("D29-H7 fixture JSON stdout")
    }

    fn assert_completed(result: &H7ToolResult) {
        assert_eq!(result.status, "started_and_exited");
        assert!(result.process_created);
        assert_eq!(result.side_effect_count, 1);
        assert!(!result.timed_out);
        assert!(!result.cancelled);
    }

    fn h7_attempt_same_length_overwrite(path: &Path, original: &[u8]) -> Result<(), String> {
        let mut writer = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|error| error.to_string())?;
        let attempt = writer
            .seek(SeekFrom::Start(0))
            .and_then(|_| writer.write_all(&vec![b'X'; original.len()]))
            .and_then(|_| writer.flush());
        if attempt.is_ok() {
            let _ = writer.seek(SeekFrom::Start(0));
            let _ = writer.write_all(original);
            let _ = writer.flush();
        }
        attempt.map_err(|error| error.to_string())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_argv_roundtrip_exact() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let args = vec![
            "echo-argv",
            "",
            "plain",
            " leading",
            "trailing ",
            "with spaces",
            "embedded\"quote",
            r"trailing\",
            "unicode-界-🙂",
            "tab\tvalue",
            "&|<>^$(){};",
        ];
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&args),
        )
        .await;
        assert_completed(&result);
        assert_eq!(parse_stdout(&result)["args"], json!(args[1..]));
        let schema = h7_process_schema_contract();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["args".to_string(), "program".to_string()])
        );
        assert_eq!(
            schema["properties"]["program"]["enum"],
            json!([H7_PROGRAM_ID])
        );
        assert_eq!(schema["properties"]["args"]["maxItems"], H7_MAX_ARGS);
        assert_eq!(
            schema["properties"]["args"]["items"]["maxLength"],
            H7_MAX_ARG_BYTES
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_shell_metacharacters_are_literal() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let args = [
            "echo-argv",
            "& whoami",
            "| type secret",
            ";$(whoami)",
            "`whoami`",
            "%PATH%",
            "<input>",
        ];
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&args),
        )
        .await;
        assert_completed(&result);
        assert_eq!(parse_stdout(&result)["args"], json!(args[1..]));
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_environment_is_explicit_not_ambient() {
        let _lock = lock_h7_tests();
        let _ambient = H7EnvironmentGuard::install(&[
            ("D29H7_AMBIENT_SENTINEL", "ambient-sentinel"),
            ("OPENAI_API_KEY", "fake-openai-key"),
            ("HTTP_PROXY", "http://ambient.invalid"),
            ("HTTPS_PROXY", "https://ambient.invalid"),
            ("CODEX_HOME", "C:\\ambient-codex-home"),
        ]);
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["report-env"]),
        )
        .await;
        assert_completed(&result);
        let output = parse_stdout(&result);
        let environment = output["environment"]
            .as_array()
            .expect("D29-H7 explicit environment array");
        assert!(environment.iter().any(|pair| {
            pair.as_array().is_some_and(|pair| {
                pair.first().and_then(Value::as_str) == Some(H7_ENV_ALLOWLIST_KEY)
                    && pair.get(1).and_then(Value::as_str) == Some(H7_ENV_ALLOWLIST_VALUE)
            })
        }));
        assert!(!environment.iter().any(|pair| {
            pair.as_array().is_some_and(|pair| {
                matches!(
                    pair.first().and_then(Value::as_str),
                    Some(
                        "PATH"
                            | "D29H7_AMBIENT_SENTINEL"
                            | "OPENAI_API_KEY"
                            | "HTTP_PROXY"
                            | "HTTPS_PROXY"
                            | "CODEX_HOME"
                    )
                )
            })
        }));
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_fixed_cwd_is_host_owned() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let expected = fs::canonicalize(harness._working_directory.path()).unwrap();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["report-cwd"]),
        )
        .await;
        assert_completed(&result);
        let actual = PathBuf::from(parse_stdout(&result)["cwd"].as_str().unwrap());
        assert_eq!(fs::canonicalize(actual).unwrap(), expected);
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7_handle_inheritance_is_restricted() {
        let _lock = lock_h7_tests();
        let harness = H7DirectHarness::new();
        let unlisted = File::create(harness._working_directory.path().join("unlisted.txt"))
            .expect("D29-H7 unlisted handle");
        let raw = unlisted.as_raw_handle() as usize;
        assert_ne!(
            unsafe {
                SetHandleInformation(raw as HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
            },
            0
        );
        let action = harness.action(&["probe-handle", &raw.to_string()]);
        let metrics = Arc::new(H7SupervisorMetrics::default());
        let mut options = native_options(Arc::clone(&metrics), H7NativeLaunchFault::None);
        options.unlisted_inheritable_handle = Some(raw);
        let native = supervise_native(&action, options);
        let result = H7ToolResult::from_native(native);
        assert_completed(&result);
        assert_eq!(parse_stdout(&result)["valid"], false);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_no_confirmation_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        drop(harness.receiver.take());
        let result = harness
            .broker
            .execute(harness.action(&["echo-argv", "denied"]))
            .await;
        assert_eq!(result.status, "denied");
        assert!(!result.process_created);
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_process_grant_is_single_use() {
        let _lock = lock_h7_tests();
        let harness = H7DirectHarness::new();
        let action = harness.action(&["echo-argv", "grant"]);
        let revision = harness
            .authority
            .provision_confirmation(&action)
            .expect("D29-H7 grant confirmation");
        let mut grant = harness
            .authority
            .issue_process_grant(&action, revision)
            .expect("D29-H7 grant issuance");
        harness
            .authority
            .revalidate_process_grant(&action, &mut grant)
            .expect("D29-H7 first grant revalidation");
        assert!(harness
            .authority
            .revalidate_process_grant(&action, &mut grant)
            .is_err());
        assert_eq!(
            harness
                .authority
                .metrics
                .grants_issued
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(
            harness
                .authority
                .metrics
                .final_revalidations
                .load(Ordering::Acquire),
            1
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_real_sqlite_rev2_to_rev3_final_fence_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let gate = H7FinalFenceGate::new();
        gate.arm();
        let broker = harness.broker_with_final_fence(Arc::clone(&gate));
        let action = harness.action(&["echo-argv", "revoked"]);
        let mut receiver = harness.receiver.take().unwrap();
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.execute(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 revocation confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 revocation confirmation");
        pending.response.send(revision).unwrap();
        gate.wait_until_entered().await;
        harness
            .authority
            .disable_authorization_for_test(2)
            .expect("D29-H7 rev2 to rev3 disable");
        gate.release();
        let result = task.await.unwrap();
        assert_eq!(result.status, "denied");
        assert_eq!(broker.metrics().process_created.load(Ordering::Acquire), 0);
        assert_eq!(
            harness
                .authority
                .metrics
                .final_revalidations
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_host_timeout_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        assert!(harness.authority.hold_for_test(4_000).is_err());
        let mut receiver = harness.receiver.take().unwrap();
        let action = harness.action(&["echo-argv", "host-timeout"]);
        let task = tokio::spawn({
            let broker = Arc::clone(&harness.broker);
            async move { broker.execute(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 host-timeout confirmation");
        pending.response.send(2).unwrap();
        let result = task.await.unwrap();
        assert_eq!(result.status, "denied");
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_late_allow_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let action = harness.action(&["echo-argv", "late"]);
        let task = tokio::spawn({
            let broker = Arc::clone(&harness.broker);
            async move { broker.execute(action).await }
        });
        let pending = receiver.recv().await.expect("D29-H7 late confirmation");
        tokio::time::sleep(H7_CONFIRMATION_TIMEOUT + Duration::from_millis(100)).await;
        let result = task.await.unwrap();
        assert_eq!(result.status, "denied");
        assert!(harness
            .authority
            .provision_confirmation(&pending.action)
            .is_ok());
        assert!(pending.response.send(2).is_err());
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_timeout_terminates_job() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["sleep", "2000"]),
        )
        .await;
        assert_eq!(result.status, "started_and_timed_out");
        assert!(result.process_created);
        assert!(result.timed_out);
        assert_eq!(result.side_effect_count, 1);
        assert!(result.job_terminated);
        assert!(result.process_exit_verified);
        assert!(result.process_tree_observed);
        assert_eq!(result.process_tree_remaining, 0);
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert!(
            harness
                .broker
                .metrics()
                .jobs_terminated
                .load(Ordering::Acquire)
                >= 1
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_cancellation_terminates_job() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let metrics = harness.broker.metrics();
        let created = metrics.created_notify.notified();
        let task = tokio::spawn({
            let broker = Arc::clone(&harness.broker);
            let action = harness.action(&["sleep", "2000"]);
            async move { broker.execute(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 cancellation confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 cancellation confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), created)
            .await
            .expect("D29-H7 process creation notification");
        harness.broker.cancel();
        let result = task.await.unwrap();
        assert_eq!(result.status, "started_and_cancelled");
        assert!(result.process_created);
        assert!(result.cancelled);
        assert!(result.job_terminated);
        assert!(result.process_exit_verified);
        assert!(result.process_tree_observed);
        assert_eq!(result.process_tree_remaining, 0);
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert!(
            harness
                .broker
                .metrics()
                .jobs_terminated
                .load(Ordering::Acquire)
                >= 1
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_stdout_limit_terminates_job() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["flood-stdout"]),
        )
        .await;
        assert_eq!(result.status, "started_and_output_limited");
        assert!(result.process_created);
        assert_eq!(result.side_effect_count, 1);
        assert!(result.job_terminated);
        assert!(result.process_exit_verified);
        assert!(result.process_tree_observed);
        assert_eq!(result.process_tree_remaining, 0);
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert!(
            harness
                .broker
                .metrics()
                .jobs_terminated
                .load(Ordering::Acquire)
                >= 1
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_stderr_limit_terminates_job() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["flood-stderr"]),
        )
        .await;
        assert_eq!(result.status, "started_and_output_limited");
        assert!(result.process_created);
        assert_eq!(result.side_effect_count, 1);
        assert!(result.job_terminated);
        assert!(result.process_exit_verified);
        assert!(result.process_tree_observed);
        assert_eq!(result.process_tree_remaining, 0);
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert!(
            harness
                .broker
                .metrics()
                .jobs_terminated
                .load(Ordering::Acquire)
                >= 1
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_descendant_process_cannot_escape() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["attempt-child"]),
        )
        .await;
        assert_completed(&result);
        assert_eq!(parse_stdout(&result)["child_spawned"], false);
        assert_eq!(result.side_effect_count, 1);
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7_panic_before_createprocess_is_zero_process() {
        let _lock = lock_h7_tests();
        let harness = H7DirectHarness::new();
        let result = supervise_native(
            &harness.action(&["echo-argv", "panic-before"]),
            native_options(
                Arc::new(H7SupervisorMetrics::default()),
                H7NativeLaunchFault::PanicBeforeCreateProcess,
            ),
        );
        assert_eq!(result.kind, H7NativeOutcomeKind::Denied);
        assert!(!result.process_created);
        assert!(!result.user_code_started);
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7_panic_after_createprocess_is_truthful_and_contained() {
        let _lock = lock_h7_tests();
        let harness = H7DirectHarness::new();
        let metrics = Arc::new(H7SupervisorMetrics::default());
        let result = supervise_native(
            &harness.action(&["sleep", "2000"]),
            native_options(
                Arc::clone(&metrics),
                H7NativeLaunchFault::PanicAfterCreateProcess,
            ),
        );
        assert_eq!(result.kind, H7NativeOutcomeKind::StartedOutcomeUnknown);
        assert!(result.process_created);
        assert!(!result.user_code_started);
        assert!(!result.job_terminated);
        assert!(result.direct_termination_attempted);
        assert!(result.direct_termination_verified);
        assert!(result.process_exit_verified);
        assert!(result.process_tree_observed);
        assert_eq!(result.process_tree_remaining, 0);
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert_eq!(metrics.process_created.load(Ordering::Acquire), 1);
        assert_eq!(metrics.process_tree_remaining.load(Ordering::Acquire), 0);
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7_assignment_failure_terminates_unassigned_suspended_process() {
        let _lock = lock_h7_tests();
        let harness = H7DirectHarness::new();
        let metrics = Arc::new(H7SupervisorMetrics::default());
        let result = supervise_native(
            &harness.action(&["echo-argv", "assignment-failure"]),
            native_options(
                Arc::clone(&metrics),
                H7NativeLaunchFault::ForceAssignmentFailure,
            ),
        );
        assert_eq!(result.kind, H7NativeOutcomeKind::LaunchFailed);
        assert!(result.process_created);
        assert!(!result.user_code_started);
        assert!(!result.job_terminated);
        assert!(result.direct_termination_attempted);
        assert!(result.direct_termination_verified);
        assert!(result.process_exit_verified);
        assert!(result.process_tree_observed);
        assert_eq!(result.process_tree_remaining, 0);
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert_eq!(metrics.process_created.load(Ordering::Acquire), 1);
        assert_eq!(metrics.job_assigned.load(Ordering::Acquire), 0);
        assert_eq!(metrics.thread_resumed.load(Ordering::Acquire), 0);
        assert_eq!(
            metrics.direct_termination_attempted.load(Ordering::Acquire),
            1
        );
        assert_eq!(
            metrics.direct_termination_verified.load(Ordering::Acquire),
            1
        );
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7_post_create_cleanup_only_marks_verified_after_observed_exit() {
        let _lock = lock_h7_tests();
        let metrics = H7SupervisorMetrics::default();
        let cleanup = super::H7CleanupEvidence::default();
        let phase = AtomicU8::new(H7LaunchPhase::CreatedSuspended as u8);
        assert!(!terminate_process_and_verify_exit(
            std::ptr::null_mut(),
            &phase,
            &metrics,
            &cleanup,
        ));
        assert!(cleanup.direct_termination_attempted.load(Ordering::Acquire));
        assert!(!cleanup.direct_termination_verified.load(Ordering::Acquire));
        assert!(!cleanup.process_exit_verified.load(Ordering::Acquire));
        assert_eq!(
            metrics.direct_termination_verified.load(Ordering::Acquire),
            0
        );

        let harness = H7DirectHarness::new();
        let result = supervise_native(
            &harness.action(&["sleep", "2000"]),
            native_options(
                Arc::new(H7SupervisorMetrics::default()),
                H7NativeLaunchFault::ForceThreadHandleFailure,
            ),
        );
        assert!(result.process_created);
        assert!(result.direct_termination_attempted);
        assert!(result.direct_termination_verified);
        assert!(result.process_exit_verified);
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7_panic_after_createprocess_really_leaves_zero_processes() {
        let _lock = lock_h7_tests();
        let harness = H7DirectHarness::new();
        let result = supervise_native(
            &harness.action(&["sleep", "2000"]),
            native_options(
                Arc::new(H7SupervisorMetrics::default()),
                H7NativeLaunchFault::PanicAfterCreateProcess,
            ),
        );
        assert_eq!(result.kind, H7NativeOutcomeKind::StartedOutcomeUnknown);
        assert!(result.process_created);
        assert!(!result.user_code_started);
        assert!(result.direct_termination_attempted);
        assert!(result.direct_termination_verified);
        assert!(result.process_exit_verified);
        assert!(result.process_tree_observed);
        assert_eq!(result.process_tree_remaining, 0);
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_timeout_job_termination_is_verified() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["sleep", "2000"]),
        )
        .await;
        assert_eq!(result.status, "started_and_timed_out");
        assert!(result.job_terminated);
        assert!(result.process_exit_verified);
        assert!(result.process_tree_observed);
        assert_eq!(result.process_tree_remaining, 0);
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_cancel_job_termination_is_verified() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_cancelled(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["sleep", "2000"]),
        )
        .await;
        assert_eq!(result.status, "started_and_cancelled");
        assert!(result.job_terminated);
        assert!(result.process_exit_verified);
        assert!(result.process_tree_observed);
        assert_eq!(result.process_tree_remaining, 0);
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_output_limit_job_termination_is_verified() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["flood-stdout"]),
        )
        .await;
        assert_eq!(result.status, "started_and_output_limited");
        assert!(result.job_terminated);
        assert!(result.process_exit_verified);
        assert!(result.process_tree_observed);
        assert_eq!(result.process_tree_remaining, 0);
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_process_tree_remaining_is_os_observed_not_constant() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["echo-argv", "tree-observation"]),
        )
        .await;
        assert_eq!(result.status, "started_and_exited");
        assert!(result.process_exit_verified);
        assert!(result.process_tree_observed);
        assert_eq!(result.process_tree_remaining, 0);
        assert!(
            harness
                .broker
                .metrics()
                .process_tree_observations
                .load(Ordering::Acquire)
                >= 1
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_reader_threads_join_boundedly_after_timeout() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["sleep", "2000"]),
        )
        .await;
        assert_eq!(result.status, "started_and_timed_out");
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_reader_threads_join_boundedly_after_cancel() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let metrics = harness.broker.metrics();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_cancelled(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["sleep", "2000"]),
        )
        .await;
        assert_eq!(result.status, "started_and_cancelled");
        assert_eq!(result.pending_stdout_reads, 0);
        assert_eq!(result.pending_stderr_reads, 0);
        assert_eq!(metrics.output_handles_active.load(Ordering::Acquire), 0);
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7_executable_same_length_write_after_preparation_is_blocked() {
        let _lock = lock_h7_tests();
        let harness = H7DirectHarness::new();
        let action = harness.action(&["echo-argv", "immutable-before-launch"]);
        let image_path = harness.catalog.entry.image_path.clone();
        let original = fs::read(&image_path).expect("D29-H7 executable image bytes");
        let overwrite = h7_attempt_same_length_overwrite(&image_path, &original);
        assert!(
            overwrite.is_err(),
            "D29-H7 executable writer unexpectedly opened"
        );
        assert_eq!(fs::read(&image_path).unwrap(), original);
        drop(action);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_executable_same_length_write_after_host_pass_cannot_change_launched_image() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let gate = H7PostHostFenceGate::new();
        gate.arm();
        let broker = harness.broker_with_post_host_gate(Arc::clone(&gate));
        let action = harness.action(&["echo-argv", "immutable-after-host"]);
        let image_path = harness.catalog.entry.image_path.clone();
        let original = fs::read(&image_path).expect("D29-H7 executable image bytes");
        let mut receiver = harness.receiver.take().unwrap();
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.execute(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 post-Host executable mutation confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 post-Host executable mutation confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), gate.wait_until_entered())
            .await
            .expect("D29-H7 final Host fence gate entry");
        assert_eq!(
            harness
                .authority
                .metrics
                .final_revalidations
                .load(Ordering::Acquire),
            1
        );
        let overwrite = h7_attempt_same_length_overwrite(&image_path, &original);
        assert!(
            overwrite.is_err(),
            "D29-H7 post-Host executable writer opened"
        );
        assert_eq!(fs::read(&image_path).unwrap(), original);
        gate.release();
        let result = task.await.unwrap();
        assert_completed(&result);
        assert_eq!(
            parse_stdout(&result)["args"],
            json!(["immutable-after-host"])
        );
        assert!(harness.authority.shutdown());
    }

    fn assert_h7_output_cleanup(result: &H7ToolResult) {
        assert!(result.stdout_reader_joined);
        assert!(result.stderr_reader_joined);
        assert_eq!(result.pending_stdout_reads, 0);
        assert_eq!(result.pending_stderr_reads, 0);
        assert!(result.stdout_retained_bytes <= H7_STDOUT_BOUND);
        assert!(result.stderr_retained_bytes <= H7_STDERR_BOUND);
    }

    fn reap_h7_quarantine_until(target: usize, deadline: Instant) {
        let quarantine = h7_pending_io_quarantine();
        while quarantine.count() > target {
            h7_reap_pending_io_nonblocking();
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
    }

    fn install_h7_pending_output_quarantine(
        stream: &str,
    ) -> (Arc<H7TerminalityGate>, Arc<H7TerminalityProbe>, usize) {
        let quarantine = h7_pending_io_quarantine();
        let before = quarantine.count();
        let gate = Arc::new(H7TerminalityGate::default());
        let probe = Arc::new(H7TerminalityProbe::default());
        let mut capture = H7OverlappedOutputCapture::new(1_024, stream)
            .expect("D29-H7 pending output quarantine capture")
            .with_terminality_test_hooks(Arc::clone(&gate), Arc::clone(&probe));
        capture.arm_read();
        capture.cancel_pending();
        assert!(capture.quarantine_if_pending());
        drop(capture);
        assert_eq!(quarantine.count(), before + 1);
        (gate, probe, before)
    }

    async fn wait_h7_pending_output_reads(metrics: &H7SupervisorMetrics) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while metrics.pending_output_reads.load(Ordering::Acquire) == 0 {
            assert!(
                Instant::now() < deadline,
                "D29-H7 output read did not become pending"
            );
            tokio::task::yield_now().await;
        }
    }

    fn h7_large_fast_exit_bytes(start: u8) -> String {
        String::from_utf8(
            (0..(24 * 1024))
                .map(|index| start + (index % 26) as u8)
                .collect(),
        )
        .expect("D29-H7 large fast-exit bytes are ASCII")
    }

    #[test]
    fn h7_output_capture_uses_overlapped_io() {
        let source = include_str!("d29h7.rs");
        assert!(source.contains("CreateNamedPipeW"));
        assert!(source.contains("FILE_FLAG_OVERLAPPED"));
        assert!(source.contains("GetOverlappedResult"));
        assert!(source.contains("ReadFile("));
        let forbidden_peek = ["Peek", "NamedPipe"].concat();
        let forbidden_reader = ["H7", "BoundedReader"].concat();
        let forbidden_spawn = ["spawn", "_bounded_reader"].concat();
        assert!(!source.contains(&forbidden_peek));
        assert!(!source.contains(&forbidden_reader));
        assert!(!source.contains(&forbidden_spawn));
    }

    #[test]
    fn h7_no_infinite_output_or_connect_waits() {
        let source = include_str!("d29h7.rs");
        let infinite = ["IN", "FINITE"].concat();
        let unbounded = ["wait_for_terminal_", "unbounded"].concat();
        let blocking_result = ["GetOverlappedResult", "(", "...", ", TRUE", ")"].concat();
        assert!(!source.contains(&infinite));
        assert!(!source.contains(&unbounded));
        assert!(!source.contains(&blocking_result));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_output_capture_has_zero_reader_threads() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let metrics = harness.broker.metrics();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["echo-argv", "no-output-reader-thread"]),
        )
        .await;
        assert_h7_output_cleanup(&result);
        assert_eq!(metrics.reader_threads_remaining.load(Ordering::Acquire), 0);
        assert_eq!(metrics.pending_output_reads.load(Ordering::Acquire), 0);
        assert_eq!(metrics.output_handles_active.load(Ordering::Acquire), 0);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_stdout_exact_tail_is_preserved_on_fast_exit() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["fast-exit-both"]).await;
        assert_eq!(result.status, "started_and_exited");
        assert_eq!(result.stdout, "D29-H7 stdout exact tail\n");
        assert_h7_output_cleanup(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_stderr_exact_tail_is_preserved_on_fast_exit() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["fast-exit-both"]).await;
        assert_eq!(result.status, "started_and_exited");
        assert_eq!(result.stderr, "D29-H7 stderr exact tail\n");
        assert_h7_output_cleanup(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_large_fast_exit_stdout_is_exact() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["large-fast-exit-both"]).await;
        assert_eq!(result.status, "started_and_exited");
        assert_eq!(result.stdout, h7_large_fast_exit_bytes(b'A'));
        assert!(!result.timed_out);
        assert!(!result.cancelled);
        assert_h7_output_cleanup(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_large_fast_exit_stderr_is_exact() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["large-fast-exit-both"]).await;
        assert_eq!(result.status, "started_and_exited");
        assert_eq!(result.stderr, h7_large_fast_exit_bytes(b'a'));
        assert!(!result.timed_out);
        assert!(!result.cancelled);
        assert_h7_output_cleanup(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_post_exit_output_events_are_not_starved_by_process_handle() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["large-fast-exit-both"]).await;
        assert_eq!(result.status, "started_and_exited");
        assert_eq!(result.stdout, h7_large_fast_exit_bytes(b'A'));
        assert_eq!(result.stderr, h7_large_fast_exit_bytes(b'a'));
        assert_eq!(result.pending_stdout_reads, 0);
        assert_eq!(result.pending_stderr_reads, 0);
        assert_h7_output_cleanup(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_stdout_overflow_terminates_job_with_pending_reads_zero() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["flood-stdout"]).await;
        assert_eq!(result.status, "started_and_output_limited");
        assert!(result.process_created);
        assert!(result.job_terminated);
        assert_eq!(result.process_tree_remaining, 0);
        assert_h7_output_cleanup(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_stderr_overflow_terminates_job_with_pending_reads_zero() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["flood-stderr"]).await;
        assert_eq!(result.status, "started_and_output_limited");
        assert!(result.process_created);
        assert!(result.job_terminated);
        assert_eq!(result.process_tree_remaining, 0);
        assert_h7_output_cleanup(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_timeout_cancels_all_pending_output_io() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["sleep", "2000"]).await;
        assert_eq!(result.status, "started_and_timed_out");
        assert!(result.process_created);
        assert!(result.job_terminated);
        assert!(result.process_exit_verified);
        assert_eq!(result.process_tree_remaining, 0);
        assert_h7_output_cleanup(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_turn_cancel_cancels_all_pending_output_io() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_cancelled(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["sleep", "2000"]),
        )
        .await;
        assert_eq!(result.status, "started_and_cancelled");
        assert!(result.job_terminated);
        assert_h7_output_cleanup(&result);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_timeout_stdout_pending_read_reaches_terminal() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["sleep", "2000"]).await;
        assert_eq!(result.status, "started_and_timed_out");
        assert_eq!(result.pending_stdout_reads, 0);
        assert_eq!(result.pending_stderr_reads, 0);
        assert_h7_output_cleanup(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_timeout_stderr_pending_read_reaches_terminal() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["sleep", "2000"]).await;
        assert_eq!(result.status, "started_and_timed_out");
        assert_eq!(result.pending_stdout_reads, 0);
        assert_eq!(result.pending_stderr_reads, 0);
        assert_h7_output_cleanup(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_cancel_stdout_pending_read_reaches_terminal() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_cancelled(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["sleep", "2000"]),
        )
        .await;
        assert_eq!(result.status, "started_and_cancelled");
        assert_eq!(result.pending_stdout_reads, 0);
        assert_eq!(result.pending_stderr_reads, 0);
        assert_h7_output_cleanup(&result);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_cancel_stderr_pending_read_reaches_terminal() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_cancelled(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["sleep", "2000"]),
        )
        .await;
        assert_eq!(result.status, "started_and_cancelled");
        assert_eq!(result.pending_stdout_reads, 0);
        assert_eq!(result.pending_stderr_reads, 0);
        assert_h7_output_cleanup(&result);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_outer_abort_pending_reads_reach_terminal() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let broker = Arc::clone(&harness.broker);
        let metrics = broker.metrics();
        let tool = h7_prepared_tool(Arc::clone(&broker));
        let action = harness.action(&["sleep", "2000"]);
        let mut receiver = harness.receiver.take().unwrap();
        let created = metrics.created_notify.notified();
        let task = tokio::spawn({
            let tool = Arc::clone(&tool);
            async move { tool.execute_prepared_action(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 terminality outer-abort confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 terminality outer-abort confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), created)
            .await
            .expect("D29-H7 terminality outer-abort process creation");
        task.abort();
        assert!(task.await.is_err());
        wait_h7_native_workers_quiet(Arc::clone(&metrics)).await;
        assert_eq!(metrics.pending_output_reads.load(Ordering::Acquire), 0);
        assert_eq!(metrics.output_handles_active.load(Ordering::Acquire), 0);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_overflow_pending_reads_reach_terminal() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["flood-stdout"]).await;
        assert_eq!(result.status, "started_and_output_limited");
        assert_eq!(result.pending_stdout_reads, 0);
        assert_eq!(result.pending_stderr_reads, 0);
        assert_h7_output_cleanup(&result);
    }

    #[test]
    fn h7_output_completion_cancel_race_is_terminal_once() {
        let _lock = lock_h7_tests();
        let mut capture =
            H7OverlappedOutputCapture::new(1_024, "completion-race").expect("H7 output capture");
        capture.arm_read();
        capture.cancel_pending();
        assert!(capture.drain_until_terminal(Instant::now() + H7_CLEANUP_TIMEOUT));
        assert!(!capture.pending());
        assert!(capture.complete_pending());
        assert!(capture.complete_pending());
    }

    #[test]
    fn h7_cancelled_output_state_is_not_freed_before_terminal_completion() {
        let _lock = lock_h7_tests();
        let gate = Arc::new(H7TerminalityGate::default());
        let probe = Arc::new(H7TerminalityProbe::default());
        let mut capture = H7OverlappedOutputCapture::new(1_024, "delayed-cancel")
            .expect("H7 delayed-cancel output capture")
            .with_terminality_test_hooks(Arc::clone(&gate), Arc::clone(&probe));
        capture.arm_read();
        assert!(capture.pending());
        capture.cancel_pending();
        assert!(gate.cancel_requested.load(Ordering::Acquire));
        let quarantine = h7_pending_io_quarantine();
        let before = quarantine.count();
        let drop_task = thread::spawn(move || drop(capture));
        let started_deadline = Instant::now() + Duration::from_secs(1);
        while !probe.drop_started.load(Ordering::Acquire) {
            assert!(Instant::now() < started_deadline);
            thread::yield_now();
        }
        assert!(!probe.drop_finished.load(Ordering::Acquire));
        assert!(!probe.terminal_observed.load(Ordering::Acquire));
        let quarantine_deadline = Instant::now() + Duration::from_secs(1);
        while quarantine.count() <= before {
            assert!(Instant::now() < quarantine_deadline);
            thread::yield_now();
        }
        gate.allow_terminal.store(true, Ordering::Release);
        drop_task.join().expect("D29-H7 delayed-cancel drop");
        let reap_deadline = Instant::now() + Duration::from_secs(1);
        while quarantine.count() > before {
            h7_reap_pending_io_nonblocking();
            assert!(Instant::now() < reap_deadline);
            thread::yield_now();
        }
        assert!(probe.terminal_observed.load(Ordering::Acquire));
        assert!(probe.drop_finished.load(Ordering::Acquire));
        assert_eq!(quarantine.count(), before);
    }

    #[test]
    fn h7_pending_output_after_cleanup_deadline_is_quarantined_not_dropped() {
        let _lock = lock_h7_tests();
        let quarantine = h7_pending_io_quarantine();
        let before = quarantine.count();
        let gate = Arc::new(H7TerminalityGate::default());
        let probe = Arc::new(H7TerminalityProbe::default());
        let mut capture = H7OverlappedOutputCapture::new(1_024, "quarantine-output")
            .expect("D29-H7 quarantine output capture")
            .with_terminality_test_hooks_and_cleanup_timeout(
                Arc::clone(&gate),
                Duration::from_millis(25),
            )
            .with_terminality_test_hooks(Arc::clone(&gate), Arc::clone(&probe));
        capture.arm_read();
        capture.cancel_pending();
        assert!(!capture.drain_until_terminal(Instant::now()));
        assert!(capture.quarantine_if_pending());
        drop(capture);
        assert_eq!(quarantine.count(), before + 1);
        assert!(!probe.terminal_observed.load(Ordering::Acquire));
        assert!(!probe.drop_finished.load(Ordering::Acquire));
        gate.allow_terminal.store(true, Ordering::Release);
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert!(probe.terminal_observed.load(Ordering::Acquire));
        assert!(probe.drop_finished.load(Ordering::Acquire));
    }

    #[test]
    fn h7_quarantine_reap_releases_only_after_terminal_completion() {
        let _lock = lock_h7_tests();
        let quarantine = h7_pending_io_quarantine();
        let before = quarantine.count();
        let gate = Arc::new(H7TerminalityGate::default());
        let probe = Arc::new(H7TerminalityProbe::default());
        let mut capture = H7OverlappedOutputCapture::new(1_024, "quarantine-reap")
            .expect("D29-H7 quarantine reap capture")
            .with_terminality_test_hooks(Arc::clone(&gate), Arc::clone(&probe));
        capture.arm_read();
        capture.cancel_pending();
        assert!(capture.quarantine_if_pending());
        drop(capture);
        assert_eq!(h7_reap_pending_io_nonblocking(), before + 1);
        assert_eq!(quarantine.count(), before + 1);
        assert!(!probe.drop_finished.load(Ordering::Acquire));
        gate.allow_terminal.store(true, Ordering::Release);
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert!(probe.terminal_observed.load(Ordering::Acquire));
        assert!(probe.drop_finished.load(Ordering::Acquire));
    }

    #[test]
    fn h7_pending_connect_after_deadline_is_quarantined_not_dropped() {
        let _lock = lock_h7_tests();
        let quarantine = h7_pending_io_quarantine();
        let before = quarantine.count();
        let gate = Arc::new(H7TerminalityGate::default());
        let probe = Arc::new(H7ConnectTerminalityProbe::default());
        let result = H7OverlappedOutputCapture::new_for_connect_quarantine_test(
            1_024,
            "connect-quarantine",
            Arc::clone(&gate),
            Arc::clone(&probe),
        );
        assert!(result.is_err());
        assert!(gate.cancel_requested.load(Ordering::Acquire));
        assert_eq!(quarantine.count(), before + 1);
        assert!(!probe.terminal_observed.load(Ordering::Acquire));
        assert!(!probe.dropped.load(Ordering::Acquire));
        gate.allow_terminal.store(true, Ordering::Release);
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert!(probe.terminal_observed.load(Ordering::Acquire));
        assert!(probe.dropped.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_native_worker_exits_boundedly_when_output_terminality_is_held() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let gate = Arc::new(H7TerminalityGate::default());
        let broker = harness
            .broker_with_output_terminality_gate(Arc::clone(&gate), Duration::from_millis(50));
        let metrics = broker.metrics();
        let quarantine = h7_pending_io_quarantine();
        let before = quarantine.count();
        let mut receiver = harness.receiver.take().unwrap();
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            let action = harness.action(&["sleep", "2000"]);
            async move { broker.execute(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 bounded terminality confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 bounded terminality confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), metrics.created_notify.notified())
            .await
            .expect("D29-H7 bounded terminality process creation");
        wait_h7_pending_output_reads(&metrics).await;
        let worker_deadline = Instant::now() + Duration::from_secs(2);
        broker.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("D29-H7 native worker bounded exit")
            .expect("D29-H7 native worker join");
        assert_eq!(result.status, "started_outcome_unknown");
        assert!(result.process_created);
        assert_eq!(result.pending_stdout_reads, 0);
        assert_eq!(result.pending_stderr_reads, 0);
        assert_eq!(metrics.pending_output_reads.load(Ordering::Acquire), 0);
        assert_eq!(metrics.output_handles_active.load(Ordering::Acquire), 0);
        assert_eq!(metrics.native_workers_active.load(Ordering::Acquire), 0);
        assert!(Instant::now() < worker_deadline);
        assert!(gate.cancel_requested.load(Ordering::Acquire));
        assert!(quarantine.count() > before);
        assert!(quarantine.count() <= before + H7_MAX_QUARANTINED_OUTPUT);
        gate.allow_terminal.store(true, Ordering::Release);
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert_eq!(quarantine.count(), before);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_quarantine_blocks_new_action_before_confirmation() {
        let _lock = lock_h7_tests();
        let (gate, probe, before) =
            install_h7_pending_output_quarantine("blocks-before-confirmation");
        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = harness
            .broker
            .execute(harness.action(&["echo-argv", "blocked-by-quarantine"]))
            .await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
        assert_eq!(
            harness
                .authority
                .metrics
                .trusted_confirmations
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            harness
                .authority
                .metrics
                .grants_issued
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), receiver.recv())
                .await
                .is_err()
        );
        gate.allow_terminal.store(true, Ordering::Release);
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert!(probe.terminal_observed.load(Ordering::Acquire));
        assert!(probe.drop_finished.load(Ordering::Acquire));
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_after_quarantine_reap_fresh_action_can_run() {
        let _lock = lock_h7_tests();
        let (gate, probe, before) = install_h7_pending_output_quarantine("reap-then-run");
        gate.allow_terminal.store(true, Ordering::Release);
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert!(probe.terminal_observed.load(Ordering::Acquire));
        assert!(probe.drop_finished.load(Ordering::Acquire));

        let mut harness = H7DirectHarness::new();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["echo-argv", "after-quarantine-reap"]),
        )
        .await;
        assert_completed(&result);
        assert_eq!(
            harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(h7_pending_io_quarantine().count(), before);
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7_getoverlappedresult_io_incomplete_remains_pending() {
        let _lock = lock_h7_tests();
        let before = h7_pending_io_quarantine().count();
        let mut capture =
            H7OverlappedOutputCapture::new(1_024, "io-incomplete-pending").expect("H7 output");
        capture.arm_read();
        let poll = {
            let owner = capture.owner();
            poll_h7_overlapped(owner.read.raw(), &owner.operation.overlapped, true)
        };
        assert_eq!(poll, H7OverlappedPoll::Pending);
        assert!(capture.pending());
        cleanup_h7_test_output_capture(capture, before);
    }

    #[test]
    fn h7_connect_io_incomplete_is_not_terminal() {
        let _lock = lock_h7_tests();
        let before = h7_pending_io_quarantine().count();
        let mut connect = h7_pending_connect_for_test("connect-io-incomplete");
        let poll = poll_h7_overlapped(
            connect.owner().read.raw(),
            connect.owner().operation.as_ref(),
            false,
        );
        assert_eq!(poll, H7OverlappedPoll::Pending);
        assert!(!connect.observe_terminal());
        assert!(connect.pending());
        cleanup_h7_test_connect(connect, before);
    }

    #[test]
    fn h7_output_io_incomplete_is_not_terminal() {
        let _lock = lock_h7_tests();
        let before = h7_pending_io_quarantine().count();
        let mut capture =
            H7OverlappedOutputCapture::new(1_024, "output-io-incomplete").expect("H7 output");
        capture.arm_read();
        assert!(capture.pending());
        assert!(!capture.complete_pending());
        assert!(capture.pending());
        cleanup_h7_test_output_capture(capture, before);
    }

    #[test]
    fn h7_quarantine_reap_io_incomplete_retains_owner() {
        let _lock = lock_h7_tests();
        for stream in ["stdout-io-incomplete", "stderr-io-incomplete"] {
            let quarantine = h7_pending_io_quarantine();
            let before = quarantine.count();
            let gate = Arc::new(H7TerminalityGate::default());
            let probe = Arc::new(H7TerminalityProbe::default());
            let mut capture = H7OverlappedOutputCapture::new(1_024, stream)
                .expect("D29-H7 incomplete quarantine output")
                .with_terminality_test_hooks(Arc::clone(&gate), Arc::clone(&probe));
            capture.arm_read();
            let poll = {
                let owner = capture.owner();
                poll_h7_overlapped(owner.read.raw(), &owner.operation.overlapped, true)
            };
            assert_eq!(poll, H7OverlappedPoll::Pending);
            capture.cancel_pending();
            assert!(capture.quarantine_if_pending());
            drop(capture);
            assert_eq!(quarantine.count(), before + 1);
            h7_reap_pending_io_nonblocking();
            assert_eq!(quarantine.count(), before + 1);
            assert!(!probe.drop_finished.load(Ordering::Acquire));
            gate.allow_terminal.store(true, Ordering::Release);
            reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
            assert!(probe.terminal_observed.load(Ordering::Acquire));
            assert!(probe.drop_finished.load(Ordering::Acquire));
        }
    }

    #[test]
    fn h7_quarantine_reap_terminal_cancel_releases_owner() {
        let _lock = lock_h7_tests();
        let quarantine = h7_pending_io_quarantine();
        let before = quarantine.count();
        let gate = Arc::new(H7TerminalityGate::default());
        let probe = Arc::new(H7TerminalityProbe::default());
        let mut capture = H7OverlappedOutputCapture::new(1_024, "terminal-cancel-release")
            .expect("D29-H7 terminal cancellation output")
            .with_terminality_test_hooks(Arc::clone(&gate), Arc::clone(&probe));
        capture.arm_read();
        capture.cancel_pending();
        assert!(capture.quarantine_if_pending());
        drop(capture);
        assert_eq!(quarantine.count(), before + 1);
        gate.allow_terminal.store(true, Ordering::Release);
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert!(probe.terminal_observed.load(Ordering::Acquire));
        assert!(probe.drop_finished.load(Ordering::Acquire));
    }

    #[test]
    fn h7_unknown_completion_status_does_not_free_pending_owner() {
        let _lock = lock_h7_tests();
        let probe = Arc::new(H7TerminalityProbe::default());
        let event =
            H7Handle::new(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })
                .expect("D29-H7 unknown completion event");
        let event_raw = event.raw();
        let mut owner = H7OutputIoOwner {
            read: H7Handle(INVALID_HANDLE_VALUE),
            child_write: H7Handle(std::ptr::null_mut()),
            event,
            operation: Box::new(H7OutputReadOperation {
                overlapped: OVERLAPPED {
                    hEvent: event_raw,
                    ..Default::default()
                },
                scratch: [0_u8; H7_OUTPUT_SCRATCH_BYTES],
                state: H7OverlappedState::Pending,
            }),
            terminality_gate: None,
            terminality_probe: Some(Arc::clone(&probe)),
        };
        assert!(!owner.observe_terminal_poll(classify_h7_overlapped_error(0xdead_beef, true,)));
        assert!(owner.pending());
        assert!(!probe.terminal_observed.load(Ordering::Acquire));
        assert!(!probe.drop_finished.load(Ordering::Acquire));
        assert_eq!(
            classify_h7_overlapped_error(0xdead_beef, true),
            H7OverlappedPoll::Indeterminate(0xdead_beef)
        );
        owner.operation.state = H7OverlappedState::TerminalCancelled;
        owner.mark_released();
        assert!(probe.drop_finished.load(Ordering::Acquire));
    }

    #[test]
    fn h7_process_admission_is_shared_across_brokers() {
        let _lock = lock_h7_tests();
        let broker_a_harness = H7DirectHarness::new();
        let broker_b_harness = H7DirectHarness::new();
        assert!(Arc::ptr_eq(
            &broker_a_harness.broker.admission,
            &broker_b_harness.broker.admission
        ));
        assert!(broker_a_harness.authority.shutdown());
        assert!(broker_b_harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_cross_broker_second_action_confirmation_zero() {
        let _lock = lock_h7_tests();
        assert_h7_cross_broker_second_action_is_denied().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_cross_broker_second_action_createprocess_zero() {
        let _lock = lock_h7_tests();
        assert_h7_cross_broker_second_action_is_denied().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_cross_broker_quarantine_blocks_new_action() {
        let _lock = lock_h7_tests();
        assert_h7_cross_broker_quarantine_is_safe().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_cross_broker_quarantine_never_overflows() {
        let _lock = lock_h7_tests();
        assert_h7_cross_broker_quarantine_is_safe().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_outer_abort_keeps_global_admission_until_worker_exit() {
        let _lock = lock_h7_tests();
        let mut broker_a_harness = H7DirectHarness::new();
        let mut broker_b_harness = H7DirectHarness::new();
        let gate = Arc::new(H7TerminalityGate::default());
        let broker_a = broker_a_harness
            .broker_with_output_terminality_gate(Arc::clone(&gate), Duration::from_millis(250));
        let metrics = broker_a.metrics();
        let tool = h7_prepared_tool(Arc::clone(&broker_a));
        let quarantine = h7_pending_io_quarantine();
        let before = quarantine.count();
        let mut receiver_a = broker_a_harness.receiver.take().unwrap();
        let mut receiver_b = broker_b_harness.receiver.take().unwrap();
        let task = tokio::spawn({
            let tool = Arc::clone(&tool);
            let action = broker_a_harness.action(&["sleep", "2000"]);
            async move { tool.execute_prepared_action(action).await }
        });
        let pending = receiver_a
            .recv()
            .await
            .expect("D29-H7 global outer-abort confirmation");
        let revision = broker_a_harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 global outer-abort confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), metrics.created_notify.notified())
            .await
            .expect("D29-H7 global outer-abort process creation");
        wait_h7_pending_output_reads(&metrics).await;
        task.abort();
        assert!(task.await.is_err());
        let worker_deadline = Instant::now() + Duration::from_secs(1);
        while metrics.native_workers_active.load(Ordering::Acquire) == 0 {
            assert!(Instant::now() < worker_deadline);
            tokio::task::yield_now().await;
        }
        assert!(broker_a.admission.active.load(Ordering::Acquire));
        assert!(Arc::ptr_eq(
            &broker_a.admission,
            &broker_b_harness.broker.admission
        ));

        let second = broker_b_harness
            .broker
            .execute(broker_b_harness.action(&["echo-argv", "global-outer-abort-second"]))
            .await;
        assert_eq!(second.status, "denied");
        assert_h7_zero_process_result(&second);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), receiver_b.recv())
                .await
                .is_err()
        );
        assert_eq!(
            broker_b_harness
                .broker
                .metrics()
                .process_created
                .load(Ordering::Acquire),
            0
        );

        gate.allow_terminal.store(true, Ordering::Release);
        wait_h7_native_workers_quiet(Arc::clone(&metrics)).await;
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert!(!broker_a.admission.active.load(Ordering::Acquire));
        assert_eq!(quarantine.count(), before);
        assert!(broker_a_harness.authority.shutdown());
        assert!(broker_b_harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_single_active_admission_rejects_concurrent_second_action() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let gate = H7FinalFenceGate::new();
        gate.arm();
        let broker = harness.broker_with_final_fence(Arc::clone(&gate));
        let mut receiver = harness.receiver.take().unwrap();
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            let action = harness.action(&["echo-argv", "first-active-action"]);
            async move { broker.execute(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 single-active first confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 single-active first confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), gate.wait_until_entered())
            .await
            .expect("D29-H7 single-active final fence entry");
        let confirmations_before = harness
            .authority
            .metrics
            .trusted_confirmations
            .load(Ordering::Acquire);
        let grants_before = harness
            .authority
            .metrics
            .grants_issued
            .load(Ordering::Acquire);
        let second = broker
            .execute(harness.action(&["echo-argv", "second-active-action"]))
            .await;
        assert_eq!(second.status, "denied");
        assert_h7_zero_process_result(&second);
        assert_eq!(
            harness
                .authority
                .metrics
                .trusted_confirmations
                .load(Ordering::Acquire),
            confirmations_before
        );
        assert_eq!(
            harness
                .authority
                .metrics
                .grants_issued
                .load(Ordering::Acquire),
            grants_before
        );
        assert_eq!(broker.metrics().process_created.load(Ordering::Acquire), 0);
        gate.release();
        let first = task.await.unwrap();
        assert_completed(&first);
        assert_eq!(broker.metrics().process_created.load(Ordering::Acquire), 1);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_outer_abort_keeps_admission_until_worker_exit() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let gate = Arc::new(H7TerminalityGate::default());
        let broker = harness
            .broker_with_output_terminality_gate(Arc::clone(&gate), Duration::from_millis(250));
        let metrics = broker.metrics();
        let tool = h7_prepared_tool(Arc::clone(&broker));
        let quarantine = h7_pending_io_quarantine();
        let before = quarantine.count();
        let mut receiver = harness.receiver.take().unwrap();
        let task = tokio::spawn({
            let tool = Arc::clone(&tool);
            let action = harness.action(&["sleep", "2000"]);
            async move { tool.execute_prepared_action(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 outer-abort admission confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 outer-abort admission confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), metrics.created_notify.notified())
            .await
            .expect("D29-H7 outer-abort admission process creation");
        wait_h7_pending_output_reads(&metrics).await;
        task.abort();
        assert!(task.await.is_err());
        let worker_deadline = Instant::now() + Duration::from_secs(1);
        while metrics.native_workers_active.load(Ordering::Acquire) == 0 {
            assert!(Instant::now() < worker_deadline);
            tokio::task::yield_now().await;
        }
        assert!(broker.admission.active.load(Ordering::Acquire));
        let confirmations_before = harness
            .authority
            .metrics
            .trusted_confirmations
            .load(Ordering::Acquire);
        let second = broker
            .execute(harness.action(&["echo-argv", "outer-abort-second-action"]))
            .await;
        assert_eq!(second.status, "denied");
        assert_h7_zero_process_result(&second);
        assert_eq!(
            harness
                .authority
                .metrics
                .trusted_confirmations
                .load(Ordering::Acquire),
            confirmations_before
        );
        assert_eq!(metrics.process_created.load(Ordering::Acquire), 1);
        gate.allow_terminal.store(true, Ordering::Release);
        wait_h7_native_workers_quiet(Arc::clone(&metrics)).await;
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert!(!broker.admission.active.load(Ordering::Acquire));
        let third = run_approved(
            Arc::clone(&broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["echo-argv", "outer-abort-reusable-action"]),
        )
        .await;
        assert_completed(&third);
        assert_eq!(metrics.process_created.load(Ordering::Acquire), 2);
        assert_eq!(h7_pending_io_quarantine().count(), before);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_quarantined_io_blocks_action_even_after_admission_released() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let gate = Arc::new(H7TerminalityGate::default());
        let broker = harness
            .broker_with_output_terminality_gate(Arc::clone(&gate), Duration::from_millis(50));
        let metrics = broker.metrics();
        let quarantine = h7_pending_io_quarantine();
        let before = quarantine.count();
        let mut receiver = harness.receiver.take().unwrap();
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            let action = harness.action(&["sleep", "2000"]);
            async move { broker.execute(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 quarantined-I/O confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 quarantined-I/O confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), metrics.created_notify.notified())
            .await
            .expect("D29-H7 quarantined-I/O process creation");
        wait_h7_pending_output_reads(&metrics).await;
        broker.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("D29-H7 quarantined-I/O worker exit")
            .expect("D29-H7 quarantined-I/O worker join");
        assert_eq!(result.status, "started_outcome_unknown");
        assert!(!broker.admission.active.load(Ordering::Acquire));
        assert!(quarantine.count() > before);
        let confirmations_before = harness
            .authority
            .metrics
            .trusted_confirmations
            .load(Ordering::Acquire);
        let second = broker
            .execute(harness.action(&["echo-argv", "quarantine-poisoned-action"]))
            .await;
        assert_eq!(second.status, "denied");
        assert_h7_zero_process_result(&second);
        assert_eq!(
            harness
                .authority
                .metrics
                .trusted_confirmations
                .load(Ordering::Acquire),
            confirmations_before
        );
        assert_eq!(metrics.process_created.load(Ordering::Acquire), 1);
        gate.allow_terminal.store(true, Ordering::Release);
        reap_h7_quarantine_until(before, Instant::now() + Duration::from_secs(1));
        assert_eq!(quarantine.count(), before);
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7_connect_overlapped_is_terminal_before_constructor_error_returns() {
        let _lock = lock_h7_tests();
        let probe = Arc::new(H7ConnectTerminalityProbe::default());
        let result = H7OverlappedOutputCapture::new_for_connect_terminality_test(
            1_024,
            "connect-terminality",
            Arc::clone(&probe),
        );
        assert!(result.is_err());
        assert!(probe.terminal_observed.load(Ordering::Acquire));
        assert!(probe.dropped.load(Ordering::Acquire));
    }

    #[test]
    fn h7_named_pipe_connect_cancel_reaches_terminal_before_state_drop() {
        let _lock = lock_h7_tests();
        let probe = Arc::new(H7ConnectTerminalityProbe::default());
        let result = H7OverlappedOutputCapture::new_for_connect_terminality_test(
            1_024,
            "connect-cancel-terminality",
            Arc::clone(&probe),
        );
        assert!(result.is_err());
        assert!(probe.terminal_observed.load(Ordering::Acquire));
        assert!(probe.dropped.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_output_overflow_exit_race_is_output_limited() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["flood-stdout"]).await;
        assert_eq!(result.status, "started_and_output_limited");
        assert!(result.stdout_retained_bytes <= H7_STDOUT_BOUND);
        assert_h7_output_cleanup(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_output_handle_evidence_is_truthful() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let metrics = harness.broker.metrics();
        let mut receiver = harness.receiver.take().unwrap();
        let result = run_approved(
            Arc::clone(&harness.broker),
            Arc::clone(&harness.authority),
            &mut receiver,
            harness.action(&["echo-argv", "handle-evidence"]),
        )
        .await;
        assert_h7_output_cleanup(&result);
        assert_eq!(metrics.output_handles_active.load(Ordering::Acquire), 0);
        assert_eq!(metrics.pending_output_reads.load(Ordering::Acquire), 0);
        assert!(harness.authority.shutdown());
    }

    #[test]
    fn h7_output_capture_handles_are_not_inherited() {
        let _lock = lock_h7_tests();
        let capture =
            H7OverlappedOutputCapture::new(1_024, "inheritance").expect("H7 output capture");
        let mut read_flags = 0_u32;
        let mut event_flags = 0_u32;
        let mut child_flags = 0_u32;
        assert_ne!(
            unsafe { GetHandleInformation(capture.owner().read.raw(), &mut read_flags) },
            0
        );
        assert_ne!(
            unsafe { GetHandleInformation(capture.owner().event.raw(), &mut event_flags) },
            0
        );
        assert_ne!(
            unsafe { GetHandleInformation(capture.child_handle(), &mut child_flags) },
            0
        );
        assert_eq!(read_flags & HANDLE_FLAG_INHERIT, 0);
        assert_eq!(event_flags & HANDLE_FLAG_INHERIT, 0);
        assert_ne!(child_flags & HANDLE_FLAG_INHERIT, 0);
    }

    #[test]
    fn h7_reader_cleanup_never_uses_thread_termination() {
        let source = include_str!("d29h7.rs");
        let forbidden = ["Terminate", "Thread"].concat();
        assert!(!source.contains(&forbidden));
    }

    #[test]
    fn h7_executable_intermediate_reparse_retarget_cannot_launch() {
        let _lock = lock_h7_tests();
        let root = tempdir().expect("D29-H7 namespace root");
        let nested = root.path().join("nested");
        fs::create_dir(&nested).expect("D29-H7 nested directory");
        let image = nested.join("fixture.exe");
        File::create(&image)
            .expect("D29-H7 namespace fixture")
            .write_all(b"MZ-D29-H7")
            .expect("D29-H7 namespace fixture write");
        let namespace =
            PreparedExecutableNamespace::prepare(&image).expect("D29-H7 executable namespace");
        let replacement = root.path().join("nested-replacement");
        assert!(
            fs::rename(&nested, &replacement).is_err(),
            "D29-H7 retained namespace handles must block intermediate retarget"
        );
        assert!(namespace.rebind_leaf().is_ok());

        let target = root.path().join("reparse-target");
        fs::create_dir(&target).expect("D29-H7 reparse target");
        let target_image = target.join("fixture.exe");
        File::create(&target_image)
            .expect("D29-H7 reparse fixture")
            .write_all(b"MZ-D29-H7")
            .expect("D29-H7 reparse fixture write");
        let link = root.path().join("reparse-link");
        if std::os::windows::fs::symlink_dir(&target, &link).is_ok() {
            assert!(
                PreparedExecutableNamespace::prepare(&link.join("fixture.exe")).is_err(),
                "D29-H7 intermediate reparse must be rejected"
            );
        }
    }

    #[test]
    fn h7_cwd_retarget_cannot_launch() {
        let _lock = lock_h7_tests();
        let root = tempdir().expect("D29-H7 cwd root");
        let cwd = root.path().join("cwd");
        fs::create_dir(&cwd).expect("D29-H7 cwd directory");
        let prepared = PreparedWorkingDirectory::prepare(&cwd).expect("D29-H7 cwd namespace");
        let replacement = root.path().join("cwd-replacement");
        assert!(
            fs::rename(&cwd, &replacement).is_err(),
            "D29-H7 retained cwd handle must block retarget"
        );
        assert_eq!(
            namespace_identity(prepared.rebind_leaf().unwrap().raw()).unwrap(),
            prepared.identity()
        );
    }

    #[test]
    fn h7_cwd_binding_uses_real_directory_identity() {
        let _lock = lock_h7_tests();
        let root = tempdir().expect("D29-H7 cwd identity root");
        let prepared =
            PreparedWorkingDirectory::prepare(root.path()).expect("D29-H7 cwd identity namespace");
        let identity = prepared.identity();
        assert!(identity.directory);
        assert!(!identity.reparse);
        assert_ne!(
            identity.wire(),
            sha256_hex(root.path().to_string_lossy().as_bytes())
        );
        let rebound = prepared.rebind_leaf().expect("D29-H7 cwd identity rebind");
        assert_eq!(namespace_identity(rebound.raw()).unwrap(), identity);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_cancel_after_host_pass_before_createprocess_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let gate = H7PostHostFenceGate::new();
        gate.arm();
        let broker = harness.broker_with_post_host_gate(Arc::clone(&gate));
        let action = harness.action(&["echo-argv", "post-host-cancel"]);
        let mut receiver = harness.receiver.take().unwrap();
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            async move { broker.execute(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 post-Host cancellation confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 post-Host cancellation confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), gate.wait_until_entered())
            .await
            .expect("D29-H7 post-Host gate entry");
        broker.cancel();
        gate.release();
        let result = task.await.unwrap();
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
        assert_eq!(broker.metrics().process_created.load(Ordering::Acquire), 0);
        assert_eq!(
            harness
                .authority
                .metrics
                .final_revalidations
                .load(Ordering::Acquire),
            1
        );
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_outer_future_abort_after_host_pass_before_createprocess_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let gate = H7PostHostFenceGate::new();
        gate.arm();
        let broker = harness.broker_with_post_host_gate(Arc::clone(&gate));
        let metrics = broker.metrics();
        let tool = h7_prepared_tool(Arc::clone(&broker));
        let action = harness.action(&["echo-argv", "outer-abort-before-create"]);
        let mut receiver = harness.receiver.take().unwrap();
        let task = tokio::spawn({
            let tool = Arc::clone(&tool);
            async move { tool.execute_prepared_action(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 outer-abort pre-create confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 outer-abort pre-create confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), gate.wait_until_entered())
            .await
            .expect("D29-H7 outer-abort pre-create gate entry");
        assert_eq!(
            harness
                .authority
                .metrics
                .final_revalidations
                .load(Ordering::Acquire),
            1
        );
        task.abort();
        assert!(task.await.is_err());
        gate.release();
        wait_h7_native_workers_quiet(Arc::clone(&metrics)).await;
        assert_eq!(metrics.process_created.load(Ordering::Acquire), 0);
        assert_eq!(metrics.automatic_retries.load(Ordering::Acquire), 0);
        assert_eq!(metrics.reader_threads_remaining.load(Ordering::Acquire), 0);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_outer_future_abort_after_createprocess_terminates_job() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let broker = Arc::clone(&harness.broker);
        let metrics = broker.metrics();
        let tool = h7_prepared_tool(Arc::clone(&broker));
        let action = harness.action(&["sleep", "2000"]);
        let mut receiver = harness.receiver.take().unwrap();
        let created = metrics.created_notify.notified();
        let task = tokio::spawn({
            let tool = Arc::clone(&tool);
            async move { tool.execute_prepared_action(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 outer-abort post-create confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 outer-abort post-create confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), created)
            .await
            .expect("D29-H7 outer-abort process creation");
        let deadline = Instant::now() + Duration::from_secs(2);
        while metrics.job_assigned.load(Ordering::Acquire) == 0
            || metrics.thread_resumed.load(Ordering::Acquire) == 0
        {
            assert!(
                Instant::now() < deadline,
                "D29-H7 outer-abort launch did not resume"
            );
            tokio::task::yield_now().await;
        }
        task.abort();
        assert!(task.await.is_err());
        wait_h7_native_workers_quiet(Arc::clone(&metrics)).await;
        assert_eq!(metrics.process_created.load(Ordering::Acquire), 1);
        assert_eq!(metrics.job_assigned.load(Ordering::Acquire), 1);
        assert_eq!(metrics.thread_resumed.load(Ordering::Acquire), 1);
        assert_eq!(metrics.jobs_terminated.load(Ordering::Acquire), 1);
        assert_eq!(metrics.process_exit_verified.load(Ordering::Acquire), 1);
        assert_eq!(metrics.process_tree_remaining.load(Ordering::Acquire), 0);
        assert_eq!(metrics.reader_threads_remaining.load(Ordering::Acquire), 0);
        assert_eq!(metrics.pending_output_reads.load(Ordering::Acquire), 0);
        assert_eq!(metrics.output_handles_active.load(Ordering::Acquire), 0);
        assert_eq!(metrics.automatic_retries.load(Ordering::Acquire), 0);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_outer_future_abort_cancels_all_pending_output_io() {
        let _lock = lock_h7_tests();
        let mut harness = H7DirectHarness::new();
        let broker = Arc::clone(&harness.broker);
        let metrics = broker.metrics();
        let tool = h7_prepared_tool(Arc::clone(&broker));
        let action = harness.action(&["sleep", "2000"]);
        let mut receiver = harness.receiver.take().unwrap();
        let created = metrics.created_notify.notified();
        let task = tokio::spawn({
            let tool = Arc::clone(&tool);
            async move { tool.execute_prepared_action(action).await }
        });
        let pending = receiver
            .recv()
            .await
            .expect("D29-H7 output-cancel confirmation");
        let revision = harness
            .authority
            .provision_confirmation(&pending.action)
            .expect("D29-H7 output-cancel confirmation");
        pending.response.send(revision).unwrap();
        tokio::time::timeout(Duration::from_secs(2), created)
            .await
            .expect("D29-H7 output-cancel process creation");
        task.abort();
        assert!(task.await.is_err());
        wait_h7_native_workers_quiet(Arc::clone(&metrics)).await;
        assert_eq!(metrics.process_created.load(Ordering::Acquire), 1);
        assert_eq!(metrics.jobs_terminated.load(Ordering::Acquire), 1);
        assert_eq!(metrics.process_exit_verified.load(Ordering::Acquire), 1);
        assert_eq!(metrics.process_tree_remaining.load(Ordering::Acquire), 0);
        assert_eq!(metrics.pending_output_reads.load(Ordering::Acquire), 0);
        assert_eq!(metrics.output_handles_active.load(Ordering::Acquire), 0);
        assert_eq!(metrics.reader_threads_remaining.load(Ordering::Acquire), 0);
        assert_eq!(metrics.automatic_retries.load(Ordering::Acquire), 0);
        assert!(harness.authority.shutdown());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_post_host_argv_binding_mismatch_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_post_host_mutation(H7PostHostMutation::ArgvHash).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_post_host_executable_binding_mismatch_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_post_host_mutation(H7PostHostMutation::ExecutableIdentity).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_post_host_cwd_binding_mismatch_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_post_host_mutation(H7PostHostMutation::CwdIdentity).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_post_host_environment_binding_mismatch_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_post_host_mutation(H7PostHostMutation::EnvironmentHash).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_final_host_wrong_binding_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_final_host_fault(H7HostResponseFault::FinalWrongBinding).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_final_host_wrong_revision_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_final_host_fault(H7HostResponseFault::FinalWrongRevision).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_final_host_wrong_confirmation_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_final_host_fault(H7HostResponseFault::FinalWrongConfirmation).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_final_host_single_use_false_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_final_host_fault(H7HostResponseFault::FinalSingleUseFalse).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_final_host_used_false_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_final_host_fault(H7HostResponseFault::FinalUsedFalse).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_final_host_contradictory_response_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_final_host_fault(H7HostResponseFault::FinalContradictory).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_final_host_extra_confirmation_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_final_host_fault(H7HostResponseFault::FinalExtraConfirmation).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_final_host_malformed_response_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_final_host_fault(H7HostResponseFault::FinalMalformed).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h7_final_host_truncated_response_creates_zero_processes() {
        let _lock = lock_h7_tests();
        let result = run_with_final_host_fault(H7HostResponseFault::FinalTruncated).await;
        assert_eq!(result.status, "denied");
        assert_h7_zero_process_result(&result);
    }

    #[derive(Clone, Debug, Default)]
    struct H7FixtureObservation {
        request_count: usize,
        first_request_schema_exact: bool,
        initial_turn_id: Option<String>,
        function_call_output: Option<Value>,
        output_has_authority_facts: bool,
        error: Option<String>,
    }

    #[derive(Default)]
    struct H7GateState {
        initial_turn_id: Option<String>,
        released: bool,
        error: Option<String>,
    }

    struct H7Gate {
        state: Mutex<H7GateState>,
        changed: Condvar,
    }

    impl H7Gate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(H7GateState::default()),
                changed: Condvar::new(),
            })
        }

        fn capture_turn_id(&self, body: &[u8]) -> Result<(), String> {
            let turn_id = extract_h7_turn_id(body)
                .ok_or_else(|| "D29-H7 Responses request omitted turn_id".to_string());
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match turn_id {
                Ok(turn_id) => {
                    state.initial_turn_id = Some(turn_id);
                    self.changed.notify_all();
                    Ok(())
                }
                Err(error) => {
                    state.error = Some(error.clone());
                    self.changed.notify_all();
                    Err(error)
                }
            }
        }

        fn wait_for_turn_id(&self) -> Result<String, String> {
            let deadline = Instant::now() + H7_TURN_TIMEOUT;
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                if let Some(error) = state.error.clone() {
                    return Err(error);
                }
                if let Some(turn_id) = state.initial_turn_id.clone() {
                    return Ok(turn_id);
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("D29-H7 turn-id wait timed out".to_string());
                }
                let (next, timeout) = self
                    .changed
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state = next;
                if timeout.timed_out() {
                    return Err("D29-H7 turn-id wait timed out".to_string());
                }
            }
        }

        fn wait_until_released(&self) -> Result<(), String> {
            let deadline = Instant::now() + H7_TURN_TIMEOUT;
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !state.released {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("D29-H7 fixture release wait timed out".to_string());
                }
                let (next, timeout) = self
                    .changed
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state = next;
                if timeout.timed_out() && !state.released {
                    return Err("D29-H7 fixture release wait timed out".to_string());
                }
            }
            Ok(())
        }

        fn release(&self) {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .released = true;
            self.changed.notify_all();
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum H7FixtureKind {
        Process,
        WorkspaceProcess,
        GitStatus,
    }

    struct H7ResponsesFixture {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        observation: Arc<Mutex<H7FixtureObservation>>,
        gate: Arc<H7Gate>,
        kind: H7FixtureKind,
        join: Option<JoinHandle<()>>,
    }

    impl H7ResponsesFixture {
        fn start() -> Self {
            Self::start_kind(H7FixtureKind::Process)
        }

        fn start_workspace() -> Self {
            Self::start_kind(H7FixtureKind::WorkspaceProcess)
        }

        fn start_git_status() -> Self {
            Self::start_kind(H7FixtureKind::GitStatus)
        }

        fn start_kind(kind: H7FixtureKind) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind D29-H7 fixture");
            let address = listener.local_addr().expect("D29-H7 fixture address");
            let stop = Arc::new(AtomicBool::new(false));
            let observation = Arc::new(Mutex::new(H7FixtureObservation::default()));
            let gate = H7Gate::new();
            let stop_for_thread = Arc::clone(&stop);
            let observation_for_thread = Arc::clone(&observation);
            let gate_for_thread = Arc::clone(&gate);
            let join = thread::spawn(move || {
                let mut request_index = 0usize;
                while !stop_for_thread.load(Ordering::Acquire) && request_index < 2 {
                    let (mut stream, peer) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(error) => {
                            observation_for_thread
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .error = Some(error.to_string());
                            return;
                        }
                    };
                    if stop_for_thread.load(Ordering::Acquire) {
                        break;
                    }
                    let result = handle_h7_fixture_request(
                        &mut stream,
                        peer,
                        request_index,
                        &gate_for_thread,
                        kind,
                    );
                    let mut observed = observation_for_thread
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    observed.request_count += 1;
                    if let Ok(body) = &result {
                        if request_index == 0 {
                            observed.first_request_schema_exact = match kind {
                                H7FixtureKind::Process => exact_h7_process_schema(body),
                                H7FixtureKind::WorkspaceProcess => {
                                    exact_h7_workspace_process_schema(body)
                                }
                                H7FixtureKind::GitStatus => exact_h7c_git_status_schema(body),
                            };
                            observed.initial_turn_id = extract_h7_turn_id(body);
                        } else {
                            observed.function_call_output =
                                h7_function_call_output_for(body, h7_fixture_call_id(kind));
                            observed.output_has_authority_facts = observed
                                .function_call_output
                                .as_ref()
                                .is_some_and(h7_output_has_authority_facts);
                        }
                    }
                    if let Err(error) = result {
                        observed.error = Some(error);
                    }
                    request_index += 1;
                }
            });
            Self {
                address,
                stop,
                observation,
                gate,
                kind,
                join: Some(join),
            }
        }

        fn base_url(&self) -> String {
            format!("http://127.0.0.1:{}/v1", self.address.port())
        }

        async fn wait_for_turn_id(&self) -> Result<String, String> {
            let gate = Arc::clone(&self.gate);
            tokio::task::spawn_blocking(move || gate.wait_for_turn_id())
                .await
                .map_err(|_| "D29-H7 turn-id wait task failed".to_string())?
        }

        fn release(&self) {
            self.gate.release();
        }

        fn shutdown(mut self) -> (H7FixtureObservation, bool) {
            self.stop.store(true, Ordering::Release);
            self.gate.release();
            let _ = TcpStream::connect(self.address);
            let joined = self
                .join
                .take()
                .map(|join| join.join().is_ok())
                .unwrap_or(true);
            let observation = self
                .observation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            (observation, joined)
        }
    }

    impl Drop for H7ResponsesFixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            self.gate.release();
            let _ = TcpStream::connect(self.address);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    fn handle_h7_fixture_request(
        stream: &mut TcpStream,
        peer: SocketAddr,
        request_index: usize,
        gate: &H7Gate,
        kind: H7FixtureKind,
    ) -> Result<Vec<u8>, String> {
        if !peer.ip().is_loopback() {
            return Err("D29-H7 fixture received a non-loopback peer".to_string());
        }
        let body = read_h7_http_request(stream)?;
        if request_index == 0 {
            gate.capture_turn_id(&body)?;
            gate.wait_until_released()?;
            let events = match kind {
                H7FixtureKind::Process => h7_first_response_events(),
                H7FixtureKind::WorkspaceProcess => h7b_first_response_events(),
                H7FixtureKind::GitStatus => h7c_first_response_events(),
            };
            write_h7_sse_response(stream, events)?;
        } else if request_index == 1 {
            write_h7_sse_response(stream, h7_completion_response_events())?;
        } else {
            return Err("D29-H7 fixture received too many requests".to_string());
        }
        Ok(body)
    }

    fn h7_fixture_call_id(kind: H7FixtureKind) -> &'static str {
        match kind {
            H7FixtureKind::Process => "call-d29h7-process",
            H7FixtureKind::WorkspaceProcess => "call-d29h7b-process",
            H7FixtureKind::GitStatus => "call-d29h7c-git-status",
        }
    }

    fn h7_first_response_events() -> Vec<Value> {
        let arguments = serde_json::to_string(&json!({
            "program": H7_PROGRAM_ID,
            "args": ["echo-argv", "from-codex", "&|;", "$(not-shell)", "界"]
        }))
        .expect("D29-H7 function arguments");
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h7-1", "object": "response", "status": "in_progress", "model": H7_MODEL}
            }),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "function_call", "call_id": "call-d29h7-process", "name": VITA_PROCESS_RUN_TOOL_NAME, "arguments": arguments}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h7-1", "object": "response", "status": "completed", "model": H7_MODEL}
            }),
        ]
    }

    fn h7b_first_response_events() -> Vec<Value> {
        let arguments = serde_json::to_string(&json!({
            "operation": "report_workspace"
        }))
        .expect("D29-H7-B function arguments");
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h7b-1", "object": "response", "status": "in_progress", "model": H7_MODEL}
            }),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "function_call", "call_id": "call-d29h7b-process", "name": H7B_TOOL_NAME, "arguments": arguments}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h7b-1", "object": "response", "status": "completed", "model": H7_MODEL}
            }),
        ]
    }

    fn h7c_first_response_events() -> Vec<Value> {
        let arguments = serde_json::to_string(&json!({
            "operation": "status"
        }))
        .expect("D29-H7-C function arguments");
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h7c-1", "object": "response", "status": "in_progress", "model": H7_MODEL}
            }),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "function_call", "call_id": "call-d29h7c-git-status", "name": H7C_TOOL_NAME, "arguments": arguments}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h7c-1", "object": "response", "status": "completed", "model": H7_MODEL}
            }),
        ]
    }

    fn h7_completion_response_events() -> Vec<Value> {
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h7-2", "object": "response", "status": "in_progress", "model": H7_MODEL}
            }),
            json!({
                "type": "response.output_item.added",
                "item": {"type": "message", "id": "msg-d29h7", "role": "assistant", "status": "in_progress", "content": []}
            }),
            json!({"type": "response.content_part.added"}),
            json!({"type": "response.output_text.delta", "delta": H7_REPLY}),
            json!({"type": "response.output_text.done", "text": H7_REPLY}),
            json!({"type": "response.content_part.done"}),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "message", "id": "msg-d29h7", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": H7_REPLY}]}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h7-2", "object": "response", "status": "completed", "model": H7_MODEL}
            }),
        ]
    }

    fn write_h7_sse_response(stream: &mut TcpStream, events: Vec<Value>) -> Result<(), String> {
        let mut body = String::new();
        for event in events {
            let event_type = event
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| "D29-H7 fixture event omitted type".to_string())?;
            body.push_str("event: ");
            body.push_str(event_type);
            body.push_str("\ndata: ");
            body.push_str(
                &serde_json::to_string(&event)
                    .map_err(|_| "D29-H7 fixture event serialization failed".to_string())?,
            );
            body.push_str("\n\n");
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .set_write_timeout(Some(H7_HTTP_TIMEOUT))
            .map_err(|_| "D29-H7 fixture write timeout setup failed".to_string())?;
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(body.as_bytes()))
            .map_err(|_| "D29-H7 fixture response write failed".to_string())
    }

    fn read_h7_http_request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
        stream
            .set_read_timeout(Some(H7_HTTP_TIMEOUT))
            .map_err(|_| "D29-H7 fixture read timeout setup failed".to_string())?;
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 8192];
        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .map_err(|_| "D29-H7 fixture request read failed".to_string())?;
            if read == 0 {
                return Err("D29-H7 fixture request closed before headers".to_string());
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() > H7_HTTP_MAX_BODY {
                return Err("D29-H7 fixture request exceeded bound".to_string());
            }
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec())
            .map_err(|_| "D29-H7 fixture headers were not UTF-8".to_string())?;
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .ok_or_else(|| "D29-H7 fixture request omitted content length".to_string())?;
        if content_length > H7_HTTP_MAX_BODY || header_end + content_length > H7_HTTP_MAX_BODY {
            return Err("D29-H7 fixture content length exceeded bound".to_string());
        }
        while bytes.len() < header_end + content_length {
            let read = stream
                .read(&mut chunk)
                .map_err(|_| "D29-H7 fixture body read failed".to_string())?;
            if read == 0 {
                return Err("D29-H7 fixture request closed before body".to_string());
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() > H7_HTTP_MAX_BODY {
                return Err("D29-H7 fixture body exceeded bound".to_string());
            }
        }
        Ok(bytes[header_end..header_end + content_length].to_vec())
    }

    fn extract_h7_turn_id(body: &[u8]) -> Option<String> {
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| value.get("client_metadata").cloned())
            .and_then(|value| value.get("turn_id").cloned())
            .and_then(|value| value.as_str().map(str::to_owned))
    }

    fn h7_function_call_output(body: &[u8]) -> Option<Value> {
        h7_function_call_output_for(body, "call-d29h7-process")
    }

    fn h7_function_call_output_for(body: &[u8], call_id: &str) -> Option<Value> {
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| value.get("input").cloned())
            .and_then(|value| value.as_array().cloned())
            .and_then(|items| {
                items.into_iter().find_map(|item| {
                    (item.get("type").and_then(Value::as_str) == Some("function_call_output")
                        && item.get("call_id").and_then(Value::as_str) == Some(call_id))
                    .then(|| item.get("output").and_then(Value::as_str))
                    .flatten()
                    .and_then(|output| serde_json::from_str::<Value>(output).ok())
                })
            })
    }

    fn exact_h7_process_schema(body: &[u8]) -> bool {
        let Some(tool) = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| value.get("tools").cloned())
            .and_then(|value| value.as_array().cloned())
            .and_then(|tools| {
                tools.into_iter().find(|tool| {
                    tool.get("name").and_then(Value::as_str) == Some(VITA_PROCESS_RUN_TOOL_NAME)
                })
            })
        else {
            return false;
        };
        let parameters = tool.get("parameters").or_else(|| {
            tool.get("function")
                .and_then(|function| function.get("parameters"))
        });
        let Some(parameters) = parameters else {
            return false;
        };
        let Some(properties) = parameters.get("properties").and_then(Value::as_object) else {
            return false;
        };
        let names = properties.keys().cloned().collect::<BTreeSet<_>>();
        let required = parameters
            .get("required")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            });
        names == BTreeSet::from(["args".to_string(), "program".to_string()])
            && required == Some(names.clone())
            && parameters
                .get("additionalProperties")
                .and_then(Value::as_bool)
                == Some(false)
            && tool.get("strict").and_then(Value::as_bool) == Some(true)
            && properties["program"]["enum"] == json!([H7_PROGRAM_ID])
            && properties["args"]["type"] == "array"
            && properties["args"]["items"]["type"] == "string"
            && properties["args"].as_object().is_some_and(|args| {
                args.keys().cloned().collect::<BTreeSet<_>>()
                    == BTreeSet::from(["items".to_string(), "type".to_string()])
            })
            && properties["args"]["items"]
                .as_object()
                .is_some_and(|items| {
                    items.keys().cloned().collect::<BTreeSet<_>>()
                        == BTreeSet::from(["type".to_string()])
                })
    }

    fn exact_h7_workspace_process_schema(body: &[u8]) -> bool {
        let Some(tool) = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| value.get("tools").cloned())
            .and_then(|value| value.as_array().cloned())
            .and_then(|tools| {
                tools
                    .into_iter()
                    .find(|tool| tool.get("name").and_then(Value::as_str) == Some(H7B_TOOL_NAME))
            })
        else {
            return false;
        };
        let parameters = tool.get("parameters").or_else(|| {
            tool.get("function")
                .and_then(|function| function.get("parameters"))
        });
        let Some(parameters) = parameters else {
            return false;
        };
        let Some(properties) = parameters.get("properties").and_then(Value::as_object) else {
            return false;
        };
        let names = properties.keys().cloned().collect::<BTreeSet<_>>();
        let required = parameters
            .get("required")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            });
        names == BTreeSet::from(["operation".to_string()])
            && required == Some(names)
            && parameters
                .get("additionalProperties")
                .and_then(Value::as_bool)
                == Some(false)
            && tool.get("strict").and_then(Value::as_bool) == Some(true)
            && properties["operation"]["type"] == "string"
            && properties["operation"]["enum"] == json!(["report_workspace"])
            && properties["operation"]
                .as_object()
                .is_some_and(|operation| {
                    operation.keys().cloned().collect::<BTreeSet<_>>()
                        == BTreeSet::from(["enum".to_string(), "type".to_string()])
                })
    }

    fn h7_output_has_authority_facts(value: &Value) -> bool {
        const FORBIDDEN: &[&str] = &[
            "grant_id",
            "confirmation_id",
            "authorization_revision",
            "raw_handle",
            "credentials",
            "executable_identity",
            "executable_sha256",
            "environment_policy_hash",
            "working_directory_identity",
            "workspace_root_identity",
        ];
        match value {
            Value::Object(object) => object.iter().any(|(key, value)| {
                FORBIDDEN.contains(&key.as_str()) || h7_output_has_authority_facts(value)
            }),
            Value::Array(values) => values.iter().any(h7_output_has_authority_facts),
            _ => false,
        }
    }

    fn exact_h7c_git_status_schema(body: &[u8]) -> bool {
        let Some(tool) = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| value.get("tools").cloned())
            .and_then(|value| value.as_array().cloned())
            .and_then(|tools| {
                tools
                    .into_iter()
                    .find(|tool| tool.get("name").and_then(Value::as_str) == Some(H7C_TOOL_NAME))
            })
        else {
            return false;
        };
        let parameters = tool.get("parameters").or_else(|| {
            tool.get("function")
                .and_then(|function| function.get("parameters"))
        });
        let Some(parameters) = parameters else {
            return false;
        };
        let Some(properties) = parameters.get("properties").and_then(Value::as_object) else {
            return false;
        };
        let names = properties.keys().cloned().collect::<BTreeSet<_>>();
        let required = parameters
            .get("required")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            });
        names == BTreeSet::from(["operation".to_string()])
            && required == Some(names)
            && parameters
                .get("additionalProperties")
                .and_then(Value::as_bool)
                == Some(false)
            && tool.get("strict").and_then(Value::as_bool) == Some(true)
            && properties["operation"]["type"] == "string"
            && properties["operation"]["enum"] == json!(["status"])
            && properties["operation"]
                .as_object()
                .is_some_and(|operation| {
                    operation.keys().cloned().collect::<BTreeSet<_>>()
                        == BTreeSet::from(["enum".to_string(), "type".to_string()])
                })
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum H7ShutdownStatus {
        NotAttempted,
        Success,
        TimedOut,
        Failed,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct H7CleanupEvidence {
        initial_shutdown: H7ShutdownStatus,
        final_shutdown: H7ShutdownStatus,
        manager_thread_count: usize,
        fixture_listener_joined: bool,
    }

    struct H7Runtime {
        manager: Arc<ThreadManager>,
        thread: Option<Arc<codex_core_api::CodexThread>>,
        thread_id: Option<ThreadId>,
        fixture: Option<H7ResponsesFixture>,
        tool_call_count: Arc<AtomicUsize>,
    }

    impl H7Runtime {
        async fn shutdown(mut self) -> (H7CleanupEvidence, H7FixtureObservation, usize) {
            let mut initial_shutdown = H7ShutdownStatus::NotAttempted;
            let mut final_shutdown = H7ShutdownStatus::NotAttempted;
            if let Some(thread) = self.thread.take() {
                initial_shutdown = match tokio::time::timeout(
                    H7_CLEANUP_TIMEOUT,
                    thread.shutdown_and_wait(),
                )
                .await
                {
                    Ok(Ok(())) => H7ShutdownStatus::Success,
                    Ok(Err(_)) => H7ShutdownStatus::Failed,
                    Err(_) => H7ShutdownStatus::TimedOut,
                };
                if initial_shutdown != H7ShutdownStatus::Success {
                    let _ = tokio::time::timeout(H7_CLEANUP_TIMEOUT, thread.submit(Op::Interrupt))
                        .await;
                }
                final_shutdown = match tokio::time::timeout(
                    H7_CLEANUP_TIMEOUT,
                    thread.shutdown_and_wait(),
                )
                .await
                {
                    Ok(Ok(())) => H7ShutdownStatus::Success,
                    Ok(Err(_)) => H7ShutdownStatus::Failed,
                    Err(_) => H7ShutdownStatus::TimedOut,
                };
                if final_shutdown == H7ShutdownStatus::Success {
                    if let Some(thread_id) = self.thread_id.as_ref() {
                        let _ = self
                            .manager
                            .remove_thread_if_matches(thread_id, &thread)
                            .await;
                    }
                }
            }
            let manager_thread_count = self.manager.list_thread_ids().await.len();
            let (observation, fixture_listener_joined) = self
                .fixture
                .take()
                .map(H7ResponsesFixture::shutdown)
                .unwrap_or_else(|| (H7FixtureObservation::default(), true));
            (
                H7CleanupEvidence {
                    initial_shutdown,
                    final_shutdown,
                    manager_thread_count,
                    fixture_listener_joined,
                },
                observation,
                self.tool_call_count.load(Ordering::Acquire),
            )
        }
    }

    async fn start_h7_runtime<C>(
        app_data_root: PathBuf,
        workspace_root: PathBuf,
        fixture: H7ResponsesFixture,
        contributor: C,
        tool_call_count: Arc<AtomicUsize>,
    ) -> Result<H7Runtime, String>
    where
        C: ToolContributor + Send + Sync + 'static,
    {
        let profile =
            VitaAgentRuntimeProfile::from_explicit_app_data_root(app_data_root, workspace_root)
                .map_err(|error| format!("create D29-H7 profile: {error}"))?;
        let provider = ProviderProfile::new_for_test_localhost(
            H7_PROVIDER_ID,
            "D29-H7 local Responses fixture",
            ProviderProtocol::OpenAiResponses,
            fixture.base_url(),
            H7_MODEL,
            None,
            H7_HTTP_TIMEOUT,
            ProviderRetryPolicy::default(),
            ProviderCapabilities {
                tools: true,
                ..ProviderCapabilities::none()
            },
        )
        .map_err(|error| format!("create D29-H7 provider: {error}"))?;
        let provider_authority = VitaProviderAuthority::configure(provider)
            .map_err(|error| format!("configure D29-H7 provider: {error}"))?;
        let binding = VitaGatewayBinding::for_owned_private_listener(fixture.address.port())
            .map_err(|error| format!("create D29-H7 gateway binding: {error}"))?;
        let ready = provider_authority
            .prepare_gateway(binding)
            .map_err(|error| format!("prepare D29-H7 gateway: {error}"))?;
        let entrypoint = VitaAgentEntrypoint::initialize_with_gateway_for_tests(profile, &ready)
            .await
            .map_err(|error| format!("initialize D29-H7 Codex config: {error}"))?;
        let config = entrypoint.config().clone();
        let mut extensions =
            codex_core_api::ExtensionRegistryBuilder::<codex_core::config::Config>::new();
        extensions.tool_contributor(Arc::new(contributor));
        let extensions = Arc::new(extensions.build());
        let auth_manager = codex_core::test_support::auth_manager_from_auth_with_home(
            CodexAuth::from_api_key("d29h7-in-memory-kernel-auth"),
            config.codex_home.to_path_buf(),
        );
        let manager = Arc::new(ThreadManager::new(
            &config,
            Arc::clone(&auth_manager),
            codex_core_api::build_models_manager(&config, Arc::clone(&auth_manager)),
            CodexAppsToolsCache::default(),
            SessionSource::Exec,
            Arc::new(EnvironmentManager::default_for_tests()),
            extensions,
            Arc::new(codex_core::test_support::EmptyUserInstructionsProvider),
            None,
            codex_core_api::thread_store_from_config(&config, None),
            None,
            "d29h7-local-installation".to_string(),
            None,
            None,
        ));
        let new_thread = tokio::time::timeout(
            H7_TURN_TIMEOUT,
            manager.start_thread(StartThreadOptions::new(config)),
        )
        .await
        .map_err(|_| "D29-H7 thread startup timed out".to_string())?
        .map_err(|error| format!("D29-H7 thread startup failed: {error}"))?;
        Ok(H7Runtime {
            manager,
            thread: Some(new_thread.thread),
            thread_id: Some(new_thread.thread_id),
            fixture: Some(fixture),
            tool_call_count,
        })
    }

    async fn start_h7_turn(thread: &Arc<codex_core_api::CodexThread>) -> Result<String, String> {
        let submission = tokio::time::timeout(
            H7_TURN_TIMEOUT,
            thread.start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
                text: H7_PROMPT.to_string(),
                text_elements: Vec::new(),
            }])),
        )
        .await
        .map_err(|_| "D29-H7 turn submission timed out".to_string())?
        .map_err(|error| format!("D29-H7 turn submission failed: {error}"))?;
        match submission {
            TurnInputSubmission::Started { turn_id } | TurnInputSubmission::Steered { turn_id } => {
                Ok(turn_id)
            }
            TurnInputSubmission::NotSubmitted { reason } => {
                Err(format!("D29-H7 turn was not submitted: {reason:?}"))
            }
        }
    }

    async fn wait_h7_turn(
        thread: &Arc<codex_core_api::CodexThread>,
    ) -> Result<(Option<String>, Option<String>, usize), String> {
        let deadline = Instant::now() + H7_TURN_TIMEOUT;
        let mut event_count = 0usize;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("D29-H7 turn did not reach terminal event".to_string());
            }
            let event = tokio::time::timeout(remaining, thread.next_event())
                .await
                .map_err(|_| "D29-H7 event wait timed out".to_string())?
                .map_err(|error| format!("D29-H7 event stream failed: {error}"))?;
            event_count += 1;
            if let EventMsg::TurnComplete(complete) = event.msg {
                return Ok((
                    complete.last_agent_message,
                    complete.error.map(|error| error.message),
                    event_count,
                ));
            }
        }
    }

    struct H7CanaryEvidence {
        reply: Option<String>,
        error: Option<String>,
        observation: H7FixtureObservation,
        tool_call_count: usize,
        process_created: usize,
        job_assigned: usize,
        thread_resumed: usize,
        process_exited: usize,
        final_revalidations: usize,
        grants_issued: usize,
        trusted_confirmations: usize,
        request_derived_confirmations: usize,
        trusted_workspace_scopes: usize,
        request_derived_workspace_scopes: usize,
        workspace_cwd_matches: bool,
        cleanup: H7CleanupEvidence,
    }

    async fn run_real_h7_canary(approve: bool) -> H7CanaryEvidence {
        let app_data = tempdir().expect("D29-H7 app-data temp root");
        let workspace = tempdir().expect("D29-H7 workspace temp root");
        let fixture = H7ResponsesFixture::start();
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("D29-H7 repository root")
            .to_path_buf();
        let image = h7_process_fixture_executable(&repo_root).expect("D29-H7 process image");
        let catalog = Arc::new(
            H7ExecutableCatalog::fixture(image, workspace.path().to_path_buf())
                .expect("D29-H7 canary catalog"),
        );
        let authority = H7Authority::new().expect("D29-H7 canary authority");
        let (bridge, mut receiver) = H7PendingConfirmationBridge::new();
        let context =
            VitaExecutionContext::try_new(H7_LIFE_ID, H7_TASK_ID).expect("D29-H7 canary context");
        let broker = H7ProcessBroker::new(
            context,
            Arc::clone(&catalog),
            Arc::clone(&authority),
            Arc::clone(&bridge),
        );
        let tool_call_count = Arc::new(AtomicUsize::new(0));
        let contributor = VitaProcessToolContributor::new(Arc::clone(&broker))
            .with_tool_call_count(Arc::clone(&tool_call_count));
        let runtime = start_h7_runtime(
            app_data.path().to_path_buf(),
            workspace.path().to_path_buf(),
            fixture,
            contributor,
            Arc::clone(&tool_call_count),
        )
        .await
        .expect("D29-H7 Codex runtime");
        let turn_id = start_h7_turn(runtime.thread.as_ref().unwrap())
            .await
            .expect("D29-H7 canary turn");
        let observed_turn_id = runtime
            .fixture
            .as_ref()
            .unwrap()
            .wait_for_turn_id()
            .await
            .expect("D29-H7 Responses fixture turn id");
        assert_eq!(observed_turn_id, turn_id);
        runtime.fixture.as_ref().unwrap().release();
        if approve {
            let pending = tokio::time::timeout(H7_TURN_TIMEOUT, receiver.recv())
                .await
                .expect("D29-H7 canary confirmation wait")
                .expect("D29-H7 canary confirmation");
            let revision = authority
                .provision_confirmation(&pending.action)
                .expect("D29-H7 canary trusted confirmation");
            pending
                .response
                .send(revision)
                .expect("D29-H7 canary confirmation response");
        } else {
            drop(receiver);
        }
        let (reply, error, _) = wait_h7_turn(runtime.thread.as_ref().unwrap())
            .await
            .expect("D29-H7 canary turn completion");
        let (cleanup, observation, tool_calls) = runtime.shutdown().await;
        let metrics = broker.metrics();
        let provenance = authority.provenance();
        let grants_issued = authority.metrics.grants_issued.load(Ordering::Acquire);
        let final_revalidations = authority
            .metrics
            .final_revalidations
            .load(Ordering::Acquire);
        assert!(authority.shutdown());
        H7CanaryEvidence {
            reply,
            error,
            observation,
            tool_call_count: tool_calls,
            process_created: metrics.process_created.load(Ordering::Acquire),
            job_assigned: metrics.job_assigned.load(Ordering::Acquire),
            thread_resumed: metrics.thread_resumed.load(Ordering::Acquire),
            process_exited: metrics.process_exited.load(Ordering::Acquire),
            final_revalidations,
            grants_issued,
            trusted_confirmations: provenance.0,
            request_derived_confirmations: provenance.1,
            trusted_workspace_scopes: 0,
            request_derived_workspace_scopes: 0,
            workspace_cwd_matches: false,
            cleanup,
        }
    }

    fn h7_fixture_cwd_matches(raw: Option<&[u8]>, workspace_root: &Path) -> bool {
        raw.and_then(|raw| serde_json::from_slice::<Value>(raw).ok())
            .and_then(|value| value.get("cwd").cloned())
            .and_then(|value| value.as_str().map(PathBuf::from))
            .is_some_and(|cwd| h7_workspace_paths_equal(&cwd, workspace_root))
    }

    async fn run_real_h7b_canary(with_workspace_scope: bool, approve: bool) -> H7CanaryEvidence {
        let app_data = tempdir().expect("D29-H7-B app-data temp root");
        let workspace = tempdir().expect("D29-H7-B workspace temp root");
        let root = TrustedWorkspaceRoot::acquire(workspace.path())
            .expect("D29-H7-B canary trusted workspace root");
        let fixture = H7ResponsesFixture::start_workspace();
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("D29-H7-B repository root")
            .to_path_buf();
        let image =
            h7_process_fixture_executable(&repo_root).expect("D29-H7-B canary process image");
        let catalog = Arc::new(
            H7ExecutableCatalog::fixture(image, root.requested_path().to_path_buf())
                .expect("D29-H7-B canary catalog"),
        );
        let authority = H7Authority::new_workspace(&root).expect("D29-H7-B canary authority");
        let (bridge, mut receiver) = H7PendingConfirmationBridge::new();
        let context =
            VitaExecutionContext::try_new(H7_LIFE_ID, H7_TASK_ID).expect("D29-H7-B canary context");
        let broker = H7BWorkspaceProcessBroker::new(
            context,
            Arc::clone(&catalog),
            Arc::clone(&authority),
            Arc::clone(&bridge),
            with_workspace_scope.then(|| root.clone()),
        );
        let tool_call_count = Arc::new(AtomicUsize::new(0));
        let contributor = VitaWorkspaceProcessToolContributor::new(Arc::clone(&broker))
            .with_tool_call_count(Arc::clone(&tool_call_count));
        let runtime = start_h7_runtime(
            app_data.path().to_path_buf(),
            workspace.path().to_path_buf(),
            fixture,
            contributor,
            Arc::clone(&tool_call_count),
        )
        .await
        .expect("D29-H7-B Codex runtime");
        let turn_id = start_h7_turn(runtime.thread.as_ref().unwrap())
            .await
            .expect("D29-H7-B canary turn");
        let observed_turn_id = runtime
            .fixture
            .as_ref()
            .unwrap()
            .wait_for_turn_id()
            .await
            .expect("D29-H7-B Responses fixture turn id");
        assert_eq!(observed_turn_id, turn_id);
        runtime.fixture.as_ref().unwrap().release();
        if with_workspace_scope && approve {
            let pending = tokio::time::timeout(H7_TURN_TIMEOUT, receiver.recv())
                .await
                .expect("D29-H7-B canary confirmation wait")
                .expect("D29-H7-B canary confirmation");
            let revision = authority
                .provision_workspace_confirmation(&pending.action)
                .expect("D29-H7-B canary trusted confirmation");
            pending
                .response
                .send(revision)
                .expect("D29-H7-B canary confirmation response");
        } else {
            if !with_workspace_scope {
                assert!(
                    tokio::time::timeout(Duration::from_millis(250), receiver.recv())
                        .await
                        .is_err(),
                    "D29-H7-B without Host workspace scope must not request confirmation"
                );
            }
            drop(receiver);
        }
        let (reply, error, _) = wait_h7_turn(runtime.thread.as_ref().unwrap())
            .await
            .expect("D29-H7-B canary turn completion");
        let (cleanup, observation, tool_calls) = runtime.shutdown().await;
        let metrics = broker.metrics();
        let provenance = authority.provenance();
        let workspace_scope_provenance = authority.workspace_scope_provenance();
        let grants_issued = authority.metrics.grants_issued.load(Ordering::Acquire);
        let final_revalidations = authority
            .metrics
            .final_revalidations
            .load(Ordering::Acquire);
        let workspace_cwd_matches = h7_fixture_cwd_matches(
            broker.last_fixture_stdout().as_deref(),
            root.requested_path(),
        );
        assert!(authority.shutdown());
        H7CanaryEvidence {
            reply,
            error,
            observation,
            tool_call_count: tool_calls,
            process_created: metrics.process_created.load(Ordering::Acquire),
            job_assigned: metrics.job_assigned.load(Ordering::Acquire),
            thread_resumed: metrics.thread_resumed.load(Ordering::Acquire),
            process_exited: metrics.process_exited.load(Ordering::Acquire),
            final_revalidations,
            grants_issued,
            trusted_confirmations: provenance.0,
            request_derived_confirmations: provenance.1,
            trusted_workspace_scopes: workspace_scope_provenance.0,
            request_derived_workspace_scopes: workspace_scope_provenance.1,
            workspace_cwd_matches,
            cleanup,
        }
    }

    struct H7CGitCanaryEvidence {
        reply: Option<String>,
        error: Option<String>,
        observation: H7FixtureObservation,
        tool_call_count: usize,
        process_created: usize,
        job_assigned: usize,
        thread_resumed: usize,
        process_exited: usize,
        final_revalidations: usize,
        grants_issued: usize,
        trusted_confirmations: usize,
        trusted_workspace_scopes: usize,
        parsed_entries: BTreeSet<(String, String, String)>,
        expected_entries: BTreeSet<(String, String, String)>,
        workspace_bytes_unchanged: bool,
        git_metadata_bytes_unchanged: bool,
        index_lock_absent: bool,
        actual_git_image: bool,
        native_process_tree_remaining: usize,
        cleanup: H7CleanupEvidence,
    }

    async fn run_real_h7c_canary(
        with_workspace_scope: bool,
        approve: bool,
    ) -> H7CGitCanaryEvidence {
        let app_data = tempdir().expect("D29-H7-C app-data temp root");
        let workspace = tempdir().expect("D29-H7-C workspace temp root");
        let git_path = h7c_installed_git_path();
        h7c_initialize_repo(workspace.path(), &git_path);
        fs::write(workspace.path().join("modified.txt"), b"after\n")
            .expect("D29-H7-C modified tracked file");
        fs::write(workspace.path().join("untracked.txt"), b"untracked\n")
            .expect("D29-H7-C untracked file");
        let root = TrustedWorkspaceRoot::acquire(workspace.path())
            .expect("D29-H7-C canary trusted workspace root");
        let before =
            h7c_snapshot_workspace(root.requested_path()).expect("D29-H7-C before snapshot");
        let profile = Arc::new(
            H7CGitStatusProfile::new(&root, git_path.clone()).expect("D29-H7-C canary profile"),
        );
        let fixture = H7ResponsesFixture::start_git_status();
        let authority = H7Authority::new_git_workspace(&root).expect("D29-H7-C canary authority");
        let (bridge, mut receiver) = H7PendingConfirmationBridge::new();
        let context =
            VitaExecutionContext::try_new(H7_LIFE_ID, H7_TASK_ID).expect("D29-H7-C canary context");
        let broker = H7CGitStatusBroker::new(
            context,
            Arc::clone(&profile),
            Arc::clone(&authority),
            Arc::clone(&bridge),
            with_workspace_scope.then(|| root.clone()),
        );
        let tool_call_count = Arc::new(AtomicUsize::new(0));
        let contributor = VitaGitStatusToolContributor::new(Arc::clone(&broker))
            .with_tool_call_count(Arc::clone(&tool_call_count));
        let runtime = start_h7_runtime(
            app_data.path().to_path_buf(),
            workspace.path().to_path_buf(),
            fixture,
            contributor,
            Arc::clone(&tool_call_count),
        )
        .await
        .expect("D29-H7-C Codex runtime");
        let turn_id = start_h7_turn(runtime.thread.as_ref().unwrap())
            .await
            .expect("D29-H7-C canary turn");
        let observed_turn_id = runtime
            .fixture
            .as_ref()
            .unwrap()
            .wait_for_turn_id()
            .await
            .expect("D29-H7-C Responses fixture turn id");
        assert_eq!(observed_turn_id, turn_id);
        runtime.fixture.as_ref().unwrap().release();
        if with_workspace_scope && approve {
            let pending = tokio::time::timeout(H7_TURN_TIMEOUT, receiver.recv())
                .await
                .expect("D29-H7-C canary confirmation wait")
                .expect("D29-H7-C canary confirmation");
            let revision = authority
                .provision_workspace_confirmation(&pending.action)
                .expect("D29-H7-C canary trusted confirmation");
            pending
                .response
                .send(revision)
                .expect("D29-H7-C canary confirmation response");
        } else {
            drop(receiver);
        }
        let (reply, error, _) = wait_h7_turn(runtime.thread.as_ref().unwrap())
            .await
            .expect("D29-H7-C canary turn completion");
        let (cleanup, observation, tool_calls) = runtime.shutdown().await;
        let metrics = broker.metrics();
        let provenance = authority.workspace_scope_provenance();
        let grants_issued = authority.metrics.grants_issued.load(Ordering::Acquire);
        let final_revalidations = authority
            .metrics
            .final_revalidations
            .load(Ordering::Acquire);
        let after = h7c_snapshot_workspace(root.requested_path()).expect("D29-H7-C after snapshot");
        let parsed_entries = observation
            .function_call_output
            .as_ref()
            .and_then(|value| value.get("entries"))
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| {
                        Some((
                            entry.get("index")?.as_str()?.to_string(),
                            entry.get("worktree")?.as_str()?.to_string(),
                            entry.get("path")?.as_str()?.to_string(),
                        ))
                    })
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let expected_entries = BTreeSet::from([
            (" ".to_string(), "M".to_string(), "modified.txt".to_string()),
            (
                "?".to_string(),
                "?".to_string(),
                "untracked.txt".to_string(),
            ),
        ]);
        let native_process_tree_remaining = broker
            .last_native()
            .map(|native| native.process_tree_remaining)
            .unwrap_or(0);
        let actual_git_image = profile.git_path == git_path
            && profile
                .git_path
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("\\git\\");
        assert!(authority.shutdown());
        H7CGitCanaryEvidence {
            reply,
            error,
            observation,
            tool_call_count: tool_calls,
            process_created: metrics.process_created.load(Ordering::Acquire),
            job_assigned: metrics.job_assigned.load(Ordering::Acquire),
            thread_resumed: metrics.thread_resumed.load(Ordering::Acquire),
            process_exited: metrics.process_exited.load(Ordering::Acquire),
            final_revalidations,
            grants_issued,
            trusted_confirmations: authority
                .metrics
                .trusted_confirmations
                .load(Ordering::Acquire),
            trusted_workspace_scopes: provenance.0,
            parsed_entries,
            expected_entries,
            workspace_bytes_unchanged: before.workspace_files == after.workspace_files,
            git_metadata_bytes_unchanged: before.git_files == after.git_files,
            index_lock_absent: !h7c_index_lock_present(root.requested_path()),
            actual_git_image,
            native_process_tree_remaining,
            cleanup,
        }
    }

    fn run_h7_test_body<F>(body: F)
    where
        F: FnOnce() + Send + 'static,
    {
        thread::Builder::new()
            .name("d29h7-real-codex".to_string())
            .stack_size(H7_TEST_STACK_SIZE)
            .spawn(body)
            .expect("D29-H7 test thread should start")
            .join()
            .expect("D29-H7 test thread should finish");
    }

    #[test]
    fn real_codex_h7_process_canary() {
        run_h7_test_body(|| {
            let _lock = lock_h7_tests();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H7 real Codex runtime");
            let evidence = runtime.block_on(run_real_h7_canary(true));
            assert_eq!(evidence.error, None);
            assert_eq!(evidence.reply.as_deref(), Some(H7_REPLY));
            assert_eq!(evidence.observation.request_count, 2);
            assert!(
                evidence.observation.first_request_schema_exact,
                "D29-H7 observed first request: {:?}",
                evidence.observation
            );
            assert_eq!(evidence.tool_call_count, 1);
            assert_eq!(evidence.process_created, 1);
            assert_eq!(evidence.job_assigned, 1);
            assert_eq!(evidence.thread_resumed, 1);
            assert_eq!(evidence.process_exited, 1);
            assert_eq!(evidence.grants_issued, 1);
            assert_eq!(evidence.final_revalidations, 1);
            assert_eq!(evidence.trusted_confirmations, 1);
            assert_eq!(evidence.request_derived_confirmations, 0);
            assert!(!evidence.observation.output_has_authority_facts);
            assert_eq!(evidence.cleanup.initial_shutdown, H7ShutdownStatus::Success);
            assert_eq!(evidence.cleanup.final_shutdown, H7ShutdownStatus::Success);
            assert_eq!(evidence.cleanup.manager_thread_count, 0);
            assert!(evidence.cleanup.fixture_listener_joined);
            let output = evidence
                .observation
                .function_call_output
                .expect("D29-H7 function output");
            assert_eq!(output["status"], "started_and_exited");
            assert_eq!(output["process_created"], true);
            assert_eq!(output["side_effect_count"], 1);
        });
    }

    #[test]
    fn real_codex_h7_without_confirmation_creates_zero_processes() {
        run_h7_test_body(|| {
            let _lock = lock_h7_tests();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H7 no-confirmation runtime");
            let evidence = runtime.block_on(run_real_h7_canary(false));
            assert_eq!(evidence.error, None);
            assert_eq!(evidence.reply.as_deref(), Some(H7_REPLY));
            assert_eq!(evidence.tool_call_count, 1);
            assert_eq!(evidence.process_created, 0);
            assert_eq!(evidence.job_assigned, 0);
            assert_eq!(evidence.thread_resumed, 0);
            assert_eq!(evidence.process_exited, 0);
            assert_eq!(evidence.grants_issued, 0);
            assert_eq!(evidence.final_revalidations, 0);
            assert_eq!(evidence.trusted_confirmations, 0);
            assert_eq!(evidence.request_derived_confirmations, 0);
            assert!(!evidence.observation.output_has_authority_facts);
        });
    }

    #[test]
    fn real_codex_h7_output_exposes_no_authority_facts() {
        run_h7_test_body(|| {
            let _lock = lock_h7_tests();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H7 output runtime");
            let evidence = runtime.block_on(run_real_h7_canary(true));
            assert!(!evidence.observation.output_has_authority_facts);
            let output = evidence
                .observation
                .function_call_output
                .expect("D29-H7 output");
            assert!(!h7_output_has_authority_facts(&output));
            assert_eq!(output["side_effect_count"], 1);
        });
    }

    #[test]
    fn real_codex_h7b_workspace_process_canary() {
        run_h7_test_body(|| {
            let _lock = lock_h7_tests();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H7-B real Codex runtime");
            let evidence = runtime.block_on(run_real_h7b_canary(true, true));
            assert_eq!(evidence.error, None);
            assert_eq!(evidence.reply.as_deref(), Some(H7_REPLY));
            assert_eq!(evidence.observation.request_count, 2);
            assert!(
                evidence.observation.first_request_schema_exact,
                "D29-H7-B observed first request: {:?}",
                evidence.observation
            );
            assert_eq!(evidence.tool_call_count, 1);
            assert_eq!(evidence.process_created, 1);
            assert_eq!(evidence.job_assigned, 1);
            assert_eq!(evidence.thread_resumed, 1);
            assert_eq!(evidence.process_exited, 1);
            assert_eq!(evidence.trusted_workspace_scopes, 1);
            assert_eq!(evidence.request_derived_workspace_scopes, 0);
            assert_eq!(evidence.grants_issued, 1);
            assert_eq!(evidence.final_revalidations, 1);
            assert_eq!(evidence.trusted_confirmations, 1);
            assert_eq!(evidence.request_derived_confirmations, 0);
            assert!(evidence.workspace_cwd_matches);
            assert!(!evidence.observation.output_has_authority_facts);
            assert_eq!(evidence.cleanup.initial_shutdown, H7ShutdownStatus::Success);
            assert_eq!(evidence.cleanup.final_shutdown, H7ShutdownStatus::Success);
            assert_eq!(evidence.cleanup.manager_thread_count, 0);
            assert!(evidence.cleanup.fixture_listener_joined);
            let output = evidence
                .observation
                .function_call_output
                .expect("D29-H7-B function output");
            assert_eq!(output["status"], "workspace_process_completed");
            assert_eq!(output["process_created"], true);
            assert_eq!(output["side_effect_count"], 1);
        });
    }

    #[test]
    fn real_codex_h7b_without_scope_createprocess_zero() {
        run_h7_test_body(|| {
            let _lock = lock_h7_tests();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H7-B no-scope runtime");
            let evidence = runtime.block_on(run_real_h7b_canary(false, false));
            assert_eq!(evidence.error, None);
            assert_eq!(evidence.reply.as_deref(), Some(H7_REPLY));
            assert_eq!(evidence.tool_call_count, 1);
            assert_eq!(evidence.process_created, 0);
            assert_eq!(evidence.job_assigned, 0);
            assert_eq!(evidence.thread_resumed, 0);
            assert_eq!(evidence.process_exited, 0);
            assert_eq!(evidence.trusted_workspace_scopes, 0);
            assert_eq!(evidence.request_derived_workspace_scopes, 0);
            assert_eq!(evidence.grants_issued, 0);
            assert_eq!(evidence.final_revalidations, 0);
            assert_eq!(evidence.trusted_confirmations, 0);
            assert_eq!(evidence.request_derived_confirmations, 0);
            assert!(!evidence.workspace_cwd_matches);
            assert!(!evidence.observation.output_has_authority_facts);
            let output = evidence
                .observation
                .function_call_output
                .expect("D29-H7-B no-scope function output");
            assert_eq!(output["status"], "denied");
            assert_eq!(output["process_created"], false);
            assert_eq!(output["side_effect_count"], 0);
        });
    }

    #[test]
    fn real_codex_h7b_output_exposes_no_authority_facts() {
        run_h7_test_body(|| {
            let _lock = lock_h7_tests();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H7-B output runtime");
            let evidence = runtime.block_on(run_real_h7b_canary(true, true));
            assert!(!evidence.observation.output_has_authority_facts);
            let output = evidence
                .observation
                .function_call_output
                .expect("D29-H7-B output");
            assert!(!h7_output_has_authority_facts(&output));
            assert!(!output.to_string().contains("workspace_root_identity"));
            assert!(!output.to_string().contains("authorization_revision"));
            assert_eq!(output["side_effect_count"], 1);
        });
    }

    #[test]
    fn real_codex_h7c_git_status_canary() {
        run_h7_test_body(|| {
            let _lock = lock_h7_tests();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H7-C real Codex runtime");
            let evidence = runtime.block_on(run_real_h7c_canary(true, true));
            assert_eq!(evidence.error, None);
            assert_eq!(evidence.reply.as_deref(), Some(H7_REPLY));
            assert_eq!(evidence.observation.request_count, 2);
            assert!(evidence.observation.first_request_schema_exact);
            assert_eq!(evidence.tool_call_count, 1);
            assert_eq!(evidence.process_created, 1);
            assert_eq!(evidence.job_assigned, 1);
            assert_eq!(evidence.thread_resumed, 1);
            assert_eq!(evidence.process_exited, 1);
            assert_eq!(evidence.grants_issued, 1);
            assert_eq!(evidence.final_revalidations, 1);
            assert_eq!(evidence.trusted_confirmations, 1);
            assert_eq!(evidence.trusted_workspace_scopes, 1);
            assert_eq!(evidence.parsed_entries, evidence.expected_entries);
            assert!(evidence.workspace_bytes_unchanged);
            assert!(evidence.git_metadata_bytes_unchanged);
            assert!(evidence.index_lock_absent);
            assert!(evidence.actual_git_image);
            assert_eq!(evidence.native_process_tree_remaining, 0);
            assert!(!evidence.observation.output_has_authority_facts);
            assert_eq!(evidence.cleanup.initial_shutdown, H7ShutdownStatus::Success);
            assert_eq!(evidence.cleanup.final_shutdown, H7ShutdownStatus::Success);
            assert_eq!(evidence.cleanup.manager_thread_count, 0);
            assert!(evidence.cleanup.fixture_listener_joined);
        });
    }

    #[test]
    fn real_codex_h7c_without_scope_createprocess_zero() {
        run_h7_test_body(|| {
            let _lock = lock_h7_tests();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H7-C no-scope runtime");
            let evidence = runtime.block_on(run_real_h7c_canary(false, false));
            assert_eq!(evidence.error, None);
            assert_eq!(evidence.reply.as_deref(), Some(H7_REPLY));
            assert_eq!(evidence.tool_call_count, 1);
            assert_eq!(evidence.process_created, 0);
            assert_eq!(evidence.job_assigned, 0);
            assert_eq!(evidence.thread_resumed, 0);
            assert_eq!(evidence.process_exited, 0);
            assert_eq!(evidence.grants_issued, 0);
            assert_eq!(evidence.final_revalidations, 0);
            assert_eq!(evidence.trusted_confirmations, 0);
            assert_eq!(evidence.trusted_workspace_scopes, 0);
            assert!(!evidence.observation.output_has_authority_facts);
        });
    }

    #[test]
    fn real_codex_h7c_output_exposes_no_authority_facts() {
        run_h7_test_body(|| {
            let _lock = lock_h7_tests();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H7-C output runtime");
            let evidence = runtime.block_on(run_real_h7c_canary(true, true));
            assert!(!evidence.observation.output_has_authority_facts);
            let output = evidence
                .observation
                .function_call_output
                .expect("D29-H7-C output");
            assert!(!h7_output_has_authority_facts(&output));
            assert!(!output.to_string().contains("workspace_root_identity"));
            assert!(!output.to_string().contains("authorization_revision"));
            assert!(output["entries"].is_array());
        });
    }
}
