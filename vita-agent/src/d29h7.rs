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
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetHandleInformation, GetLastError, SetHandleInformation,
    DUPLICATE_SAME_ACCESS, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_CONNECTED, FALSE, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, UNICODE_STRING, WAIT_OBJECT_0, WAIT_TIMEOUT,
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

use crate::{sha256_hex, VitaExecutionContext};

pub(crate) const VITA_PROCESS_RUN_TOOL_NAME: &str = "vita_run_process";
const H7_CAPABILITY_ID: &str = "vita.process.run";
const H7_PROGRAM_ID: &str = "d29h7_fixture";
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
        Ok(Arc::new(PreparedProcessAction {
            context,
            tool_call_id: request.tool_call_id,
            turn_id: request.turn_id,
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
        }))
    }
}

struct PreparedProcessAction {
    context: VitaExecutionContext,
    tool_call_id: String,
    turn_id: String,
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
            capability_id: H7_CAPABILITY_ID.to_string(),
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
        }
    }
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
    output_handles_closed: bool,
}

const H7_OUTPUT_SCRATCH_BYTES: usize = 8 * 1024;

struct H7OverlappedOutputCapture {
    read: H7Handle,
    child_write: H7Handle,
    event: H7Handle,
    overlapped: OVERLAPPED,
    scratch: [u8; H7_OUTPUT_SCRATCH_BYTES],
    bytes: Vec<u8>,
    bound: usize,
    pending: bool,
    complete: bool,
    cancelled: bool,
    overflow: bool,
    error: Option<u32>,
}

unsafe impl Send for H7OverlappedOutputCapture {}

impl H7OverlappedOutputCapture {
    fn new(bound: usize, stream: &str) -> Result<Self, String> {
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

        let connect_event =
            H7Handle::new(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })?;
        let mut connect_overlapped = OVERLAPPED {
            hEvent: connect_event.raw(),
            ..Default::default()
        };
        let connected = unsafe { ConnectNamedPipe(read.raw(), &mut connect_overlapped) } != 0;
        let connect_pending = if connected {
            false
        } else {
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => false,
                ERROR_IO_PENDING => true,
                error => {
                    return Err(format!(
                        "H7 overlapped {} named-pipe connect failed: {}",
                        stream, error
                    ));
                }
            }
        };

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
        if connect_pending {
            if unsafe { WaitForSingleObject(connect_event.raw(), 2_000) } != WAIT_OBJECT_0 {
                unsafe {
                    let _ = CancelIoEx(read.raw(), &connect_overlapped);
                }
                return Err(format!(
                    "H7 overlapped {} named-pipe connect timed out",
                    stream
                ));
            }
            let mut transferred = 0_u32;
            if unsafe {
                GetOverlappedResult(read.raw(), &connect_overlapped, &mut transferred, FALSE)
            } == 0
            {
                return Err(format!(
                    "H7 overlapped {} named-pipe connect completion failed: {}",
                    stream,
                    unsafe { GetLastError() }
                ));
            }
        }

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
            read,
            child_write,
            event,
            overlapped,
            scratch: [0_u8; H7_OUTPUT_SCRATCH_BYTES],
            bytes: Vec::with_capacity(bound.min(H7_OUTPUT_SCRATCH_BYTES)),
            bound,
            pending: false,
            complete: false,
            cancelled: false,
            overflow: false,
            error: None,
        })
    }

    fn child_handle(&self) -> HANDLE {
        self.child_write.raw()
    }

    fn close_child_endpoint(&mut self) {
        let child_write = std::mem::replace(&mut self.child_write, H7Handle(std::ptr::null_mut()));
        drop(child_write);
    }

    fn event_handle(&self) -> HANDLE {
        self.event.raw()
    }

    fn pending(&self) -> bool {
        self.pending
    }

    fn is_complete(&self) -> bool {
        self.complete
    }

    fn overflowed(&self) -> bool {
        self.overflow
    }

    fn failed(&self) -> bool {
        self.error.is_some()
    }

    fn retained_len(&self) -> usize {
        self.bytes.len()
    }

    fn arm_read(&mut self) {
        if self.pending || self.complete {
            return;
        }
        let remaining = self.bound.saturating_sub(self.bytes.len());
        let requested = remaining
            .saturating_add(1)
            .min(H7_OUTPUT_SCRATCH_BYTES)
            .max(1);
        unsafe {
            let _ = ResetEvent(self.event.raw());
        }
        self.overlapped = OVERLAPPED {
            hEvent: self.event.raw(),
            ..Default::default()
        };
        self.pending = true;
        let started = unsafe {
            ReadFile(
                self.read.raw(),
                self.scratch.as_mut_ptr().cast(),
                requested as u32,
                std::ptr::null_mut(),
                &mut self.overlapped,
            )
        } != 0;
        if started {
            let _ = self.complete_pending();
            return;
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            self.pending = false;
            self.complete = true;
            self.cancelled = error == ERROR_OPERATION_ABORTED;
            if error != ERROR_BROKEN_PIPE && error != ERROR_OPERATION_ABORTED {
                self.error = Some(error);
            }
        }
    }

    fn complete_pending(&mut self) -> bool {
        if !self.pending {
            return self.complete;
        }
        let mut transferred = 0_u32;
        let completed = unsafe {
            GetOverlappedResult(self.read.raw(), &self.overlapped, &mut transferred, FALSE)
        } != 0;
        if !completed {
            let error = unsafe { GetLastError() };
            if error == ERROR_IO_PENDING {
                return false;
            }
            self.pending = false;
            self.complete = true;
            self.cancelled = error == ERROR_OPERATION_ABORTED;
            if error != ERROR_BROKEN_PIPE && error != ERROR_OPERATION_ABORTED {
                self.error = Some(error);
            }
            unsafe {
                let _ = ResetEvent(self.event.raw());
            }
            return true;
        }
        self.pending = false;
        unsafe {
            let _ = ResetEvent(self.event.raw());
        }
        if transferred == 0 {
            self.complete = true;
            return true;
        }
        let remaining = self.bound.saturating_sub(self.bytes.len());
        let take = remaining.min(transferred as usize);
        self.bytes.extend_from_slice(&self.scratch[..take]);
        if take < transferred as usize {
            self.overflow = true;
            self.complete = true;
        }
        true
    }

    fn cancel_pending(&mut self) {
        if self.pending {
            unsafe {
                let _ = CancelIoEx(self.read.raw(), &self.overlapped);
            }
        }
    }

    fn drain_until_terminal(&mut self, deadline: Instant) -> bool {
        while self.pending {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let wait_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
            if unsafe { WaitForSingleObject(self.event.raw(), wait_ms) } != WAIT_OBJECT_0 {
                return false;
            }
            let _ = self.complete_pending();
        }
        true
    }
}

impl Drop for H7OverlappedOutputCapture {
    fn drop(&mut self) {
        if self.pending {
            self.cancel_pending();
            let _ = self.drain_until_terminal(Instant::now() + H7_CLEANUP_TIMEOUT);
        }
    }
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

fn cancel_and_drain_h7_output(
    metrics: &H7SupervisorMetrics,
    stdout: &mut H7OverlappedOutputCapture,
    stderr: &mut H7OverlappedOutputCapture,
) -> bool {
    stdout.cancel_pending();
    stderr.cancel_pending();
    let deadline = Instant::now() + H7_CLEANUP_TIMEOUT;
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
        let job = create_job_object()?;
        let (stdin_read, stdin_write) = create_stdin_pipe()?;
        let stdout_capture = H7OverlappedOutputCapture::new(action.stdout_bound, "stdout")?;
        let stderr_capture = H7OverlappedOutputCapture::new(action.stderr_bound, "stderr")?;
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
}

fn supervise_native(action: &PreparedProcessAction, options: H7NativeOptions) -> H7NativeResult {
    let preparation =
        match H7LaunchPreparation::prepare(action, options.unlisted_inheritable_handle) {
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
            output_handles_closed: cleanup.stdout_reader_joined.load(Ordering::Acquire)
                && cleanup.stderr_reader_joined.load(Ordering::Acquire),
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
    let cleanup_deadline = Instant::now() + H7_CLEANUP_TIMEOUT;
    let mut timed_out = false;
    let mut cancelled = false;
    let mut output_failure = false;
    let mut output_cleanup_bounded = true;
    let mut process_signaled = false;

    loop {
        if options.cancellation.load(Ordering::Acquire) {
            cancelled = true;
            let _ = resources.terminate_assigned_job();
            output_cleanup_bounded = cancel_and_drain_h7_output(
                &options.metrics,
                &mut stdout_capture,
                &mut stderr_capture,
            );
            break;
        }
        stdout_capture.arm_read();
        stderr_capture.arm_read();
        update_h7_pending_output_metric(&options.metrics, &stdout_capture, &stderr_capture);
        if stdout_capture.overflowed() || stderr_capture.overflowed() {
            let _ = resources.terminate_assigned_job();
            output_cleanup_bounded = cancel_and_drain_h7_output(
                &options.metrics,
                &mut stdout_capture,
                &mut stderr_capture,
            );
            break;
        }
        if stdout_capture.failed() || stderr_capture.failed() {
            output_failure = true;
            let _ = resources.terminate_assigned_job();
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
            cleanup_deadline
        } else {
            deadline
        };
        let remaining = wait_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if process_signaled {
                output_failure = true;
            } else {
                timed_out = true;
            }
            let _ = resources.terminate_assigned_job();
            output_cleanup_bounded = cancel_and_drain_h7_output(
                &options.metrics,
                &mut stdout_capture,
                &mut stderr_capture,
            );
            break;
        }
        let wait_ms = remaining.as_millis().min(20).max(1) as u32;
        let handles = [
            resources.process.raw(),
            stdout_capture.event_handle(),
            stderr_capture.event_handle(),
        ];
        let wait = unsafe {
            WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, wait_ms)
        };
        if wait == WAIT_OBJECT_0 {
            if !process_signaled {
                process_signaled = true;
                phase.store(H7LaunchPhase::Exited as u8, Ordering::Release);
                options
                    .metrics
                    .process_exited
                    .fetch_add(1, Ordering::AcqRel);
            }
        } else if wait == WAIT_OBJECT_0 + 1 {
            let _ = stdout_capture.complete_pending();
            update_h7_pending_output_metric(&options.metrics, &stdout_capture, &stderr_capture);
        } else if wait == WAIT_OBJECT_0 + 2 {
            let _ = stderr_capture.complete_pending();
            update_h7_pending_output_metric(&options.metrics, &stdout_capture, &stderr_capture);
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
    if !phase_at_least(&phase, H7LaunchPhase::Exited) && !resources.job_terminated {
        let _ = resources.terminate_for_cleanup();
    }
    if stdout_capture.pending() || stderr_capture.pending() {
        output_cleanup_bounded =
            cancel_and_drain_h7_output(&options.metrics, &mut stdout_capture, &mut stderr_capture)
                && output_cleanup_bounded;
    }
    update_h7_pending_output_metric(&options.metrics, &stdout_capture, &stderr_capture);
    // Compatibility fields retained from the R2 result shape.  R3 has no
    // reader threads to join; a stream is cleanup-complete once it has no
    // outstanding overlapped read, including the pre-arm cancellation race.
    let stdout_reader_joined = !stdout_capture.pending();
    let stderr_reader_joined = !stderr_capture.pending();
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
    options
        .metrics
        .pending_output_reads
        .store(0, Ordering::Release);
    let output_handles_closed = options
        .metrics
        .output_handles_active
        .load(Ordering::Acquire)
        == 4;
    drop(_output_handle_guard);
    let termination_unproven =
        (output_limited || cancelled || timed_out || output_failure || !output_cleanup_bounded)
            && !resources.job_terminated;
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
        output_handles_closed,
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
        output_handles_closed: stdout_reader_joined && stderr_reader_joined,
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
    fn start(repo_root: &Path) -> Result<Arc<Self>, String> {
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
            capability_id: H7_CAPABILITY_ID.to_string(),
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
    if executable.is_file() {
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
}

impl H7Authority {
    fn new() -> Result<Arc<Self>, String> {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| "D29-H7 manifest has no repository parent".to_string())?
            .to_path_buf();
        Ok(Arc::new(Self {
            process: H7PersistentHostProcess::start(&repo_root)?,
            metrics: Arc::new(H7AuthorityMetrics::default()),
            response_fault: Mutex::new(None),
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
                    capability_id: H7_CAPABILITY_ID.to_string(),
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
    if canonical.canonical_evaluations != 1
        || canonical.production_registry_size != 0
        || canonical.test_registry_size != 1
        || canonical.authorization_row_reads != 1
        || canonical.life_id != binding.life_id
        || canonical.capability_id != H7_CAPABILITY_ID
        || canonical.outcome != "explicit_confirmation_required"
        || canonical.decision_code != "CAPABILITY_CONFIRMATION_REQUIRED"
        || canonical.risk_class != "Critical"
        || canonical.approval_floor != "ExplicitPerAction"
        || canonical.scope_requirement != "None"
        || canonical.authorization_revision != Some(revision)
    {
        return Err("D29-H7 canonical D28 evidence was invalid".to_string());
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
    output_handles_closed: bool,
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
            output_handles_closed: true,
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
            output_handles_closed: native.output_handles_closed,
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
    active_cancellation: Arc<Mutex<Option<H7ActiveCancellation>>>,
    metrics: Arc<H7SupervisorMetrics>,
    final_fence_gate: Option<Arc<H7FinalFenceGate>>,
    post_host_gate: Option<Arc<H7PostHostFenceGate>>,
    native_fault: H7NativeLaunchFault,
    unlisted_inheritable_handle: Option<usize>,
    post_host_mutation: H7PostHostMutation,
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
            active_cancellation: Arc::new(Mutex::new(None)),
            metrics: Arc::new(H7SupervisorMetrics::default()),
            final_fence_gate: None,
            post_host_gate: None,
            native_fault: H7NativeLaunchFault::None,
            unlisted_inheritable_handle: None,
            post_host_mutation: H7PostHostMutation::None,
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
        let cancellation = Arc::new(AtomicBool::new(false));
        let cancellation_notify = Arc::new(Notify::new());
        let guard = H7ActionCancellationGuard::new(
            Arc::clone(&self.active_cancellation),
            Arc::clone(&cancellation),
            Arc::clone(&cancellation_notify),
        );
        let result = self
            .execute_with_cancellation(action, cancellation, cancellation_notify)
            .await;
        guard.disarm();
        result
    }

    async fn execute_with_cancellation(
        self: &Arc<Self>,
        action: Arc<PreparedProcessAction>,
        cancellation: Arc<AtomicBool>,
        cancellation_notify: Arc<Notify>,
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
        let grant = match tokio::task::spawn_blocking(move || {
            authority.issue_process_grant(&action_for_grant, authorization_revision)
        })
        .await
        {
            Ok(Ok(grant)) => grant,
            _ => return H7ToolResult::denied(),
        };
        let preparation_action = Arc::clone(&action);
        let unlisted_inheritable_handle = self.unlisted_inheritable_handle;
        let preparation = match tokio::task::spawn_blocking(move || {
            H7LaunchPreparation::prepare(&preparation_action, unlisted_inheritable_handle)
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
        let worker_metrics = Arc::clone(&metrics);
        match tokio::task::spawn_blocking(move || {
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
        let cancellation = Arc::new(AtomicBool::new(false));
        let cancellation_notify = Arc::new(Notify::new());
        let guard = H7ActionCancellationGuard::new(
            Arc::clone(&self.broker.active_cancellation),
            Arc::clone(&cancellation),
            Arc::clone(&cancellation_notify),
        );
        let result = self
            .broker
            .execute_with_cancellation(action, cancellation, cancellation_notify)
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
        assert!(result.output_handles_closed);
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
        assert!(result.output_handles_closed);
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

    #[tokio::test(flavor = "current_thread")]
    async fn h7_output_overflow_exit_race_is_output_limited() {
        let _lock = lock_h7_tests();
        let result = run_h7_approved_fixture(&["flood-stdout"]).await;
        assert_eq!(result.status, "started_and_output_limited");
        assert!(result.stdout_retained_bytes <= H7_STDOUT_BOUND);
        assert_h7_output_cleanup(&result);
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
            unsafe { GetHandleInformation(capture.read.raw(), &mut read_flags) },
            0
        );
        assert_ne!(
            unsafe { GetHandleInformation(capture.event.raw(), &mut event_flags) },
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

    struct H7ResponsesFixture {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        observation: Arc<Mutex<H7FixtureObservation>>,
        gate: Arc<H7Gate>,
        join: Option<JoinHandle<()>>,
    }

    impl H7ResponsesFixture {
        fn start() -> Self {
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
                    );
                    let mut observed = observation_for_thread
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    observed.request_count += 1;
                    if let Ok(body) = &result {
                        if request_index == 0 {
                            observed.first_request_schema_exact = exact_h7_process_schema(body);
                            observed.initial_turn_id = extract_h7_turn_id(body);
                        } else {
                            observed.function_call_output = h7_function_call_output(body);
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
    ) -> Result<Vec<u8>, String> {
        if !peer.ip().is_loopback() {
            return Err("D29-H7 fixture received a non-loopback peer".to_string());
        }
        let body = read_h7_http_request(stream)?;
        if request_index == 0 {
            gate.capture_turn_id(&body)?;
            gate.wait_until_released()?;
            write_h7_sse_response(stream, h7_first_response_events())?;
        } else if request_index == 1 {
            write_h7_sse_response(stream, h7_completion_response_events())?;
        } else {
            return Err("D29-H7 fixture received too many requests".to_string());
        }
        Ok(body)
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
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| value.get("input").cloned())
            .and_then(|value| value.as_array().cloned())
            .and_then(|items| {
                items.into_iter().find_map(|item| {
                    (item.get("type").and_then(Value::as_str) == Some("function_call_output")
                        && item.get("call_id").and_then(Value::as_str)
                            == Some("call-d29h7-process"))
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
        ];
        match value {
            Value::Object(object) => object.iter().any(|(key, value)| {
                FORBIDDEN.contains(&key.as_str()) || h7_output_has_authority_facts(value)
            }),
            Value::Array(values) => values.iter().any(h7_output_has_authority_facts),
            _ => false,
        }
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

    async fn start_h7_runtime(
        app_data_root: PathBuf,
        workspace_root: PathBuf,
        fixture: H7ResponsesFixture,
        contributor: VitaProcessToolContributor,
        tool_call_count: Arc<AtomicUsize>,
    ) -> Result<H7Runtime, String> {
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
}
