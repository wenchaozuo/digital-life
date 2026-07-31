use std::{
    ffi::OsStr,
    fs,
    io::ErrorKind,
    os::windows::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    ptr,
};

use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, ERROR_SUCCESS,
        FILETIME, HANDLE, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::{
        RestartManager::{
            RmEndSession, RmGetList, RmRegisterResources, RmStartSession, CCH_RM_SESSION_KEY,
            RM_PROCESS_INFO, RM_UNIQUE_PROCESS,
        },
        Threading::{
            CreateMutexW, GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess,
            ReleaseMutex, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE,
        },
    },
};

use super::{LegacyWriterInspection, LegacyWriterSnapshot, ProcessInstanceId, UpgradeGateError};

const UPGRADE_MUTEX_PREFIX: &str = "Global\\DigitalLife-H1-Upgrade-v1-";
const MAX_UPGRADE_MUTEX_NAME_UTF16: usize = 128;
const UPGRADE_MUTEX_TIMEOUT_MS: u32 = 0;
const MAX_RESTART_MANAGER_PROCESS_CAPACITY: u32 = 4096;
const MAX_RESTART_MANAGER_LIST_ATTEMPTS: usize = 8;

/// Owns a Windows Global mutex for one normalized database identity.
///
/// `HANDLE` remains private and is intentionally not asserted `Send` or
/// `Sync`; Windows mutex ownership is thread-affine.
pub(crate) struct WindowsUpgradeMutexGuard {
    handle: HANDLE,
    owns_mutex: bool,
}

impl Drop for WindowsUpgradeMutexGuard {
    fn drop(&mut self) {
        unsafe {
            if self.owns_mutex {
                let _ = ReleaseMutex(self.handle);
            }
            if !self.handle.is_null() {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

/// Acquires the bounded, database-specific Windows Global upgrade mutex.
///
/// This function does not open the database and is not wired into storage
/// initialization. H1-A3 will acquire it before opening SQLite.
pub(crate) fn acquire_upgrade_mutex(
    database_path: &Path,
) -> Result<WindowsUpgradeMutexGuard, UpgradeGateError> {
    let name = upgrade_mutex_name(database_path)?;
    let name = wide_nul_from_text(&name)
        .map_err(|_| UpgradeGateError::UpgradeMutexNameDerivationFailed)?;

    let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(UpgradeGateError::UpgradeExclusiveGateUnavailable);
    }

    let wait_result = unsafe { WaitForSingleObject(handle, UPGRADE_MUTEX_TIMEOUT_MS) };
    match wait_result {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(WindowsUpgradeMutexGuard {
            handle,
            owns_mutex: true,
        }),
        WAIT_TIMEOUT => close_failed_mutex_acquisition(handle),
        WAIT_FAILED => close_failed_mutex_acquisition(handle),
        _ => close_failed_mutex_acquisition(handle),
    }
}

fn close_failed_mutex_acquisition(
    handle: HANDLE,
) -> Result<WindowsUpgradeMutexGuard, UpgradeGateError> {
    unsafe {
        let _ = CloseHandle(handle);
    }
    Err(UpgradeGateError::UpgradeExclusiveGateUnavailable)
}

/// Captures non-current processes that currently occupy the database resources.
///
/// The returned snapshot is opaque. A `Clear` result is only a point-in-time
/// observation and must not be used to skip H1-A3's final recheck.
pub(crate) fn inspect_database_resource_occupants(
    database_path: &Path,
) -> Result<LegacyWriterInspection, UpgradeGateError> {
    let resources = database_resource_paths(database_path)?;
    inspect_with_restart_manager(&SystemRestartManagerApi, &SystemProcessApi, &resources)
}

/// Verifies whether every process in a previous inspection snapshot has ended.
///
/// A changed creation time is treated as PID reuse, meaning the original
/// Restart Manager process has ended. Process-status uncertainty fails closed.
pub(crate) fn verify_processes_terminated(
    snapshot: &LegacyWriterSnapshot,
) -> Result<LegacyWriterInspection, UpgradeGateError> {
    verify_processes_terminated_with_api(&SystemProcessApi, snapshot)
}

fn inspect_with_restart_manager<R: RestartManagerApi, P: ProcessApi>(
    restart_manager: &R,
    process_api: &P,
    resources: &[PathBuf],
) -> Result<LegacyWriterInspection, UpgradeGateError> {
    let session = RestartManagerSession::start(restart_manager)?;
    let resource_names = resources
        .iter()
        .map(|path| {
            wide_nul_from_path(path).map_err(|_| UpgradeGateError::RestartManagerRegistrationFailed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let resource_name_ptrs = resource_names
        .iter()
        .map(|name| name.as_ptr())
        .collect::<Vec<_>>();

    restart_manager
        .register_resources(session.handle, &resource_name_ptrs)
        .map_err(|_| UpgradeGateError::RestartManagerRegistrationFailed)?;

    let processes = collect_restart_manager_processes(restart_manager, session.handle)?;
    let current_process = process_api
        .current_process_instance()
        .map_err(|_| UpgradeGateError::ProcessIdentityReadFailed)?;
    let non_current_processes = processes
        .into_iter()
        .filter(|process| !process.is_same_instance(current_process))
        .collect::<Vec<_>>();

    inspection_from_processes(non_current_processes)
}

fn inspection_from_processes(
    processes: Vec<ProcessInstanceId>,
) -> Result<LegacyWriterInspection, UpgradeGateError> {
    if processes.is_empty() {
        Ok(LegacyWriterInspection::Clear)
    } else {
        let count = processes.len();
        Ok(LegacyWriterInspection::Occupied {
            count,
            snapshot: LegacyWriterSnapshot { processes },
        })
    }
}

fn verify_processes_terminated_with_api<P: ProcessApi>(
    process_api: &P,
    snapshot: &LegacyWriterSnapshot,
) -> Result<LegacyWriterInspection, UpgradeGateError> {
    let mut still_running = Vec::new();

    for process in &snapshot.processes {
        match process_api.open_process(process.pid) {
            OpenProcessResult::NoLongerExists => {}
            OpenProcessResult::Failed => return Err(UpgradeGateError::ProcessVerificationFailed),
            OpenProcessResult::Open(handle) => {
                let verification = match process_api.creation_time(&handle) {
                    Err(()) => Err(UpgradeGateError::ProcessVerificationFailed),
                    Ok(creation_time) if creation_time != process.creation_time => Ok(false),
                    Ok(_) => match process_api.wait_for_termination(&handle) {
                        ProcessWaitResult::Signaled => Ok(false),
                        ProcessWaitResult::Timeout => Ok(true),
                        ProcessWaitResult::Failed => {
                            Err(UpgradeGateError::ProcessVerificationFailed)
                        }
                    },
                };
                process_api.close_process(handle);

                if verification? {
                    still_running.push(*process);
                }
            }
        }
    }

    inspection_from_processes(still_running)
}

fn collect_restart_manager_processes<R: RestartManagerApi>(
    restart_manager: &R,
    session_handle: u32,
) -> Result<Vec<ProcessInstanceId>, UpgradeGateError> {
    let mut capacity = 0_u32;

    for _ in 0..MAX_RESTART_MANAGER_LIST_ATTEMPTS {
        let capacity_usize =
            usize::try_from(capacity).map_err(|_| UpgradeGateError::RestartManagerQueryFailed)?;
        let mut process_infos = vec![RM_PROCESS_INFO::default(); capacity_usize];

        match restart_manager.get_list(session_handle, &mut process_infos) {
            RestartManagerListReply::Complete {
                returned,
                reboot_reasons,
            } => {
                if returned == 0 && reboot_reasons != 0 {
                    return Err(UpgradeGateError::RestartManagerQueryFailed);
                }
                if returned > capacity {
                    return Err(UpgradeGateError::RestartManagerQueryFailed);
                }
                let returned_usize = usize::try_from(returned)
                    .map_err(|_| UpgradeGateError::RestartManagerQueryFailed)?;
                process_infos.truncate(returned_usize);

                let mut processes = Vec::with_capacity(process_infos.len());
                for process_info in process_infos {
                    let process = ProcessInstanceId::from_restart_manager(process_info.Process)?;
                    if !processes
                        .iter()
                        .any(|known: &ProcessInstanceId| known.is_same_instance(process))
                    {
                        processes.push(process);
                    }
                }
                return Ok(processes);
            }
            RestartManagerListReply::MoreData { needed } => {
                if needed == 0
                    || needed <= capacity
                    || needed > MAX_RESTART_MANAGER_PROCESS_CAPACITY
                {
                    return Err(UpgradeGateError::RestartManagerQueryFailed);
                }
                capacity = needed;
            }
            RestartManagerListReply::Failed => {
                return Err(UpgradeGateError::RestartManagerQueryFailed);
            }
        }
    }

    Err(UpgradeGateError::RestartManagerQueryFailed)
}

fn database_resource_paths(database_path: &Path) -> Result<Vec<PathBuf>, UpgradeGateError> {
    let mut resources = vec![database_path.to_path_buf()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = append_path_suffix(database_path, suffix);
        match fs::metadata(&sidecar) {
            Ok(metadata) if metadata.is_file() => resources.push(sidecar),
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(UpgradeGateError::RestartManagerRegistrationFailed),
        }
    }
    deduplicate_resource_paths(resources)
}

fn append_path_suffix(database_path: &Path, suffix: &str) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn deduplicate_resource_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>, UpgradeGateError> {
    let mut keys = Vec::with_capacity(paths.len());
    let mut deduplicated = Vec::with_capacity(paths.len());

    for path in paths {
        let key = normalized_windows_path_text(&path)
            .map_err(|_| UpgradeGateError::RestartManagerRegistrationFailed)?;
        if !keys.iter().any(|known| known == &key) {
            keys.push(key);
            deduplicated.push(path);
        }
    }

    Ok(deduplicated)
}

fn upgrade_mutex_name(database_path: &Path) -> Result<String, UpgradeGateError> {
    let normalized_path = normalized_windows_path_text(database_path)?;
    let digest = Sha256::digest(normalized_path.as_bytes());
    let mut database_id = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(database_id, "{byte:02x}");
    }

    let name = format!("{UPGRADE_MUTEX_PREFIX}{database_id}");
    if name.encode_utf16().count() > MAX_UPGRADE_MUTEX_NAME_UTF16 {
        return Err(UpgradeGateError::UpgradeMutexNameDerivationFailed);
    }
    Ok(name)
}

fn normalized_windows_path_text(database_path: &Path) -> Result<String, UpgradeGateError> {
    if database_path.as_os_str().is_empty() {
        return Err(UpgradeGateError::UpgradeMutexNameDerivationFailed);
    }

    if !database_path.is_absolute() {
        return Err(UpgradeGateError::UpgradeMutexNameDerivationFailed);
    }
    let absolute = database_path.to_path_buf();
    let lexical = lexically_normalize(&absolute)?;
    let canonical = fs::canonicalize(&lexical).unwrap_or(lexical);
    let wide = canonical.as_os_str().encode_wide().collect::<Vec<_>>();
    let path_text = String::from_utf16(&wide)
        .map_err(|_| UpgradeGateError::UpgradeMutexNameDerivationFailed)?;
    let path_text = path_text.replace('/', "\\");
    let path_text = strip_extended_path_prefix(path_text);
    let normalized = path_text.to_lowercase();

    if normalized.is_empty() || normalized.contains('\0') {
        return Err(UpgradeGateError::UpgradeMutexNameDerivationFailed);
    }
    Ok(normalized)
}

fn lexically_normalize(path: &Path) -> Result<PathBuf, UpgradeGateError> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
        }
    }

    if !normalized.is_absolute() {
        return Err(UpgradeGateError::UpgradeMutexNameDerivationFailed);
    }
    Ok(normalized)
}

fn strip_extended_path_prefix(path: String) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        path
    }
}

fn wide_nul_from_path(path: &Path) -> Result<Vec<u16>, ()> {
    wide_nul(path.as_os_str())
}

fn wide_nul_from_text(text: &str) -> Result<Vec<u16>, ()> {
    wide_nul(OsStr::new(text))
}

fn wide_nul(value: &OsStr) -> Result<Vec<u16>, ()> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(());
    }
    wide.push(0);
    Ok(wide)
}

impl ProcessInstanceId {
    fn from_restart_manager(process: RM_UNIQUE_PROCESS) -> Result<Self, UpgradeGateError> {
        Self::new(
            process.dwProcessId,
            filetime_to_u64(process.ProcessStartTime),
        )
    }

    fn new(pid: u32, creation_time: u64) -> Result<Self, UpgradeGateError> {
        if pid == 0 || creation_time == 0 {
            return Err(UpgradeGateError::ProcessIdentityReadFailed);
        }
        Ok(Self { pid, creation_time })
    }

    fn is_same_instance(self, other: Self) -> bool {
        self.pid == other.pid && self.creation_time == other.creation_time
    }
}

fn filetime_to_u64(filetime: FILETIME) -> u64 {
    (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime)
}

trait RestartManagerApi {
    fn start_session(&self, session_key: &mut [u16]) -> Result<u32, ()>;
    fn end_session(&self, handle: u32);
    fn register_resources(&self, handle: u32, resources: &[*const u16]) -> Result<(), ()>;
    fn get_list(
        &self,
        handle: u32,
        process_infos: &mut [RM_PROCESS_INFO],
    ) -> RestartManagerListReply;
}

struct RestartManagerSession<'a, R: RestartManagerApi> {
    api: &'a R,
    handle: u32,
}

impl<'a, R: RestartManagerApi> RestartManagerSession<'a, R> {
    fn start(api: &'a R) -> Result<Self, UpgradeGateError> {
        let mut session_key = [0_u16; CCH_RM_SESSION_KEY as usize + 1];
        let handle = api
            .start_session(&mut session_key)
            .map_err(|_| UpgradeGateError::RestartManagerSessionFailed)?;
        Ok(Self { api, handle })
    }
}

impl<R: RestartManagerApi> Drop for RestartManagerSession<'_, R> {
    fn drop(&mut self) {
        self.api.end_session(self.handle);
    }
}

enum RestartManagerListReply {
    Complete { returned: u32, reboot_reasons: u32 },
    MoreData { needed: u32 },
    Failed,
}

struct SystemRestartManagerApi;

impl RestartManagerApi for SystemRestartManagerApi {
    fn start_session(&self, session_key: &mut [u16]) -> Result<u32, ()> {
        let mut handle = 0_u32;
        let result = unsafe { RmStartSession(&mut handle, 0, session_key.as_mut_ptr()) };
        if result == ERROR_SUCCESS {
            Ok(handle)
        } else {
            Err(())
        }
    }

    fn end_session(&self, handle: u32) {
        unsafe {
            let _ = RmEndSession(handle);
        }
    }

    fn register_resources(&self, handle: u32, resources: &[*const u16]) -> Result<(), ()> {
        let resource_count = u32::try_from(resources.len()).map_err(|_| ())?;
        let result = unsafe {
            RmRegisterResources(
                handle,
                resource_count,
                resources.as_ptr(),
                0,
                ptr::null(),
                0,
                ptr::null(),
            )
        };
        if result == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(())
        }
    }

    fn get_list(
        &self,
        handle: u32,
        process_infos: &mut [RM_PROCESS_INFO],
    ) -> RestartManagerListReply {
        let mut needed = 0_u32;
        let mut returned = match u32::try_from(process_infos.len()) {
            Ok(value) => value,
            Err(_) => return RestartManagerListReply::Failed,
        };
        let mut reboot_reasons = 0_u32;
        let process_info_ptr = if process_infos.is_empty() {
            ptr::null_mut()
        } else {
            process_infos.as_mut_ptr()
        };
        let result = unsafe {
            RmGetList(
                handle,
                &mut needed,
                &mut returned,
                process_info_ptr,
                &mut reboot_reasons,
            )
        };
        match result {
            ERROR_SUCCESS => RestartManagerListReply::Complete {
                returned,
                reboot_reasons,
            },
            ERROR_MORE_DATA => RestartManagerListReply::MoreData { needed },
            _ => RestartManagerListReply::Failed,
        }
    }
}

enum OpenProcessResult<H> {
    Open(H),
    NoLongerExists,
    Failed,
}

#[derive(Clone, Copy)]
enum ProcessWaitResult {
    Signaled,
    Timeout,
    Failed,
}

trait ProcessApi {
    type Handle;

    fn current_process_instance(&self) -> Result<ProcessInstanceId, ()>;
    fn open_process(&self, pid: u32) -> OpenProcessResult<Self::Handle>;
    fn creation_time(&self, handle: &Self::Handle) -> Result<u64, ()>;
    fn wait_for_termination(&self, handle: &Self::Handle) -> ProcessWaitResult;
    fn close_process(&self, handle: Self::Handle);
}

struct SystemProcessApi;

impl ProcessApi for SystemProcessApi {
    type Handle = HANDLE;

    fn current_process_instance(&self) -> Result<ProcessInstanceId, ()> {
        let pid = unsafe { GetCurrentProcessId() };
        let creation_time = process_creation_time(unsafe { GetCurrentProcess() })?;
        ProcessInstanceId::new(pid, creation_time).map_err(|_| ())
    }

    fn open_process(&self, pid: u32) -> OpenProcessResult<Self::Handle> {
        let access = PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if !handle.is_null() {
            return OpenProcessResult::Open(handle);
        }

        if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
            OpenProcessResult::NoLongerExists
        } else {
            OpenProcessResult::Failed
        }
    }

    fn creation_time(&self, handle: &Self::Handle) -> Result<u64, ()> {
        process_creation_time(*handle)
    }

    fn wait_for_termination(&self, handle: &Self::Handle) -> ProcessWaitResult {
        match unsafe { WaitForSingleObject(*handle, 0) } {
            WAIT_OBJECT_0 => ProcessWaitResult::Signaled,
            WAIT_TIMEOUT => ProcessWaitResult::Timeout,
            WAIT_FAILED => ProcessWaitResult::Failed,
            _ => ProcessWaitResult::Failed,
        }
    }

    fn close_process(&self, handle: Self::Handle) {
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
}

fn process_creation_time(handle: HANDLE) -> Result<u64, ()> {
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();
    let result = unsafe {
        GetProcessTimes(
            handle,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
    };
    if result == 0 {
        return Err(());
    }

    let value = filetime_to_u64(creation_time);
    if value == 0 {
        return Err(());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        io::{BufRead, BufReader, Write},
        process::{Child, ChildStdin, Command, Stdio},
        sync::mpsc,
        thread,
        time::Duration,
    };

    use super::*;

    const CHILD_DATABASE_PATH_ENV: &str = "DIGITAL_LIFE_UPGRADE_GATE_CHILD_DATABASE_PATH";
    const CHILD_READY_MARKER: &str = "DIGITAL_LIFE_UPGRADE_GATE_CHILD_READY";
    const CHILD_RELEASE_MARKER: &[u8] = b"release\n";
    const CHILD_READY_TIMEOUT: Duration = Duration::from_secs(10);
    const STABILITY_REPETITIONS: usize = 10;

    struct FakeRestartManagerApi {
        start_succeeds: bool,
        register_succeeds: bool,
        list_replies: RefCell<VecDeque<TestRestartManagerListReply>>,
        ended_sessions: Cell<usize>,
    }

    impl FakeRestartManagerApi {
        fn new(list_replies: Vec<TestRestartManagerListReply>) -> Self {
            Self {
                start_succeeds: true,
                register_succeeds: true,
                list_replies: RefCell::new(list_replies.into()),
                ended_sessions: Cell::new(0),
            }
        }
    }

    enum TestRestartManagerListReply {
        Complete(Vec<RM_UNIQUE_PROCESS>),
        MoreData(u32),
        ReportedCount(u32),
        RebootReasonsWithoutProcesses,
        Failed,
    }

    impl RestartManagerApi for FakeRestartManagerApi {
        fn start_session(&self, session_key: &mut [u16]) -> Result<u32, ()> {
            if self.start_succeeds && session_key.len() == CCH_RM_SESSION_KEY as usize + 1 {
                Ok(1)
            } else {
                Err(())
            }
        }

        fn end_session(&self, _handle: u32) {
            self.ended_sessions.set(self.ended_sessions.get() + 1);
        }

        fn register_resources(&self, _handle: u32, resources: &[*const u16]) -> Result<(), ()> {
            if self.register_succeeds && !resources.is_empty() {
                Ok(())
            } else {
                Err(())
            }
        }

        fn get_list(
            &self,
            _handle: u32,
            process_infos: &mut [RM_PROCESS_INFO],
        ) -> RestartManagerListReply {
            match self.list_replies.borrow_mut().pop_front() {
                Some(TestRestartManagerListReply::Complete(processes)) => {
                    for (slot, process) in process_infos.iter_mut().zip(processes.iter()) {
                        slot.Process = *process;
                    }
                    RestartManagerListReply::Complete {
                        returned: u32::try_from(processes.len()).unwrap(),
                        reboot_reasons: 0,
                    }
                }
                Some(TestRestartManagerListReply::MoreData(needed)) => {
                    RestartManagerListReply::MoreData { needed }
                }
                Some(TestRestartManagerListReply::ReportedCount(returned)) => {
                    RestartManagerListReply::Complete {
                        returned,
                        reboot_reasons: 0,
                    }
                }
                Some(TestRestartManagerListReply::RebootReasonsWithoutProcesses) => {
                    RestartManagerListReply::Complete {
                        returned: 0,
                        reboot_reasons: 1,
                    }
                }
                Some(TestRestartManagerListReply::Failed) | None => RestartManagerListReply::Failed,
            }
        }
    }

    struct FakeProcessApi {
        current: Result<ProcessInstanceId, ()>,
        open_results: RefCell<VecDeque<TestOpenProcessResult>>,
        closed_handles: Cell<usize>,
    }

    impl FakeProcessApi {
        fn with_current(current: Result<ProcessInstanceId, ()>) -> Self {
            Self {
                current,
                open_results: RefCell::new(VecDeque::new()),
                closed_handles: Cell::new(0),
            }
        }

        fn with_open_results(open_results: Vec<TestOpenProcessResult>) -> Self {
            Self {
                current: Ok(process_instance(900, 900)),
                open_results: RefCell::new(open_results.into()),
                closed_handles: Cell::new(0),
            }
        }
    }

    enum TestOpenProcessResult {
        Open {
            creation_time: Result<u64, ()>,
            wait: ProcessWaitResult,
        },
        NoLongerExists,
        Failed,
    }

    struct FakeProcessHandle {
        creation_time: Result<u64, ()>,
        wait: ProcessWaitResult,
    }

    impl ProcessApi for FakeProcessApi {
        type Handle = FakeProcessHandle;

        fn current_process_instance(&self) -> Result<ProcessInstanceId, ()> {
            self.current
        }

        fn open_process(&self, _pid: u32) -> OpenProcessResult<Self::Handle> {
            match self.open_results.borrow_mut().pop_front() {
                Some(TestOpenProcessResult::Open {
                    creation_time,
                    wait,
                }) => OpenProcessResult::Open(FakeProcessHandle {
                    creation_time,
                    wait,
                }),
                Some(TestOpenProcessResult::NoLongerExists) => OpenProcessResult::NoLongerExists,
                Some(TestOpenProcessResult::Failed) | None => OpenProcessResult::Failed,
            }
        }

        fn creation_time(&self, handle: &Self::Handle) -> Result<u64, ()> {
            handle.creation_time
        }

        fn wait_for_termination(&self, handle: &Self::Handle) -> ProcessWaitResult {
            match handle.wait {
                ProcessWaitResult::Signaled => ProcessWaitResult::Signaled,
                ProcessWaitResult::Timeout => ProcessWaitResult::Timeout,
                ProcessWaitResult::Failed => ProcessWaitResult::Failed,
            }
        }

        fn close_process(&self, _handle: Self::Handle) {
            self.closed_handles.set(self.closed_handles.get() + 1);
        }
    }

    struct ChildResourceHolder {
        child: Child,
        stdin: Option<ChildStdin>,
        reader: Option<thread::JoinHandle<()>>,
        reaped: bool,
    }

    impl ChildResourceHolder {
        fn release(mut self) {
            if let Some(mut stdin) = self.stdin.take() {
                stdin.write_all(CHILD_RELEASE_MARKER).unwrap();
            }
            let status = self.child.wait().unwrap();
            self.reaped = true;
            assert!(status.success());
            if let Some(reader) = self.reader.take() {
                reader.join().unwrap();
            }
        }
    }

    impl Drop for ChildResourceHolder {
        fn drop(&mut self) {
            self.stdin.take();
            if !self.reaped {
                let _ = self.child.wait();
            }
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }

    #[test]
    fn upgrade_mutex_name_is_stable_for_equivalent_paths() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("identity");
        fs::create_dir_all(&directory).unwrap();
        let database = directory.join("database.sqlite3");
        fs::write(&database, b"fixture").unwrap();

        let canonical = fs::canonicalize(&database).unwrap();
        let equivalent = PathBuf::from(
            canonical
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_uppercase(),
        );

        assert_eq!(
            upgrade_mutex_name(&database).unwrap(),
            upgrade_mutex_name(&equivalent).unwrap()
        );
    }

    #[test]
    fn upgrade_mutex_name_changes_for_distinct_database_paths() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first.sqlite3");
        let second = root.path().join("second.sqlite3");

        assert_ne!(
            upgrade_mutex_name(&first).unwrap(),
            upgrade_mutex_name(&second).unwrap()
        );
    }

    #[test]
    fn upgrade_mutex_name_rejects_a_non_authoritative_relative_path() {
        let error = upgrade_mutex_name(Path::new("database.sqlite3")).unwrap_err();
        assert_eq!(error, UpgradeGateError::UpgradeMutexNameDerivationFailed);
    }

    #[test]
    fn upgrade_mutex_name_is_bounded_and_contains_no_raw_database_path() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("database.sqlite3");
        let name = upgrade_mutex_name(&database).unwrap();

        assert!(name.starts_with(UPGRADE_MUTEX_PREFIX));
        assert!(name.encode_utf16().count() <= MAX_UPGRADE_MUTEX_NAME_UTF16);
        assert!(!name.contains("database.sqlite3"));
        assert!(!name.contains(&root.path().to_string_lossy().to_string()));
    }

    #[test]
    fn database_resource_occupants_include_main_and_existing_sidecars_only() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("database.sqlite3");
        fs::write(&database, b"fixture").unwrap();
        fs::write(append_path_suffix(&database, "-wal"), b"wal").unwrap();
        fs::write(append_path_suffix(&database, "-journal"), b"journal").unwrap();

        let resources = database_resource_paths(&database).unwrap();
        assert_eq!(resources.len(), 3);
        assert!(resources.contains(&database));
        assert!(resources.contains(&append_path_suffix(&database, "-wal")));
        assert!(resources.contains(&append_path_suffix(&database, "-journal")));
        assert!(!resources.contains(&append_path_suffix(&database, "-shm")));
    }

    #[test]
    fn database_resource_occupants_are_deduplicated() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("database.sqlite3");
        let resources = deduplicate_resource_paths(vec![database.clone(), database]).unwrap();
        assert_eq!(resources.len(), 1);
    }

    #[test]
    fn process_instance_requires_pid_and_creation_time_match() {
        let current = process_instance(41, 100);
        assert!(current.is_same_instance(process_instance(41, 100)));
        assert!(!current.is_same_instance(process_instance(41, 101)));
        assert!(!current.is_same_instance(process_instance(42, 100)));
    }

    #[test]
    fn restart_manager_excludes_only_the_exact_current_process_instance() {
        let current = process_instance(41, 100);
        let restart_manager = FakeRestartManagerApi::new(vec![
            TestRestartManagerListReply::MoreData(2),
            TestRestartManagerListReply::Complete(vec![rm_process(41, 100), rm_process(41, 101)]),
        ]);
        let process_api = FakeProcessApi::with_current(Ok(current));

        let inspection = inspect_with_restart_manager(
            &restart_manager,
            &process_api,
            &[PathBuf::from(r"C:\fixture\database.sqlite3")],
        )
        .unwrap();

        assert_eq!(inspection.count(), 1);
        assert!(matches!(
            inspection,
            LegacyWriterInspection::Occupied { .. }
        ));
        assert_eq!(restart_manager.ended_sessions.get(), 1);
    }

    #[test]
    fn restart_manager_more_data_loop_expands_until_complete() {
        let restart_manager = FakeRestartManagerApi::new(vec![
            TestRestartManagerListReply::MoreData(1),
            TestRestartManagerListReply::MoreData(2),
            TestRestartManagerListReply::Complete(vec![rm_process(10, 10), rm_process(11, 11)]),
        ]);
        let process_api = FakeProcessApi::with_current(Ok(process_instance(99, 99)));

        let inspection = inspect_with_restart_manager(
            &restart_manager,
            &process_api,
            &[PathBuf::from(r"C:\fixture\database.sqlite3")],
        )
        .unwrap();

        assert_eq!(inspection.count(), 2);
        assert_eq!(restart_manager.ended_sessions.get(), 1);
    }

    #[test]
    fn restart_manager_unknown_query_result_fails_closed() {
        let restart_manager = FakeRestartManagerApi::new(vec![TestRestartManagerListReply::Failed]);
        let process_api = FakeProcessApi::with_current(Ok(process_instance(99, 99)));

        let error = expect_upgrade_gate_error(inspect_with_restart_manager(
            &restart_manager,
            &process_api,
            &[PathBuf::from(r"C:\fixture\database.sqlite3")],
        ));

        assert_eq!(error, UpgradeGateError::RestartManagerQueryFailed);
        assert_eq!(restart_manager.ended_sessions.get(), 1);
    }

    #[test]
    fn restart_manager_reboot_reasons_without_a_process_list_fail_closed() {
        let restart_manager = FakeRestartManagerApi::new(vec![
            TestRestartManagerListReply::RebootReasonsWithoutProcesses,
        ]);
        let process_api = FakeProcessApi::with_current(Ok(process_instance(99, 99)));

        let error = expect_upgrade_gate_error(inspect_with_restart_manager(
            &restart_manager,
            &process_api,
            &[PathBuf::from(r"C:\fixture\database.sqlite3")],
        ));

        assert_eq!(error, UpgradeGateError::RestartManagerQueryFailed);
    }

    #[test]
    fn restart_manager_capacity_overflow_fails_closed() {
        let restart_manager =
            FakeRestartManagerApi::new(vec![TestRestartManagerListReply::MoreData(
                MAX_RESTART_MANAGER_PROCESS_CAPACITY + 1,
            )]);
        let process_api = FakeProcessApi::with_current(Ok(process_instance(99, 99)));

        let error = expect_upgrade_gate_error(inspect_with_restart_manager(
            &restart_manager,
            &process_api,
            &[PathBuf::from(r"C:\fixture\database.sqlite3")],
        ));

        assert_eq!(error, UpgradeGateError::RestartManagerQueryFailed);
    }

    #[test]
    fn restart_manager_returned_count_outside_capacity_fails_closed() {
        let restart_manager =
            FakeRestartManagerApi::new(vec![TestRestartManagerListReply::ReportedCount(1)]);
        let process_api = FakeProcessApi::with_current(Ok(process_instance(99, 99)));

        let error = expect_upgrade_gate_error(inspect_with_restart_manager(
            &restart_manager,
            &process_api,
            &[PathBuf::from(r"C:\fixture\database.sqlite3")],
        ));

        assert_eq!(error, UpgradeGateError::RestartManagerQueryFailed);
    }

    #[test]
    fn restart_manager_start_and_registration_failures_are_distinct_and_close_sessions() {
        let mut start_fails = FakeRestartManagerApi::new(Vec::new());
        start_fails.start_succeeds = false;
        let process_api = FakeProcessApi::with_current(Ok(process_instance(99, 99)));
        let start_error = expect_upgrade_gate_error(inspect_with_restart_manager(
            &start_fails,
            &process_api,
            &[PathBuf::from(r"C:\fixture\database.sqlite3")],
        ));
        assert_eq!(start_error, UpgradeGateError::RestartManagerSessionFailed);
        assert_eq!(start_fails.ended_sessions.get(), 0);

        let mut registration_fails = FakeRestartManagerApi::new(Vec::new());
        registration_fails.register_succeeds = false;
        let registration_error = expect_upgrade_gate_error(inspect_with_restart_manager(
            &registration_fails,
            &process_api,
            &[PathBuf::from(r"C:\fixture\database.sqlite3")],
        ));
        assert_eq!(
            registration_error,
            UpgradeGateError::RestartManagerRegistrationFailed
        );
        assert_eq!(registration_fails.ended_sessions.get(), 1);
    }

    #[test]
    fn restart_manager_current_process_identity_failure_fails_closed() {
        let restart_manager =
            FakeRestartManagerApi::new(vec![TestRestartManagerListReply::Complete(Vec::new())]);
        let process_api = FakeProcessApi::with_current(Err(()));

        let error = expect_upgrade_gate_error(inspect_with_restart_manager(
            &restart_manager,
            &process_api,
            &[PathBuf::from(r"C:\fixture\database.sqlite3")],
        ));

        assert_eq!(error, UpgradeGateError::ProcessIdentityReadFailed);
    }

    #[test]
    fn process_instance_pid_reuse_is_treated_as_original_process_terminated() {
        let snapshot = snapshot_with(process_instance(41, 100));
        let process_api = FakeProcessApi::with_open_results(vec![TestOpenProcessResult::Open {
            creation_time: Ok(101),
            wait: ProcessWaitResult::Failed,
        }]);

        let inspection = verify_processes_terminated_with_api(&process_api, &snapshot).unwrap();
        assert!(matches!(inspection, LegacyWriterInspection::Clear));
        assert_eq!(process_api.closed_handles.get(), 1);
    }

    #[test]
    fn process_instance_open_process_access_denied_fails_closed() {
        let snapshot = snapshot_with(process_instance(41, 100));
        let process_api = FakeProcessApi::with_open_results(vec![TestOpenProcessResult::Failed]);

        let error = expect_upgrade_gate_error(verify_processes_terminated_with_api(
            &process_api,
            &snapshot,
        ));
        assert_eq!(error, UpgradeGateError::ProcessVerificationFailed);
    }

    #[test]
    fn process_instance_get_process_times_failure_fails_closed() {
        let snapshot = snapshot_with(process_instance(41, 100));
        let process_api = FakeProcessApi::with_open_results(vec![TestOpenProcessResult::Open {
            creation_time: Err(()),
            wait: ProcessWaitResult::Signaled,
        }]);

        let error = expect_upgrade_gate_error(verify_processes_terminated_with_api(
            &process_api,
            &snapshot,
        ));
        assert_eq!(error, UpgradeGateError::ProcessVerificationFailed);
        assert_eq!(process_api.closed_handles.get(), 1);
    }

    #[test]
    fn process_instance_wait_failure_fails_closed() {
        let snapshot = snapshot_with(process_instance(41, 100));
        let process_api = FakeProcessApi::with_open_results(vec![TestOpenProcessResult::Open {
            creation_time: Ok(100),
            wait: ProcessWaitResult::Failed,
        }]);

        let error = expect_upgrade_gate_error(verify_processes_terminated_with_api(
            &process_api,
            &snapshot,
        ));
        assert_eq!(error, UpgradeGateError::ProcessVerificationFailed);
        assert_eq!(process_api.closed_handles.get(), 1);
    }

    #[test]
    fn process_instance_live_process_remains_occupied() {
        let snapshot = snapshot_with(process_instance(41, 100));
        let process_api = FakeProcessApi::with_open_results(vec![TestOpenProcessResult::Open {
            creation_time: Ok(100),
            wait: ProcessWaitResult::Timeout,
        }]);

        let inspection = verify_processes_terminated_with_api(&process_api, &snapshot).unwrap();
        assert_eq!(inspection.count(), 1);
        assert!(matches!(
            inspection,
            LegacyWriterInspection::Occupied { .. }
        ));
    }

    #[test]
    fn process_instance_explicitly_missing_process_is_clear() {
        let snapshot = snapshot_with(process_instance(41, 100));
        let process_api =
            FakeProcessApi::with_open_results(vec![TestOpenProcessResult::NoLongerExists]);

        let inspection = verify_processes_terminated_with_api(&process_api, &snapshot).unwrap();
        assert!(matches!(inspection, LegacyWriterInspection::Clear));
    }

    #[test]
    fn upgrade_gate_errors_are_static_and_deidentified() {
        for error in [
            UpgradeGateError::UnsupportedPlatform,
            UpgradeGateError::UpgradeMutexNameDerivationFailed,
            UpgradeGateError::UpgradeExclusiveGateUnavailable,
            UpgradeGateError::RestartManagerSessionFailed,
            UpgradeGateError::RestartManagerRegistrationFailed,
            UpgradeGateError::RestartManagerQueryFailed,
            UpgradeGateError::ProcessIdentityReadFailed,
            UpgradeGateError::ProcessVerificationFailed,
            UpgradeGateError::LegacyWriterDetected,
        ] {
            assert!(!error.code().contains(':'));
            assert!(!error.message().contains(r"C:\"));
            assert!(!error.message().contains("fixture"));
        }
    }

    #[test]
    fn upgrade_gate_windows_upgrade_mutex_releases_before_a_new_acquisition() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("database.sqlite3");

        let guard = acquire_upgrade_mutex(&database).unwrap();
        drop(guard);
        let guard = acquire_upgrade_mutex(&database).unwrap();
        drop(guard);
    }

    #[test]
    fn upgrade_gate_windows_upgrade_mutex_allows_distinct_database_identities_in_parallel() {
        let root = tempfile::tempdir().unwrap();
        let first_database = root.path().join("first.sqlite3");
        let second_database = root.path().join("second.sqlite3");

        let first_guard = acquire_upgrade_mutex(&first_database).unwrap();
        let second_guard = acquire_upgrade_mutex(&second_database).unwrap();
        drop(second_guard);
        drop(first_guard);
    }

    #[test]
    fn upgrade_gate_windows_upgrade_mutex_same_identity_competition_is_stable() {
        for repetition in 0..STABILITY_REPETITIONS {
            let root = tempfile::tempdir().unwrap();
            let database = root.path().join(format!("database-{repetition}.sqlite3"));
            let guard = acquire_upgrade_mutex(&database).unwrap();
            let contender_path = database.clone();
            let contender = thread::spawn(move || {
                acquire_upgrade_mutex(&contender_path).map(|guard| {
                    drop(guard);
                })
            });

            let error = contender.join().unwrap().unwrap_err();
            assert_eq!(error, UpgradeGateError::UpgradeExclusiveGateUnavailable);
            drop(guard);
        }
    }

    #[test]
    fn upgrade_gate_windows_restart_manager_database_resource_occupants_excludes_current_process_with_open_target(
    ) {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("database.sqlite3");
        fs::write(&database, b"fixture").unwrap();
        let _open_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&database)
            .unwrap();

        let inspection = inspect_database_resource_occupants(&database).unwrap();
        assert!(matches!(inspection, LegacyWriterInspection::Clear));
    }

    #[test]
    fn upgrade_gate_windows_restart_manager_database_resource_occupants_child_detection_and_exit_verification_is_stable(
    ) {
        for repetition in 0..STABILITY_REPETITIONS {
            let root = tempfile::tempdir().unwrap();
            let database = root.path().join(format!("database-{repetition}.sqlite3"));
            fs::write(&database, b"fixture").unwrap();
            let child = spawn_child_holding_resource(&database);

            let inspection = inspect_database_resource_occupants(&database).unwrap();
            let snapshot = match inspection {
                LegacyWriterInspection::Occupied { count, snapshot } => {
                    assert!(count >= 1);
                    snapshot
                }
                LegacyWriterInspection::Clear => {
                    panic!("the child process must occupy the registered test resource")
                }
            };

            child.release();
            let verification = verify_processes_terminated(&snapshot).unwrap();
            assert!(matches!(verification, LegacyWriterInspection::Clear));
        }
    }

    #[test]
    fn upgrade_gate_windows_child_process_helper() {
        let Some(path) = std::env::var_os(CHILD_DATABASE_PATH_ENV) else {
            return;
        };
        let _open_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(PathBuf::from(path))
            .unwrap();

        println!("{CHILD_READY_MARKER}");
        std::io::stdout().flush().unwrap();
        let mut release = String::new();
        std::io::stdin().read_line(&mut release).unwrap();
    }

    fn spawn_child_holding_resource(database: &Path) -> ChildResourceHolder {
        let executable = std::env::current_exe().unwrap();
        let mut child = Command::new(executable)
            .arg("upgrade_gate_windows_child_process_helper")
            .arg("--nocapture")
            .env(CHILD_DATABASE_PATH_ENV, database)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (ready_sender, ready_receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut ready_sent = false;
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) if line == CHILD_READY_MARKER && !ready_sent => {
                        ready_sent = true;
                        let _ = ready_sender.send(true);
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            if !ready_sent {
                let _ = ready_sender.send(false);
            }
        });

        match ready_receiver.recv_timeout(CHILD_READY_TIMEOUT) {
            Ok(true) => ChildResourceHolder {
                child,
                stdin: Some(stdin),
                reader: Some(reader),
                reaped: false,
            },
            Ok(false) | Err(_) => {
                drop(stdin);
                let _ = child.wait();
                let _ = reader.join();
                panic!("the test child process did not complete the explicit readiness handshake")
            }
        }
    }

    fn process_instance(pid: u32, creation_time: u64) -> ProcessInstanceId {
        ProcessInstanceId::new(pid, creation_time).unwrap()
    }

    fn rm_process(pid: u32, creation_time: u64) -> RM_UNIQUE_PROCESS {
        RM_UNIQUE_PROCESS {
            dwProcessId: pid,
            ProcessStartTime: FILETIME {
                dwLowDateTime: creation_time as u32,
                dwHighDateTime: (creation_time >> 32) as u32,
            },
        }
    }

    fn snapshot_with(process: ProcessInstanceId) -> LegacyWriterSnapshot {
        LegacyWriterSnapshot {
            processes: vec![process],
        }
    }

    fn expect_upgrade_gate_error(
        result: Result<LegacyWriterInspection, UpgradeGateError>,
    ) -> UpgradeGateError {
        match result {
            Err(error) => error,
            Ok(_) => panic!("the upgrade gate operation must fail closed"),
        }
    }
}
