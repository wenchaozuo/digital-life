//! The Host-owned capability-authorization linearization boundary.
//!
//! D30 and D31 decisions can be made by more than one Host process.  The
//! process-local mutex is therefore only the first layer of this gate.  On
//! Windows a database-identity-bound Global mutex is acquired while the local
//! guard is held, giving all independently initialized services for the same
//! authoritative SQLite file one durable serialization point.

use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

#[cfg(windows)]
use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
};

#[cfg(windows)]
use super::upgrade_gate;

const CAPABILITY_AUTHORITY_MUTEX_PREFIX: &str = "Global\\DigitalLife-CapabilityAuthority-v1-";
const CAPABILITY_AUTHORITY_MUTEX_TIMEOUT_MS: u32 = 2_000;
const MAX_CAPABILITY_AUTHORITY_MUTEX_NAME_UTF16: usize = 128;

/// Stable, deidentified failure category for the D30/D31 composite gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CapabilityAuthorizationGateError;

impl CapabilityAuthorizationGateError {
    pub(super) const CODE: &'static str = "CAPABILITY_AUTHORIZATION_GATE_UNAVAILABLE";

    #[cfg(test)]
    pub(super) const fn code(self) -> &'static str {
        Self::CODE
    }
}

/// One process-local gate identity.  A separately initialized service gets a
/// distinct `Arc<CapabilityAuthorizationGate>`, while authority views opened
/// from one service intentionally clone that Arc.
pub(super) struct CapabilityAuthorizationGate {
    process_local: Mutex<()>,
    #[cfg(windows)]
    database_mutex_name: String,
}

impl CapabilityAuthorizationGate {
    pub(super) fn new(database_path: &Path) -> Result<Self, CapabilityAuthorizationGateError> {
        #[cfg(windows)]
        {
            let database_id = upgrade_gate::database_identity_hash(database_path)
                .map_err(|_| CapabilityAuthorizationGateError)?;
            let database_mutex_name = format!("{CAPABILITY_AUTHORITY_MUTEX_PREFIX}{database_id}");
            if database_mutex_name.encode_utf16().count()
                > MAX_CAPABILITY_AUTHORITY_MUTEX_NAME_UTF16
            {
                return Err(CapabilityAuthorizationGateError);
            }
            return Ok(Self {
                process_local: Mutex::new(()),
                database_mutex_name,
            });
        }

        #[cfg(not(windows))]
        {
            // D30 remains usable on non-Windows platforms, but a caller may
            // not manufacture an authority identity from a relative path.
            if !database_path.is_absolute() || database_path.as_os_str().is_empty() {
                return Err(CapabilityAuthorizationGateError);
            }
            Ok(Self {
                process_local: Mutex::new(()),
            })
        }
    }

    pub(super) fn lock(
        &self,
    ) -> Result<CapabilityAuthorizationGateGuard<'_>, CapabilityAuthorizationGateError> {
        let process_local = self
            .process_local
            .lock()
            .map_err(|_| CapabilityAuthorizationGateError)?;

        #[cfg(windows)]
        let windows = match acquire_windows_mutex(&self.database_mutex_name) {
            Ok(windows) => windows,
            Err(error) => {
                // Returning the error drops the process-local guard before
                // the caller can attempt another authorization mutation.
                drop(process_local);
                return Err(error);
            }
        };

        Ok(CapabilityAuthorizationGateGuard {
            process_local,
            #[cfg(windows)]
            windows,
        })
    }

    #[cfg(test)]
    pub(super) fn process_local_identity_for_test(&self) -> usize {
        &self.process_local as *const Mutex<()> as usize
    }

    #[cfg(test)]
    pub(super) fn mutex_name_for_test(&self) -> Option<&str> {
        #[cfg(windows)]
        {
            return Some(&self.database_mutex_name);
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    #[cfg(all(test, windows))]
    pub(super) fn keep_mutex_object_alive_for_test(
        &self,
    ) -> Result<CapabilityAuthorityMutexObjectKeeper, CapabilityAuthorizationGateError> {
        let name = wide_nul_from_text(&self.database_mutex_name)
            .map_err(|_| CapabilityAuthorizationGateError)?;
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(CapabilityAuthorizationGateError);
        }
        Ok(CapabilityAuthorityMutexObjectKeeper { handle })
    }
}

/// Guard returned by the one storage API used by D30 and D31.
#[allow(dead_code)]
pub(crate) struct CapabilityAuthorizationGateGuard<'a> {
    #[cfg(windows)]
    windows: WindowsCapabilityAuthorityMutexGuard,
    process_local: MutexGuard<'a, ()>,
}

impl<'a> CapabilityAuthorizationGateGuard<'a> {
    #[cfg(test)]
    pub(super) fn was_abandoned_for_test(&self) -> bool {
        #[cfg(windows)]
        {
            return self.windows.was_abandoned;
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

#[cfg(windows)]
struct WindowsCapabilityAuthorityMutexGuard {
    handle: HANDLE,
    #[cfg_attr(not(test), allow(dead_code))]
    was_abandoned: bool,
}

#[cfg(all(test, windows))]
pub(super) struct CapabilityAuthorityMutexObjectKeeper {
    handle: HANDLE,
}

#[cfg(all(test, windows))]
impl Drop for CapabilityAuthorityMutexObjectKeeper {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsCapabilityAuthorityMutexGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.handle);
            if !self.handle.is_null() {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(windows)]
fn acquire_windows_mutex(
    mutex_name: &str,
) -> Result<WindowsCapabilityAuthorityMutexGuard, CapabilityAuthorizationGateError> {
    let name = wide_nul_from_text(mutex_name).map_err(|_| CapabilityAuthorizationGateError)?;
    let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(CapabilityAuthorizationGateError);
    }

    let wait_result = unsafe { WaitForSingleObject(handle, CAPABILITY_AUTHORITY_MUTEX_TIMEOUT_MS) };
    match wait_result {
        WAIT_OBJECT_0 => Ok(WindowsCapabilityAuthorityMutexGuard {
            handle,
            was_abandoned: false,
        }),
        // An abandoned mutex still gives this caller ownership.  The mutex
        // stores no authority state; D30 immediately performs its CAS and
        // D31 immediately performs its fresh SQLite read while this composite
        // guard is held, so no state is inferred from the dead owner.
        WAIT_ABANDONED => Ok(WindowsCapabilityAuthorityMutexGuard {
            handle,
            was_abandoned: true,
        }),
        WAIT_TIMEOUT | WAIT_FAILED => close_failed_mutex_acquisition(handle),
        _ => close_failed_mutex_acquisition(handle),
    }
}

#[cfg(windows)]
fn close_failed_mutex_acquisition(
    handle: HANDLE,
) -> Result<WindowsCapabilityAuthorityMutexGuard, CapabilityAuthorizationGateError> {
    unsafe {
        let _ = CloseHandle(handle);
    }
    Err(CapabilityAuthorizationGateError)
}

#[cfg(windows)]
fn wide_nul_from_text(value: &str) -> Result<Vec<u16>, ()> {
    if value.is_empty() || value.encode_utf16().any(|unit| unit == 0) {
        return Err(());
    }
    let mut wide = OsStr::new(value).encode_wide().collect::<Vec<_>>();
    wide.push(0);
    Ok(wide)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
    };

    use tempfile::TempDir;

    use super::*;

    #[cfg(windows)]
    const CHILD_MODE_ENV: &str = "DIGITAL_LIFE_CAPABILITY_GATE_CHILD_MODE";
    #[cfg(windows)]
    const CHILD_DATABASE_ENV: &str = "DIGITAL_LIFE_CAPABILITY_GATE_CHILD_DATABASE";
    #[cfg(windows)]
    const CHILD_READY: &str = "CAPABILITY_GATE_CHILD_READY";
    #[cfg(windows)]
    const CHILD_ACQUIRED: &str = "CAPABILITY_GATE_CHILD_ACQUIRED";
    #[cfg(windows)]
    const CHILD_HELD: &str = "CAPABILITY_GATE_CHILD_HELD";
    #[cfg(windows)]
    const CHILD_TIMEOUT: &str = "CAPABILITY_GATE_CHILD_TIMEOUT";

    fn fixture_database() -> (TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("database.sqlite3");
        fs::write(&database, b"fixture").unwrap();
        let database = fs::canonicalize(database).unwrap();
        (root, database)
    }

    #[cfg(windows)]
    #[test]
    fn same_database_identity_uses_same_capability_mutex_name() {
        let (_root, database) = fixture_database();
        let equivalent = PathBuf::from(
            database
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_uppercase(),
        );

        let first = CapabilityAuthorizationGate::new(&database).unwrap();
        let second = CapabilityAuthorizationGate::new(&equivalent).unwrap();
        assert_eq!(first.mutex_name_for_test(), second.mutex_name_for_test());
    }

    #[cfg(windows)]
    #[test]
    fn different_database_identities_use_different_capability_mutex_names() {
        let (root, first_path) = fixture_database();
        let second_path = root.path().join("other.sqlite3");
        fs::write(&second_path, b"fixture").unwrap();

        let first = CapabilityAuthorizationGate::new(&first_path).unwrap();
        let second = CapabilityAuthorizationGate::new(&second_path).unwrap();
        assert_ne!(first.mutex_name_for_test(), second.mutex_name_for_test());
    }

    #[cfg(windows)]
    #[test]
    fn capability_mutex_name_is_bounded_and_contains_no_raw_database_path() {
        let (root, database) = fixture_database();
        let gate = CapabilityAuthorizationGate::new(&database).unwrap();
        let name = gate.mutex_name_for_test().unwrap();
        assert!(name.starts_with(CAPABILITY_AUTHORITY_MUTEX_PREFIX));
        assert!(name.encode_utf16().count() <= MAX_CAPABILITY_AUTHORITY_MUTEX_NAME_UTF16);
        assert!(!name.contains(&database.to_string_lossy().to_string()));
        assert!(!name.contains(&root.path().to_string_lossy().to_string()));
    }

    #[test]
    fn relative_database_identity_is_rejected() {
        let error = match CapabilityAuthorizationGate::new(Path::new("database.sqlite3")) {
            Ok(_) => panic!("a relative database path must not create an authority identity"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "CAPABILITY_AUTHORIZATION_GATE_UNAVAILABLE");
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_gate_keeps_d30_process_local_only() {
        let (_root, database) = fixture_database();
        let first = CapabilityAuthorizationGate::new(&database).unwrap();
        let second = CapabilityAuthorizationGate::new(&database).unwrap();
        assert_ne!(
            first.process_local_identity_for_test(),
            second.process_local_identity_for_test()
        );
        assert_eq!(first.mutex_name_for_test(), None);
        assert_eq!(second.mutex_name_for_test(), None);
        let first_guard = first.lock().unwrap();
        let second_guard = second.lock().unwrap();
        drop(second_guard);
        drop(first_guard);
    }

    #[cfg(windows)]
    #[test]
    fn independent_gate_instances_have_distinct_local_guards_but_same_global_name() {
        let (_root, database) = fixture_database();
        let first = CapabilityAuthorizationGate::new(&database).unwrap();
        let second = CapabilityAuthorizationGate::new(&database).unwrap();
        assert_ne!(
            first.process_local_identity_for_test(),
            second.process_local_identity_for_test()
        );
        assert_eq!(first.mutex_name_for_test(), second.mutex_name_for_test());
    }

    #[cfg(windows)]
    #[test]
    fn bounded_contention_fails_closed_without_retry() {
        use std::thread;

        let (_root, database) = fixture_database();
        let first = CapabilityAuthorizationGate::new(&database).unwrap();
        let guard = first.lock().unwrap();
        let contender_path = database.clone();
        let contender = thread::spawn(move || {
            let second = CapabilityAuthorizationGate::new(&contender_path).unwrap();
            let result = match second.lock() {
                Ok(_) => panic!("the capability gate must reject bounded contention"),
                Err(error) => error,
            };
            result
        });
        let error = contender.join().unwrap();
        assert_eq!(error.code(), "CAPABILITY_AUTHORIZATION_GATE_UNAVAILABLE");
        drop(guard);
        let second = CapabilityAuthorizationGate::new(&database).unwrap();
        assert!(second.lock().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn abandoned_mutex_is_accepted_and_marked_for_fresh_read_behavior() {
        let (_root, database) = fixture_database();
        let gate = CapabilityAuthorizationGate::new(&database).unwrap();
        let _keep_alive = gate.keep_mutex_object_alive_for_test().unwrap();
        let mut child = spawn_child(&database, "abandon");
        assert!(read_child_marker(&mut child, CHILD_READY));
        assert!(read_child_marker(&mut child, CHILD_HELD));
        assert!(child.wait().unwrap().success());

        let guard = gate.lock().unwrap();
        assert!(guard.was_abandoned_for_test());
    }

    #[cfg(windows)]
    #[test]
    fn subprocess_waits_for_and_then_acquires_released_capability_mutex() {
        let (_root, database) = fixture_database();
        let gate = CapabilityAuthorizationGate::new(&database).unwrap();
        let guard = gate.lock().unwrap();
        let mut child = spawn_child(&database, "wait-release");
        assert!(read_child_marker(&mut child, CHILD_READY));
        drop(guard);
        assert!(read_child_marker(&mut child, CHILD_ACQUIRED));
        assert!(child.wait().unwrap().success());
    }

    #[cfg(windows)]
    #[test]
    fn subprocess_contention_times_out_with_stable_gate_error() {
        let (_root, database) = fixture_database();
        let gate = CapabilityAuthorizationGate::new(&database).unwrap();
        let guard = gate.lock().unwrap();
        let mut child = spawn_child(&database, "timeout");
        assert!(read_child_marker(&mut child, CHILD_READY));
        assert!(read_child_marker(&mut child, CHILD_TIMEOUT));
        assert!(child.wait().unwrap().success());
        drop(guard);
    }

    #[cfg(windows)]
    #[test]
    fn capability_gate_child_process_probe() {
        let Ok(mode) = std::env::var(CHILD_MODE_ENV) else {
            return;
        };
        let database = PathBuf::from(std::env::var_os(CHILD_DATABASE_ENV).unwrap());
        let gate = CapabilityAuthorizationGate::new(&database).unwrap();
        println!("{CHILD_READY}");
        std::io::stdout().flush().unwrap();
        match mode.as_str() {
            "wait-release" => {
                let _guard = gate.lock().unwrap();
                println!("{CHILD_ACQUIRED}");
            }
            "timeout" => {
                let error = match gate.lock() {
                    Ok(_) => panic!("the child capability gate must time out"),
                    Err(error) => error,
                };
                assert_eq!(error.code(), "CAPABILITY_AUTHORIZATION_GATE_UNAVAILABLE");
                println!("{CHILD_TIMEOUT}");
            }
            "abandon" => {
                let _guard = gate.lock().unwrap();
                println!("{CHILD_HELD}");
                std::io::stdout().flush().unwrap();
                std::process::exit(0);
            }
            _ => panic!("unknown capability gate child mode"),
        }
    }

    #[cfg(windows)]
    fn spawn_child(database: &Path, mode: &str) -> Child {
        let executable = std::env::current_exe().unwrap();
        Command::new(executable)
            .arg("capability_gate_child_process_probe")
            .arg("--nocapture")
            .env(CHILD_MODE_ENV, mode)
            .env(CHILD_DATABASE_ENV, database)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[cfg(windows)]
    fn read_child_marker(child: &mut Child, expected: &str) -> bool {
        let stdout = child.stdout.as_mut().unwrap();
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            line.clear();
            loop {
                if stdout.read_exact(&mut byte).is_err() {
                    return false;
                }
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
            }
            while line.last().copied() == Some(b'\r') {
                line.pop();
            }
            if line == expected.as_bytes() {
                return true;
            }
        }
    }
}
