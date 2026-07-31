//! Authoritative storage schema-upgrade coordination.
//!
//! The coordinator is the only production path that combines the Windows
//! process gate with SQLite's transaction boundary. It deliberately does not
//! install the future version-13 writer-fence schema.

use std::path::Path;

use rusqlite::{Connection, TransactionBehavior};

use super::{
    connection, migration,
    upgrade_gate::{self, LegacyWriterInspection, UpgradeGateError, WindowsUpgradeMutexGuard},
    StorageError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpgradeOccupancy {
    Clear,
    Occupied,
}

trait StorageUpgradeGate {
    type Guard;

    fn acquire_mutex(&self, database_path: &Path) -> Result<Self::Guard, UpgradeGateError>;
    fn inspect_occupants(&self, database_path: &Path)
        -> Result<UpgradeOccupancy, UpgradeGateError>;
}

struct SystemStorageUpgradeGate;

impl StorageUpgradeGate for SystemStorageUpgradeGate {
    type Guard = WindowsUpgradeMutexGuard;

    fn acquire_mutex(&self, database_path: &Path) -> Result<Self::Guard, UpgradeGateError> {
        upgrade_gate::acquire_upgrade_mutex(database_path)
    }

    fn inspect_occupants(
        &self,
        database_path: &Path,
    ) -> Result<UpgradeOccupancy, UpgradeGateError> {
        match upgrade_gate::inspect_database_resource_occupants(database_path)? {
            LegacyWriterInspection::Clear => Ok(UpgradeOccupancy::Clear),
            LegacyWriterInspection::Occupied { .. } => Ok(UpgradeOccupancy::Occupied),
        }
    }
}

/// Opens the authoritative storage database under the bounded Windows upgrade
/// mutex. The mutex is acquired before SQLite can open or create the file and
/// stays live until the fully initialized connection is returned.
pub(super) fn open_coordinated_storage_connection(
    database_path: &Path,
) -> Result<Connection, StorageError> {
    open_coordinated_storage_connection_with_gate(database_path, &SystemStorageUpgradeGate)
}

fn open_coordinated_storage_connection_with_gate<G: StorageUpgradeGate>(
    database_path: &Path,
    gate: &G,
) -> Result<Connection, StorageError> {
    record_upgrade_event("mutex");
    let _mutex_guard = gate
        .acquire_mutex(database_path)
        .map_err(StorageError::from_upgrade_gate_error)?;

    open_after_mutex(database_path, gate)
}

fn open_after_mutex<G: StorageUpgradeGate>(
    database_path: &Path,
    gate: &G,
) -> Result<Connection, StorageError> {
    record_upgrade_event("open-before-wal");
    let mut connection = connection::open_authorized_storage_connection_before_wal(database_path)?;

    record_upgrade_event("version-read");
    let version = connection::read_schema_version(&connection)?;
    if version > connection::MAX_SUPPORTED_SCHEMA_VERSION {
        return Err(StorageError::database_version_too_new());
    }

    if version == connection::MAX_SUPPORTED_SCHEMA_VERSION {
        record_upgrade_event("wal");
        connection::configure_authorized_connection_wal(&connection)?;
        return Ok(connection);
    }

    record_upgrade_event("preflight-rm");
    match gate
        .inspect_occupants(database_path)
        .map_err(StorageError::from_upgrade_gate_error)?
    {
        UpgradeOccupancy::Clear => {}
        UpgradeOccupancy::Occupied => return Err(StorageError::legacy_writer_detected()),
    }

    record_upgrade_event("begin-immediate");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StorageError::upgrade_quiescence_not_reached())?;

    record_upgrade_event("final-rm");
    match gate
        .inspect_occupants(database_path)
        .map_err(StorageError::from_upgrade_gate_error)?
    {
        UpgradeOccupancy::Clear => {}
        UpgradeOccupancy::Occupied => return Err(StorageError::upgrade_quiescence_not_reached()),
    }

    record_upgrade_event("migrations");
    migration::apply_pending_migrations_in_transaction(
        &transaction,
        version,
        connection::MAX_SUPPORTED_SCHEMA_VERSION,
    )?;
    let writer_fence_upgrade =
        migration::apply_writer_fence_schema_upgrade_if_registered(&transaction)?;
    debug_assert_eq!(
        writer_fence_upgrade,
        migration::WriterFenceSchemaUpgrade::NotRegistered
    );

    record_upgrade_event("commit");
    transaction
        .commit()
        .map_err(|_| StorageError::migration_transaction_failed())?;

    record_upgrade_event("post-verify");
    migration::verify_schema_after_upgrade(&connection, connection::MAX_SUPPORTED_SCHEMA_VERSION)?;

    record_upgrade_event("wal");
    connection::configure_authorized_connection_wal(&connection)?;
    Ok(connection)
}

#[cfg(test)]
thread_local! {
    static STORAGE_UPGRADE_EVENTS: std::cell::RefCell<Vec<&'static str>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

#[cfg(test)]
fn record_upgrade_event(event: &'static str) {
    STORAGE_UPGRADE_EVENTS.with(|events| events.borrow_mut().push(event));
}

#[cfg(not(test))]
fn record_upgrade_event(_event: &'static str) {}

#[cfg(test)]
pub(super) fn record_storage_service_publish_for_test() {
    record_upgrade_event("publish");
}

#[cfg(test)]
fn take_upgrade_events() -> Vec<&'static str> {
    STORAGE_UPGRADE_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        path::Path,
        sync::mpsc,
        thread,
    };

    #[cfg(windows)]
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Child, ChildStdin, Command, Stdio},
        time::Duration,
    };

    use rusqlite::{Connection, TransactionBehavior};

    use super::*;

    #[derive(Default)]
    struct FakeGate {
        mutex_result: RefCell<Option<Result<(), UpgradeGateError>>>,
        inspections: RefCell<VecDeque<Result<UpgradeOccupancy, UpgradeGateError>>>,
        acquire_calls: Cell<usize>,
        inspection_calls: Cell<usize>,
    }

    impl FakeGate {
        fn clear() -> Self {
            Self {
                mutex_result: RefCell::new(Some(Ok(()))),
                inspections: RefCell::new(
                    [Ok(UpgradeOccupancy::Clear), Ok(UpgradeOccupancy::Clear)].into(),
                ),
                acquire_calls: Cell::new(0),
                inspection_calls: Cell::new(0),
            }
        }

        fn with_inspections(inspections: Vec<Result<UpgradeOccupancy, UpgradeGateError>>) -> Self {
            Self {
                mutex_result: RefCell::new(Some(Ok(()))),
                inspections: RefCell::new(inspections.into()),
                acquire_calls: Cell::new(0),
                inspection_calls: Cell::new(0),
            }
        }

        fn mutex_failure(error: UpgradeGateError) -> Self {
            Self {
                mutex_result: RefCell::new(Some(Err(error))),
                inspections: RefCell::new(VecDeque::new()),
                acquire_calls: Cell::new(0),
                inspection_calls: Cell::new(0),
            }
        }
    }

    impl StorageUpgradeGate for FakeGate {
        type Guard = ();

        fn acquire_mutex(&self, _database_path: &Path) -> Result<Self::Guard, UpgradeGateError> {
            self.acquire_calls.set(self.acquire_calls.get() + 1);
            self.mutex_result.borrow_mut().take().unwrap_or(Ok(()))
        }

        fn inspect_occupants(
            &self,
            _database_path: &Path,
        ) -> Result<UpgradeOccupancy, UpgradeGateError> {
            self.inspection_calls.set(self.inspection_calls.get() + 1);
            self.inspections
                .borrow_mut()
                .pop_front()
                .unwrap_or(Ok(UpgradeOccupancy::Clear))
        }
    }

    #[cfg(windows)]
    const CHILD_DATABASE_PATH_ENV: &str = "DIGITAL_LIFE_UPGRADE_COORDINATOR_CHILD_DATABASE_PATH";
    #[cfg(windows)]
    const CHILD_READY_MARKER: &str = "DIGITAL_LIFE_UPGRADE_COORDINATOR_CHILD_READY";
    #[cfg(windows)]
    const CHILD_READY_TIMEOUT: Duration = Duration::from_secs(10);

    #[cfg(windows)]
    struct ChildResourceHolder {
        child: Child,
        stdin: Option<ChildStdin>,
        reader: Option<thread::JoinHandle<()>>,
        reaped: bool,
    }

    #[cfg(windows)]
    impl ChildResourceHolder {
        fn release(mut self) {
            if let Some(mut stdin) = self.stdin.take() {
                stdin.write_all(b"release\n").unwrap();
            }
            let status = self.child.wait().unwrap();
            self.reaped = true;
            assert!(status.success());
            if let Some(reader) = self.reader.take() {
                reader.join().unwrap();
            }
        }
    }

    #[cfg(windows)]
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

    #[cfg(windows)]
    fn spawn_child_holding_resource(database_path: &Path) -> ChildResourceHolder {
        let executable = std::env::current_exe().unwrap();
        let mut child = Command::new(executable)
            .arg("storage_upgrade_coordinator_windows_child_resource_helper")
            .arg("--nocapture")
            .env(CHILD_DATABASE_PATH_ENV, database_path)
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
                panic!("the upgrade coordinator child did not complete its readiness handshake")
            }
        }
    }

    #[cfg(windows)]
    struct SpawnOnFinalSystemGate {
        inspection_calls: Cell<usize>,
        child: RefCell<Option<ChildResourceHolder>>,
    }

    #[cfg(windows)]
    impl SpawnOnFinalSystemGate {
        fn new() -> Self {
            Self {
                inspection_calls: Cell::new(0),
                child: RefCell::new(None),
            }
        }

        fn release_child(&self) {
            self.child
                .borrow_mut()
                .take()
                .expect("the final Restart Manager recheck must have spawned a child")
                .release();
        }
    }

    #[cfg(windows)]
    impl StorageUpgradeGate for SpawnOnFinalSystemGate {
        type Guard = WindowsUpgradeMutexGuard;

        fn acquire_mutex(&self, database_path: &Path) -> Result<Self::Guard, UpgradeGateError> {
            upgrade_gate::acquire_upgrade_mutex(database_path)
        }

        fn inspect_occupants(
            &self,
            database_path: &Path,
        ) -> Result<UpgradeOccupancy, UpgradeGateError> {
            let calls = self.inspection_calls.get() + 1;
            self.inspection_calls.set(calls);
            if calls == 2 {
                *self.child.borrow_mut() = Some(spawn_child_holding_resource(database_path));
            }
            match upgrade_gate::inspect_database_resource_occupants(database_path)? {
                LegacyWriterInspection::Clear => Ok(UpgradeOccupancy::Clear),
                LegacyWriterInspection::Occupied { .. } => Ok(UpgradeOccupancy::Occupied),
            }
        }
    }

    #[cfg(windows)]
    struct BlockingSystemGate {
        ready: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }

    #[cfg(windows)]
    impl StorageUpgradeGate for BlockingSystemGate {
        type Guard = WindowsUpgradeMutexGuard;

        fn acquire_mutex(&self, database_path: &Path) -> Result<Self::Guard, UpgradeGateError> {
            let guard = upgrade_gate::acquire_upgrade_mutex(database_path)?;
            self.ready
                .send(())
                .map_err(|_| UpgradeGateError::UpgradeExclusiveGateUnavailable)?;
            self.release
                .recv()
                .map_err(|_| UpgradeGateError::UpgradeExclusiveGateUnavailable)?;
            Ok(guard)
        }

        fn inspect_occupants(
            &self,
            database_path: &Path,
        ) -> Result<UpgradeOccupancy, UpgradeGateError> {
            match upgrade_gate::inspect_database_resource_occupants(database_path)? {
                LegacyWriterInspection::Clear => Ok(UpgradeOccupancy::Clear),
                LegacyWriterInspection::Occupied { .. } => Ok(UpgradeOccupancy::Occupied),
            }
        }
    }

    fn database_path(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(format!("{name}.sqlite3"));
        (root, path)
    }

    fn prepare_schema_version(path: &Path, version: i64) {
        let mut connection = Connection::open(path).unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        migration::apply_pending_migrations_in_transaction(&transaction, 0, version).unwrap();
        transaction.commit().unwrap();
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .unwrap();
    }

    fn journal_mode(path: &Path) -> String {
        let connection = Connection::open(path).unwrap();
        connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn storage_upgrade_coordinator_runs_the_full_fresh_upgrade_order() {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("full-order");
        let gate = FakeGate::clear();
        let _connection = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap();

        assert_eq!(
            take_upgrade_events(),
            vec![
                "mutex",
                "open-before-wal",
                "version-read",
                "preflight-rm",
                "begin-immediate",
                "final-rm",
                "migrations",
                "commit",
                "post-verify",
                "wal",
            ]
        );
        assert_eq!(gate.acquire_calls.get(), 1);
        assert_eq!(gate.inspection_calls.get(), 2);
        assert_eq!(journal_mode(&path), "wal");
    }

    #[test]
    fn storage_upgrade_coordinator_current_schema_skips_rm_and_immediate() {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("current-schema");
        prepare_schema_version(&path, connection::MAX_SUPPORTED_SCHEMA_VERSION);
        let gate = FakeGate::clear();

        let _connection = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap();

        assert_eq!(
            take_upgrade_events(),
            vec!["mutex", "open-before-wal", "version-read", "wal"]
        );
        assert_eq!(gate.inspection_calls.get(), 0);
        assert_eq!(journal_mode(&path), "wal");
    }

    #[test]
    fn storage_upgrade_coordinator_version_twelve_does_not_require_the_future_writer_manifest() {
        let (_root, path) = database_path("current-without-writer-manifest");
        prepare_schema_version(&path, connection::MAX_SUPPORTED_SCHEMA_VERSION);
        let gate = FakeGate::clear();

        let connection = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap();
        assert_eq!(
            connection::read_schema_version(&connection).unwrap(),
            connection::MAX_SUPPORTED_SCHEMA_VERSION
        );
        let writer_fence_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE name GLOB 'digital_life_writer_epoch_*'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(writer_fence_count, 0);
        assert_eq!(gate.inspection_calls.get(), 0);
    }

    #[test]
    fn storage_upgrade_coordinator_future_schema_is_rejected_before_rm_migration_and_wal() {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("future-schema");
        let connection = Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );
                INSERT INTO schema_migration (version, name, applied_at)
                VALUES (13, 'future', '2026-01-01T00:00:00Z');",
            )
            .unwrap();
        drop(connection);
        let gate = FakeGate::clear();

        let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();
        assert_eq!(error.code, "DATABASE_VERSION_TOO_NEW");
        assert_eq!(gate.inspection_calls.get(), 0);
        assert_eq!(journal_mode(&path), "delete");
        assert_eq!(take_upgrade_events(), vec!["mutex", "open-before-wal"]);
    }

    #[test]
    fn storage_upgrade_coordinator_rejects_mutex_before_creating_database() {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("mutex-failure");
        let gate = FakeGate::mutex_failure(UpgradeGateError::UpgradeExclusiveGateUnavailable);

        let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();
        assert_eq!(error.code, "UPGRADE_EXCLUSIVE_GATE_UNAVAILABLE");
        assert!(!path.exists());
        assert_eq!(gate.inspection_calls.get(), 0);
        assert_eq!(take_upgrade_events(), vec!["mutex"]);
    }

    #[test]
    fn storage_upgrade_coordinator_preflight_occupancy_stops_before_immediate() {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("preflight-occupied");
        let gate = FakeGate::with_inspections(vec![Ok(UpgradeOccupancy::Occupied)]);

        let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();
        assert_eq!(error.code, "LEGACY_WRITER_DETECTED");
        assert_eq!(gate.inspection_calls.get(), 1);
        assert_eq!(
            take_upgrade_events(),
            vec!["mutex", "open-before-wal", "version-read", "preflight-rm"]
        );
        assert_eq!(journal_mode(&path), "delete");
    }

    #[test]
    fn upgrade_quiescence_final_recheck_rolls_back_all_migrations() {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("final-occupied");
        let gate = FakeGate::with_inspections(vec![
            Ok(UpgradeOccupancy::Clear),
            Ok(UpgradeOccupancy::Occupied),
        ]);

        let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();
        assert_eq!(error.code, "UPGRADE_QUIESCENCE_NOT_REACHED");
        let connection = Connection::open(&path).unwrap();
        assert_eq!(connection::read_schema_version(&connection).unwrap(), 0);
        assert_eq!(journal_mode(&path), "delete");
        assert_eq!(
            take_upgrade_events(),
            vec![
                "mutex",
                "open-before-wal",
                "version-read",
                "preflight-rm",
                "begin-immediate",
                "final-rm",
            ]
        );
    }

    #[test]
    fn storage_upgrade_coordinator_maps_each_upgrade_gate_error_without_parsing_messages() {
        let expected = [
            (
                UpgradeGateError::UnsupportedPlatform,
                "UNSUPPORTED_PLATFORM",
            ),
            (
                UpgradeGateError::UpgradeMutexNameDerivationFailed,
                "UPGRADE_EXCLUSIVE_GATE_UNAVAILABLE",
            ),
            (
                UpgradeGateError::UpgradeExclusiveGateUnavailable,
                "UPGRADE_EXCLUSIVE_GATE_UNAVAILABLE",
            ),
            (
                UpgradeGateError::RestartManagerSessionFailed,
                "UPGRADE_PROCESS_INSPECTION_FAILED",
            ),
            (
                UpgradeGateError::RestartManagerRegistrationFailed,
                "UPGRADE_PROCESS_INSPECTION_FAILED",
            ),
            (
                UpgradeGateError::RestartManagerQueryFailed,
                "UPGRADE_PROCESS_INSPECTION_FAILED",
            ),
            (
                UpgradeGateError::ProcessIdentityReadFailed,
                "UPGRADE_PROCESS_INSPECTION_FAILED",
            ),
            (
                UpgradeGateError::ProcessVerificationFailed,
                "UPGRADE_PROCESS_INSPECTION_FAILED",
            ),
            (
                UpgradeGateError::LegacyWriterDetected,
                "LEGACY_WRITER_DETECTED",
            ),
        ];

        for (gate_error, code) in expected {
            assert_eq!(StorageError::from_upgrade_gate_error(gate_error).code, code);
        }
    }

    #[test]
    fn storage_upgrade_coordinator_holds_an_immediate_transaction_against_a_second_writer() {
        let (_root, path) = database_path("immediate-second-writer");
        let mut first = Connection::open(&path).unwrap();
        let transaction = first
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let second = Connection::open(&path).unwrap();

        assert!(second
            .execute_batch("CREATE TABLE blocked_writer (id INTEGER)")
            .is_err());
        drop(transaction);
        second
            .execute_batch("CREATE TABLE released_writer (id INTEGER)")
            .unwrap();
    }

    #[test]
    fn upgrade_quiescence_immediate_contention_stops_before_migrations_and_releases_the_writer() {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("immediate-contention");
        let mut first = Connection::open(&path).unwrap();
        let first_transaction = first
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let gate = FakeGate::clear();

        let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();
        assert_eq!(error.code, "UPGRADE_QUIESCENCE_NOT_REACHED");
        assert_eq!(gate.inspection_calls.get(), 1);
        assert_eq!(
            take_upgrade_events(),
            vec![
                "mutex",
                "open-before-wal",
                "version-read",
                "preflight-rm",
                "begin-immediate",
            ]
        );
        drop(first_transaction);

        let second = Connection::open(&path).unwrap();
        second
            .execute_batch("CREATE TABLE writer_after_quiescence_failure (id INTEGER)")
            .unwrap();
        assert_eq!(connection::read_schema_version(&second).unwrap(), 0);
    }

    #[test]
    fn storage_upgrade_coordinator_post_commit_verification_failure_skips_wal_and_publish() {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("post-commit-verification-failure");
        let gate = FakeGate::clear();
        migration::fail_next_post_commit_verification_for_test();

        let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();
        assert_eq!(error.code, "MIGRATION_POST_COMMIT_VERIFICATION_FAILED");
        let connection = Connection::open(&path).unwrap();
        assert_eq!(
            connection::read_schema_version(&connection).unwrap(),
            connection::MAX_SUPPORTED_SCHEMA_VERSION
        );
        assert_eq!(journal_mode(&path), "delete");
        assert_eq!(
            take_upgrade_events(),
            vec![
                "mutex",
                "open-before-wal",
                "version-read",
                "preflight-rm",
                "begin-immediate",
                "final-rm",
                "migrations",
                "commit",
                "post-verify",
            ]
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn storage_upgrade_coordinator_non_windows_fails_before_opening_the_database() {
        let (_root, path) = database_path("unsupported-platform");

        let error = open_coordinated_storage_connection(&path).unwrap_err();
        assert_eq!(error.code, "UNSUPPORTED_PLATFORM");
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn storage_upgrade_coordinator_windows_child_resource_helper() {
        let Some(database_path) = std::env::var_os(CHILD_DATABASE_PATH_ENV) else {
            return;
        };
        let _open_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(database_path)
            .unwrap();
        println!("{CHILD_READY_MARKER}");
        std::io::stdout().flush().unwrap();
        let mut release = String::new();
        std::io::stdin().read_line(&mut release).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn storage_upgrade_coordinator_windows_restart_manager_blocks_a_legacy_writer_then_retries() {
        let _ = take_upgrade_events();
        let root = tempfile::tempdir().unwrap();
        let database_path = root.path().join(super::super::DATABASE_FILE_NAME);
        let legacy = Connection::open(&database_path).unwrap();
        legacy
            .pragma_update(None, "journal_mode", "DELETE")
            .unwrap();
        drop(legacy);
        let child = spawn_child_holding_resource(&database_path);

        let error = match super::super::StorageService::initialize_with_roots(
            root.path().to_path_buf(),
            None,
        ) {
            Ok(_) => panic!("a legacy writer must prevent storage publication"),
            Err(error) => error,
        };
        assert_eq!(error.code, "LEGACY_WRITER_DETECTED");
        assert_eq!(journal_mode(&database_path), "delete");
        let legacy = Connection::open(&database_path).unwrap();
        assert_eq!(connection::read_schema_version(&legacy).unwrap(), 0);
        drop(legacy);
        child.release();

        let service =
            super::super::StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .unwrap();
        let state = service.state().unwrap();
        assert_eq!(
            connection::read_schema_version(&state.connection).unwrap(),
            connection::MAX_SUPPORTED_SCHEMA_VERSION
        );
    }

    #[cfg(windows)]
    #[test]
    fn upgrade_quiescence_windows_final_restart_manager_recheck_blocks_a_late_legacy_writer() {
        for repetition in 0..10 {
            let _ = take_upgrade_events();
            let (_root, path) = database_path(&format!("windows-final-recheck-{repetition}"));
            let gate = SpawnOnFinalSystemGate::new();

            let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();
            assert_eq!(error.code, "UPGRADE_QUIESCENCE_NOT_REACHED");
            assert_eq!(gate.inspection_calls.get(), 2);
            gate.release_child();

            let connection = Connection::open(&path).unwrap();
            assert_eq!(connection::read_schema_version(&connection).unwrap(), 0);
            assert_eq!(journal_mode(&path), "delete");
            assert_eq!(
                take_upgrade_events(),
                vec![
                    "mutex",
                    "open-before-wal",
                    "version-read",
                    "preflight-rm",
                    "begin-immediate",
                    "final-rm",
                ]
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn storage_upgrade_coordinator_windows_same_database_competition_allows_one_initializer() {
        for _ in 0..10 {
            let root = tempfile::tempdir().unwrap();
            let database_path = root.path().join(super::super::DATABASE_FILE_NAME);
            let (ready_sender, ready_receiver) = mpsc::channel();
            let (release_sender, release_receiver) = mpsc::channel();
            let first_path = database_path.clone();
            let first = thread::spawn(move || {
                let gate = BlockingSystemGate {
                    ready: ready_sender,
                    release: release_receiver,
                };
                open_coordinated_storage_connection_with_gate(&first_path, &gate)
                    .map(drop)
                    .map_err(|error| error.code)
            });
            ready_receiver
                .recv_timeout(Duration::from_secs(10))
                .expect("the first initializer must acquire the actual Global mutex");

            let second = match super::super::StorageService::initialize_with_roots(
                root.path().to_path_buf(),
                None,
            ) {
                Ok(_) => panic!("the competing initializer must not enter while the mutex is held"),
                Err(error) => error,
            };
            assert_eq!(second.code, "UPGRADE_EXCLUSIVE_GATE_UNAVAILABLE");
            assert!(!database_path.exists());

            release_sender.send(()).unwrap();
            first.join().unwrap().unwrap();
            let second = super::super::StorageService::initialize_with_roots(
                root.path().to_path_buf(),
                None,
            )
            .unwrap();
            let state = second.state().unwrap();
            assert_eq!(
                connection::read_schema_version(&state.connection).unwrap(),
                connection::MAX_SUPPORTED_SCHEMA_VERSION
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn storage_upgrade_coordinator_windows_second_initializer_rereads_version_twelve() {
        let root = tempfile::tempdir().unwrap();
        let first =
            super::super::StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .unwrap();
        let state = first.state().unwrap();
        let before = state
            .connection
            .prepare("SELECT version, name, applied_at FROM schema_migration ORDER BY version")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        drop(state);

        let second =
            super::super::StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .unwrap();
        let state = second.state().unwrap();
        let after = state
            .connection
            .prepare("SELECT version, name, applied_at FROM schema_migration ORDER BY version")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            before.len(),
            connection::MAX_SUPPORTED_SCHEMA_VERSION as usize
        );
    }

    #[test]
    fn storage_initialize_records_publish_only_after_the_coordinator_completes() {
        let _ = take_upgrade_events();
        let root = tempfile::tempdir().unwrap();
        let _service =
            super::super::StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .unwrap();

        assert_eq!(
            take_upgrade_events(),
            vec![
                "mutex",
                "open-before-wal",
                "version-read",
                "preflight-rm",
                "begin-immediate",
                "final-rm",
                "migrations",
                "commit",
                "post-verify",
                "wal",
                "publish",
            ]
        );
    }
}
