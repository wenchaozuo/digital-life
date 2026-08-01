//! Authoritative storage schema-upgrade coordination.
//!
//! The coordinator is the only production path that combines the Windows
//! process gate with SQLite's transaction boundary and installs the fixed
//! version-13 writer-fence and version-14 attempt-identity schema only within
//! that transaction.

use std::path::Path;

use rusqlite::{Connection, TransactionBehavior};

use super::{
    connection, migration,
    upgrade_gate::{self, LegacyWriterInspection, UpgradeGateError, WindowsUpgradeMutexGuard},
    writer_fence_manifest, StorageError,
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
        record_upgrade_event("schema-14");
        migration::validate_attempt_claim_identity_schema(&connection)?;
        record_upgrade_event("manifest");
        writer_fence_manifest::validate_writer_fence_manifest(&connection)?;
        record_upgrade_event("post-verify");
        migration::verify_schema_after_upgrade(
            &connection,
            connection::MAX_SUPPORTED_SCHEMA_VERSION,
        )?;
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

    if version <= migration::LAST_STATIC_MIGRATION_VERSION {
        record_upgrade_event("migrations");
        migration::apply_pending_migrations_in_transaction(
            &transaction,
            version,
            connection::MAX_SUPPORTED_SCHEMA_VERSION,
        )?;
        record_upgrade_event("h1-b");
        let writer_fence_upgrade =
            migration::apply_writer_fence_schema_upgrade_if_registered(&transaction)?;
        if writer_fence_upgrade != migration::WriterFenceSchemaUpgrade::Applied {
            return Err(StorageError::migration_version_invariant_failed());
        }
    }

    record_upgrade_event("att-i1");
    let attempt_upgrade = migration::apply_attempt_claim_identity_schema_upgrade(&transaction)?;
    if attempt_upgrade != migration::AttemptClaimIdentitySchemaUpgrade::Applied {
        return Err(StorageError::migration_version_invariant_failed());
    }

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
        assert!(
            version == migration::LAST_STATIC_MIGRATION_VERSION
                || version == writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION
                || version == connection::MAX_SUPPORTED_SCHEMA_VERSION
        );
        let mut connection = Connection::open(path).unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        migration::apply_pending_migrations_in_transaction(
            &transaction,
            0,
            connection::MAX_SUPPORTED_SCHEMA_VERSION,
        )
        .unwrap();
        if version >= writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION {
            assert_eq!(
                migration::apply_writer_fence_schema_upgrade_if_registered(&transaction).unwrap(),
                migration::WriterFenceSchemaUpgrade::Applied
            );
        }
        if version == connection::MAX_SUPPORTED_SCHEMA_VERSION {
            assert_eq!(
                migration::apply_attempt_claim_identity_schema_upgrade(&transaction).unwrap(),
                migration::AttemptClaimIdentitySchemaUpgrade::Applied
            );
        }
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

    fn writer_fence_count(connection: &Connection) -> i64 {
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='trigger' AND name GLOB 'digital_life_writer_epoch_*'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn attempt_identity_column_count(connection: &Connection) -> i64 {
        connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('memory_vector_sync_outbox')
                 WHERE name IN ('fenced_claim_epoch', 'last_marked_claim_epoch')",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn assert_version_thirteen_has_no_attempt_identity_columns(path: &Path) {
        let connection = Connection::open(path).unwrap();
        assert_eq!(
            connection::read_schema_version(&connection).unwrap(),
            writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION
        );
        assert_eq!(attempt_identity_column_count(&connection), 0);
        assert_eq!(writer_fence_count(&connection), 18);
    }

    fn damage_attempt_identity_schema(
        path: &Path,
        fenced_claim_epoch_definition: Option<&str>,
        last_marked_claim_epoch_definition: Option<&str>,
    ) {
        let connection = Connection::open(path).unwrap();
        let definitions = [
            Some("id INTEGER PRIMARY KEY"),
            Some("attempt_count INTEGER NOT NULL DEFAULT 0"),
            fenced_claim_epoch_definition,
            last_marked_claim_epoch_definition,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
        connection
            .execute_batch(&format!(
                "PRAGMA foreign_keys=OFF;
                 DROP TABLE memory_vector_sync_outbox;
                 CREATE TABLE memory_vector_sync_outbox ({definitions})"
            ))
            .unwrap();
    }

    #[derive(Debug, Eq, PartialEq)]
    struct VersionTwelveHistoricalEvidence {
        state: String,
        migration_disposition: Option<String>,
        attempt_count: i64,
        mutation_sequence: i64,
        claimed_generation_id: Option<String>,
        last_error_code: Option<String>,
        last_send_disposition: Option<String>,
        next_attempt_at: Option<String>,
        lease_owner: Option<String>,
        lease_fence_epoch: Option<i64>,
        lease_expires_at: Option<String>,
    }

    fn seed_version_twelve_historical_row(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "INSERT INTO memory_vector_sync_outbox
                 (life_id, memory_id, desired_action, state, attempt_count,
                  mutation_sequence, claimed_generation_id, last_error_code,
                  last_send_disposition, next_attempt_at, lease_owner,
                  lease_fence_epoch, lease_expires_at)
                 VALUES
                 ('upgrade-life', 'upgrade-memory', 'delete', 'pending', 3, 18,
                  'upgrade-generation', 'UPGRADE_OLD_ERROR', 'possibly_sent',
                  '2026-06-01T00:00:00.000Z', 'upgrade-owner', 12,
                  '2026-06-02T00:00:00.000Z');
                 UPDATE memory_vector_sync_mutation_clock
                 SET last_sequence=30 WHERE singleton=1;",
            )
            .unwrap();
    }

    fn version_twelve_historical_evidence(
        connection: &Connection,
    ) -> VersionTwelveHistoricalEvidence {
        connection
            .query_row(
                "SELECT state, migration_disposition, attempt_count, mutation_sequence,
                        claimed_generation_id, last_error_code, last_send_disposition,
                        next_attempt_at, lease_owner, lease_fence_epoch, lease_expires_at
                 FROM memory_vector_sync_outbox
                 WHERE life_id='upgrade-life' AND memory_id='upgrade-memory'",
                [],
                |row| {
                    Ok(VersionTwelveHistoricalEvidence {
                        state: row.get(0)?,
                        migration_disposition: row.get(1)?,
                        attempt_count: row.get(2)?,
                        mutation_sequence: row.get(3)?,
                        claimed_generation_id: row.get(4)?,
                        last_error_code: row.get(5)?,
                        last_send_disposition: row.get(6)?,
                        next_attempt_at: row.get(7)?,
                        lease_owner: row.get(8)?,
                        lease_fence_epoch: row.get(9)?,
                        lease_expires_at: row.get(10)?,
                    })
                },
            )
            .unwrap()
    }

    fn assert_version_twelve_historical_data_is_unchanged(path: &Path) {
        let connection = Connection::open(path).unwrap();
        assert_eq!(
            connection::read_schema_version(&connection).unwrap(),
            migration::LAST_STATIC_MIGRATION_VERSION
        );
        assert_eq!(
            version_twelve_historical_evidence(&connection),
            VersionTwelveHistoricalEvidence {
                state: "pending".into(),
                migration_disposition: None,
                attempt_count: 3,
                mutation_sequence: 18,
                claimed_generation_id: Some("upgrade-generation".into()),
                last_error_code: Some("UPGRADE_OLD_ERROR".into()),
                last_send_disposition: Some("possibly_sent".into()),
                next_attempt_at: Some("2026-06-01T00:00:00.000Z".into()),
                lease_owner: Some("upgrade-owner".into()),
                lease_fence_epoch: Some(12),
                lease_expires_at: Some("2026-06-02T00:00:00.000Z".into()),
            }
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            30
        );
        assert_eq!(writer_fence_count(&connection), 0);
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
                "h1-b",
                "att-i1",
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
            vec![
                "mutex",
                "open-before-wal",
                "version-read",
                "schema-14",
                "manifest",
                "post-verify",
                "wal",
            ]
        );
        assert_eq!(gate.inspection_calls.get(), 0);
        assert_eq!(journal_mode(&path), "wal");
    }

    #[test]
    fn storage_upgrade_coordinator_version_thirteen_upgrades_attempt_identity_without_replaying_historical_isolation(
    ) {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("current-schema-no-repeat");
        prepare_schema_version(&path, writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION);
        let authorized = connection::open_authorized_test_connection(&path).unwrap();
        authorized
            .execute_batch(
                "INSERT INTO memory_vector_sync_outbox
                 (life_id, memory_id, desired_action, state, migration_disposition,
                  attempt_count, mutation_sequence, claimed_generation_id,
                  last_send_disposition)
                 VALUES ('current-life', 'current-memory', 'delete', 'failed',
                         'legacy_upsert_rebuild_required', 4, 33, 'current-generation',
                         'possibly_sent');
                 UPDATE memory_vector_sync_mutation_clock
                 SET last_sequence=33 WHERE singleton=1;",
            )
            .unwrap();
        drop(authorized);
        let gate = FakeGate::clear();

        let connection = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap();

        assert_eq!(gate.inspection_calls.get(), 2);
        assert_eq!(
            connection::read_schema_version(&connection).unwrap(),
            connection::MAX_SUPPORTED_SCHEMA_VERSION
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            33
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT state, migration_disposition, attempt_count, mutation_sequence,
                            claimed_generation_id, last_send_disposition
                     FROM memory_vector_sync_outbox
                     WHERE life_id='current-life' AND memory_id='current-memory'",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                        ))
                    },
                )
                .unwrap(),
            (
                "failed".into(),
                Some("legacy_upsert_rebuild_required".into()),
                4,
                33,
                Some("current-generation".into()),
                Some("possibly_sent".into()),
            )
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT fenced_claim_epoch, last_marked_claim_epoch
                     FROM memory_vector_sync_outbox
                     WHERE life_id='current-life' AND memory_id='current-memory'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap(),
            (0, 0)
        );
        assert_eq!(writer_fence_count(&connection), 18);
        assert_eq!(
            take_upgrade_events(),
            vec![
                "mutex",
                "open-before-wal",
                "version-read",
                "preflight-rm",
                "begin-immediate",
                "final-rm",
                "att-i1",
                "commit",
                "post-verify",
                "wal",
            ]
        );
    }

    #[test]
    fn schema_fourteen_startup_rejects_missing_or_weakened_attempt_identity_columns_before_wal() {
        let malformed_schemas = [
            (
                None,
                Some(
                    "last_marked_claim_epoch INTEGER NOT NULL DEFAULT 0
                     CHECK (last_marked_claim_epoch >= 0)",
                ),
            ),
            (
                Some(
                    "fenced_claim_epoch INTEGER NOT NULL DEFAULT 0
                     CHECK (fenced_claim_epoch >= 0)",
                ),
                None,
            ),
            (
                Some(
                    "fenced_claim_epoch TEXT NOT NULL DEFAULT 0
                     CHECK (fenced_claim_epoch >= 0)",
                ),
                Some(
                    "last_marked_claim_epoch INTEGER NOT NULL DEFAULT 0
                     CHECK (last_marked_claim_epoch >= 0
                         AND last_marked_claim_epoch <= fenced_claim_epoch
                         AND (last_marked_claim_epoch = 0 OR attempt_count > 0))",
                ),
            ),
            (
                Some("fenced_claim_epoch INTEGER DEFAULT 0 CHECK (fenced_claim_epoch >= 0)"),
                Some(
                    "last_marked_claim_epoch INTEGER NOT NULL DEFAULT 0
                     CHECK (last_marked_claim_epoch >= 0
                         AND last_marked_claim_epoch <= fenced_claim_epoch
                         AND (last_marked_claim_epoch = 0 OR attempt_count > 0))",
                ),
            ),
            (
                Some(
                    "fenced_claim_epoch INTEGER NOT NULL DEFAULT 1
                     CHECK (fenced_claim_epoch >= 0)",
                ),
                Some(
                    "last_marked_claim_epoch INTEGER NOT NULL DEFAULT 0
                     CHECK (last_marked_claim_epoch >= 0
                         AND last_marked_claim_epoch <= fenced_claim_epoch
                         AND (last_marked_claim_epoch = 0 OR attempt_count > 0))",
                ),
            ),
            (
                Some(
                    "fenced_claim_epoch INTEGER NOT NULL DEFAULT 0
                     CHECK (fenced_claim_epoch >= -1)",
                ),
                Some(
                    "last_marked_claim_epoch INTEGER NOT NULL DEFAULT 0
                     CHECK (last_marked_claim_epoch >= 0
                         AND last_marked_claim_epoch <= fenced_claim_epoch
                         AND (last_marked_claim_epoch = 0 OR attempt_count > 0))",
                ),
            ),
            (
                Some(
                    "fenced_claim_epoch INTEGER NOT NULL DEFAULT 0
                     CHECK (fenced_claim_epoch >= 0)",
                ),
                Some(
                    "last_marked_claim_epoch INTEGER NOT NULL DEFAULT 0
                     CHECK (last_marked_claim_epoch >= 0
                         AND last_marked_claim_epoch <= fenced_claim_epoch)",
                ),
            ),
        ];

        for (fenced_claim_epoch_definition, last_marked_claim_epoch_definition) in malformed_schemas
        {
            let _ = take_upgrade_events();
            let (_root, path) = database_path("schema-fourteen-attempt-damage");
            prepare_schema_version(&path, connection::MAX_SUPPORTED_SCHEMA_VERSION);
            damage_attempt_identity_schema(
                &path,
                fenced_claim_epoch_definition,
                last_marked_claim_epoch_definition,
            );
            let gate = FakeGate::clear();

            let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();

            assert_eq!(error.code, "ATTEMPT_CLAIM_IDENTITY_SCHEMA_INVALID");
            assert_eq!(gate.inspection_calls.get(), 0);
            assert_eq!(journal_mode(&path), "delete");
            assert_eq!(
                take_upgrade_events(),
                vec!["mutex", "open-before-wal", "version-read", "schema-14"]
            );
        }
    }

    #[test]
    fn storage_upgrade_coordinator_version_fourteen_manifest_damage_fails_closed_before_wal() {
        enum ManifestDamage {
            Missing,
            Mismatched,
            ExtraReserved,
        }

        for damage in [
            ManifestDamage::Missing,
            ManifestDamage::Mismatched,
            ManifestDamage::ExtraReserved,
        ] {
            let _ = take_upgrade_events();
            let (_root, path) = database_path("current-schema-manifest-damage");
            prepare_schema_version(&path, connection::MAX_SUPPORTED_SCHEMA_VERSION);
            let raw = Connection::open(&path).unwrap();
            match damage {
                ManifestDamage::Missing => raw
                    .execute_batch(
                        "DROP TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert",
                    )
                    .unwrap(),
                ManifestDamage::Mismatched => {
                    raw.execute_batch(
                        "DROP TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert;
                         CREATE TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert
                         BEFORE UPDATE ON memory_vector_sync_outbox
                         WHEN digital_life_writer_epoch() IS NOT 1
                         BEGIN
                             SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
                         END",
                    )
                    .unwrap();
                }
                ManifestDamage::ExtraReserved => raw
                    .execute_batch(
                        "CREATE TRIGGER digital_life_writer_epoch_extra_reserved
                         BEFORE INSERT ON memory_vector_sync_outbox
                         WHEN digital_life_writer_epoch() IS NOT 1
                         BEGIN
                             SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
                         END",
                    )
                    .unwrap(),
            }
            drop(raw);
            let gate = FakeGate::clear();

            let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();

            let expected_code = match damage {
                ManifestDamage::Missing => "WRITER_FENCE_MANIFEST_MISSING",
                ManifestDamage::Mismatched | ManifestDamage::ExtraReserved => {
                    "WRITER_FENCE_MANIFEST_MISMATCH"
                }
            };
            assert_eq!(error.code, expected_code);
            assert_eq!(gate.inspection_calls.get(), 0);
            assert_eq!(journal_mode(&path), "delete");
            assert_eq!(
                take_upgrade_events(),
                vec![
                    "mutex",
                    "open-before-wal",
                    "version-read",
                    "schema-14",
                    "manifest"
                ]
            );
        }
    }

    #[test]
    fn storage_initialize_version_fourteen_missing_manifest_skips_wal_and_publication() {
        let _ = take_upgrade_events();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(super::super::DATABASE_FILE_NAME);
        prepare_schema_version(&path, connection::MAX_SUPPORTED_SCHEMA_VERSION);
        let raw = Connection::open(&path).unwrap();
        raw.execute_batch(
            "DROP TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert",
        )
        .unwrap();
        drop(raw);

        let error = match super::super::StorageService::initialize_with_roots(
            root.path().to_path_buf(),
            None,
        ) {
            Ok(_) => panic!("a damaged version-14 manifest must prevent storage publication"),
            Err(error) => error,
        };

        assert_eq!(error.code, "WRITER_FENCE_MANIFEST_MISSING");
        assert_eq!(journal_mode(&path), "delete");
        assert_eq!(
            take_upgrade_events(),
            vec![
                "mutex",
                "open-before-wal",
                "version-read",
                "schema-14",
                "manifest"
            ]
        );
    }

    #[test]
    fn storage_initialize_version_fourteen_invalid_attempt_schema_skips_wal_and_publication() {
        let _ = take_upgrade_events();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(super::super::DATABASE_FILE_NAME);
        prepare_schema_version(&path, connection::MAX_SUPPORTED_SCHEMA_VERSION);
        damage_attempt_identity_schema(
            &path,
            None,
            Some(
                "last_marked_claim_epoch INTEGER NOT NULL DEFAULT 0
                 CHECK (last_marked_claim_epoch >= 0)",
            ),
        );

        let error = match super::super::StorageService::initialize_with_roots(
            root.path().to_path_buf(),
            None,
        ) {
            Ok(_) => panic!("a damaged version-14 attempt schema must prevent storage publication"),
            Err(error) => error,
        };

        assert_eq!(error.code, "ATTEMPT_CLAIM_IDENTITY_SCHEMA_INVALID");
        assert_eq!(journal_mode(&path), "delete");
        assert_eq!(
            take_upgrade_events(),
            vec!["mutex", "open-before-wal", "version-read", "schema-14"]
        );
    }

    #[test]
    fn storage_initialize_restored_version_fourteen_validates_then_publishes() {
        let _ = take_upgrade_events();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(super::super::DATABASE_FILE_NAME);
        prepare_schema_version(&path, connection::MAX_SUPPORTED_SCHEMA_VERSION);

        let service =
            super::super::StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .unwrap();
        let state = service.state().unwrap();

        assert_eq!(
            connection::read_schema_version(&state.connection).unwrap(),
            connection::MAX_SUPPORTED_SCHEMA_VERSION
        );
        migration::validate_attempt_claim_identity_schema(&state.connection).unwrap();
        assert_eq!(writer_fence_count(&state.connection), 18);
        assert_eq!(
            take_upgrade_events(),
            vec![
                "mutex",
                "open-before-wal",
                "version-read",
                "schema-14",
                "manifest",
                "post-verify",
                "wal",
                "publish",
            ]
        );
    }

    #[test]
    fn storage_upgrade_coordinator_version_twelve_requires_writer_fence_and_attempt_identity_upgrades(
    ) {
        let (_root, path) = database_path("version-twelve-upgrade");
        prepare_schema_version(&path, migration::LAST_STATIC_MIGRATION_VERSION);
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
        assert_eq!(writer_fence_count, 18);
        migration::validate_attempt_claim_identity_schema(&connection).unwrap();
        assert_eq!(gate.inspection_calls.get(), 2);
    }

    #[test]
    fn storage_upgrade_coordinator_version_twelve_preflight_occupancy_leaves_h1_b_data_untouched() {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("version-twelve-preflight-occupied");
        prepare_schema_version(&path, migration::LAST_STATIC_MIGRATION_VERSION);
        seed_version_twelve_historical_row(&path);
        let gate = FakeGate::with_inspections(vec![Ok(UpgradeOccupancy::Occupied)]);

        let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();

        assert_eq!(error.code, "LEGACY_WRITER_DETECTED");
        assert_eq!(gate.inspection_calls.get(), 1);
        assert_version_twelve_historical_data_is_unchanged(&path);
        assert_eq!(journal_mode(&path), "delete");
        assert_eq!(
            take_upgrade_events(),
            vec!["mutex", "open-before-wal", "version-read", "preflight-rm"]
        );
    }

    #[test]
    fn storage_upgrade_coordinator_version_twelve_final_occupancy_rolls_back_h1_b_data() {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("version-twelve-final-occupied");
        prepare_schema_version(&path, migration::LAST_STATIC_MIGRATION_VERSION);
        seed_version_twelve_historical_row(&path);
        let gate = FakeGate::with_inspections(vec![
            Ok(UpgradeOccupancy::Clear),
            Ok(UpgradeOccupancy::Occupied),
        ]);

        let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();

        assert_eq!(error.code, "UPGRADE_QUIESCENCE_NOT_REACHED");
        assert_eq!(gate.inspection_calls.get(), 2);
        assert_version_twelve_historical_data_is_unchanged(&path);
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
    fn storage_upgrade_coordinator_version_thirteen_preflight_occupancy_preserves_schema_and_data()
    {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("version-thirteen-preflight-occupied");
        prepare_schema_version(&path, writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION);
        let gate = FakeGate::with_inspections(vec![Ok(UpgradeOccupancy::Occupied)]);

        let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();

        assert_eq!(error.code, "LEGACY_WRITER_DETECTED");
        assert_eq!(gate.inspection_calls.get(), 1);
        assert_version_thirteen_has_no_attempt_identity_columns(&path);
        assert_eq!(journal_mode(&path), "delete");
        assert_eq!(
            take_upgrade_events(),
            vec!["mutex", "open-before-wal", "version-read", "preflight-rm"]
        );
    }

    #[test]
    fn storage_upgrade_coordinator_version_thirteen_final_occupancy_rolls_back_migration_014() {
        let _ = take_upgrade_events();
        let (_root, path) = database_path("version-thirteen-final-occupied");
        prepare_schema_version(&path, writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION);
        let gate = FakeGate::with_inspections(vec![
            Ok(UpgradeOccupancy::Clear),
            Ok(UpgradeOccupancy::Occupied),
        ]);

        let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();

        assert_eq!(error.code, "UPGRADE_QUIESCENCE_NOT_REACHED");
        assert_eq!(gate.inspection_calls.get(), 2);
        assert_version_thirteen_has_no_attempt_identity_columns(&path);
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
    fn storage_upgrade_coordinator_migration_013_failures_leave_version_twelve_without_wal() {
        enum Failure {
            Migration(migration::Migration013Failpoint),
            Trigger(usize),
        }

        for failure in [
            Failure::Migration(migration::Migration013Failpoint::HistoricalIsolation),
            Failure::Migration(migration::Migration013Failpoint::MutationClock),
            Failure::Trigger(1),
            Failure::Trigger(9),
            Failure::Trigger(18),
            Failure::Migration(migration::Migration013Failpoint::SchemaVersion),
            Failure::Migration(migration::Migration013Failpoint::ManifestValidation),
        ] {
            let _ = take_upgrade_events();
            let (_root, path) = database_path("version-twelve-h1-b-failure");
            prepare_schema_version(&path, migration::LAST_STATIC_MIGRATION_VERSION);
            seed_version_twelve_historical_row(&path);
            match failure {
                Failure::Migration(failpoint) => {
                    migration::fail_next_migration_013_at_for_test(failpoint)
                }
                Failure::Trigger(index) => {
                    writer_fence_manifest::fail_trigger_install_at_for_test(index)
                }
            }
            let gate = FakeGate::clear();

            let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();

            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
            assert_eq!(gate.inspection_calls.get(), 2);
            assert_version_twelve_historical_data_is_unchanged(&path);
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
                    "h1-b",
                ]
            );
        }
    }

    #[test]
    fn migration_014_failures_leave_version_thirteen_without_columns_or_wal() {
        for failpoint in [
            migration::Migration014Failpoint::FirstColumn,
            migration::Migration014Failpoint::SecondColumn,
            migration::Migration014Failpoint::SchemaVersion,
            migration::Migration014Failpoint::SchemaValidation,
            migration::Migration014Failpoint::ManifestValidation,
        ] {
            let _ = take_upgrade_events();
            let (_root, path) = database_path("version-thirteen-migration-014-failure");
            prepare_schema_version(&path, writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION);
            migration::fail_next_migration_014_at_for_test(failpoint);
            let gate = FakeGate::clear();

            let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();

            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
            assert_eq!(gate.inspection_calls.get(), 2);
            assert_version_thirteen_has_no_attempt_identity_columns(&path);
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
                    "att-i1",
                ]
            );
        }
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
                VALUES (15, 'future', '2026-01-01T00:00:00Z');",
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
    fn storage_initialize_restored_future_schema_is_rejected_before_wal_or_publication() {
        let _ = take_upgrade_events();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(super::super::DATABASE_FILE_NAME);
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
                VALUES (15, 'future', '2026-01-01T00:00:00Z')",
            )
            .unwrap();
        drop(connection);

        let error = match super::super::StorageService::initialize_with_roots(
            root.path().to_path_buf(),
            None,
        ) {
            Ok(_) => panic!("a restored future-schema database must not be published"),
            Err(error) => error,
        };

        assert_eq!(error.code, "DATABASE_VERSION_TOO_NEW");
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
                "h1-b",
                "att-i1",
                "commit",
                "post-verify",
            ]
        );
    }

    #[test]
    fn schema_fourteen_and_manifest_post_commit_failures_skip_wal_and_publish() {
        for failpoint in [
            migration::PostCommitVerificationFailpoint::AttemptClaimIdentitySchema,
            migration::PostCommitVerificationFailpoint::WriterFenceManifest,
        ] {
            let _ = take_upgrade_events();
            let (_root, path) = database_path("post-commit-schema-fourteen-failure");
            let gate = FakeGate::clear();
            migration::fail_next_post_commit_verification_at_for_test(failpoint);

            let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();

            assert_eq!(error.code, "MIGRATION_POST_COMMIT_VERIFICATION_FAILED");
            let connection = Connection::open(&path).unwrap();
            assert_eq!(
                connection::read_schema_version(&connection).unwrap(),
                connection::MAX_SUPPORTED_SCHEMA_VERSION
            );
            migration::validate_attempt_claim_identity_schema(&connection).unwrap();
            assert_eq!(writer_fence_count(&connection), 18);
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
                    "h1-b",
                    "att-i1",
                    "commit",
                    "post-verify",
                ]
            );
        }
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
    fn upgrade_quiescence_windows_final_restart_manager_recheck_blocks_a_late_legacy_writer_before_migration_014(
    ) {
        for repetition in 0..10 {
            let _ = take_upgrade_events();
            let (_root, path) = database_path(&format!("windows-final-recheck-{repetition}"));
            prepare_schema_version(&path, writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION);
            let gate = SpawnOnFinalSystemGate::new();

            let error = open_coordinated_storage_connection_with_gate(&path, &gate).unwrap_err();
            assert_eq!(error.code, "UPGRADE_QUIESCENCE_NOT_REACHED");
            assert_eq!(gate.inspection_calls.get(), 2);
            gate.release_child();

            let connection = Connection::open(&path).unwrap();
            assert_eq!(
                connection::read_schema_version(&connection).unwrap(),
                writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION
            );
            assert_eq!(attempt_identity_column_count(&connection), 0);
            assert_eq!(writer_fence_count(&connection), 18);
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
    fn storage_upgrade_coordinator_windows_version_thirteen_competition_upgrades_once_to_fourteen()
    {
        for repetition in 0..10 {
            let root = tempfile::tempdir().unwrap();
            let database_path = root.path().join(super::super::DATABASE_FILE_NAME);
            prepare_schema_version(
                &database_path,
                writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION,
            );
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
                Ok(_) => panic!(
                    "the competing version-13 initializer must not enter while the mutex is held"
                ),
                Err(error) => error,
            };
            assert_eq!(second.code, "UPGRADE_EXCLUSIVE_GATE_UNAVAILABLE");
            assert_version_thirteen_has_no_attempt_identity_columns(&database_path);

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
                connection::MAX_SUPPORTED_SCHEMA_VERSION,
                "version-13 competition repetition {repetition}"
            );
            migration::validate_attempt_claim_identity_schema(&state.connection).unwrap();
            assert_eq!(writer_fence_count(&state.connection), 18);
        }
    }

    #[cfg(windows)]
    #[test]
    fn storage_upgrade_coordinator_windows_restored_version_twelve_reopens_through_migration_014() {
        for repetition in 0..10 {
            let root = tempfile::tempdir().unwrap();
            let database_path = root.path().join(super::super::DATABASE_FILE_NAME);
            prepare_schema_version(&database_path, migration::LAST_STATIC_MIGRATION_VERSION);
            seed_version_twelve_historical_row(&database_path);

            let first = super::super::StorageService::initialize_with_roots(
                root.path().to_path_buf(),
                None,
            )
            .unwrap();
            let state = first.state().unwrap();
            assert_eq!(
                connection::read_schema_version(&state.connection).unwrap(),
                connection::MAX_SUPPORTED_SCHEMA_VERSION,
                "restored version-12 fixture must upgrade on repetition {repetition}"
            );
            assert_eq!(writer_fence_count(&state.connection), 18);
            migration::validate_attempt_claim_identity_schema(&state.connection).unwrap();
            assert_eq!(
                state
                    .connection
                    .query_row(
                        "SELECT fenced_claim_epoch, last_marked_claim_epoch
                         FROM memory_vector_sync_outbox
                         WHERE life_id='upgrade-life' AND memory_id='upgrade-memory'",
                        [],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .unwrap(),
                (0, 0)
            );
            assert_eq!(
                version_twelve_historical_evidence(&state.connection),
                VersionTwelveHistoricalEvidence {
                    state: "failed".into(),
                    migration_disposition: Some("legacy_upsert_rebuild_required".into()),
                    attempt_count: 3,
                    mutation_sequence: 18,
                    claimed_generation_id: Some("upgrade-generation".into()),
                    last_error_code: Some("UPGRADE_OLD_ERROR".into()),
                    last_send_disposition: Some("possibly_sent".into()),
                    next_attempt_at: None,
                    lease_owner: None,
                    lease_fence_epoch: None,
                    lease_expires_at: None,
                }
            );
            let first_clock: i64 = state
                .connection
                .query_row(
                    "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(first_clock, 31);
            drop(state);

            let second = super::super::StorageService::initialize_with_roots(
                root.path().to_path_buf(),
                None,
            )
            .unwrap();
            let state = second.state().unwrap();
            let second_clock: i64 = state
                .connection
                .query_row(
                    "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(second_clock, first_clock);
            assert_eq!(writer_fence_count(&state.connection), 18);
            migration::validate_attempt_claim_identity_schema(&state.connection).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn storage_upgrade_coordinator_windows_restored_version_thirteen_reopens_through_migration_014()
    {
        for repetition in 0..10 {
            let root = tempfile::tempdir().unwrap();
            let database_path = root.path().join(super::super::DATABASE_FILE_NAME);
            prepare_schema_version(
                &database_path,
                writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION,
            );
            let authorized = connection::open_authorized_test_connection(&database_path).unwrap();
            authorized
                .execute_batch(
                    "INSERT INTO memory_vector_sync_outbox
                     (life_id, memory_id, desired_action, state, attempt_count, mutation_sequence)
                     VALUES ('restored-thirteen-life', 'restored-thirteen-memory',
                             'delete', 'pending', 2, 8)",
                )
                .unwrap();
            drop(authorized);

            let service = super::super::StorageService::initialize_with_roots(
                root.path().to_path_buf(),
                None,
            )
            .unwrap();
            let state = service.state().unwrap();
            assert_eq!(
                connection::read_schema_version(&state.connection).unwrap(),
                connection::MAX_SUPPORTED_SCHEMA_VERSION,
                "restored version-13 fixture must upgrade on repetition {repetition}"
            );
            assert_eq!(
                state
                    .connection
                    .query_row(
                        "SELECT fenced_claim_epoch, last_marked_claim_epoch
                         FROM memory_vector_sync_outbox
                         WHERE life_id='restored-thirteen-life'
                           AND memory_id='restored-thirteen-memory'",
                        [],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .unwrap(),
                (0, 0)
            );
            assert_eq!(writer_fence_count(&state.connection), 18);
            migration::validate_attempt_claim_identity_schema(&state.connection).unwrap();
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct VersionThirteenCommitEvidence {
        state: String,
        migration_disposition: Option<String>,
        attempt_count: i64,
        mutation_sequence: i64,
        target_revision: Option<i64>,
        target_content_hash: Option<String>,
        claimed_generation_id: Option<String>,
        last_error_code: Option<String>,
        last_send_disposition: Option<String>,
        next_attempt_at: Option<String>,
        lease_owner: Option<String>,
        lease_fence_epoch: Option<i64>,
        lease_expires_at: Option<String>,
    }

    fn version_thirteen_commit_evidence(connection: &Connection) -> VersionThirteenCommitEvidence {
        connection
            .query_row(
                "SELECT state, migration_disposition, attempt_count, mutation_sequence,
                        target_revision, target_content_hash, claimed_generation_id,
                        last_error_code, last_send_disposition, next_attempt_at,
                        lease_owner, lease_fence_epoch, lease_expires_at
                 FROM memory_vector_sync_outbox
                 WHERE life_id='commit-life' AND memory_id='commit-row'",
                [],
                |row| {
                    Ok(VersionThirteenCommitEvidence {
                        state: row.get(0)?,
                        migration_disposition: row.get(1)?,
                        attempt_count: row.get(2)?,
                        mutation_sequence: row.get(3)?,
                        target_revision: row.get(4)?,
                        target_content_hash: row.get(5)?,
                        claimed_generation_id: row.get(6)?,
                        last_error_code: row.get(7)?,
                        last_send_disposition: row.get(8)?,
                        next_attempt_at: row.get(9)?,
                        lease_owner: row.get(10)?,
                        lease_fence_epoch: row.get(11)?,
                        lease_expires_at: row.get(12)?,
                    })
                },
            )
            .unwrap()
    }

    /// Seeds one outbox row whose evidence fields are all non-default, plus a
    /// recognizable mutation clock, into an existing version-13 database. The
    /// authorized epoch-1 connection shape is required because the 18 writer
    /// fences are already installed at this point.
    fn seed_version_thirteen_commit_row(path: &Path) -> VersionThirteenCommitEvidence {
        let authorized = connection::open_authorized_test_connection(path).unwrap();
        authorized
            .execute_batch(
                "INSERT INTO memory_vector_sync_outbox
                 (life_id, memory_id, desired_action, state, migration_disposition,
                  attempt_count, mutation_sequence, target_revision, target_content_hash,
                  claimed_generation_id, last_error_code, last_send_disposition,
                  next_attempt_at, lease_owner, lease_fence_epoch, lease_expires_at)
                 VALUES ('commit-life', 'commit-row', 'delete', 'failed',
                         'legacy_upsert_rebuild_required', 5, 7654, 21,
                         'commit-target-hash', 'commit-generation',
                         'COMMIT_BOUNDARY_ERROR', 'possibly_sent',
                         '2026-10-01T00:00:00.000Z', 'commit-owner', 31,
                         '2026-10-02T00:00:00.000Z');
                 UPDATE memory_vector_sync_mutation_clock
                 SET last_sequence=7654 WHERE singleton=1;",
            )
            .unwrap();
        let evidence = version_thirteen_commit_evidence(&authorized);
        drop(authorized);
        evidence
    }

    /// Proves that when the authoritative upgrade's **real**
    /// `Transaction::commit()` fails, the production coordinator rolls the whole
    /// version-14 transaction back, maps the failure to its stable deidentified
    /// category, and reaches neither the WAL step nor `StorageService`
    /// publication.
    ///
    /// The commit failure is genuine SQLite lock arbitration, not injection. On
    /// this rollback-journal (`DELETE`) database a second connection's plain read
    /// transaction holds a SHARED lock, which is compatible with the
    /// coordinator's `BEGIN IMMEDIATE` (RESERVED) — so `final-rm`, `att-i1`, and
    /// every in-transaction validation run normally — but denies the EXCLUSIVE
    /// promotion that `COMMIT` needs. Holding the reader's transaction object
    /// alive across the call is the synchronization; no sleep is involved.
    #[test]
    fn storage_initialize_real_commit_failure_rolls_back_and_skips_wal_and_publish() {
        let _ = take_upgrade_events();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(super::super::DATABASE_FILE_NAME);
        prepare_schema_version(&path, writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION);
        let evidence = seed_version_thirteen_commit_row(&path);
        assert_eq!(journal_mode(&path), "delete");

        let mut reader = Connection::open(&path).unwrap();
        let reader_transaction = reader.transaction().unwrap();
        reader_transaction
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();

        let error = match super::super::StorageService::initialize_with_roots(
            root.path().to_path_buf(),
            None,
        ) {
            Ok(_) => panic!("a failed migration commit must prevent storage publication"),
            Err(error) => error,
        };

        // The stable, deidentified category. It carries no SQLite text, path,
        // SQL, DDL, identifier, or process id.
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        let message = error.message.to_lowercase();
        for leak in [
            "database is locked",
            "sqlite",
            "commit",
            "memory_vector_sync_outbox",
            "commit-life",
            "commit-generation",
            ".sqlite3",
        ] {
            assert!(
                !message.contains(leak),
                "the mapped message must not leak {leak}"
            );
        }

        // The coordinator reached the real commit and stopped there: no
        // post-verify, no WAL, no publish.
        assert_eq!(
            take_upgrade_events(),
            vec![
                "mutex",
                "open-before-wal",
                "version-read",
                "preflight-rm",
                "begin-immediate",
                "final-rm",
                "att-i1",
                "commit",
            ]
        );

        drop(reader_transaction);

        // A brand-new independent connection reads only committed on-disk state.
        let verifier = Connection::open(&path).unwrap();
        assert_eq!(
            connection::read_schema_version(&verifier).unwrap(),
            writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION
        );
        assert_eq!(attempt_identity_column_count(&verifier), 0);
        assert_eq!(writer_fence_count(&verifier), 18);
        assert_eq!(version_thirteen_commit_evidence(&verifier), evidence);
        assert_eq!(
            verifier
                .query_row(
                    "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            7_654
        );
        assert_eq!(journal_mode(&path), "delete");
        assert!(!path.with_extension("sqlite3-wal").exists());
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
                "h1-b",
                "att-i1",
                "commit",
                "post-verify",
                "wal",
                "publish",
            ]
        );
    }
}
