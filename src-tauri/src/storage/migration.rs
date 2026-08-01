use std::{fs, path::Path, time::Duration};

use rusqlite::{backup::Backup, params, Connection, OptionalExtension, Transaction};

use super::{connection, writer_fence_manifest, StorageError, MIGRATIONS};

pub(super) const LAST_STATIC_MIGRATION_VERSION: i64 = 12;
const WRITER_FENCE_MIGRATION_NAME: &str = "013_historical_outbox_isolation_and_writer_fence";
pub(super) const ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION: i64 = 14;
const ATTEMPT_CLAIM_IDENTITY_MIGRATION_NAME: &str = "014_vector_sync_attempt_claim_identity";
#[cfg(test)]
const FENCED_CLAIM_EPOCH_COLUMN_DDL: &str =
    "fenced_claim_epoch INTEGER NOT NULL DEFAULT 0 CHECK (fenced_claim_epoch >= 0)";
#[cfg(test)]
const LAST_MARKED_CLAIM_EPOCH_COLUMN_DDL: &str = "last_marked_claim_epoch INTEGER NOT NULL DEFAULT 0 CHECK (last_marked_claim_epoch >= 0 AND last_marked_claim_epoch <= fenced_claim_epoch AND (last_marked_claim_epoch = 0 OR attempt_count > 0))";
const ADD_FENCED_CLAIM_EPOCH_COLUMN_SQL: &str = "ALTER TABLE memory_vector_sync_outbox ADD COLUMN fenced_claim_epoch INTEGER NOT NULL DEFAULT 0 CHECK (fenced_claim_epoch >= 0)";
const ADD_LAST_MARKED_CLAIM_EPOCH_COLUMN_SQL: &str = "ALTER TABLE memory_vector_sync_outbox ADD COLUMN last_marked_claim_epoch INTEGER NOT NULL DEFAULT 0 CHECK (last_marked_claim_epoch >= 0 AND last_marked_claim_epoch <= fenced_claim_epoch AND (last_marked_claim_epoch = 0 OR attempt_count > 0))";
const NORMALIZED_FENCED_CLAIM_EPOCH_COLUMN_DDL: &str =
    "fenced_claim_epochintegernotnulldefault0check(fenced_claim_epoch>=0)";
const NORMALIZED_LAST_MARKED_CLAIM_EPOCH_COLUMN_DDL: &str = "last_marked_claim_epochintegernotnulldefault0check(last_marked_claim_epoch>=0andlast_marked_claim_epoch<=fenced_claim_epochand(last_marked_claim_epoch=0orattempt_count>0))";

/// The fixed H1-B schema phase is applied exactly once after static migrations
/// 1 through 12 have completed in the caller-owned transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WriterFenceSchemaUpgrade {
    Applied,
}

/// The fixed ATT-I1 schema phase is applied exactly once after the version-13
/// writer-fence phase in the caller-owned transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AttemptClaimIdentitySchemaUpgrade {
    Applied,
}

/// Applies every pending registered migration in a caller-owned transaction.
///
/// This function never creates a nested transaction, commits, configures WAL,
/// invokes Restart Manager, or installs the writer-fence Trigger schema.
pub(super) fn apply_pending_migrations_in_transaction(
    transaction: &Transaction<'_>,
    from_version: i64,
    target_version: i64,
) -> Result<(), StorageError> {
    if target_version != connection::MAX_SUPPORTED_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    if !(0..=LAST_STATIC_MIGRATION_VERSION).contains(&from_version) {
        return Err(StorageError::migration_version_invariant_failed());
    }
    apply_migrations_from_static_registry(
        transaction,
        from_version,
        LAST_STATIC_MIGRATION_VERSION,
        MIGRATIONS,
    )
}

/// Fixed H1-B extension location. It accepts only the caller-owned transaction
/// and executes the repository's static historical-isolation and writer-fence
/// steps; callers cannot supply SQL, callbacks, names, or a migration registry.
pub(super) fn apply_writer_fence_schema_upgrade_if_registered(
    transaction: &Transaction<'_>,
) -> Result<WriterFenceSchemaUpgrade, StorageError> {
    debug_assert_eq!(writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION, 13);
    debug_assert_eq!(
        writer_fence_manifest::writer_fence_trigger_specs().len(),
        18
    );
    if connection::read_schema_version(transaction)? != LAST_STATIC_MIGRATION_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }

    isolate_historical_outbox_in_transaction(transaction)?;
    writer_fence_manifest::install_writer_fence_manifest_in_transaction(transaction)?;

    #[cfg(test)]
    if should_fail_migration_013_at_for_test(Migration013Failpoint::SchemaVersion) {
        return Err(StorageError::migration_transaction_failed());
    }
    transaction
        .execute(
            "INSERT INTO schema_migration (version, name, applied_at)
             VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![
                writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION,
                WRITER_FENCE_MIGRATION_NAME
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;

    #[cfg(test)]
    if should_fail_migration_013_at_for_test(Migration013Failpoint::ManifestValidation) {
        return Err(StorageError::migration_transaction_failed());
    }
    writer_fence_manifest::validate_writer_fence_manifest(transaction)?;
    Ok(WriterFenceSchemaUpgrade::Applied)
}

/// Fixed ATT-I1 extension location. It accepts only the caller-owned
/// transaction and performs the repository's sole authoritative version-14
/// schema change; callers cannot supply SQL, callbacks, names, or versions.
pub(super) fn apply_attempt_claim_identity_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<AttemptClaimIdentitySchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)?
        != writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION
    {
        return Err(StorageError::migration_version_invariant_failed());
    }

    #[cfg(test)]
    if should_fail_migration_014_at_for_test(Migration014Failpoint::FirstColumn) {
        return Err(StorageError::migration_transaction_failed());
    }
    transaction
        .execute_batch(ADD_FENCED_CLAIM_EPOCH_COLUMN_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;

    #[cfg(test)]
    if should_fail_migration_014_at_for_test(Migration014Failpoint::SecondColumn) {
        return Err(StorageError::migration_transaction_failed());
    }
    transaction
        .execute_batch(ADD_LAST_MARKED_CLAIM_EPOCH_COLUMN_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;

    #[cfg(test)]
    if should_fail_migration_014_at_for_test(Migration014Failpoint::SchemaVersion) {
        return Err(StorageError::migration_transaction_failed());
    }
    transaction
        .execute(
            "INSERT INTO schema_migration (version, name, applied_at)
             VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![
                ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION,
                ATTEMPT_CLAIM_IDENTITY_MIGRATION_NAME
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;

    #[cfg(test)]
    if should_fail_migration_014_at_for_test(Migration014Failpoint::SchemaValidation) {
        return Err(StorageError::migration_transaction_failed());
    }
    validate_attempt_claim_identity_schema(transaction)?;

    #[cfg(test)]
    if should_fail_migration_014_at_for_test(Migration014Failpoint::ManifestValidation) {
        return Err(StorageError::migration_transaction_failed());
    }
    writer_fence_manifest::validate_writer_fence_manifest(transaction)?;
    Ok(AttemptClaimIdentitySchemaUpgrade::Applied)
}

/// Validates the exact ATT-I1 outbox column definitions from SQLite's own
/// schema. This read-only validator does not repair or mutate database state.
pub(super) fn validate_attempt_claim_identity_schema(
    connection: &Connection,
) -> Result<(), StorageError> {
    let mut statement = connection
        .prepare("PRAGMA table_info(memory_vector_sync_outbox)")
        .map_err(|_| StorageError::attempt_claim_identity_schema_invalid())?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(|_| StorageError::attempt_claim_identity_schema_invalid())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StorageError::attempt_claim_identity_schema_invalid())?;

    for expected in ["fenced_claim_epoch", "last_marked_claim_epoch"] {
        let matches = columns
            .iter()
            .filter(|(name, _, _, _)| name == expected)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(StorageError::attempt_claim_identity_schema_invalid());
        }
        let (_, declared_type, not_null, default_value) = matches[0];
        if !declared_type.eq_ignore_ascii_case("INTEGER")
            || *not_null != 1
            || default_value
                .as_deref()
                .map(normalize_schema_fragment)
                .as_deref()
                != Some("0")
        {
            return Err(StorageError::attempt_claim_identity_schema_invalid());
        }
    }

    let table_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type='table' AND name='memory_vector_sync_outbox'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StorageError::attempt_claim_identity_schema_invalid())?;
    let definitions = table_sql
        .as_deref()
        .and_then(normalized_top_level_column_definitions)
        .ok_or_else(StorageError::attempt_claim_identity_schema_invalid)?;
    for expected in [
        NORMALIZED_FENCED_CLAIM_EPOCH_COLUMN_DDL,
        NORMALIZED_LAST_MARKED_CLAIM_EPOCH_COLUMN_DDL,
    ] {
        if definitions
            .iter()
            .filter(|definition| definition.as_str() == expected)
            .count()
            != 1
        {
            return Err(StorageError::attempt_claim_identity_schema_invalid());
        }
    }
    Ok(())
}

fn normalize_schema_fragment(value: &str) -> String {
    value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase())
        .map(char::from)
        .collect()
}

fn normalized_top_level_column_definitions(table_sql: &str) -> Option<Vec<String>> {
    let opening = table_sql.find('(')?;
    let body = &table_sql[opening + 1..];
    let mut definitions = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, character) in body.char_indices() {
        match character {
            '(' => depth = depth.checked_add(1)?,
            ')' if depth == 0 => {
                definitions.push(normalize_schema_fragment(&body[start..index]));
                return Some(definitions);
            }
            ')' => depth -= 1,
            ',' if depth == 0 => {
                definitions.push(normalize_schema_fragment(&body[start..index]));
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    None
}

fn isolate_historical_outbox_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    #[cfg(test)]
    if should_fail_migration_013_at_for_test(Migration013Failpoint::HistoricalIsolation) {
        return Err(StorageError::migration_transaction_failed());
    }

    // The SQL engine, rather than a Rust-side set, determines the exact
    // distinct Memory set that receives one mutation-clock increment.
    let affected_memory_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM (
                 SELECT DISTINCT life_id, memory_id
                 FROM memory_vector_sync_outbox
                 WHERE state IN ('pending', 'processing')
                   AND migration_disposition IS NULL
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if affected_memory_count < 0 {
        return Err(StorageError::migration_transaction_failed());
    }

    let isolated = transaction
        .execute(
            "UPDATE memory_vector_sync_outbox
             SET state='failed', next_attempt_at=NULL,
                 lease_owner=NULL, lease_expires_at=NULL, lease_fence_epoch=NULL,
                 migration_disposition='legacy_upsert_rebuild_required',
                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE state IN ('pending', 'processing')
               AND migration_disposition IS NULL",
            [],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if affected_memory_count == 0 && isolated != 0 {
        return Err(StorageError::migration_transaction_failed());
    }

    if affected_memory_count == 0 {
        return Ok(());
    }

    #[cfg(test)]
    if should_fail_migration_013_at_for_test(Migration013Failpoint::MutationClock) {
        return Err(StorageError::migration_transaction_failed());
    }
    let clock_changed = transaction
        .execute(
            "UPDATE memory_vector_sync_mutation_clock
             SET last_sequence=last_sequence + ?1
             WHERE singleton=1
               AND last_sequence <= 9223372036854775807 - ?1",
            [affected_memory_count],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if clock_changed != 1 {
        return Err(StorageError::migration_transaction_failed());
    }
    Ok(())
}

/// Performs schema-only post-commit verification for the authoritative
/// database. Backup verification has additional LifeIdentity requirements and
/// therefore remains a separate operation below.
pub(super) fn verify_schema_after_upgrade(
    connection: &Connection,
    expected_schema_version: i64,
) -> Result<(), StorageError> {
    #[cfg(test)]
    if should_fail_post_commit_verification_at_for_test(PostCommitVerificationFailpoint::Generic) {
        return Err(StorageError::migration_post_commit_verification_failed());
    }

    let found_version = connection::read_schema_version(connection)
        .map_err(|_| StorageError::migration_post_commit_verification_failed())?;
    if found_version != expected_schema_version {
        return Err(StorageError::migration_version_invariant_failed());
    }

    if expected_schema_version == ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION {
        #[cfg(test)]
        if should_fail_post_commit_verification_at_for_test(
            PostCommitVerificationFailpoint::AttemptClaimIdentitySchema,
        ) {
            return Err(StorageError::migration_post_commit_verification_failed());
        }
        validate_attempt_claim_identity_schema(connection)?;
    }
    if expected_schema_version >= writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION {
        #[cfg(test)]
        if should_fail_post_commit_verification_at_for_test(
            PostCommitVerificationFailpoint::WriterFenceManifest,
        ) {
            return Err(StorageError::migration_post_commit_verification_failed());
        }
        writer_fence_manifest::validate_writer_fence_manifest(connection)?;
    }

    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| StorageError::migration_post_commit_verification_failed())?;
    if integrity != "ok" {
        return Err(StorageError::migration_post_commit_verification_failed());
    }
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PostCommitVerificationFailpoint {
    Generic,
    AttemptClaimIdentitySchema,
    WriterFenceManifest,
}

#[cfg(test)]
thread_local! {
    static POST_COMMIT_VERIFICATION_FAILPOINT: std::cell::Cell<Option<PostCommitVerificationFailpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_post_commit_verification_for_test() {
    fail_next_post_commit_verification_at_for_test(PostCommitVerificationFailpoint::Generic);
}

#[cfg(test)]
pub(super) fn fail_next_post_commit_verification_at_for_test(
    failpoint: PostCommitVerificationFailpoint,
) {
    POST_COMMIT_VERIFICATION_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_post_commit_verification_at_for_test(
    failpoint: PostCommitVerificationFailpoint,
) -> bool {
    POST_COMMIT_VERIFICATION_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration013Failpoint {
    HistoricalIsolation,
    MutationClock,
    SchemaVersion,
    ManifestValidation,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_013_FAILPOINT: std::cell::Cell<Option<Migration013Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_013_at_for_test(failpoint: Migration013Failpoint) {
    MIGRATION_013_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_013_at_for_test(failpoint: Migration013Failpoint) -> bool {
    MIGRATION_013_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration014Failpoint {
    FirstColumn,
    SecondColumn,
    SchemaVersion,
    SchemaValidation,
    ManifestValidation,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_014_FAILPOINT: std::cell::Cell<Option<Migration014Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_014_at_for_test(failpoint: Migration014Failpoint) {
    MIGRATION_014_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_014_at_for_test(failpoint: Migration014Failpoint) -> bool {
    MIGRATION_014_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

fn apply_migrations_from_static_registry(
    transaction: &Transaction<'_>,
    from_version: i64,
    target_version: i64,
    registered_migrations: &[(i64, &str, &str)],
) -> Result<(), StorageError> {
    validate_migration_registry(registered_migrations, target_version)?;
    if from_version < 0 || from_version > target_version {
        return Err(StorageError::migration_version_invariant_failed());
    }

    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migration (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );",
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    validate_applied_migration_history(transaction, from_version, registered_migrations)?;

    for (version, name, sql) in registered_migrations {
        if *version <= from_version {
            continue;
        }

        transaction
            .execute_batch(sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
        transaction
            .execute(
                "INSERT INTO schema_migration (version, name, applied_at)
                 VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                params![version, name],
            )
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

fn validate_migration_registry(
    registered_migrations: &[(i64, &str, &str)],
    target_version: i64,
) -> Result<(), StorageError> {
    if target_version <= 0 || registered_migrations.len() != target_version as usize {
        return Err(StorageError::migration_version_invariant_failed());
    }

    for (index, (version, _name, sql)) in registered_migrations.iter().enumerate() {
        let expected_version = i64::try_from(index + 1)
            .map_err(|_| StorageError::migration_version_invariant_failed())?;
        if *version != expected_version || name_is_invalid(sql) {
            return Err(StorageError::migration_version_invariant_failed());
        }
    }
    Ok(())
}

fn name_is_invalid(sql: &str) -> bool {
    sql.trim().is_empty()
}

fn validate_applied_migration_history(
    transaction: &Transaction<'_>,
    from_version: i64,
    registered_migrations: &[(i64, &str, &str)],
) -> Result<(), StorageError> {
    let mut statement = transaction
        .prepare("SELECT version, name FROM schema_migration ORDER BY version ASC")
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let applied = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StorageError::migration_transaction_failed())?;

    let expected = registered_migrations
        .iter()
        .take(
            usize::try_from(from_version)
                .map_err(|_| StorageError::migration_version_invariant_failed())?,
        )
        .map(|(version, name, _)| (*version, (*name).to_string()))
        .collect::<Vec<_>>();
    if applied != expected {
        return Err(StorageError::migration_version_invariant_failed());
    }
    Ok(())
}

pub fn backup_and_verify(
    source: &Connection,
    temporary_database: &Path,
    expected_schema_version: i64,
    expected_life_id: &str,
) -> Result<(), StorageError> {
    if temporary_database.exists() {
        fs::remove_file(temporary_database).map_err(|error| {
            StorageError::new(
                "MIGRATION_TEMP_CLEANUP_FAILED",
                format!("Cannot remove a stale temporary database: {error}"),
                true,
            )
        })?;
    }

    let result = (|| -> Result<(), StorageError> {
        let mut target = connection::open_authorized_storage_connection(temporary_database)?;

        {
            let backup = Backup::new(source, &mut target).map_err(|error| {
                StorageError::new(
                    "MIGRATION_BACKUP_INIT_FAILED",
                    format!("Cannot initialize SQLite Online Backup: {error}"),
                    true,
                )
            })?;
            backup
                .run_to_completion(32, Duration::from_millis(10), None)
                .map_err(|error| {
                    StorageError::new(
                        "MIGRATION_BACKUP_FAILED",
                        format!("SQLite Online Backup failed: {error}"),
                        true,
                    )
                })?;
        }

        verify_database(&target, expected_schema_version, expected_life_id)
    })();

    if result.is_err() {
        let _ = fs::remove_file(temporary_database);
    }
    result
}

pub fn verify_database(
    connection: &Connection,
    expected_schema_version: i64,
    expected_life_id: &str,
) -> Result<(), StorageError> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|error| {
            StorageError::new(
                "MIGRATION_INTEGRITY_CHECK_FAILED",
                format!("Cannot run target integrity_check: {error}"),
                true,
            )
        })?;
    if integrity != "ok" {
        return Err(StorageError::new(
            "MIGRATION_INTEGRITY_INVALID",
            format!("Target integrity_check returned: {integrity}"),
            true,
        ));
    }

    let schema_version: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migration",
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            StorageError::new(
                "MIGRATION_SCHEMA_CHECK_FAILED",
                format!("Cannot read the target schema version: {error}"),
                true,
            )
        })?;
    if schema_version != expected_schema_version {
        return Err(StorageError::new(
            "MIGRATION_SCHEMA_MISMATCH",
            format!(
                "Target schema version {schema_version} does not match source version {expected_schema_version}."
            ),
            true,
        ));
    }

    if expected_schema_version == ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION {
        validate_attempt_claim_identity_schema(connection)?;
    }
    if expected_schema_version >= writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION {
        writer_fence_manifest::validate_writer_fence_manifest(connection)?;
    }

    let current_life_id: Option<String> = connection
        .query_row(
            "SELECT current_life_id FROM app_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| {
            StorageError::new(
                "MIGRATION_CURRENT_LIFE_CHECK_FAILED",
                format!("Cannot read current_life_id from the target database: {error}"),
                true,
            )
        })?;
    if current_life_id.as_deref() != Some(expected_life_id) {
        return Err(StorageError::new(
            "MIGRATION_CURRENT_LIFE_MISMATCH",
            "The target database current_life_id does not match the source database.",
            true,
        ));
    }

    let life_exists: i64 = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
            [expected_life_id],
            |row| row.get(0),
        )
        .map_err(|error| {
            StorageError::new(
                "MIGRATION_LIFE_CHECK_FAILED",
                format!("Cannot read the current LifeIdentity from the target database: {error}"),
                true,
            )
        })?;
    if life_exists != 1 {
        return Err(StorageError::new(
            "MIGRATION_LIFE_MISSING",
            "The current LifeIdentity is missing from the target database.",
            true,
        ));
    }

    Ok(())
}

pub fn activate_temporary_database(
    temporary_database: &Path,
    final_database: &Path,
) -> Result<(), StorageError> {
    if final_database.exists() {
        return Err(StorageError::new(
            "MIGRATION_TARGET_EXISTS",
            "The target directory already contains a digital-life.sqlite3 database.",
            true,
        ));
    }

    fs::rename(temporary_database, final_database).map_err(|error| {
        StorageError::new(
            "MIGRATION_ACTIVATION_FAILED",
            format!("Cannot atomically activate the target database: {error}"),
            true,
        )
    })
}

#[cfg(test)]
mod transaction_tests {
    use rusqlite::{functions::FunctionFlags, params, Connection, TransactionBehavior};

    use super::*;

    const TEST_MIGRATIONS: &[(i64, &str, &str)] = &[
        (
            1,
            "one",
            "CREATE TABLE migration_test_one (id INTEGER PRIMARY KEY)",
        ),
        (
            2,
            "two",
            "CREATE TABLE migration_test_two (id INTEGER PRIMARY KEY)",
        ),
    ];

    fn transaction_connection() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    fn schema_version(connection: &Connection) -> i64 {
        connection
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migration",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct HistoricalOutboxSnapshot {
        desired_action: String,
        state: String,
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
        migration_disposition: Option<String>,
    }

    struct HistoricalRowFixture<'a> {
        life_id: &'a str,
        memory_id: &'a str,
        desired_action: &'a str,
        state: &'a str,
        migration_disposition: Option<&'a str>,
        attempt_count: i64,
        mutation_sequence: i64,
        target_revision: Option<i64>,
        target_content_hash: Option<&'a str>,
        claimed_generation_id: Option<&'a str>,
        last_error_code: Option<&'a str>,
        last_send_disposition: Option<&'a str>,
        next_attempt_at: Option<&'a str>,
        lease_owner: Option<&'a str>,
        lease_fence_epoch: Option<i64>,
        lease_expires_at: Option<&'a str>,
    }

    fn version_twelve_connection() -> Connection {
        let mut connection = transaction_connection();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        apply_pending_migrations_in_transaction(
            &transaction,
            0,
            connection::MAX_SUPPORTED_SCHEMA_VERSION,
        )
        .unwrap();
        transaction.commit().unwrap();
        assert_eq!(schema_version(&connection), LAST_STATIC_MIGRATION_VERSION);
        connection
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

    fn historical_snapshot(
        connection: &Connection,
        life_id: &str,
        memory_id: &str,
    ) -> HistoricalOutboxSnapshot {
        connection
            .query_row(
                "SELECT desired_action, state, attempt_count, mutation_sequence,
                        target_revision, target_content_hash, claimed_generation_id,
                        last_error_code, last_send_disposition, next_attempt_at,
                        lease_owner, lease_fence_epoch, lease_expires_at,
                        migration_disposition
                 FROM memory_vector_sync_outbox
                 WHERE life_id=?1 AND memory_id=?2",
                params![life_id, memory_id],
                |row| {
                    Ok(HistoricalOutboxSnapshot {
                        desired_action: row.get(0)?,
                        state: row.get(1)?,
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
                        migration_disposition: row.get(13)?,
                    })
                },
            )
            .unwrap()
    }

    fn insert_historical_row(connection: &Connection, row: HistoricalRowFixture<'_>) {
        connection
            .execute(
                "INSERT INTO memory_vector_sync_outbox
                 (life_id, memory_id, desired_action, state, migration_disposition,
                  attempt_count, mutation_sequence, target_revision, target_content_hash,
                  claimed_generation_id, last_error_code, last_send_disposition,
                  next_attempt_at, lease_owner, lease_fence_epoch, lease_expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                         ?13, ?14, ?15, ?16)",
                params![
                    row.life_id,
                    row.memory_id,
                    row.desired_action,
                    row.state,
                    row.migration_disposition,
                    row.attempt_count,
                    row.mutation_sequence,
                    row.target_revision,
                    row.target_content_hash,
                    row.claimed_generation_id,
                    row.last_error_code,
                    row.last_send_disposition,
                    row.next_attempt_at,
                    row.lease_owner,
                    row.lease_fence_epoch,
                    row.lease_expires_at,
                ],
            )
            .unwrap();
    }

    fn apply_writer_fence_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_writer_fence_schema_upgrade_if_registered(&transaction).unwrap(),
            WriterFenceSchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn version_thirteen_connection() -> Connection {
        let mut connection = version_twelve_connection();
        connection
            .create_scalar_function(
                "digital_life_writer_epoch",
                0,
                FunctionFlags::SQLITE_UTF8
                    | FunctionFlags::SQLITE_DETERMINISTIC
                    | FunctionFlags::SQLITE_INNOCUOUS,
                |_| Ok(1_i64),
            )
            .unwrap();
        apply_writer_fence_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION
        );
        connection
    }

    fn apply_attempt_claim_identity_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_attempt_claim_identity_schema_upgrade(&transaction).unwrap(),
            AttemptClaimIdentitySchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn attempt_epoch_values(connection: &Connection, life_id: &str, memory_id: &str) -> (i64, i64) {
        connection
            .query_row(
                "SELECT fenced_claim_epoch, last_marked_claim_epoch
                 FROM memory_vector_sync_outbox WHERE life_id=?1 AND memory_id=?2",
                params![life_id, memory_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    fn attempt_column_count(connection: &Connection) -> i64 {
        connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('memory_vector_sync_outbox')
                 WHERE name IN ('fenced_claim_epoch', 'last_marked_claim_epoch')",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn schema_fourteen_validation_connection(
        fenced_claim_epoch_definition: Option<&str>,
        last_marked_claim_epoch_definition: Option<&str>,
    ) -> Connection {
        let connection = transaction_connection();
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
                "CREATE TABLE memory_vector_sync_outbox ({definitions})"
            ))
            .unwrap();
        connection
    }

    #[test]
    fn migration_transaction_registry_is_unique_and_strictly_incrementing() {
        validate_migration_registry(MIGRATIONS, LAST_STATIC_MIGRATION_VERSION).unwrap();
        let missing = [(1, "one", "SELECT 1"), (3, "three", "SELECT 1")];
        let duplicate = [(1, "one", "SELECT 1"), (1, "again", "SELECT 1")];
        let reversed = [(2, "two", "SELECT 1"), (1, "one", "SELECT 1")];
        for registry in [&missing[..], &duplicate[..], &reversed[..]] {
            let error = validate_migration_registry(registry, 2).unwrap_err();
            assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        }
    }

    #[test]
    fn migration_transaction_rejects_targets_outside_the_h1_a3_contract() {
        let mut connection = transaction_connection();
        let transaction = connection.transaction().unwrap();
        for target in [0, writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION, 15] {
            let error =
                apply_pending_migrations_in_transaction(&transaction, 0, target).unwrap_err();
            assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        }
    }

    #[test]
    fn migration_transaction_skips_already_applied_versions_and_uses_the_caller_transaction() {
        let mut connection = transaction_connection();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        apply_migrations_from_static_registry(&transaction, 0, 2, TEST_MIGRATIONS).unwrap();
        transaction.commit().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        apply_migrations_from_static_registry(&transaction, 2, 2, TEST_MIGRATIONS).unwrap();
        assert_eq!(
            transaction
                .query_row("SELECT COUNT(*) FROM schema_migration", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        drop(transaction);
        assert_eq!(schema_version(&connection), 2);
    }

    #[test]
    fn migration_transaction_rejects_an_applied_history_gap() {
        let mut connection = transaction_connection();
        connection.execute_batch("CREATE TABLE schema_migration (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL); INSERT INTO schema_migration (version, name, applied_at) VALUES (2, 'two', '2026-01-01T00:00:00Z');").unwrap();
        let transaction = connection.transaction().unwrap();
        let error =
            apply_migrations_from_static_registry(&transaction, 2, 2, TEST_MIGRATIONS).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
    }

    #[test]
    fn migration_transaction_rolls_back_every_ddl_and_version_row_when_a_migration_fails() {
        let migrations = [
            (1, "one", "CREATE TABLE atomic_one (id INTEGER PRIMARY KEY)"),
            (2, "bad", "SELECT intentionally_invalid_sql"),
        ];
        let mut connection = transaction_connection();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error =
            apply_migrations_from_static_registry(&transaction, 0, 2, &migrations).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        drop(transaction);
        let object_count: i64 = connection.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('atomic_one', 'schema_migration')", [], |row| row.get(0)).unwrap();
        assert_eq!(object_count, 0);
    }

    #[test]
    fn migration_transaction_rolls_back_ddl_when_the_version_row_insert_fails() {
        let migrations = [(
            1,
            "one",
            "CREATE TABLE version_insert_atomic (id INTEGER PRIMARY KEY)",
        )];
        let mut connection = transaction_connection();
        connection.execute_batch("CREATE TABLE schema_migration (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL); CREATE TRIGGER reject_schema_migration_insert BEFORE INSERT ON schema_migration BEGIN SELECT RAISE(ABORT, 'reject'); END;").unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error =
            apply_migrations_from_static_registry(&transaction, 0, 1, &migrations).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        drop(transaction);
        let table_exists: i64 = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'version_insert_atomic')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_exists, 0);
    }

    #[test]
    fn migration_transaction_does_not_commit_configure_wal_or_install_writer_fences() {
        let mut connection = transaction_connection();
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        apply_migrations_from_static_registry(&transaction, 0, 2, TEST_MIGRATIONS).unwrap();
        let journal_mode: String = transaction
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_ne!(journal_mode, "wal");
        let writer_fence_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name GLOB 'digital_life_writer_epoch_*'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(writer_fence_count, 0);
        drop(transaction);
        let table_exists: i64 = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'migration_test_one')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_exists, 0);
    }

    #[test]
    fn migration_transaction_h1_b_extension_is_fixed_after_static_migrations() {
        let mut connection = transaction_connection();
        let transaction = connection.transaction().unwrap();
        apply_migrations_from_static_registry(
            &transaction,
            0,
            LAST_STATIC_MIGRATION_VERSION,
            MIGRATIONS,
        )
        .unwrap();
        assert_eq!(
            apply_writer_fence_schema_upgrade_if_registered(&transaction).unwrap(),
            WriterFenceSchemaUpgrade::Applied
        );
        drop(transaction);
    }

    #[test]
    fn migration_014_adds_zero_default_epochs_without_rewriting_existing_evidence() {
        let mut connection = version_thirteen_connection();
        insert_historical_row(
            &connection,
            HistoricalRowFixture {
                life_id: "attempt-life",
                memory_id: "processing-row",
                desired_action: "delete",
                state: "processing",
                migration_disposition: None,
                attempt_count: 3,
                mutation_sequence: 91,
                target_revision: Some(7),
                target_content_hash: Some("attempt-target"),
                claimed_generation_id: Some("attempt-generation"),
                last_error_code: Some("ATTEMPT_OLD_ERROR"),
                last_send_disposition: Some("possibly_sent"),
                next_attempt_at: Some("2026-07-01T00:00:00.000Z"),
                lease_owner: Some("attempt-owner"),
                lease_fence_epoch: Some(8),
                lease_expires_at: Some("2026-07-02T00:00:00.000Z"),
            },
        );
        let before = historical_snapshot(&connection, "attempt-life", "processing-row");

        apply_attempt_claim_identity_upgrade(&mut connection);

        assert_eq!(
            schema_version(&connection),
            ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION
        );
        assert_eq!(
            historical_snapshot(&connection, "attempt-life", "processing-row"),
            before
        );
        assert_eq!(
            attempt_epoch_values(&connection, "attempt-life", "processing-row"),
            (0, 0)
        );
        assert_eq!(writer_fence_count(&connection), 18);
        validate_attempt_claim_identity_schema(&connection).unwrap();
    }

    #[test]
    fn migration_014_preserves_non_processing_rows_and_migration_disposition() {
        let mut connection = version_thirteen_connection();
        for (memory_id, state, disposition) in [
            ("failed", "failed", None),
            ("blocked", "blocked", None),
            ("retry", "retry_wait", None),
            ("isolated", "failed", Some("legacy_upsert_rebuild_required")),
        ] {
            insert_historical_row(
                &connection,
                HistoricalRowFixture {
                    life_id: "attempt-life",
                    memory_id,
                    desired_action: "delete",
                    state,
                    migration_disposition: disposition,
                    attempt_count: 2,
                    mutation_sequence: 11,
                    target_revision: Some(2),
                    target_content_hash: Some("preserved-target"),
                    claimed_generation_id: Some("preserved-generation"),
                    last_error_code: Some("PRESERVED_ERROR"),
                    last_send_disposition: Some("definitely_not_sent"),
                    next_attempt_at: Some("2026-08-01T00:00:00.000Z"),
                    lease_owner: Some("preserved-owner"),
                    lease_fence_epoch: Some(7),
                    lease_expires_at: Some("2026-08-02T00:00:00.000Z"),
                },
            );
        }
        let before = ["failed", "blocked", "retry", "isolated"]
            .into_iter()
            .map(|memory_id| historical_snapshot(&connection, "attempt-life", memory_id))
            .collect::<Vec<_>>();

        apply_attempt_claim_identity_upgrade(&mut connection);

        for (memory_id, expected) in ["failed", "blocked", "retry", "isolated"]
            .into_iter()
            .zip(before)
        {
            assert_eq!(
                historical_snapshot(&connection, "attempt-life", memory_id),
                expected
            );
            assert_eq!(
                attempt_epoch_values(&connection, "attempt-life", memory_id),
                (0, 0)
            );
        }
    }

    #[test]
    fn schema_fourteen_validator_accepts_exact_real_sqlite_schema() {
        let connection = schema_fourteen_validation_connection(
            Some(FENCED_CLAIM_EPOCH_COLUMN_DDL),
            Some(LAST_MARKED_CLAIM_EPOCH_COLUMN_DDL),
        );
        validate_attempt_claim_identity_schema(&connection).unwrap();
    }

    #[test]
    fn schema_fourteen_validator_rejects_missing_or_weakened_identity_columns() {
        let malformed_schemas = [
            (None, Some("last_marked_claim_epoch INTEGER NOT NULL DEFAULT 0 CHECK (last_marked_claim_epoch >= 0)")),
            (Some(FENCED_CLAIM_EPOCH_COLUMN_DDL), None),
            (Some("fenced_claim_epoch TEXT NOT NULL DEFAULT 0 CHECK (fenced_claim_epoch >= 0)"), Some(LAST_MARKED_CLAIM_EPOCH_COLUMN_DDL)),
            (Some("fenced_claim_epoch INTEGER DEFAULT 0 CHECK (fenced_claim_epoch >= 0)"), Some(LAST_MARKED_CLAIM_EPOCH_COLUMN_DDL)),
            (Some("fenced_claim_epoch INTEGER NOT NULL DEFAULT 1 CHECK (fenced_claim_epoch >= 0)"), Some(LAST_MARKED_CLAIM_EPOCH_COLUMN_DDL)),
            (Some("fenced_claim_epoch INTEGER NOT NULL DEFAULT 0 CHECK (fenced_claim_epoch >= -1)"), Some(LAST_MARKED_CLAIM_EPOCH_COLUMN_DDL)),
            (Some(FENCED_CLAIM_EPOCH_COLUMN_DDL), Some("last_marked_claim_epoch TEXT NOT NULL DEFAULT 0 CHECK (last_marked_claim_epoch >= 0 AND last_marked_claim_epoch <= fenced_claim_epoch AND (last_marked_claim_epoch = 0 OR attempt_count > 0))")),
            (Some(FENCED_CLAIM_EPOCH_COLUMN_DDL), Some("last_marked_claim_epoch INTEGER DEFAULT 0 CHECK (last_marked_claim_epoch >= 0 AND last_marked_claim_epoch <= fenced_claim_epoch AND (last_marked_claim_epoch = 0 OR attempt_count > 0))")),
            (Some(FENCED_CLAIM_EPOCH_COLUMN_DDL), Some("last_marked_claim_epoch INTEGER NOT NULL DEFAULT 1 CHECK (last_marked_claim_epoch >= 0 AND last_marked_claim_epoch <= fenced_claim_epoch AND (last_marked_claim_epoch = 0 OR attempt_count > 0))")),
            (Some(FENCED_CLAIM_EPOCH_COLUMN_DDL), Some("last_marked_claim_epoch INTEGER NOT NULL DEFAULT 0 CHECK (last_marked_claim_epoch >= 0 AND last_marked_claim_epoch <= fenced_claim_epoch)")),
        ];
        for (fenced_claim_epoch_definition, last_marked_claim_epoch_definition) in malformed_schemas
        {
            let connection = schema_fourteen_validation_connection(
                fenced_claim_epoch_definition,
                last_marked_claim_epoch_definition,
            );
            let error = validate_attempt_claim_identity_schema(&connection).unwrap_err();
            assert_eq!(error.code, "ATTEMPT_CLAIM_IDENTITY_SCHEMA_INVALID");
        }
    }

    #[test]
    fn schema_fourteen_sqlite_constraints_reject_invalid_epoch_values() {
        let mut connection = version_thirteen_connection();
        insert_historical_row(
            &connection,
            HistoricalRowFixture {
                life_id: "attempt-life",
                memory_id: "constraint-row",
                desired_action: "delete",
                state: "pending",
                migration_disposition: None,
                attempt_count: 0,
                mutation_sequence: 1,
                target_revision: None,
                target_content_hash: None,
                claimed_generation_id: None,
                last_error_code: None,
                last_send_disposition: None,
                next_attempt_at: None,
                lease_owner: None,
                lease_fence_epoch: None,
                lease_expires_at: None,
            },
        );
        apply_attempt_claim_identity_upgrade(&mut connection);

        assert!(connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET fenced_claim_epoch=-1
                 WHERE life_id='attempt-life' AND memory_id='constraint-row'",
                [],
            )
            .is_err());
        assert!(connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET last_marked_claim_epoch=1
                 WHERE life_id='attempt-life' AND memory_id='constraint-row'",
                [],
            )
            .is_err());
        assert!(connection
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET fenced_claim_epoch=1, last_marked_claim_epoch=1
                 WHERE life_id='attempt-life' AND memory_id='constraint-row'",
                [],
            )
            .is_err());
        assert_eq!(
            attempt_epoch_values(&connection, "attempt-life", "constraint-row"),
            (0, 0)
        );
    }

    #[test]
    fn migration_014_failure_injection_rolls_back_columns_and_version() {
        for failpoint in [
            Migration014Failpoint::FirstColumn,
            Migration014Failpoint::SecondColumn,
            Migration014Failpoint::SchemaVersion,
            Migration014Failpoint::SchemaValidation,
            Migration014Failpoint::ManifestValidation,
        ] {
            let mut connection = version_thirteen_connection();
            insert_historical_row(
                &connection,
                HistoricalRowFixture {
                    life_id: "attempt-life",
                    memory_id: "rollback-row",
                    desired_action: "delete",
                    state: "processing",
                    migration_disposition: None,
                    attempt_count: 3,
                    mutation_sequence: 17,
                    target_revision: Some(4),
                    target_content_hash: Some("rollback-target"),
                    claimed_generation_id: Some("rollback-generation"),
                    last_error_code: Some("ROLLBACK_ERROR"),
                    last_send_disposition: Some("possibly_sent"),
                    next_attempt_at: Some("2026-09-01T00:00:00.000Z"),
                    lease_owner: Some("rollback-owner"),
                    lease_fence_epoch: Some(12),
                    lease_expires_at: Some("2026-09-02T00:00:00.000Z"),
                },
            );
            let before = historical_snapshot(&connection, "attempt-life", "rollback-row");
            fail_next_migration_014_at_for_test(failpoint);

            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_attempt_claim_identity_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
            drop(transaction);

            assert_eq!(
                schema_version(&connection),
                writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION
            );
            assert_eq!(attempt_column_count(&connection), 0);
            assert_eq!(
                historical_snapshot(&connection, "attempt-life", "rollback-row"),
                before
            );
            assert_eq!(writer_fence_count(&connection), 18);
        }
    }

    #[test]
    fn migration_014_rejects_a_second_application() {
        let mut connection = version_thirteen_connection();
        apply_attempt_claim_identity_upgrade(&mut connection);
        let transaction = connection.transaction().unwrap();
        let error = apply_attempt_claim_identity_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
    }

    #[test]
    fn migration_013_isolates_historical_pending_and_processing_rows_preserving_evidence() {
        let mut connection = version_twelve_connection();
        connection
            .execute(
                "UPDATE memory_vector_sync_mutation_clock SET last_sequence=40 WHERE singleton=1",
                [],
            )
            .unwrap();
        insert_historical_row(
            &connection,
            HistoricalRowFixture {
                life_id: "life-a",
                memory_id: "pending-upsert",
                desired_action: "upsert",
                state: "pending",
                migration_disposition: None,
                attempt_count: 2,
                mutation_sequence: 17,
                target_revision: Some(7),
                target_content_hash: Some("hash-pending"),
                claimed_generation_id: Some("generation-pending"),
                last_error_code: Some("OLD_PENDING"),
                last_send_disposition: Some("possibly_sent"),
                next_attempt_at: Some("2026-02-01T00:00:00.000Z"),
                lease_owner: Some("legacy-owner-pending"),
                lease_fence_epoch: Some(41),
                lease_expires_at: Some("2026-02-02T00:00:00.000Z"),
            },
        );
        insert_historical_row(
            &connection,
            HistoricalRowFixture {
                life_id: "life-b",
                memory_id: "processing-delete",
                desired_action: "delete",
                state: "processing",
                migration_disposition: None,
                attempt_count: 3,
                mutation_sequence: 19,
                target_revision: None,
                target_content_hash: None,
                claimed_generation_id: Some("generation-delete"),
                last_error_code: Some("OLD_DELETE"),
                last_send_disposition: Some("definitely_not_sent"),
                next_attempt_at: Some("2026-03-01T00:00:00.000Z"),
                lease_owner: Some("legacy-owner-delete"),
                lease_fence_epoch: Some(42),
                lease_expires_at: Some("2026-03-02T00:00:00.000Z"),
            },
        );
        let before_pending = historical_snapshot(&connection, "life-a", "pending-upsert");
        let before_processing = historical_snapshot(&connection, "life-b", "processing-delete");

        apply_writer_fence_upgrade(&mut connection);

        for (life_id, memory_id, before) in [
            ("life-a", "pending-upsert", before_pending),
            ("life-b", "processing-delete", before_processing),
        ] {
            let mut expected = before;
            expected.state = "failed".into();
            expected.next_attempt_at = None;
            expected.lease_owner = None;
            expected.lease_fence_epoch = None;
            expected.lease_expires_at = None;
            expected.migration_disposition = Some("legacy_upsert_rebuild_required".into());
            assert_eq!(
                historical_snapshot(&connection, life_id, memory_id),
                expected
            );
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            42
        );
        assert_eq!(
            schema_version(&connection),
            writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION
        );
        assert_eq!(writer_fence_count(&connection), 18);

        let transaction = connection.transaction().unwrap();
        let error = apply_writer_fence_schema_upgrade_if_registered(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
    }

    #[test]
    fn migration_013_leaves_non_operational_and_preisolated_rows_unchanged() {
        let mut connection = version_twelve_connection();
        connection
            .execute(
                "UPDATE memory_vector_sync_mutation_clock SET last_sequence=27 WHERE singleton=1",
                [],
            )
            .unwrap();
        let fixtures = [
            ("retry", "retry_wait", None),
            ("failed", "failed", None),
            ("blocked", "blocked", None),
            (
                "already-isolated",
                "pending",
                Some("legacy_upsert_rebuild_required"),
            ),
        ];
        for (index, (memory_id, state, disposition)) in fixtures.iter().enumerate() {
            insert_historical_row(
                &connection,
                HistoricalRowFixture {
                    life_id: "life",
                    memory_id,
                    desired_action: "delete",
                    state,
                    migration_disposition: *disposition,
                    attempt_count: (index + 1) as i64,
                    mutation_sequence: (index + 1) as i64,
                    target_revision: None,
                    target_content_hash: None,
                    claimed_generation_id: Some("generation-existing"),
                    last_error_code: Some("UNCHANGED"),
                    last_send_disposition: Some("definitely_not_sent"),
                    next_attempt_at: Some("2026-04-01T00:00:00.000Z"),
                    lease_owner: Some("existing-owner"),
                    lease_fence_epoch: Some(9),
                    lease_expires_at: Some("2026-04-02T00:00:00.000Z"),
                },
            );
        }
        let before = fixtures
            .iter()
            .map(|(memory_id, _, _)| historical_snapshot(&connection, "life", memory_id))
            .collect::<Vec<_>>();

        apply_writer_fence_upgrade(&mut connection);

        for ((memory_id, _, _), expected) in fixtures.iter().zip(before) {
            assert_eq!(
                historical_snapshot(&connection, "life", memory_id),
                expected,
                "{memory_id} must remain outside Migration 013's frozen set"
            );
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            27
        );
    }

    #[test]
    fn migration_013_is_a_noop_for_an_empty_historical_set() {
        let mut connection = version_twelve_connection();
        connection
            .execute(
                "UPDATE memory_vector_sync_mutation_clock SET last_sequence=11 WHERE singleton=1",
                [],
            )
            .unwrap();

        apply_writer_fence_upgrade(&mut connection);

        assert_eq!(
            connection
                .query_row(
                    "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            11
        );
        assert_eq!(
            schema_version(&connection),
            writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION
        );
        assert_eq!(writer_fence_count(&connection), 18);
    }

    #[test]
    fn migration_013_failure_injection_rolls_back_outbox_clock_triggers_and_version() {
        enum Failure {
            Migration(Migration013Failpoint),
            Trigger(usize),
        }

        for failure in [
            Failure::Migration(Migration013Failpoint::HistoricalIsolation),
            Failure::Migration(Migration013Failpoint::MutationClock),
            Failure::Trigger(1),
            Failure::Trigger(9),
            Failure::Trigger(18),
            Failure::Migration(Migration013Failpoint::SchemaVersion),
            Failure::Migration(Migration013Failpoint::ManifestValidation),
        ] {
            let mut connection = version_twelve_connection();
            connection
                .execute(
                    "UPDATE memory_vector_sync_mutation_clock SET last_sequence=8 WHERE singleton=1",
                    [],
                )
                .unwrap();
            insert_historical_row(
                &connection,
                HistoricalRowFixture {
                    life_id: "life",
                    memory_id: "rollback-row",
                    desired_action: "upsert",
                    state: "pending",
                    migration_disposition: None,
                    attempt_count: 4,
                    mutation_sequence: 31,
                    target_revision: Some(3),
                    target_content_hash: Some("rollback-hash"),
                    claimed_generation_id: Some("rollback-generation"),
                    last_error_code: Some("ROLLBACK_CODE"),
                    last_send_disposition: Some("possibly_sent"),
                    next_attempt_at: Some("2026-05-01T00:00:00.000Z"),
                    lease_owner: Some("rollback-owner"),
                    lease_fence_epoch: Some(17),
                    lease_expires_at: Some("2026-05-02T00:00:00.000Z"),
                },
            );
            let before = historical_snapshot(&connection, "life", "rollback-row");
            match failure {
                Failure::Migration(failpoint) => fail_next_migration_013_at_for_test(failpoint),
                Failure::Trigger(index) => {
                    writer_fence_manifest::fail_trigger_install_at_for_test(index)
                }
            }

            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_writer_fence_schema_upgrade_if_registered(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
            drop(transaction);

            assert_eq!(schema_version(&connection), LAST_STATIC_MIGRATION_VERSION);
            assert_eq!(
                historical_snapshot(&connection, "life", "rollback-row"),
                before
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                8
            );
            assert_eq!(writer_fence_count(&connection), 0);
        }
    }
}
