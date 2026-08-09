use std::{fs, path::Path, time::Duration};

use rusqlite::{backup::Backup, params, Connection, OptionalExtension, Transaction};

use super::{connection, writer_fence_manifest, StorageError, MIGRATIONS};

pub(super) const LAST_STATIC_MIGRATION_VERSION: i64 = 12;
const WRITER_FENCE_MIGRATION_NAME: &str = "013_historical_outbox_isolation_and_writer_fence";
pub(super) const ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION: i64 = 14;
const ATTEMPT_CLAIM_IDENTITY_MIGRATION_NAME: &str = "014_vector_sync_attempt_claim_identity";
pub(super) const LATE_DELETE_RESOLUTION_SCHEMA_VERSION: i64 = 15;
const LATE_DELETE_RESOLUTION_MIGRATION_NAME: &str = "015_vector_sync_late_delete_resolution";
pub(super) const LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION: i64 = 16;
const LATE_DELETE_GENERATION_AUTHORITY_MIGRATION_NAME: &str =
    "016_late_delete_generation_authority";
const ADD_DELETE_WITNESS_AT_SQL: &str =
    "ALTER TABLE memory_vector_sync_outbox ADD COLUMN delete_witness_at TEXT NULL";
const ADD_WITNESS_AGE_ANCHOR_AT_SQL: &str = "ALTER TABLE memory_vector_late_delete_resolution ADD COLUMN witness_age_anchor_at TEXT NOT NULL DEFAULT ''";
const ADD_CAPTURED_GENERATION_AUTHORITY_EPOCH_SQL: &str = "ALTER TABLE memory_vector_late_delete_resolution ADD COLUMN captured_generation_authority_epoch INTEGER NOT NULL DEFAULT 0 CHECK (captured_generation_authority_epoch >= 0)";
const ADD_GENERATION_AUTHORITY_EPOCH_SQL: &str = "ALTER TABLE memory_vector_generation ADD COLUMN authority_epoch INTEGER NOT NULL DEFAULT 1 CHECK (authority_epoch >= 1)";
const GENERATION_SEMANTIC_DELETE_TRIGGER_SQL: &str =
    "CREATE TRIGGER memory_vector_generation_semantic_delete_guard
BEFORE DELETE ON memory_vector_generation
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'GENERATION_AUTHORITY_DELETE_FORBIDDEN');
END";
const GENERATION_SEMANTIC_IDENTITY_TRIGGER_SQL: &str =
    "CREATE TRIGGER memory_vector_generation_semantic_identity_guard
BEFORE UPDATE OF generation_id, descriptor_hash, dimension ON memory_vector_generation
WHEN digital_life_writer_epoch() IS 1
BEGIN
    SELECT RAISE(ROLLBACK, 'GENERATION_IDENTITY_IMMUTABLE');
END";
const GENERATION_SEMANTIC_EPOCH_TRIGGER_SQL: &str = "CREATE TRIGGER memory_vector_generation_semantic_epoch_guard
BEFORE UPDATE ON memory_vector_generation
WHEN digital_life_writer_epoch() IS 1
 AND ((NEW.state <> OLD.state AND (OLD.authority_epoch = 9223372036854775807 OR NEW.authority_epoch <> OLD.authority_epoch + 1))
   OR (NEW.state = OLD.state AND NEW.authority_epoch <> OLD.authority_epoch))
BEGIN
    SELECT RAISE(ROLLBACK, 'GENERATION_AUTHORITY_EPOCH_INVALID');
END";
const CREATE_LATE_DELETE_RESOLUTION_TABLE_SQL: &str = "CREATE TABLE memory_vector_late_delete_resolution (
    resolution_id INTEGER PRIMARY KEY,
    outbox_id INTEGER NOT NULL,
    life_id TEXT NOT NULL,
    memory_id TEXT NOT NULL,
    mutation_sequence INTEGER NOT NULL CHECK (mutation_sequence > 0),
    claimed_generation_id TEXT NOT NULL CHECK (claimed_generation_id <> ''),
    embedding_descriptor_id TEXT NOT NULL CHECK (embedding_descriptor_id <> ''),
    embedding_dimension INTEGER NOT NULL CHECK (embedding_dimension > 0),
    captured_generation_state TEXT NOT NULL CHECK (captured_generation_state IN ('building','active','retired','failed')),
    witness_attempt_ordinal INTEGER NOT NULL CHECK (witness_attempt_ordinal BETWEEN 1 AND 5),
    witness_claim_epoch INTEGER NOT NULL CHECK (witness_claim_epoch > 0),
    witness_marked_claim_epoch INTEGER NOT NULL CHECK (witness_marked_claim_epoch > 0 AND witness_marked_claim_epoch <= witness_claim_epoch),
    witness_send_disposition TEXT NULL CHECK (witness_send_disposition IS NULL OR witness_send_disposition = 'possibly_sent'),
    witness_error_code TEXT NULL CHECK (witness_error_code IS NULL OR witness_error_code = 'PROVIDER_RESULT_UNKNOWN'),
    state TEXT NOT NULL CHECK (state IN ('pending','claimed','processing','unknown','retry_wait','exhausted','waiting_rebuild','blocked','resolved_absent','resolved_deleted','resolved_rebuilt','superseded')),
    resolution_count INTEGER NOT NULL DEFAULT 0 CHECK (resolution_count BETWEEN 0 AND 3),
    resolution_epoch INTEGER NOT NULL DEFAULT 0 CHECK (resolution_epoch >= 0),
    last_reserved_resolution_epoch INTEGER NOT NULL DEFAULT 0 CHECK (last_reserved_resolution_epoch >= 0 AND last_reserved_resolution_epoch <= resolution_epoch AND ((resolution_count = 0 AND last_reserved_resolution_epoch = 0) OR (resolution_count > 0 AND last_reserved_resolution_epoch > 0))),
    lease_owner TEXT NULL,
    lease_fence_epoch INTEGER NULL,
    lease_expires_at TEXT NULL,
    next_attempt_at TEXT NULL CHECK ((state = 'retry_wait' AND next_attempt_at IS NOT NULL) OR (state <> 'retry_wait' AND next_attempt_at IS NULL)),
    last_resolution_disposition TEXT NULL CHECK (last_resolution_disposition IS NULL OR last_resolution_disposition IN ('query_absent','query_present','query_unknown','delete_started','delete_absent','delete_deleted','identity_mismatch','delete_unknown','finalize_unknown','waiting_rebuild','resolved_rebuilt','superseded')),
    last_disposition_epoch INTEGER NOT NULL DEFAULT 0 CHECK (last_disposition_epoch >= 0 AND last_disposition_epoch <= resolution_epoch),
    last_error_code TEXT NULL,
    resolved_at TEXT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(life_id, memory_id, mutation_sequence),
    CHECK (witness_send_disposition = 'possibly_sent' OR witness_error_code = 'PROVIDER_RESULT_UNKNOWN'),
    CHECK ((lease_owner IS NULL AND lease_fence_epoch IS NULL AND lease_expires_at IS NULL) OR (lease_owner IS NOT NULL AND lease_owner <> '' AND lease_fence_epoch > 0 AND lease_expires_at IS NOT NULL)),
    CHECK ((state IN ('resolved_absent','resolved_deleted','resolved_rebuilt','superseded') AND resolved_at IS NOT NULL) OR (state NOT IN ('resolved_absent','resolved_deleted','resolved_rebuilt','superseded') AND resolved_at IS NULL))
)";
const CREATE_LATE_DELETE_RUNTIME_LEASE_TABLE_SQL: &str = "CREATE TABLE memory_vector_late_delete_runtime_lease (
    lease_name TEXT PRIMARY KEY CHECK (lease_name = 'memory-vector-late-delete-resolver'),
    lease_owner TEXT NULL,
    lease_fence_epoch INTEGER NOT NULL DEFAULT 0 CHECK (lease_fence_epoch >= 0),
    lease_expires_at TEXT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK ((lease_owner IS NULL AND lease_expires_at IS NULL) OR (lease_owner IS NOT NULL AND lease_owner <> '' AND lease_fence_epoch > 0 AND lease_expires_at IS NOT NULL))
)";
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
type SchemaColumn = (String, String, i64, Option<String>, i64);

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LateDeleteResolutionSchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LateDeleteGenerationAuthoritySchemaUpgrade {
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

/// Fixed LD-I1 extension. It accepts only an exact Schema 14 transaction and
/// stores the historical Delete-Unknown identity independently of the ordinary
/// outbox so later outbox deletion cannot erase the diagnostic authority.
pub(super) fn apply_late_delete_resolution_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<LateDeleteResolutionSchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    for (failpoint, sql) in [
        (Migration015Failpoint::ResolutionTable, CREATE_LATE_DELETE_RESOLUTION_TABLE_SQL),
        (Migration015Failpoint::RuntimeLeaseTable, CREATE_LATE_DELETE_RUNTIME_LEASE_TABLE_SQL),
        (Migration015Failpoint::IdentityIndex, "CREATE UNIQUE INDEX memory_vector_late_delete_resolution_identity_idx ON memory_vector_late_delete_resolution(life_id, memory_id, mutation_sequence)"),
        (Migration015Failpoint::OutboxIndex, "CREATE INDEX memory_vector_late_delete_resolution_outbox_idx ON memory_vector_late_delete_resolution(outbox_id)"),
        (Migration015Failpoint::CandidateIndex, "CREATE INDEX memory_vector_late_delete_resolution_candidate_idx ON memory_vector_late_delete_resolution(state, next_attempt_at, resolution_count, lease_expires_at, resolution_id)"),
        (Migration015Failpoint::DiagnosticIndex, "CREATE INDEX memory_vector_late_delete_resolution_life_memory_state_idx ON memory_vector_late_delete_resolution(life_id, memory_id, state)"),
    ] {
        #[cfg(not(test))]
        let _ = failpoint;
        #[cfg(test)]
        if should_fail_migration_015_at_for_test(failpoint) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction.execute_batch(sql).map_err(|_| StorageError::migration_transaction_failed())?;
    }
    #[cfg(test)]
    if should_fail_migration_015_at_for_test(Migration015Failpoint::RuntimeLeaseRow) {
        return Err(StorageError::migration_transaction_failed());
    }
    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO memory_vector_late_delete_runtime_lease
         (lease_name, lease_owner, lease_fence_epoch, lease_expires_at, created_at, updated_at)
         VALUES ('memory-vector-late-delete-resolver', NULL, 0, NULL, ?1, ?1)",
            [&migration_now],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_015_at_for_test(Migration015Failpoint::Backfill) {
        return Err(StorageError::migration_transaction_failed());
    }
    transaction.execute(
        "INSERT INTO memory_vector_late_delete_resolution
         (outbox_id, life_id, memory_id, mutation_sequence, claimed_generation_id,
          embedding_descriptor_id, embedding_dimension, captured_generation_state,
          witness_attempt_ordinal, witness_claim_epoch, witness_marked_claim_epoch,
          witness_send_disposition, witness_error_code, state, created_at, updated_at)
         SELECT o.id, o.life_id, o.memory_id, o.mutation_sequence, o.claimed_generation_id,
                g.descriptor_hash, g.dimension, g.state,
                o.attempt_count, o.fenced_claim_epoch, o.last_marked_claim_epoch,
                o.last_send_disposition, o.last_error_code, 'pending', ?1, ?1
         FROM memory_vector_sync_outbox AS o
         JOIN memory_vector_generation AS g ON g.generation_id=o.claimed_generation_id
         WHERE o.desired_action='delete'
           AND (o.last_send_disposition='possibly_sent' OR o.last_error_code='PROVIDER_RESULT_UNKNOWN')
           AND o.mutation_sequence > 0
           AND o.attempt_count BETWEEN 1 AND 5
           AND o.fenced_claim_epoch > 0
           AND o.last_marked_claim_epoch > 0
           AND o.last_marked_claim_epoch <= o.fenced_claim_epoch
           AND o.claimed_generation_id IS NOT NULL AND o.claimed_generation_id <> ''
           AND o.target_revision IS NULL AND o.target_content_hash IS NULL
           AND o.migration_disposition IS NULL
           AND g.descriptor_hash <> '' AND g.dimension > 0
           AND g.state IN ('building','active','retired','failed')",
        [&migration_now],
    ).map_err(|_| StorageError::migration_transaction_failed())?;
    writer_fence_manifest::install_late_delete_writer_fence_manifest_in_transaction(transaction)?;
    #[cfg(test)]
    if should_fail_migration_015_at_for_test(Migration015Failpoint::SchemaValidation) {
        return Err(StorageError::migration_transaction_failed());
    }
    validate_late_delete_resolution_schema_objects(transaction)?;
    #[cfg(test)]
    if should_fail_migration_015_at_for_test(Migration015Failpoint::ManifestValidation) {
        return Err(StorageError::migration_transaction_failed());
    }
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(
        transaction,
        LATE_DELETE_RESOLUTION_SCHEMA_VERSION,
    )?;
    // Insert the version only after every table, index, backfill, trigger and
    // both validators have succeeded.
    #[cfg(test)]
    if should_fail_migration_015_at_for_test(Migration015Failpoint::SchemaVersion) {
        return Err(StorageError::migration_transaction_failed());
    }
    transaction.execute(
        "INSERT INTO schema_migration (version, name, applied_at) VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        params![LATE_DELETE_RESOLUTION_SCHEMA_VERSION, LATE_DELETE_RESOLUTION_MIGRATION_NAME],
    ).map_err(|_| StorageError::migration_transaction_failed())?;
    Ok(LateDeleteResolutionSchemaUpgrade::Applied)
}

/// Fixed LD-I3-M1 extension.  The migration reads SQLite time once, carries it
/// through every conservative historical anchor, and only installs semantic
/// triggers after the data shape has been made complete.
pub(super) fn apply_late_delete_generation_authority_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<LateDeleteGenerationAuthoritySchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != LATE_DELETE_RESOLUTION_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    for sql in [
        ADD_DELETE_WITNESS_AT_SQL,
        ADD_WITNESS_AGE_ANCHOR_AT_SQL,
        ADD_CAPTURED_GENERATION_AUTHORITY_EPOCH_SQL,
        ADD_GENERATION_AUTHORITY_EPOCH_SQL,
    ] {
        transaction
            .execute_batch(sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    let migration16_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let predicate = super::vector_sync_outbox::DELETE_UNKNOWN_EVIDENCE_SQL;
    // SQLite parameters cannot name a SQL predicate; keep the frozen literal
    // only in the statement assembled from this crate-private constant.
    transaction
        .execute(
            &format!("UPDATE memory_vector_sync_outbox SET delete_witness_at=?1 WHERE {predicate}"),
            params![migration16_now],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction.execute(
        "UPDATE memory_vector_late_delete_resolution
         SET witness_age_anchor_at=?1, captured_generation_authority_epoch=0,
             state=CASE WHEN state IN ('pending','claimed','processing','unknown','retry_wait','exhausted','waiting_rebuild','blocked') THEN 'waiting_rebuild' ELSE state END,
             last_resolution_disposition=CASE WHEN state IN ('pending','claimed','processing','unknown','retry_wait','exhausted','waiting_rebuild','blocked') THEN 'waiting_rebuild' ELSE last_resolution_disposition END,
             last_disposition_epoch=CASE WHEN state IN ('pending','claimed','processing','unknown','retry_wait','exhausted','waiting_rebuild','blocked') THEN resolution_epoch ELSE last_disposition_epoch END,
             lease_owner=CASE WHEN state IN ('pending','claimed','processing','unknown','retry_wait','exhausted','waiting_rebuild','blocked') THEN NULL ELSE lease_owner END,
             lease_fence_epoch=CASE WHEN state IN ('pending','claimed','processing','unknown','retry_wait','exhausted','waiting_rebuild','blocked') THEN NULL ELSE lease_fence_epoch END,
             lease_expires_at=CASE WHEN state IN ('pending','claimed','processing','unknown','retry_wait','exhausted','waiting_rebuild','blocked') THEN NULL ELSE lease_expires_at END,
             next_attempt_at=CASE WHEN state IN ('pending','claimed','processing','unknown','retry_wait','exhausted','waiting_rebuild','blocked') THEN NULL ELSE next_attempt_at END,
             updated_at=?1",
        params![migration16_now],
    ).map_err(|_| StorageError::migration_transaction_failed())?;
    transaction.execute(
        &format!("INSERT INTO memory_vector_late_delete_resolution
          (outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,embedding_descriptor_id,embedding_dimension,captured_generation_state,witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,witness_send_disposition,witness_error_code,witness_age_anchor_at,captured_generation_authority_epoch,state,last_resolution_disposition,last_disposition_epoch,created_at,updated_at)
          SELECT o.id,o.life_id,o.memory_id,o.mutation_sequence,o.claimed_generation_id,g.descriptor_hash,g.dimension,g.state,o.attempt_count,o.fenced_claim_epoch,o.last_marked_claim_epoch,o.last_send_disposition,o.last_error_code,?1,0,'waiting_rebuild','waiting_rebuild',0,?1,?1
          FROM memory_vector_sync_outbox o JOIN memory_vector_generation g ON g.generation_id=o.claimed_generation_id
          WHERE {predicate} AND o.mutation_sequence>0 AND o.attempt_count BETWEEN 1 AND 5
            AND o.fenced_claim_epoch>0 AND o.last_marked_claim_epoch>0 AND o.last_marked_claim_epoch<=o.fenced_claim_epoch
            AND o.claimed_generation_id IS NOT NULL AND o.claimed_generation_id<>'' AND o.target_revision IS NULL AND o.target_content_hash IS NULL AND o.migration_disposition IS NULL
            AND g.descriptor_hash<>'' AND g.dimension>0 AND g.state IN ('building','active','retired','failed')
            AND NOT EXISTS (SELECT 1 FROM memory_vector_late_delete_resolution r WHERE r.life_id=o.life_id AND r.memory_id=o.memory_id AND r.mutation_sequence=o.mutation_sequence)"),
        params![migration16_now],
    ).map_err(|_| StorageError::migration_transaction_failed())?;
    for sql in [
        GENERATION_SEMANTIC_DELETE_TRIGGER_SQL,
        GENERATION_SEMANTIC_IDENTITY_TRIGGER_SQL,
        GENERATION_SEMANTIC_EPOCH_TRIGGER_SQL,
    ] {
        transaction
            .execute_batch(sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION,
                LATE_DELETE_GENERATION_AUTHORITY_MIGRATION_NAME,
                migration16_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    validate_late_delete_generation_authority_schema_objects(transaction)?;
    Ok(LateDeleteGenerationAuthoritySchemaUpgrade::Applied)
}

pub(super) fn validate_late_delete_generation_authority_schema(
    connection: &Connection,
) -> Result<(), StorageError> {
    if connection::read_schema_version(connection)?
        != LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION
    {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_late_delete_generation_authority_schema_objects(connection)
}

fn validate_late_delete_generation_authority_schema_objects(
    connection: &Connection,
) -> Result<(), StorageError> {
    for (table, column, declared_type, not_null, default_value) in [
        (
            "memory_vector_sync_outbox",
            "delete_witness_at",
            "TEXT",
            0,
            None,
        ),
        (
            "memory_vector_late_delete_resolution",
            "witness_age_anchor_at",
            "TEXT",
            1,
            Some("''"),
        ),
        (
            "memory_vector_late_delete_resolution",
            "captured_generation_authority_epoch",
            "INTEGER",
            1,
            Some("0"),
        ),
        (
            "memory_vector_generation",
            "authority_epoch",
            "INTEGER",
            1,
            Some("1"),
        ),
    ] {
        let found: Option<(String, i64, Option<String>)> = connection
            .query_row(
                &format!(
                    "SELECT type, \"notnull\", dflt_value FROM pragma_table_info('{table}') WHERE name='{column}'"
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| StorageError::migration_transaction_failed())?;
        if !matches!(found.as_ref(), Some((ty, nn, default)) if ty == declared_type && *nn == not_null && default.as_deref() == default_value)
        {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    for (name, sql) in [
        (
            "memory_vector_generation_semantic_delete_guard",
            GENERATION_SEMANTIC_DELETE_TRIGGER_SQL,
        ),
        (
            "memory_vector_generation_semantic_identity_guard",
            GENERATION_SEMANTIC_IDENTITY_TRIGGER_SQL,
        ),
        (
            "memory_vector_generation_semantic_epoch_guard",
            GENERATION_SEMANTIC_EPOCH_TRIGGER_SQL,
        ),
    ] {
        let actual: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
                [name],
                |r| r.get(0),
            )
            .map_err(|_| StorageError::migration_transaction_failed())?;
        if normalize_schema_fragment(&actual) != normalize_schema_fragment(sql) {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(
        connection,
        LATE_DELETE_RESOLUTION_SCHEMA_VERSION,
    )?;
    Ok(())
}

pub(super) fn validate_late_delete_resolution_schema(
    connection: &Connection,
) -> Result<(), StorageError> {
    if connection::read_schema_version(connection)? != LATE_DELETE_RESOLUTION_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_late_delete_resolution_schema_objects(connection)
}

fn validate_late_delete_resolution_schema_objects(
    connection: &Connection,
) -> Result<(), StorageError> {
    let expected = [
        "resolution_id",
        "outbox_id",
        "life_id",
        "memory_id",
        "mutation_sequence",
        "claimed_generation_id",
        "embedding_descriptor_id",
        "embedding_dimension",
        "captured_generation_state",
        "witness_attempt_ordinal",
        "witness_claim_epoch",
        "witness_marked_claim_epoch",
        "witness_send_disposition",
        "witness_error_code",
        "state",
        "resolution_count",
        "resolution_epoch",
        "last_reserved_resolution_epoch",
        "lease_owner",
        "lease_fence_epoch",
        "lease_expires_at",
        "next_attempt_at",
        "last_resolution_disposition",
        "last_disposition_epoch",
        "last_error_code",
        "resolved_at",
        "created_at",
        "updated_at",
    ];
    let columns = |table: &str| -> Result<Vec<SchemaColumn>, StorageError> {
        let mut stmt = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(|_| StorageError::migration_transaction_failed())?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .map_err(|_| StorageError::migration_transaction_failed())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| StorageError::migration_transaction_failed())
    };
    let resolution_columns = columns("memory_vector_late_delete_resolution")?;
    if resolution_columns
        .iter()
        .map(|c| c.0.as_str())
        .collect::<Vec<_>>()
        != expected
    {
        return Err(StorageError::migration_transaction_failed());
    }
    let resolution_types = [
        "INTEGER", "INTEGER", "TEXT", "TEXT", "INTEGER", "TEXT", "TEXT", "INTEGER", "TEXT",
        "INTEGER", "INTEGER", "INTEGER", "TEXT", "TEXT", "TEXT", "INTEGER", "INTEGER", "INTEGER",
        "TEXT", "INTEGER", "TEXT", "TEXT", "TEXT", "INTEGER", "TEXT", "TEXT", "TEXT", "TEXT",
    ];
    let resolution_not_null = [
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
    ];
    let resolution_defaults = [
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some("0"),
        Some("0"),
        Some("0"),
        None,
        None,
        None,
        None,
        None,
        Some("0"),
        None,
        None,
        None,
        None,
    ];
    for (index, column) in resolution_columns.iter().enumerate() {
        if column.1 != resolution_types[index]
            || column.2 != resolution_not_null[index]
            || column.3.as_deref() != resolution_defaults[index]
            || column.4 != if index == 0 { 1 } else { 0 }
        {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    let lease_columns = columns("memory_vector_late_delete_runtime_lease")?;
    if lease_columns
        .iter()
        .map(|c| c.0.as_str())
        .collect::<Vec<_>>()
        != [
            "lease_name",
            "lease_owner",
            "lease_fence_epoch",
            "lease_expires_at",
            "created_at",
            "updated_at",
        ]
    {
        return Err(StorageError::migration_transaction_failed());
    }
    let lease_types = ["TEXT", "TEXT", "INTEGER", "TEXT", "TEXT", "TEXT"];
    let lease_not_null = [0, 0, 1, 0, 1, 1];
    let lease_defaults = [None, None, Some("0"), None, None, None];
    for (index, column) in lease_columns.iter().enumerate() {
        if column.1 != lease_types[index]
            || column.2 != lease_not_null[index]
            || column.3.as_deref() != lease_defaults[index]
            || column.4 != if index == 0 { 1 } else { 0 }
        {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    let resolution_sql: String = connection.query_row("SELECT sql FROM sqlite_schema WHERE type='table' AND name='memory_vector_late_delete_resolution'", [], |row| row.get(0)).map_err(|_| StorageError::migration_transaction_failed())?;
    if normalize_schema_fragment(&resolution_sql)
        != normalize_schema_fragment(CREATE_LATE_DELETE_RESOLUTION_TABLE_SQL)
    {
        return Err(StorageError::migration_transaction_failed());
    }
    let runtime_lease_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='memory_vector_late_delete_runtime_lease'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if normalize_schema_fragment(&runtime_lease_sql)
        != normalize_schema_fragment(CREATE_LATE_DELETE_RUNTIME_LEASE_TABLE_SQL)
    {
        return Err(StorageError::migration_transaction_failed());
    }
    let expected_indexes = [
        "memory_vector_late_delete_resolution_identity_idx",
        "memory_vector_late_delete_resolution_outbox_idx",
        "memory_vector_late_delete_resolution_candidate_idx",
        "memory_vector_late_delete_resolution_life_memory_state_idx",
    ];
    let expected_index_columns = [
        ["life_id", "memory_id", "mutation_sequence"].as_slice(),
        ["outbox_id"].as_slice(),
        [
            "state",
            "next_attempt_at",
            "resolution_count",
            "lease_expires_at",
            "resolution_id",
        ]
        .as_slice(),
        ["life_id", "memory_id", "state"].as_slice(),
    ];
    for (position, name) in expected_indexes.iter().enumerate() {
        let mut statement = connection
            .prepare(&format!("PRAGMA index_info({name})"))
            .map_err(|_| StorageError::migration_transaction_failed())?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(2))
            .map_err(|_| StorageError::migration_transaction_failed())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StorageError::migration_transaction_failed())?;
        if columns.iter().map(String::as_str).collect::<Vec<_>>()
            != expected_index_columns[position]
        {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    let foreign_keys: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('memory_vector_late_delete_resolution')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let singleton: i64 = connection.query_row("SELECT COUNT(*) FROM memory_vector_late_delete_runtime_lease WHERE lease_name='memory-vector-late-delete-resolver' AND lease_owner IS NULL AND lease_fence_epoch=0 AND lease_expires_at IS NULL", [], |row| row.get(0)).map_err(|_| StorageError::migration_transaction_failed())?;
    if foreign_keys != 0 || singleton != 1 {
        return Err(StorageError::migration_transaction_failed());
    }
    Ok(())
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

    if expected_schema_version >= ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION {
        #[cfg(test)]
        if should_fail_post_commit_verification_at_for_test(
            PostCommitVerificationFailpoint::AttemptClaimIdentitySchema,
        ) {
            return Err(StorageError::migration_post_commit_verification_failed());
        }
        validate_attempt_claim_identity_schema(connection)?;
    }
    if expected_schema_version == LATE_DELETE_RESOLUTION_SCHEMA_VERSION {
        validate_late_delete_resolution_schema(connection)?;
    }
    if expected_schema_version == LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION {
        validate_late_delete_generation_authority_schema(connection)?;
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

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration015Failpoint {
    ResolutionTable,
    RuntimeLeaseTable,
    IdentityIndex,
    OutboxIndex,
    CandidateIndex,
    DiagnosticIndex,
    RuntimeLeaseRow,
    Backfill,
    SchemaValidation,
    ManifestValidation,
    SchemaVersion,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_014_FAILPOINT: std::cell::Cell<Option<Migration014Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
thread_local! {
    static MIGRATION_015_FAILPOINT: std::cell::Cell<Option<Migration015Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_015_at_for_test(failpoint: Migration015Failpoint) {
    MIGRATION_015_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_015_at_for_test(failpoint: Migration015Failpoint) -> bool {
    MIGRATION_015_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
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

    if expected_schema_version >= ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION {
        validate_attempt_claim_identity_schema(connection)?;
    }
    if expected_schema_version == LATE_DELETE_RESOLUTION_SCHEMA_VERSION {
        validate_late_delete_resolution_schema(connection)?;
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

    type LateDeleteResolutionWitnessRow = (
        String,
        i64,
        i64,
        i64,
        Option<String>,
        Option<String>,
        String,
        i64,
    );

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

    fn version_fourteen_connection() -> Connection {
        let mut connection = version_thirteen_connection();
        apply_attempt_claim_identity_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION
        );
        connection
    }

    fn apply_late_delete_resolution_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_late_delete_resolution_schema_upgrade(&transaction).unwrap(),
            LateDeleteResolutionSchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn apply_late_delete_generation_authority_upgrade(connection: &mut Connection) {
        connection
            .create_scalar_function(
                "digital_life_writer_epoch",
                0,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8
                    | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC
                    | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
                |_| Ok(1_i64),
            )
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_late_delete_generation_authority_schema_upgrade(&transaction).unwrap(),
            LateDeleteGenerationAuthoritySchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    #[test]
    fn migration_016_schema_16_delete_witness_at_witness_age_anchor_and_generation_authority_epoch_are_complete(
    ) {
        let mut connection = version_fourteen_connection();
        apply_late_delete_resolution_upgrade(&mut connection);
        apply_late_delete_generation_authority_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION
        );
        validate_late_delete_generation_authority_schema(&connection).unwrap();
    }

    #[test]
    fn migration_016_historical_nonterminal_and_terminal_resolutions_keep_a_single_conservative_anchor(
    ) {
        let mut connection = version_fourteen_connection();
        connection
            .execute_batch(
                "INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state)
                 VALUES ('generation-a','descriptor-a',2,'active');
                 INSERT INTO memory_vector_sync_outbox
                   (life_id,memory_id,desired_action,state,attempt_count,mutation_sequence,
                    claimed_generation_id,fenced_claim_epoch,last_marked_claim_epoch,
                    last_send_disposition)
                 VALUES ('life','historical-outbox','delete','blocked',1,1,
                         'generation-a',1,1,'possibly_sent');",
            )
            .unwrap();
        apply_late_delete_resolution_upgrade(&mut connection);

        let nonterminal = [
            "pending",
            "claimed",
            "processing",
            "unknown",
            "retry_wait",
            "exhausted",
            "waiting_rebuild",
            "blocked",
        ];
        let terminal = [
            "resolved_absent",
            "resolved_deleted",
            "resolved_rebuilt",
            "superseded",
        ];
        for (offset, state) in nonterminal.iter().chain(terminal.iter()).enumerate() {
            let leased = matches!(*state, "claimed" | "processing");
            let retry_wait = *state == "retry_wait";
            let is_terminal = terminal.contains(state);
            connection
                .execute(
                    "INSERT INTO memory_vector_late_delete_resolution
                     (outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,
                      embedding_descriptor_id,embedding_dimension,captured_generation_state,
                      witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,
                      witness_send_disposition,witness_error_code,state,resolution_count,
                      resolution_epoch,last_reserved_resolution_epoch,lease_owner,
                      lease_fence_epoch,lease_expires_at,next_attempt_at,resolved_at,created_at,updated_at)
                     VALUES (?1,'historic',?2,?3,'generation-a','descriptor-a',2,'active',1,1,1,
                             'possibly_sent',NULL,?4,1,1,1,?5,?6,?7,?8,?9,
                             '2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
                    params![
                        1_000_i64 + offset as i64,
                        format!("historic-{offset}"),
                        100_i64 + offset as i64,
                        *state,
                        leased.then_some("owner-a"),
                        leased.then_some(1_i64),
                        leased.then_some("2099-01-01T00:00:00.000Z"),
                        retry_wait.then_some("2099-01-01T00:00:00.000Z"),
                        is_terminal.then_some("2026-01-01T00:00:00.000Z"),
                    ],
                )
                .unwrap();
        }

        apply_late_delete_generation_authority_upgrade(&mut connection);
        validate_late_delete_generation_authority_schema(&connection).unwrap();
        let nonterminal_waiting: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_late_delete_resolution
                 WHERE life_id='historic' AND state='waiting_rebuild'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(nonterminal_waiting, 8);
        let terminal_preserved: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_late_delete_resolution
                 WHERE life_id='historic' AND state IN
                   ('resolved_absent','resolved_deleted','resolved_rebuilt','superseded')
                   AND resolved_at IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(terminal_preserved, 4);
        let anchors_and_epochs: (i64, i64, i64) = connection
            .query_row(
                "SELECT COUNT(DISTINCT witness_age_anchor_at),
                        COUNT(*) FILTER (WHERE captured_generation_authority_epoch=0),
                        COUNT(*) FILTER (WHERE lease_owner IS NULL
                                         AND lease_fence_epoch IS NULL
                                         AND lease_expires_at IS NULL)
                 FROM memory_vector_late_delete_resolution WHERE life_id='historic'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(anchors_and_epochs, (1, 12, 12));
        let outbox_and_resolution_anchor: (String, String, i64) = connection
            .query_row(
                "SELECT o.delete_witness_at,r.witness_age_anchor_at,
                        r.captured_generation_authority_epoch
                 FROM memory_vector_sync_outbox o
                 JOIN memory_vector_late_delete_resolution r
                   ON r.outbox_id=o.id
                 WHERE o.life_id='life' AND o.memory_id='historical-outbox'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            outbox_and_resolution_anchor.0,
            outbox_and_resolution_anchor.1
        );
        assert_eq!(outbox_and_resolution_anchor.2, 0);
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

    #[test]
    fn migration_015_backfill_captures_only_complete_canonical_delete_unknown_evidence() {
        let mut connection = version_fourteen_connection();
        connection
            .execute_batch(
                "INSERT INTO memory_vector_generation (generation_id, descriptor_hash, dimension, state)
                 VALUES ('ld-generation', 'ld-descriptor', 384, 'retired');
                 INSERT INTO memory_vector_sync_outbox
                   (life_id, memory_id, desired_action, state, attempt_count, mutation_sequence,
                    claimed_generation_id, fenced_claim_epoch, last_marked_claim_epoch,
                    last_send_disposition, last_error_code)
                 VALUES
                   ('ld-life', 'possibly-sent', 'delete', 'blocked', 2, 41,
                    'ld-generation', 9, 8, 'possibly_sent', NULL),
                   ('ld-life', 'provider-unknown', 'delete', 'retry_wait', 3, 42,
                    'ld-generation', 10, 10, NULL, 'PROVIDER_RESULT_UNKNOWN'),
                   ('ld-life', 'both-witnesses', 'delete', 'processing', 4, 43,
                    'ld-generation', 11, 10, 'possibly_sent', 'PROVIDER_RESULT_UNKNOWN'),
                   ('ld-life', 'ordinary-delete', 'delete', 'blocked', 2, 44,
                    'ld-generation', 12, 11, NULL, 'TEMPORARY_FAILURE'),
                   ('ld-life', 'unknown-upsert', 'upsert', 'blocked', 2, 45,
                    'ld-generation', 13, 12, 'possibly_sent', NULL),
                   ('ld-life', 'bad-attempt', 'delete', 'blocked', 6, 46,
                    'ld-generation', 14, 13, 'possibly_sent', NULL);"
            )
            .unwrap();

        apply_late_delete_resolution_upgrade(&mut connection);
        validate_late_delete_resolution_schema(&connection).unwrap();
        assert_eq!(
            schema_version(&connection),
            LATE_DELETE_RESOLUTION_SCHEMA_VERSION
        );
        assert_eq!(writer_fence_count(&connection), 24);
        let rows: Vec<LateDeleteResolutionWitnessRow> = connection
            .prepare(
                "SELECT memory_id, witness_attempt_ordinal, witness_claim_epoch,
                        witness_marked_claim_epoch, witness_send_disposition, witness_error_code,
                        embedding_descriptor_id, embedding_dimension
                 FROM memory_vector_late_delete_resolution ORDER BY mutation_sequence",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[0],
            (
                "possibly-sent".into(),
                2,
                9,
                8,
                Some("possibly_sent".into()),
                None,
                "ld-descriptor".into(),
                384
            )
        );
        assert_eq!(
            rows[1],
            (
                "provider-unknown".into(),
                3,
                10,
                10,
                None,
                Some("PROVIDER_RESULT_UNKNOWN".into()),
                "ld-descriptor".into(),
                384
            )
        );
        assert_eq!(
            rows[2],
            (
                "both-witnesses".into(),
                4,
                11,
                10,
                Some("possibly_sent".into()),
                Some("PROVIDER_RESULT_UNKNOWN".into()),
                "ld-descriptor".into(),
                384
            )
        );
        let timestamps: i64 = connection.query_row(
            "SELECT COUNT(DISTINCT created_at || '|' || updated_at) FROM memory_vector_late_delete_resolution",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(timestamps, 1);
        assert_eq!(
            connection
                .execute(
                    "DELETE FROM memory_vector_sync_outbox WHERE memory_id='possibly-sent'",
                    []
                )
                .unwrap(),
            1
        );
        assert_eq!(connection.query_row("SELECT COUNT(*) FROM memory_vector_late_delete_resolution WHERE memory_id='possibly-sent'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
    }

    #[test]
    fn migration_015_failpoints_rollback_to_an_unchanged_schema_fourteen() {
        for failpoint in [
            Migration015Failpoint::ResolutionTable,
            Migration015Failpoint::RuntimeLeaseTable,
            Migration015Failpoint::IdentityIndex,
            Migration015Failpoint::OutboxIndex,
            Migration015Failpoint::CandidateIndex,
            Migration015Failpoint::DiagnosticIndex,
            Migration015Failpoint::RuntimeLeaseRow,
            Migration015Failpoint::Backfill,
            Migration015Failpoint::SchemaValidation,
            Migration015Failpoint::ManifestValidation,
            Migration015Failpoint::SchemaVersion,
        ] {
            let mut connection = version_fourteen_connection();
            fail_next_migration_015_at_for_test(failpoint);
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_late_delete_resolution_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
            drop(transaction);
            assert_eq!(
                schema_version(&connection),
                ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION
            );
            for table in [
                "memory_vector_late_delete_resolution",
                "memory_vector_late_delete_runtime_lease",
            ] {
                assert_eq!(connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)", [table], |row| row.get::<_, i64>(0)).unwrap(), 0, "{table} must be rolled back");
            }
            assert_eq!(writer_fence_count(&connection), 18);
        }
    }

    #[test]
    fn migration_015_each_late_delete_writer_fence_failure_rolls_back_all_schema_objects() {
        for trigger_index in 19..=24 {
            let mut connection = version_fourteen_connection();
            writer_fence_manifest::fail_trigger_install_at_for_test(trigger_index);
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_late_delete_resolution_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
            drop(transaction);
            assert_eq!(
                schema_version(&connection),
                ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION
            );
            assert_eq!(writer_fence_count(&connection), 18);
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('memory_vector_late_delete_resolution', 'memory_vector_late_delete_runtime_lease')",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn migration_015_commit_unknown_reopen_observes_only_a_complete_schema_fifteen() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("migration-015-commit-unknown.sqlite3");
        {
            let connection = version_fourteen_connection();
            let mut destination = Connection::open(&path).unwrap();
            let backup = Backup::new(&connection, &mut destination).unwrap();
            backup.run_to_completion(5, Duration::ZERO, None).unwrap();
        }
        let caller_result = {
            let mut connection = Connection::open(&path).unwrap();
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
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            assert_eq!(
                apply_late_delete_resolution_schema_upgrade(&transaction).unwrap(),
                LateDeleteResolutionSchemaUpgrade::Applied
            );
            transaction.commit().unwrap();
            Err::<(), StorageError>(StorageError::new(
                "MIGRATION_COMMIT_RESULT_UNKNOWN",
                "Test-only simulation of a lost commit acknowledgement.",
                true,
            ))
        };
        assert_eq!(
            caller_result.unwrap_err().code,
            "MIGRATION_COMMIT_RESULT_UNKNOWN"
        );
        let reopened = Connection::open(&path).unwrap();
        assert_eq!(
            schema_version(&reopened),
            LATE_DELETE_RESOLUTION_SCHEMA_VERSION
        );
        validate_late_delete_resolution_schema(&reopened).unwrap();
        writer_fence_manifest::validate_writer_fence_manifest(&reopened).unwrap();
        let trigger_count = writer_fence_count(&reopened);
        assert_eq!(trigger_count, 24);
    }

    #[test]
    fn late_delete_resolution_schema_validation_schema_15_validator_rejects_a_weakened_resolution_budget_check(
    ) {
        let mut connection = version_fourteen_connection();
        apply_late_delete_resolution_upgrade(&mut connection);
        connection
            .pragma_update(None, "writable_schema", "ON")
            .unwrap();
        connection
            .execute(
                "UPDATE sqlite_schema
                 SET sql=replace(sql, 'resolution_count BETWEEN 0 AND 3', 'resolution_count BETWEEN 0 AND 4')
                 WHERE type='table' AND name='memory_vector_late_delete_resolution'",
                [],
            )
            .unwrap();
        connection
            .pragma_update(None, "writable_schema", "OFF")
            .unwrap();
        connection
            .pragma_update(None, "schema_version", 9_001_i64)
            .unwrap();
        let error = validate_late_delete_resolution_schema(&connection).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
    }

    /// Reads the three columns the version-14 identity CHECK spans, so a
    /// rejected write can be proven to have left none of them partially applied.
    fn attempt_identity_row(connection: &Connection, memory_id: &str) -> (i64, i64, i64) {
        connection
            .query_row(
                "SELECT attempt_count, fenced_claim_epoch, last_marked_claim_epoch
                 FROM memory_vector_sync_outbox
                 WHERE life_id='attempt-life' AND memory_id=?1",
                params![memory_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
    }

    /// Asserts real SQLite rejected the write with a CHECK constraint violation.
    /// The assertion is made on SQLite's own primary and extended result codes,
    /// never on the constraint name or message text.
    fn assert_check_constraint_violation(result: rusqlite::Result<usize>) {
        match result {
            Ok(_) => panic!("real SQLite must reject this write"),
            Err(rusqlite::Error::SqliteFailure(error, _)) => {
                assert_eq!(error.code, rusqlite::ErrorCode::ConstraintViolation);
                assert_eq!(
                    error.extended_code,
                    rusqlite::ffi::SQLITE_CONSTRAINT_CHECK,
                    "the write must fail the CHECK constraint itself"
                );
            }
            Err(other) => panic!("expected a SQLite CHECK violation, got {other:?}"),
        }
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

    fn journal_mode_of(database_path: &Path) -> String {
        let connection = Connection::open(database_path).unwrap();
        connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap()
    }

    /// Builds a file-backed version-13 database in `DELETE` journal mode with the
    /// full 18-trigger writer fence, one outbox row whose evidence fields are all
    /// non-default, and a recognizable mutation-clock value. Returns the row
    /// snapshot so a later rollback can be compared field by field.
    fn seed_version_thirteen_commit_fixture(database_path: &Path) -> HistoricalOutboxSnapshot {
        let mut connection = connection::open_authorized_test_connection(database_path).unwrap();
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .unwrap();

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

        insert_historical_row(
            &connection,
            HistoricalRowFixture {
                life_id: "commit-life",
                memory_id: "commit-row",
                desired_action: "delete",
                // 'failed' with a recorded migration disposition keeps the row
                // outside Migration 013's frozen set, so the version-13 upgrade
                // below cannot rewrite the evidence this test compares.
                state: "failed",
                migration_disposition: Some("legacy_upsert_rebuild_required"),
                attempt_count: 5,
                mutation_sequence: 7_654,
                target_revision: Some(21),
                target_content_hash: Some("commit-target-hash"),
                claimed_generation_id: Some("commit-generation"),
                last_error_code: Some("COMMIT_BOUNDARY_ERROR"),
                last_send_disposition: Some("possibly_sent"),
                next_attempt_at: Some("2026-10-01T00:00:00.000Z"),
                lease_owner: Some("commit-owner"),
                lease_fence_epoch: Some(31),
                lease_expires_at: Some("2026-10-02T00:00:00.000Z"),
            },
        );
        connection
            .execute(
                "UPDATE memory_vector_sync_mutation_clock SET last_sequence=7654
                 WHERE singleton=1",
                [],
            )
            .unwrap();
        apply_writer_fence_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION
        );
        assert_eq!(writer_fence_count(&connection), 18);

        let snapshot = historical_snapshot(&connection, "commit-life", "commit-row");
        drop(connection);
        snapshot
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
        for target in [0, writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION, 17] {
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

    /// Proves the `last_marked_claim_epoch >= 0` conjunct is independently
    /// enforced by real SQLite. The first case uses the frozen default row shape
    /// (`fenced_claim_epoch = 0`, `attempt_count = 0`); the second raises the
    /// companion columns so that `>= 0` is the only conjunct a `-1` write can
    /// violate, and a positive write on that same row then proves the rejection
    /// was caused by the sign rather than by the row itself.
    #[test]
    fn schema_fourteen_last_marked_claim_epoch_negative_write_is_rejected_in_isolation() {
        let mut connection = version_thirteen_connection();
        for (memory_id, attempt_count) in [("negative-default", 0), ("negative-isolated", 2)] {
            insert_historical_row(
                &connection,
                HistoricalRowFixture {
                    life_id: "attempt-life",
                    memory_id,
                    desired_action: "delete",
                    state: "pending",
                    migration_disposition: None,
                    attempt_count,
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
        }
        apply_attempt_claim_identity_upgrade(&mut connection);

        // Case 1: the exact frozen default shape. Only `last_marked_claim_epoch`
        // is written, and it is written to -1.
        assert_eq!(
            attempt_identity_row(&connection, "negative-default"),
            (0, 0, 0)
        );
        assert_check_constraint_violation(connection.execute(
            "UPDATE memory_vector_sync_outbox SET last_marked_claim_epoch=-1
             WHERE life_id='attempt-life' AND memory_id='negative-default'",
            [],
        ));
        // Re-read proves no column was partially modified.
        assert_eq!(
            attempt_identity_row(&connection, "negative-default"),
            (0, 0, 0)
        );

        // Case 2: isolate the `>= 0` conjunct. With attempt_count = 2 and
        // fenced_claim_epoch = 5, a -1 write satisfies both companion conjuncts
        // (-1 <= 5, and attempt_count > 0), so only `>= 0` can reject it.
        connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET fenced_claim_epoch=5
                 WHERE life_id='attempt-life' AND memory_id='negative-isolated'",
                [],
            )
            .unwrap();
        assert_eq!(
            attempt_identity_row(&connection, "negative-isolated"),
            (2, 5, 0)
        );
        assert_check_constraint_violation(connection.execute(
            "UPDATE memory_vector_sync_outbox SET last_marked_claim_epoch=-1
             WHERE life_id='attempt-life' AND memory_id='negative-isolated'",
            [],
        ));
        assert_eq!(
            attempt_identity_row(&connection, "negative-isolated"),
            (2, 5, 0)
        );
        // A positive write on the identical row is accepted, which proves the
        // rejection above was caused by the negative value alone.
        connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET last_marked_claim_epoch=3
                 WHERE life_id='attempt-life' AND memory_id='negative-isolated'",
                [],
            )
            .unwrap();
        assert_eq!(
            attempt_identity_row(&connection, "negative-isolated"),
            (2, 5, 3)
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

    /// Proves that a **real** `Transaction::commit()` failure rolls back every
    /// version-14 transaction step.
    ///
    /// The failure is produced by genuine SQLite lock arbitration rather than by
    /// injection: on a file-backed rollback-journal (`DELETE`) database, a second
    /// connection's plain read transaction holds a SHARED lock. That lock is
    /// compatible with connection A's `BEGIN IMMEDIATE` (RESERVED), so the whole
    /// migration runs normally, but it blocks the EXCLUSIVE promotion that
    /// `COMMIT` requires. `COMMIT` therefore returns `SQLITE_BUSY` from SQLite
    /// itself, after every in-transaction step has already succeeded.
    ///
    /// Synchronization is structural: the reader's transaction object is alive
    /// across the commit call, so no sleep or timing assumption is involved.
    #[test]
    fn migration_014_real_commit_failure_rolls_back_every_transaction_step() {
        let root = tempfile::tempdir().unwrap();
        let database_path = root.path().join("commit-boundary.sqlite3");

        // A version-13 database with real writer fences, a non-default outbox
        // row, a recognizable mutation clock, and DELETE journal mode.
        let evidence = seed_version_thirteen_commit_fixture(&database_path);
        assert_eq!(journal_mode_of(&database_path), "delete");

        // Connection B: a plain reader. Its SHARED lock is what will deny the
        // commit its EXCLUSIVE promotion.
        let mut reader = Connection::open(&database_path).unwrap();
        let reader_transaction = reader.transaction().unwrap();
        reader_transaction
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();

        // Connection A: the authorized epoch-1 writer shape, so the 18 writer
        // fences permit the migration's own writes.
        let mut writer = connection::open_authorized_test_connection(&database_path).unwrap();
        // Fail the commit on the first denied promotion instead of retrying for
        // the production busy timeout. This bounds the test without weakening
        // it: the error still originates in SQLite's own COMMIT.
        writer.busy_timeout(Duration::from_millis(0)).unwrap();
        let transaction = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();

        // Every version-14 in-transaction step completes before the commit.
        assert_eq!(
            apply_attempt_claim_identity_schema_upgrade(&transaction).unwrap(),
            AttemptClaimIdentitySchemaUpgrade::Applied
        );
        assert_eq!(
            connection::read_schema_version(&transaction).unwrap(),
            ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION
        );
        assert_eq!(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('memory_vector_sync_outbox')
                     WHERE name IN ('fenced_claim_epoch', 'last_marked_claim_epoch')",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        validate_attempt_claim_identity_schema(&transaction).unwrap();
        writer_fence_manifest::validate_writer_fence_manifest(&transaction).unwrap();

        // The real commit boundary.
        let commit_error = transaction.commit().unwrap_err();
        match commit_error {
            rusqlite::Error::SqliteFailure(error, _) => {
                assert_eq!(error.code, rusqlite::ErrorCode::DatabaseBusy);
            }
            other => panic!("expected a real SQLite commit busy failure, got {other:?}"),
        }
        // The production mapping turns exactly this error into the stable,
        // deidentified category, without carrying SQLite's message.
        let mapped = StorageError::migration_transaction_failed();
        assert_eq!(mapped.code, "MIGRATION_TRANSACTION_FAILED");
        assert!(!mapped.message.to_lowercase().contains("database is locked"));
        // No transaction remains open on the writer connection.
        assert!(writer.is_autocommit());
        drop(writer);
        drop(reader_transaction);

        // A brand-new independent connection reads only committed on-disk state.
        let verifier = Connection::open(&database_path).unwrap();
        assert_eq!(
            connection::read_schema_version(&verifier).unwrap(),
            writer_fence_manifest::WRITER_FENCE_SCHEMA_VERSION
        );
        assert_eq!(attempt_column_count(&verifier), 0);
        assert_eq!(writer_fence_count(&verifier), 18);
        assert_eq!(
            historical_snapshot(&verifier, "commit-life", "commit-row"),
            evidence
        );
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
        // WAL was never configured: the commit failed before the coordinator's
        // WAL step could run.
        assert_eq!(journal_mode_of(&database_path), "delete");
        assert!(!database_path.with_extension("sqlite3-wal").exists());
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
