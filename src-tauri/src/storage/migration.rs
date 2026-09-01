use std::{fs, path::Path, time::Duration};

use rusqlite::{backup::Backup, params, Connection, OptionalExtension, Transaction};

use super::{
    autonomy, body_package, capability_authorization, connection, experience_episode,
    generation_lifecycle_authority, life_intent, live2d_core, model_profile, perception,
    screen_perception, screen_vision_outbound_policy, writer_fence_manifest, StorageError,
    MIGRATIONS,
};

pub(super) const LAST_STATIC_MIGRATION_VERSION: i64 = 12;
const WRITER_FENCE_MIGRATION_NAME: &str = "013_historical_outbox_isolation_and_writer_fence";
pub(super) const ATTEMPT_CLAIM_IDENTITY_SCHEMA_VERSION: i64 = 14;
const ATTEMPT_CLAIM_IDENTITY_MIGRATION_NAME: &str = "014_vector_sync_attempt_claim_identity";
pub(super) const LATE_DELETE_RESOLUTION_SCHEMA_VERSION: i64 = 15;
const LATE_DELETE_RESOLUTION_MIGRATION_NAME: &str = "015_vector_sync_late_delete_resolution";
pub(super) const LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION: i64 = 16;
const LATE_DELETE_GENERATION_AUTHORITY_MIGRATION_NAME: &str =
    "016_late_delete_generation_authority";
pub(super) const GENERATION_LIFECYCLE_SCHEMA_VERSION: i64 = 17;
const GENERATION_LIFECYCLE_MIGRATION_NAME: &str = "017_vector_generation_lifecycle_cutover";
pub(super) const GENERATION_CATCHUP_ATTEMPT_SCHEMA_VERSION: i64 = 18;
const GENERATION_CATCHUP_ATTEMPT_MIGRATION_NAME: &str =
    "018_vector_generation_catchup_attempt_identity";
pub(super) const EMOTION_AUTHORITY_SCHEMA_VERSION: i64 = 19;
const EMOTION_AUTHORITY_MIGRATION_NAME: &str = "019_emotion_authority";
const CREATE_EMOTION_STATE_TABLE_SQL: &str =
    include_str!("migrations/019_emotion_authority.state.sql");
const CREATE_EMOTION_EVENT_TABLE_SQL: &str =
    include_str!("migrations/019_emotion_authority.event.sql");
/// Schema 19 Phase C: the exact neutral-state initializer. Every future
/// `life_identity` INSERT automatically receives exactly one neutral
/// `emotion_state` row in the same statement.
const CREATE_EMOTION_STATE_INITIALIZER_TRIGGER_SQL: &str =
    include_str!("migrations/019_emotion_authority.initializer_trigger.sql");
pub(super) const RELATIONSHIP_AUTHORITY_SCHEMA_VERSION: i64 = 20;
const RELATIONSHIP_AUTHORITY_MIGRATION_NAME: &str = "020_relationship_authority";
const CREATE_RELATIONSHIP_STATE_TABLE_SQL: &str =
    include_str!("migrations/020_relationship_authority.state.sql");
const CREATE_RELATIONSHIP_EVENT_TABLE_SQL: &str =
    include_str!("migrations/020_relationship_authority.event.sql");
/// Schema 20 Phase C: the exact neutral-state initializer for the primary-user
/// relationship. Every future `life_identity` INSERT automatically receives
/// exactly one neutral `relationship_state` row in the same statement.
const CREATE_RELATIONSHIP_STATE_INITIALIZER_TRIGGER_SQL: &str =
    include_str!("migrations/020_relationship_authority.initializer_trigger.sql");
pub(super) const EXPERIENCE_EPISODE_SCHEMA_VERSION: i64 = 21;
const EXPERIENCE_EPISODE_MIGRATION_NAME: &str = "021_experience_episode_authority";
pub(super) const LIFE_INTENT_AUTHORITY_SCHEMA_VERSION: i64 = 22;
const LIFE_INTENT_AUTHORITY_MIGRATION_NAME: &str = "022_life_goal_plan_action_authority";
pub(super) const AUTONOMY_AUTHORITY_SCHEMA_VERSION: i64 = 23;
const AUTONOMY_AUTHORITY_MIGRATION_NAME: &str = "023_autonomous_life_proactive_intent_authority";
pub(super) const PERCEPTION_AUTHORITY_SCHEMA_VERSION: i64 = 24;
const PERCEPTION_AUTHORITY_MIGRATION_NAME: &str = "024_perception_focus_policy_authority";
pub(super) const BODY_PACKAGE_AUTHORITY_SCHEMA_VERSION: i64 = 25;
const BODY_PACKAGE_AUTHORITY_MIGRATION_NAME: &str = "025_managed_body_package_authority";
pub(super) const LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION: i64 = 26;
const LIVE2D_CORE_AUTHORITY_MIGRATION_NAME: &str = "026_live2d_core_component_authority";
pub(super) const SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION: i64 = 27;
const SCREEN_PERCEPTION_AUTHORITY_MIGRATION_NAME: &str = "027_screen_perception_authority";
pub(super) const SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_SCHEMA_VERSION: i64 = 28;
const SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_MIGRATION_NAME: &str =
    "028_screen_vision_outbound_policy";
pub(super) const VISION_MODEL_PROFILE_SCHEMA_VERSION: i64 = 29;
const VISION_MODEL_PROFILE_MIGRATION_NAME: &str = "029_vision_model_profiles";
const VISION_MODEL_PROFILE_MIGRATION_SQL: &str =
    include_str!("migrations/029_vision_model_profiles.sql");
pub(super) const CAPABILITY_AUTHORIZATION_SCHEMA_VERSION: i64 = 30;
const CAPABILITY_AUTHORIZATION_MIGRATION_NAME: &str = "030_capability_authorization_root";
const ADD_CLAIMED_GENERATION_AUTHORITY_EPOCH_SQL: &str = "ALTER TABLE memory_vector_sync_outbox ADD COLUMN claimed_generation_authority_epoch INTEGER NULL CHECK (claimed_generation_authority_epoch IS NULL OR claimed_generation_authority_epoch >= 1)";
const CREATE_GENERATION_AUTHORITY_TABLE_SQL: &str =
    "CREATE TABLE memory_vector_generation_authority (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    active_generation_id TEXT NULL UNIQUE,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (active_generation_id) REFERENCES memory_vector_generation(generation_id)
)";
const CREATE_GENERATION_BINDING_TABLE_SQL: &str = "CREATE TABLE memory_vector_generation_binding (
    generation_id TEXT PRIMARY KEY,
    descriptor_version TEXT NOT NULL,
    embedding_profile_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (generation_id) REFERENCES memory_vector_generation(generation_id)
)";
const CREATE_GENERATION_STORE_WITNESS_TABLE_SQL: &str = "CREATE TABLE memory_vector_generation_store_witness (
    generation_id TEXT PRIMARY KEY,
    create_operation_id TEXT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('unverified', 'absent', 'create_started', 'ready', 'uncertain', 'deleted')),
    last_error_code TEXT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (generation_id) REFERENCES memory_vector_generation(generation_id)
)";
const CREATE_REBUILD_TABLES_AND_GUARDS_SQL: &str =
    include_str!("migrations/017_vector_generation_lifecycle_cutover.sql");
/// Schema 18 Phase A: the dedicated catch-up Attempt table.  Kept as a
/// separate fixed file so the AfterTable failpoint represents a genuinely
/// distinct durable boundary inside the caller-owned transaction.
const CREATE_REBUILD_CATCHUP_ATTEMPT_TABLE_SQL: &str =
    include_str!("migrations/018_vector_generation_catchup_attempt_identity.table.sql");
/// Schema 18 Phase B part 1: the immutable identity trigger over the frozen
/// catch-up identity fields.  Validated by exact normalized SQL equality, so a
/// correct trigger name with a weakened body fails closed.
const CREATE_REBUILD_CATCHUP_ATTEMPT_IDENTITY_TRIGGER_SQL: &str =
    include_str!("migrations/018_vector_generation_catchup_attempt_identity.identity_trigger.sql");
/// Schema 18 Phase B part 2: the supersede guard over the state domain, proving
/// unknown external work is never discarded as a harmless supersession.
const CREATE_REBUILD_CATCHUP_ATTEMPT_SUPERSEDE_TRIGGER_SQL: &str =
    include_str!("migrations/018_vector_generation_catchup_attempt_identity.supersede_trigger.sql");
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
const GENERATION_SEMANTIC_EPOCH_TRIGGER_SCHEMA_SEVENTEEN_SQL: &str =
    "CREATE TRIGGER memory_vector_generation_semantic_epoch_guard
BEFORE UPDATE ON memory_vector_generation
WHEN digital_life_writer_epoch() IS 1
 AND ((NEW.state = OLD.state AND NEW.authority_epoch <> OLD.authority_epoch)
   OR (NEW.state <> OLD.state AND
       (OLD.authority_epoch = 9223372036854775807
        OR NEW.authority_epoch <> OLD.authority_epoch + 1
        OR (OLD.state = 'building' AND NEW.state NOT IN ('active','failed'))
        OR (OLD.state = 'active' AND NEW.state <> 'retired')
        OR OLD.state NOT IN ('building','active'))))
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
const NORMALIZED_CAPTURED_GENERATION_AUTHORITY_EPOCH_COLUMN_DDL: &str =
    "captured_generation_authority_epochintegernotnulldefault0check(captured_generation_authority_epoch>=0)";
const NORMALIZED_GENERATION_AUTHORITY_EPOCH_COLUMN_DDL: &str =
    "authority_epochintegernotnulldefault1check(authority_epoch>=1)";
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GenerationLifecycleSchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GenerationCatchupAttemptSchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EmotionAuthoritySchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RelationshipAuthoritySchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExperienceEpisodeSchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LifeIntentAuthoritySchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AutonomyAuthoritySchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PerceptionAuthoritySchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BodyPackageAuthoritySchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Live2DCoreAuthoritySchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScreenPerceptionAuthoritySchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScreenVisionOutboundPolicyAuthoritySchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum VisionModelProfileSchemaUpgrade {
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CapabilityAuthorizationSchemaUpgrade {
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
    for (failpoint, sql) in [
        (
            Some(Migration016Failpoint::AfterOutboxSchema),
            ADD_DELETE_WITNESS_AT_SQL,
        ),
        (None, ADD_WITNESS_AGE_ANCHOR_AT_SQL),
        (
            Some(Migration016Failpoint::AfterResolutionSchema),
            ADD_CAPTURED_GENERATION_AUTHORITY_EPOCH_SQL,
        ),
        (
            Some(Migration016Failpoint::AfterGenerationSchema),
            ADD_GENERATION_AUTHORITY_EPOCH_SQL,
        ),
    ] {
        #[cfg(not(test))]
        let _ = failpoint;
        transaction
            .execute_batch(sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
        // Test-only failpoints fire AFTER the schema phase completes (points
        // A, B, C), inside the same transaction so the ALTER rolls back.
        #[cfg(test)]
        if let Some(failpoint) = failpoint {
            if should_fail_migration_016_at_for_test(failpoint) {
                return Err(StorageError::migration_transaction_failed());
            }
        }
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
    // Failure Point D: after the historical nonterminal Resolution
    // convergence UPDATE, before the canonical-coverage analysis.
    #[cfg(test)]
    if should_fail_migration_016_at_for_test(Migration016Failpoint::AfterResolutionConvergence) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Schema 15 stores the claimed generation id with the Delete-Unknown
    // witness, but the descriptor contract itself still lives in the
    // generation table.  A missing or malformed contract cannot be invented
    // for a historical Resolution.  Reject the whole upgrade rather than
    // allowing the old SELECT filters to silently omit a canonical witness.
    let unconstructable_historical_rows: i64 = transaction
        .query_row(
            &format!(
                "SELECT COUNT(*)
                   FROM (SELECT * FROM memory_vector_sync_outbox WHERE {predicate}) AS o
              LEFT JOIN memory_vector_late_delete_resolution AS r
                     ON r.life_id=o.life_id
                    AND r.memory_id=o.memory_id
                    AND r.mutation_sequence=o.mutation_sequence
              LEFT JOIN memory_vector_generation AS g
                     ON g.generation_id=o.claimed_generation_id
                  WHERE r.resolution_id IS NULL
                    AND (o.mutation_sequence<=0
                      OR o.attempt_count NOT BETWEEN 1 AND 5
                      OR o.fenced_claim_epoch<=0
                      OR o.last_marked_claim_epoch<=0
                      OR o.last_marked_claim_epoch>o.fenced_claim_epoch
                      OR o.claimed_generation_id IS NULL
                      OR o.claimed_generation_id=''
                      OR g.generation_id IS NULL
                      OR g.descriptor_hash=''
                      OR g.dimension<=0
                      OR g.state NOT IN ('building','active','retired','failed'))"
            ),
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if unconstructable_historical_rows != 0 {
        return Err(StorageError::migration_transaction_failed());
    }
    transaction.execute(
        &format!("INSERT INTO memory_vector_late_delete_resolution
          (outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,embedding_descriptor_id,embedding_dimension,captured_generation_state,witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,witness_send_disposition,witness_error_code,witness_age_anchor_at,captured_generation_authority_epoch,state,last_resolution_disposition,last_disposition_epoch,created_at,updated_at)
          SELECT o.id,o.life_id,o.memory_id,o.mutation_sequence,o.claimed_generation_id,g.descriptor_hash,g.dimension,g.state,o.attempt_count,o.fenced_claim_epoch,o.last_marked_claim_epoch,o.last_send_disposition,CASE WHEN o.last_error_code='PROVIDER_RESULT_UNKNOWN' THEN o.last_error_code ELSE NULL END,?1,0,'waiting_rebuild','waiting_rebuild',0,?1,?1
          FROM (SELECT * FROM memory_vector_sync_outbox WHERE {predicate}) AS o
          JOIN memory_vector_generation g ON g.generation_id=o.claimed_generation_id
          WHERE o.mutation_sequence>0 AND o.attempt_count BETWEEN 1 AND 5
            AND o.fenced_claim_epoch>0 AND o.last_marked_claim_epoch>0 AND o.last_marked_claim_epoch<=o.fenced_claim_epoch
            AND o.claimed_generation_id IS NOT NULL AND o.claimed_generation_id<>''
            AND g.descriptor_hash<>'' AND g.dimension>0 AND g.state IN ('building','active','retired','failed')
            AND NOT EXISTS (SELECT 1 FROM memory_vector_late_delete_resolution r WHERE r.life_id=o.life_id AND r.memory_id=o.memory_id AND r.mutation_sequence=o.mutation_sequence)"),
        params![migration16_now],
    ).map_err(|_| StorageError::migration_transaction_failed())?;
    // Failure Point E: after the historical canonical Unknown backfill INSERT
    // and before the coverage postcondition.
    #[cfg(test)]
    if should_fail_migration_016_at_for_test(Migration016Failpoint::AfterHistoricalCoverageBackfill)
    {
        return Err(StorageError::migration_transaction_failed());
    }
    let uncovered_historical_rows: i64 = transaction
        .query_row(
            &format!(
                "SELECT COUNT(*)
                   FROM (SELECT * FROM memory_vector_sync_outbox WHERE {predicate}) AS o
                  WHERE NOT EXISTS (
                        SELECT 1
                          FROM memory_vector_late_delete_resolution AS r
                         WHERE r.outbox_id=o.id
                           AND r.life_id=o.life_id
                           AND r.memory_id=o.memory_id
                           AND r.mutation_sequence=o.mutation_sequence
                           AND r.claimed_generation_id<>''
                           AND r.embedding_descriptor_id<>''
                           AND r.embedding_dimension>0
                           AND r.captured_generation_state IN ('building','active','retired','failed')
                           AND r.witness_attempt_ordinal BETWEEN 1 AND 5
                           AND r.witness_claim_epoch>0
                           AND r.witness_marked_claim_epoch>0
                           AND r.witness_marked_claim_epoch<=r.witness_claim_epoch
                           AND (r.witness_send_disposition='possibly_sent'
                                OR r.witness_error_code='PROVIDER_RESULT_UNKNOWN')
                           AND r.witness_age_anchor_at=?1
                           AND r.captured_generation_authority_epoch=0
                           AND r.state IN ('waiting_rebuild','resolved_absent',
                                           'resolved_deleted','resolved_rebuilt','superseded')
                    )"
            ),
            params![migration16_now],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if uncovered_historical_rows != 0 {
        return Err(StorageError::migration_transaction_failed());
    }
    for sql in [
        GENERATION_SEMANTIC_DELETE_TRIGGER_SQL,
        GENERATION_SEMANTIC_IDENTITY_TRIGGER_SQL,
        GENERATION_SEMANTIC_EPOCH_TRIGGER_SQL,
    ] {
        transaction
            .execute_batch(sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
        // Failure Point F: after the first semantic trigger is installed and
        // before the remaining triggers, proving no partial trigger set can
        // survive a rollback.
        #[cfg(test)]
        if should_fail_migration_016_at_for_test(Migration016Failpoint::AfterFirstSemanticTrigger) {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    // Failure Point G: after every migration step and the object validator,
    // immediately before the schema_migration version row insert, proving
    // validator success is not commit success.
    #[cfg(test)]
    if should_fail_migration_016_at_for_test(Migration016Failpoint::PreCommit) {
        return Err(StorageError::migration_transaction_failed());
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

/// Schema-17 is a single caller-owned transaction.  The schema is deliberately
/// programmatic, like Schema 13--16, because legacy validation and conservative
/// backfill must occur in the same transaction as DDL and writer-fence install.
pub(super) fn apply_generation_lifecycle_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<GenerationLifecycleSchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)?
        != LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION
    {
        return Err(StorageError::migration_version_invariant_failed());
    }
    #[cfg(test)]
    if should_fail_migration_017_at_for_test(Migration017Failpoint::BeforeAuthorityTable) {
        return Err(StorageError::migration_transaction_failed());
    }

    // Never repair an ambiguous Schema-16 generation world.  In particular,
    // historical claimed rows retain their unavailable epoch (NULL) below.
    let invalid_legacy_generation_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM memory_vector_generation
              WHERE generation_id='' OR descriptor_hash='' OR dimension<=0
                 OR authority_epoch<1 OR state NOT IN ('building','active','retired','failed')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let active_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM memory_vector_generation WHERE state='active'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let building_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM memory_vector_generation WHERE state='building'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if invalid_legacy_generation_count != 0 || active_count > 1 || building_count > 1 {
        return Err(StorageError::migration_transaction_failed());
    }
    let now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute_batch(CREATE_GENERATION_AUTHORITY_TABLE_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO memory_vector_generation_authority (singleton,active_generation_id,updated_at)
             SELECT 1,(SELECT generation_id FROM memory_vector_generation WHERE state='active'),?1",
            [now.as_str()],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_017_at_for_test(Migration017Failpoint::AfterAuthorityObjects) {
        return Err(StorageError::migration_transaction_failed());
    }

    transaction
        .execute_batch(ADD_CLAIMED_GENERATION_AUTHORITY_EPOCH_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_017_at_for_test(Migration017Failpoint::AfterOutboxTransformation) {
        return Err(StorageError::migration_transaction_failed());
    }

    transaction
        .execute_batch(CREATE_GENERATION_BINDING_TABLE_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute_batch(CREATE_GENERATION_STORE_WITNESS_TABLE_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    // Schema 16 contains a descriptor hash but no profile identity.  The
    // immutable sentinel explicitly records that absence; it does not infer a
    // profile or claim any external store is ready.
    transaction
        .execute(
            "INSERT INTO memory_vector_generation_binding
             (generation_id,descriptor_version,embedding_profile_id,created_at)
             SELECT generation_id,descriptor_hash,?1,?2 FROM memory_vector_generation",
            params![
                generation_lifecycle_authority::legacy_unverified_embedding_profile(),
                now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO memory_vector_generation_store_witness
             (generation_id,create_operation_id,state,last_error_code,updated_at)
             SELECT generation_id,NULL,'unverified',NULL,?1 FROM memory_vector_generation",
            [now.as_str()],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute_batch(CREATE_REBUILD_TABLES_AND_GUARDS_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    // Schema 17 adds a state-preserving authority-epoch CAS. Its exact +1
    // preimage remains mandatory; only the Schema-16 same-state prohibition
    // is replaced within this atomic upgrade.
    transaction
        .execute_batch("DROP TRIGGER memory_vector_generation_semantic_epoch_guard")
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute_batch(GENERATION_SEMANTIC_EPOCH_TRIGGER_SCHEMA_SEVENTEEN_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_017_at_for_test(Migration017Failpoint::AfterIndexesAndGuards) {
        return Err(StorageError::migration_transaction_failed());
    }

    writer_fence_manifest::install_generation_lifecycle_writer_fence_manifest_in_transaction(
        transaction,
    )?;
    validate_generation_lifecycle_schema_objects(transaction)?;
    #[cfg(test)]
    if should_fail_migration_017_at_for_test(Migration017Failpoint::BeforeFinalization) {
        return Err(StorageError::migration_transaction_failed());
    }
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                GENERATION_LIFECYCLE_SCHEMA_VERSION,
                GENERATION_LIFECYCLE_MIGRATION_NAME,
                now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_017_at_for_test(Migration017Failpoint::PreCommit) {
        return Err(StorageError::migration_transaction_failed());
    }
    validate_generation_lifecycle_schema_objects(transaction)?;
    Ok(GenerationLifecycleSchemaUpgrade::Applied)
}

pub(super) fn validate_generation_lifecycle_schema(
    connection: &Connection,
) -> Result<(), StorageError> {
    if connection::read_schema_version(connection)? != GENERATION_LIFECYCLE_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_generation_lifecycle_schema_objects(connection)
}

fn validate_generation_lifecycle_schema_objects(
    connection: &Connection,
) -> Result<(), StorageError> {
    for table in [
        "memory_vector_generation_authority",
        "memory_vector_generation_binding",
        "memory_vector_generation_store_witness",
        "memory_vector_generation_rebuild_job",
        "memory_vector_generation_rebuild_item",
        "memory_vector_generation_rebuild_resolution",
    ] {
        let exists: Option<i64> = connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StorageError::migration_transaction_failed())?;
        if exists.is_none() {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    for (table, declaration) in [
        ("memory_vector_sync_outbox", "claimed_generation_authority_epochintegernullcheck(claimed_generation_authority_epochisnullorclaimed_generation_authority_epoch>=1)"),
        ("memory_vector_generation_authority", "singletonintegerprimarykeycheck(singleton=1)"),
        ("memory_vector_generation_authority", "active_generation_idtextnullunique"),
        ("memory_vector_generation_binding", "embedding_profile_idtextnotnull"),
        ("memory_vector_generation_store_witness", "statetextnotnullcheck(statein('unverified','absent','create_started','ready','uncertain','deleted'))"),
        ("memory_vector_generation_rebuild_job", "statustextnotnullcheck(statusin('registered','snapshotting','bulk_building','catching_up','verifying','ready','completed','failed','cancelled'))"),
        ("memory_vector_generation_rebuild_item", "io_phasetextnotnullcheck(io_phasein('not_started','reserved','embedding_started','vector_write_started','finalized'))"),
        ("memory_vector_generation_rebuild_resolution", "dispositiontextnotnullcheck(dispositionin('resolved_by_rebuild','legacy_rebuild_resolved','failed_generation_requeued'))"),
    ] {
        let sql: String = connection
            .query_row("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1", [table], |row| row.get(0))
            .map_err(|_| StorageError::migration_transaction_failed())?;
        let definitions = normalized_top_level_column_definitions(&sql)
            .ok_or_else(StorageError::migration_transaction_failed)?;
        if definitions.iter().filter(|value| value.as_str() == declaration).count() != 1 {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    for index in [
        "memory_vector_generation_one_active",
        "memory_vector_generation_one_building",
        "memory_vector_generation_rebuild_job_one_nonterminal",
    ] {
        let exists: Option<i64> = connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type='index' AND name=?1",
                [index],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StorageError::migration_transaction_failed())?;
        if exists.is_none() {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    for trigger in [
        "memory_vector_generation_authority_active_insert_guard",
        "memory_vector_generation_authority_active_update_guard",
        "memory_vector_generation_active_pointer_state_guard",
        "memory_vector_generation_binding_immutable_update_guard",
        "memory_vector_generation_binding_immutable_delete_guard",
    ] {
        let exists: Option<i64> = connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type='trigger' AND name=?1",
                [trigger],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StorageError::migration_transaction_failed())?;
        if exists.is_none() {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    let epoch_trigger_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='memory_vector_generation_semantic_epoch_guard'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if normalize_schema_fragment(&epoch_trigger_sql)
        != normalize_schema_fragment(GENERATION_SEMANTIC_EPOCH_TRIGGER_SCHEMA_SEVENTEEN_SQL)
    {
        return Err(StorageError::migration_transaction_failed());
    }
    let invalid_pointer_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM memory_vector_generation_authority a
              LEFT JOIN memory_vector_generation g ON g.generation_id=a.active_generation_id
              WHERE a.singleton<>1 OR (a.active_generation_id IS NOT NULL AND (g.generation_id IS NULL OR g.state<>'active'))",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if invalid_pointer_count != 0 {
        return Err(StorageError::migration_transaction_failed());
    }
    let authority_row_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM memory_vector_generation_authority WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let active_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM memory_vector_generation WHERE state='active'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let building_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM memory_vector_generation WHERE state='building'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if authority_row_count != 1 || active_count > 1 || building_count > 1 {
        return Err(StorageError::migration_transaction_failed());
    }
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(
        connection,
        GENERATION_LIFECYCLE_SCHEMA_VERSION,
    )?;
    Ok(())
}

/// Schema 18 adds the D-stage attempt authority without changing Schema 17's
/// snapshot item meaning. The caller owns the transaction and records version
/// 18 only after table, semantic guards, writer fences, and validation agree.
/// The phases below all execute inside that single caller-owned transaction;
/// each failpoint proves its phase really happened before the rollback.
pub(super) fn apply_generation_catchup_attempt_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<GenerationCatchupAttemptSchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != GENERATION_LIFECYCLE_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    // Phase A: create the catch-up table. This is a genuinely distinct durable
    // boundary: the AfterTable failpoint fires before any semantic trigger or
    // writer fence exists inside the transaction.
    transaction
        .execute_batch(CREATE_REBUILD_CATCHUP_ATTEMPT_TABLE_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_018_at_for_test(Migration018Failpoint::AfterTable) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase B: install the exact semantic guards. The AfterSemanticGuards
    // failpoint fires only after both triggers exist and before any writer
    // fence is installed.
    transaction
        .execute_batch(CREATE_REBUILD_CATCHUP_ATTEMPT_IDENTITY_TRIGGER_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute_batch(CREATE_REBUILD_CATCHUP_ATTEMPT_SUPERSEDE_TRIGGER_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_018_at_for_test(Migration018Failpoint::AfterSemanticGuards) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase C: install the Schema 18 writer fences for the catch-up table.
    writer_fence_manifest::install_generation_catchup_writer_fence_manifest_in_transaction(
        transaction,
    )?;
    #[cfg(test)]
    if should_fail_migration_018_at_for_test(Migration018Failpoint::AfterWriterFences) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase D: validate the complete object set (table, triggers, fences)
    // before the version boundary.
    validate_generation_catchup_attempt_schema_objects(transaction)?;
    #[cfg(test)]
    if should_fail_migration_018_at_for_test(Migration018Failpoint::BeforeSchemaVersion) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase E: write the schema_migration version 18 row.
    transaction.execute(
        "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        params![GENERATION_CATCHUP_ATTEMPT_SCHEMA_VERSION, GENERATION_CATCHUP_ATTEMPT_MIGRATION_NAME],
    ).map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_018_at_for_test(Migration018Failpoint::PreCommit) {
        return Err(StorageError::migration_transaction_failed());
    }
    validate_generation_catchup_attempt_schema(transaction)?;
    Ok(GenerationCatchupAttemptSchemaUpgrade::Applied)
}

/// Schema 19 adds the D11 emotion authority: one authoritative
/// `emotion_state` row per life and the immutable `emotion_event` ledger.
/// The caller owns the transaction and version 19 is recorded only after the
/// tables, existing-life neutral backfill, neutral-state initializer trigger,
/// writer fences, and validation all agree.
pub(super) fn apply_emotion_authority_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<EmotionAuthoritySchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != GENERATION_CATCHUP_ATTEMPT_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    // Phase A: the two authoritative tables. Each failpoint fires after its own
    // durable boundary has been reached (mirroring Schema 18's AfterTable
    // boundary): the AfterStateTable failpoint means the state table exists
    // but the event table does not yet.
    transaction
        .execute_batch(CREATE_EMOTION_STATE_TABLE_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_019_at_for_test(Migration019Failpoint::AfterStateTable) {
        return Err(StorageError::migration_transaction_failed());
    }
    transaction
        .execute_batch(CREATE_EMOTION_EVENT_TABLE_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_019_at_for_test(Migration019Failpoint::AfterEventTable) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase B: existing-life neutral backfill. This runs before any emotion
    // writer fence exists, so the migration connection needs no writer
    // capability; the backfill count must cover every life exactly once.
    let life_count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM life_identity", [], |row| row.get(0))
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO emotion_state
                (life_id, valence, activation, revision, policy_version,
                 last_applied_at, updated_at)
             SELECT id, 0, 0, 0, 1, ?1, ?1 FROM life_identity",
            params![migration_now],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let backfilled_state_count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM emotion_state", [], |row| row.get(0))
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if backfilled_state_count != life_count {
        return Err(StorageError::migration_transaction_failed());
    }
    #[cfg(test)]
    if should_fail_migration_019_at_for_test(Migration019Failpoint::AfterBackfill) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase C: neutral-state initialization for every future life insert.
    // The exact trigger body is authority-bearing and validated below.
    transaction
        .execute_batch(CREATE_EMOTION_STATE_INITIALIZER_TRIGGER_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_019_at_for_test(Migration019Failpoint::AfterInitializerTrigger) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase D: install the emotion writer fences so raw legacy connections
    // can never write emotion authority.
    writer_fence_manifest::install_emotion_writer_fence_manifest_in_transaction(transaction)?;
    #[cfg(test)]
    if should_fail_migration_019_at_for_test(Migration019Failpoint::AfterWriterFences) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase E: validate the complete object set (tables, FKs, trigger, data
    // invariants) before the version boundary.
    validate_emotion_authority_schema_objects(transaction)?;
    #[cfg(test)]
    if should_fail_migration_019_at_for_test(Migration019Failpoint::BeforeSchemaVersion) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase F: write the schema_migration version 19 row.
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                EMOTION_AUTHORITY_SCHEMA_VERSION,
                EMOTION_AUTHORITY_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_019_at_for_test(Migration019Failpoint::PreCommit) {
        return Err(StorageError::migration_transaction_failed());
    }
    validate_emotion_authority_schema_objects(transaction)?;
    Ok(EmotionAuthoritySchemaUpgrade::Applied)
}

pub(super) fn validate_emotion_authority_schema(
    connection: &Connection,
) -> Result<(), StorageError> {
    // Schema 19 introduced the emotion authority; every later schema keeps
    // those tables authoritative, so the guard admits 19 and above. The fence
    // manifest follows the live version: later schemas add their own triggers
    // on top of the 51-triggers emotion epoch.
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < EMOTION_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_emotion_authority_schema_objects_for_fence_epoch(connection, schema_version)
}

fn validate_emotion_authority_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    validate_emotion_authority_schema_objects_for_fence_epoch(
        connection,
        EMOTION_AUTHORITY_SCHEMA_VERSION,
    )
}

fn validate_emotion_authority_schema_objects_for_fence_epoch(
    connection: &Connection,
    fence_schema_version: i64,
) -> Result<(), StorageError> {
    // The frozen domains and constraints are proven from SQLite's own
    // persisted DDL: a normalized full-statement comparison represents CHECK
    // expressions and table constraints that `PRAGMA table_info` cannot.
    for (table, expected_sql) in [
        ("emotion_state", CREATE_EMOTION_STATE_TABLE_SQL),
        ("emotion_event", CREATE_EMOTION_EVENT_TABLE_SQL),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StorageError::migration_transaction_failed())?;
        let Some(actual) = actual else {
            return Err(StorageError::migration_transaction_failed());
        };
        if normalized_frozen_object_sql(&actual) != normalized_frozen_object_sql(expected_sql) {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    // Life isolation and deletion cascade come from SQLite's own FK metadata.
    for table in ["emotion_state", "emotion_event"] {
        let cascade_fk: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)
                 WHERE \"table\"='life_identity' AND \"from\"='life_id'
                   AND on_delete='CASCADE'",
                [table],
                |row| row.get(0),
            )
            .map_err(|_| StorageError::migration_transaction_failed())?;
        if cascade_fk != 1 {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    // The neutral-state initializer must be exact, not merely present.
    let trigger_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type='trigger' AND name='emotion_state_life_insert_initializer'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let Some(trigger_sql) = trigger_sql else {
        return Err(StorageError::migration_transaction_failed());
    };
    if normalized_frozen_object_sql(&trigger_sql)
        != normalized_frozen_object_sql(CREATE_EMOTION_STATE_INITIALIZER_TRIGGER_SQL)
    {
        return Err(StorageError::migration_transaction_failed());
    }
    // Exactly one authoritative state row per life.
    let missing_state_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM life_identity AS l
              LEFT JOIN emotion_state AS s ON s.life_id = l.id
             WHERE s.life_id IS NULL",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if missing_state_count != 0 {
        return Err(StorageError::migration_transaction_failed());
    }
    // Row-level frozen invariants.
    let invalid_state_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM emotion_state
             WHERE valence NOT BETWEEN -1000 AND 1000
                OR activation NOT BETWEEN -1000 AND 1000
                OR revision < 0
                OR policy_version <= 0
                OR last_applied_at = ''
                OR updated_at = ''",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if invalid_state_count != 0 {
        return Err(StorageError::migration_transaction_failed());
    }
    let invalid_event_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM emotion_event
             WHERE source_kind = ''
                OR source_ref = ''
                OR valence_delta NOT BETWEEN -1000 AND 1000
                OR activation_delta NOT BETWEEN -1000 AND 1000
                OR result_valence NOT BETWEEN -1000 AND 1000
                OR result_activation NOT BETWEEN -1000 AND 1000
                OR applied_revision <= 0
                OR event_time = ''
                OR policy_version <= 0
                OR created_at = ''",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if invalid_event_count != 0 {
        return Err(StorageError::migration_transaction_failed());
    }
    // Both frozen UNIQUE constraints must actually exist as UNIQUE-origin
    // autoindexes (origin 'u'); the TEXT PRIMARY KEY also creates a unique
    // pk-origin autoindex and must not be counted here.
    let unique_index_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_index_list('emotion_event')
             WHERE \"unique\" = 1 AND origin = 'u'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if unique_index_count != 2 {
        return Err(StorageError::migration_transaction_failed());
    }
    // The Schema 18 catch-up objects stay validated on Schema 19+ (without the
    // schema-18 manifest selection, which cannot see later fence triggers), and
    // the writer fence must match the caller's epoch: 51 triggers at Schema 19,
    // 57 once Schema 20's relationship fences are installed, and 60 after
    // Schema 21's experience-episode fences are installed.
    validate_generation_catchup_attempt_schema_objects_inner(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(
        connection,
        fence_schema_version,
    )
}

/// Schema 20 adds the D12-B1 relationship authority: one authoritative
/// `relationship_state` row per (life, primary-user subject) and the immutable
/// `relationship_event` ledger. The caller owns the transaction and version 20
/// is recorded only after the tables, existing-life neutral backfill,
/// neutral-state initializer trigger, writer fences, and validation all agree.
pub(super) fn apply_relationship_authority_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<RelationshipAuthoritySchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != EMOTION_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    // Phase A: the two authoritative tables. Each failpoint fires after its own
    // durable boundary has been reached: the AfterStateTable failpoint means
    // the state table exists but the event table does not yet.
    transaction
        .execute_batch(CREATE_RELATIONSHIP_STATE_TABLE_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_020_at_for_test(Migration020Failpoint::AfterStateTable) {
        return Err(StorageError::migration_transaction_failed());
    }
    transaction
        .execute_batch(CREATE_RELATIONSHIP_EVENT_TABLE_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_020_at_for_test(Migration020Failpoint::AfterEventTable) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase B: existing-life neutral primary-user backfill. This runs before
    // any relationship writer fence exists, so the migration connection needs
    // no writer capability; the backfill count must cover every life exactly
    // once.
    let life_count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM life_identity", [], |row| row.get(0))
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO relationship_state
                (life_id, subject_id, familiarity, trust, emotional_closeness,
                 collaboration, safety, dependency_tendency, boundary_comfort, tension,
                 revision, policy_version, last_applied_at, updated_at)
             SELECT id, 'primary_user', 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, ?1, ?1
             FROM life_identity",
            params![migration_now],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let backfilled_state_count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM relationship_state", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if backfilled_state_count != life_count {
        return Err(StorageError::migration_transaction_failed());
    }
    #[cfg(test)]
    if should_fail_migration_020_at_for_test(Migration020Failpoint::AfterBackfill) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase C: neutral-state initialization for every future life insert.
    // The exact trigger body is authority-bearing and validated below.
    transaction
        .execute_batch(CREATE_RELATIONSHIP_STATE_INITIALIZER_TRIGGER_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_020_at_for_test(Migration020Failpoint::AfterInitializerTrigger) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase D: install the relationship writer fences so raw legacy
    // connections can never write relationship authority.
    writer_fence_manifest::install_relationship_writer_fence_manifest_in_transaction(transaction)?;
    #[cfg(test)]
    if should_fail_migration_020_at_for_test(Migration020Failpoint::AfterWriterFences) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase E: validate the complete object set (tables, FKs, trigger, data
    // invariants) before the version boundary.
    validate_relationship_authority_schema_objects(transaction)?;
    #[cfg(test)]
    if should_fail_migration_020_at_for_test(Migration020Failpoint::BeforeSchemaVersion) {
        return Err(StorageError::migration_transaction_failed());
    }
    // Phase F: write the schema_migration version 20 row.
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                RELATIONSHIP_AUTHORITY_SCHEMA_VERSION,
                RELATIONSHIP_AUTHORITY_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_020_at_for_test(Migration020Failpoint::PreCommit) {
        return Err(StorageError::migration_transaction_failed());
    }
    validate_relationship_authority_schema_objects(transaction)?;
    Ok(RelationshipAuthoritySchemaUpgrade::Applied)
}

pub(super) fn validate_relationship_authority_schema(
    connection: &Connection,
) -> Result<(), StorageError> {
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < RELATIONSHIP_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_relationship_authority_schema_objects_for_fence_epoch(connection, schema_version)
}

fn validate_relationship_authority_schema_objects(
    connection: &Connection,
) -> Result<(), StorageError> {
    validate_relationship_authority_schema_objects_for_fence_epoch(
        connection,
        RELATIONSHIP_AUTHORITY_SCHEMA_VERSION,
    )
}

fn validate_relationship_authority_schema_objects_for_fence_epoch(
    connection: &Connection,
    fence_schema_version: i64,
) -> Result<(), StorageError> {
    // The frozen domains and constraints are proven from SQLite's own
    // persisted DDL: a normalized full-statement comparison represents CHECK
    // expressions and table constraints that `PRAGMA table_info` cannot.
    for (table, expected_sql) in [
        ("relationship_state", CREATE_RELATIONSHIP_STATE_TABLE_SQL),
        ("relationship_event", CREATE_RELATIONSHIP_EVENT_TABLE_SQL),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StorageError::migration_transaction_failed())?;
        let Some(actual) = actual else {
            return Err(StorageError::migration_transaction_failed());
        };
        if normalized_frozen_object_sql(&actual) != normalized_frozen_object_sql(expected_sql) {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    // Life isolation and deletion cascade come from SQLite's own FK metadata:
    // the state rows hang off life_identity, the events off their state row.
    for (table, parent, column) in [
        ("relationship_state", "life_identity", "life_id"),
        ("relationship_event", "relationship_state", "life_id"),
    ] {
        let cascade_fk: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)
                 WHERE \"table\"=?2 AND \"from\"=?3 AND on_delete='CASCADE'",
                params![table, parent, column],
                |row| row.get(0),
            )
            .map_err(|_| StorageError::migration_transaction_failed())?;
        if cascade_fk != 1 {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    let event_subject_fk: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('relationship_event')
             WHERE \"table\"='relationship_state' AND \"from\"='subject_id'
               AND \"to\"='subject_id'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if event_subject_fk != 1 {
        return Err(StorageError::migration_transaction_failed());
    }
    // The neutral-state initializer must be exact, not merely present.
    let trigger_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type='trigger' AND name='relationship_state_life_insert_initializer'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StorageError::migration_transaction_failed())?;
    let Some(trigger_sql) = trigger_sql else {
        return Err(StorageError::migration_transaction_failed());
    };
    if normalized_frozen_object_sql(&trigger_sql)
        != normalized_frozen_object_sql(CREATE_RELATIONSHIP_STATE_INITIALIZER_TRIGGER_SQL)
    {
        return Err(StorageError::migration_transaction_failed());
    }
    // Exactly one authoritative primary-user state row per life.
    let missing_state_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM life_identity AS l
              LEFT JOIN relationship_state AS s
                ON s.life_id = l.id AND s.subject_id = 'primary_user'
             WHERE s.life_id IS NULL",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if missing_state_count != 0 {
        return Err(StorageError::migration_transaction_failed());
    }
    // Row-level frozen invariants.
    let invalid_state_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM relationship_state
             WHERE subject_id = ''
                OR familiarity NOT BETWEEN 0 AND 1000
                OR trust NOT BETWEEN -1000 AND 1000
                OR emotional_closeness NOT BETWEEN 0 AND 1000
                OR collaboration NOT BETWEEN 0 AND 1000
                OR safety NOT BETWEEN -1000 AND 1000
                OR dependency_tendency NOT BETWEEN 0 AND 1000
                OR boundary_comfort NOT BETWEEN -1000 AND 1000
                OR tension NOT BETWEEN 0 AND 1000
                OR revision < 0
                OR policy_version <= 0
                OR last_applied_at = ''
                OR updated_at = ''",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if invalid_state_count != 0 {
        return Err(StorageError::migration_transaction_failed());
    }
    let invalid_event_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM relationship_event
             WHERE subject_id = ''
                OR source_kind = ''
                OR source_ref = ''
                OR change_reason = ''
                OR familiarity_delta NOT BETWEEN -1000 AND 1000
                OR trust_delta NOT BETWEEN -1000 AND 1000
                OR emotional_closeness_delta NOT BETWEEN -1000 AND 1000
                OR collaboration_delta NOT BETWEEN -1000 AND 1000
                OR safety_delta NOT BETWEEN -1000 AND 1000
                OR dependency_tendency_delta NOT BETWEEN -1000 AND 1000
                OR boundary_comfort_delta NOT BETWEEN -1000 AND 1000
                OR tension_delta NOT BETWEEN -1000 AND 1000
                OR result_familiarity NOT BETWEEN 0 AND 1000
                OR result_trust NOT BETWEEN -1000 AND 1000
                OR result_emotional_closeness NOT BETWEEN 0 AND 1000
                OR result_collaboration NOT BETWEEN 0 AND 1000
                OR result_safety NOT BETWEEN -1000 AND 1000
                OR result_dependency_tendency NOT BETWEEN 0 AND 1000
                OR result_boundary_comfort NOT BETWEEN -1000 AND 1000
                OR result_tension NOT BETWEEN 0 AND 1000
                OR applied_revision <= 0
                OR event_time = ''
                OR policy_version <= 0
                OR created_at = ''",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if invalid_event_count != 0 {
        return Err(StorageError::migration_transaction_failed());
    }
    // Both frozen UNIQUE constraints must actually exist as UNIQUE-origin
    // autoindexes (origin 'u'); the composite PRIMARY KEY of
    // relationship_state creates a pk-origin autoindex and must not be
    // counted here.
    let unique_index_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_index_list('relationship_event')
             WHERE \"unique\" = 1 AND origin = 'u'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if unique_index_count != 2 {
        return Err(StorageError::migration_transaction_failed());
    }
    // The Schema 18 catch-up objects stay validated on Schema 20+ (without the
    // schema-18 manifest selection, which cannot see later fence triggers).
    validate_generation_catchup_attempt_schema_objects_inner(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(
        connection,
        fence_schema_version,
    )
}

/// Schema 21 adds the SQLite-authoritative bounded occurrence record for a
/// completed conversation turn. The migration is intentionally DDL-only: no
/// historical conversation rows are scanned or backfilled.
pub(super) fn apply_experience_episode_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<ExperienceEpisodeSchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != RELATIONSHIP_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }

    transaction
        .execute_batch(experience_episode::CREATE_EXPERIENCE_EPISODE_TABLE_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_021_at_for_test(Migration021Failpoint::AfterTable) {
        return Err(StorageError::migration_transaction_failed());
    }

    transaction
        .execute_batch(experience_episode::CREATE_EXPERIENCE_EPISODE_SOURCE_BINDING_TRIGGER_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute_batch(experience_episode::CREATE_EXPERIENCE_EPISODE_IMMUTABLE_TRIGGER_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_021_at_for_test(Migration021Failpoint::AfterSemanticGuards) {
        return Err(StorageError::migration_transaction_failed());
    }

    writer_fence_manifest::install_experience_episode_writer_fence_manifest_in_transaction(
        transaction,
    )?;
    #[cfg(test)]
    if should_fail_migration_021_at_for_test(Migration021Failpoint::AfterWriterFences) {
        return Err(StorageError::migration_transaction_failed());
    }

    validate_experience_episode_schema_objects(transaction)?;
    #[cfg(test)]
    if should_fail_migration_021_at_for_test(Migration021Failpoint::BeforeSchemaVersion) {
        return Err(StorageError::migration_transaction_failed());
    }

    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                EXPERIENCE_EPISODE_SCHEMA_VERSION,
                EXPERIENCE_EPISODE_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_021_at_for_test(Migration021Failpoint::PreCommit) {
        return Err(StorageError::migration_transaction_failed());
    }
    validate_experience_episode_schema_objects(transaction)?;
    Ok(ExperienceEpisodeSchemaUpgrade::Applied)
}

/// Schema 22 adds the explicit user-governed Life intention authority: the
/// five bounded tables `life_goal`, `life_plan`, `life_plan_step`,
/// `life_action_intent`, and `life_intent_event`, their same-life composite
/// parent bindings, B1 whole-table immutability guards, and the 15-trigger
/// writer-fence extension. The migration is intentionally DDL-only: no
/// historical Goal/Plan/Step/Action rows are synthesized, no default Goal is
/// initialized, and no `life_identity` initializer trigger is installed.
pub(super) fn apply_life_intent_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<LifeIntentAuthoritySchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != EXPERIENCE_EPISODE_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }

    for table_sql in life_intent::MIGRATION_022_TABLE_SQLS {
        transaction
            .execute_batch(table_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    #[cfg(test)]
    if should_fail_migration_022_at_for_test(Migration022Failpoint::AfterTable) {
        return Err(StorageError::migration_transaction_failed());
    }

    for trigger_sql in life_intent::MIGRATION_022_TRIGGER_SQLS {
        transaction
            .execute_batch(trigger_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    #[cfg(test)]
    if should_fail_migration_022_at_for_test(Migration022Failpoint::AfterSemanticGuards) {
        return Err(StorageError::migration_transaction_failed());
    }

    writer_fence_manifest::install_life_intent_writer_fence_manifest_in_transaction(transaction)?;
    #[cfg(test)]
    if should_fail_migration_022_at_for_test(Migration022Failpoint::AfterWriterFences) {
        return Err(StorageError::migration_transaction_failed());
    }

    validate_life_intent_schema_objects(transaction)?;
    #[cfg(test)]
    if should_fail_migration_022_at_for_test(Migration022Failpoint::BeforeSchemaVersion) {
        return Err(StorageError::migration_transaction_failed());
    }

    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                LIFE_INTENT_AUTHORITY_SCHEMA_VERSION,
                LIFE_INTENT_AUTHORITY_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_022_at_for_test(Migration022Failpoint::PreCommit) {
        return Err(StorageError::migration_transaction_failed());
    }
    validate_life_intent_schema_objects(transaction)?;
    Ok(LifeIntentAuthoritySchemaUpgrade::Applied)
}

pub(super) fn validate_life_intent_schema(connection: &Connection) -> Result<(), StorageError> {
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < LIFE_INTENT_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_life_intent_schema_objects(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(connection, schema_version)
}

fn validate_life_intent_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    life_intent::validate_schema_objects(connection)
}

/// Schema 23 adds the bounded, opt-in autonomy policy and proactive-intent
/// authority tables. The migration is deliberately DDL-only: it creates no
/// policy for existing lives and no proactive-intent rows. All objects are
/// installed inside the caller-owned IMMEDIATE transaction.
pub(super) fn apply_autonomy_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<AutonomyAuthoritySchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != LIFE_INTENT_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }

    for table_sql in autonomy::MIGRATION_023_TABLE_SQLS {
        transaction
            .execute_batch(table_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    #[cfg(test)]
    if should_fail_migration_023_at_for_test(Migration023Failpoint::AfterTable) {
        return Err(StorageError::migration_transaction_failed());
    }

    for trigger_sql in autonomy::MIGRATION_023_TRIGGER_SQLS {
        transaction
            .execute_batch(trigger_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    #[cfg(test)]
    if should_fail_migration_023_at_for_test(Migration023Failpoint::AfterSemanticGuards) {
        return Err(StorageError::migration_transaction_failed());
    }

    writer_fence_manifest::install_autonomy_writer_fence_manifest_in_transaction(transaction)?;
    #[cfg(test)]
    if should_fail_migration_023_at_for_test(Migration023Failpoint::AfterWriterFences) {
        return Err(StorageError::migration_transaction_failed());
    }

    validate_autonomy_schema_objects(transaction)?;
    #[cfg(test)]
    if should_fail_migration_023_at_for_test(Migration023Failpoint::BeforeSchemaVersion) {
        return Err(StorageError::migration_transaction_failed());
    }

    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                AUTONOMY_AUTHORITY_SCHEMA_VERSION,
                AUTONOMY_AUTHORITY_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_023_at_for_test(Migration023Failpoint::PreCommit) {
        return Err(StorageError::migration_transaction_failed());
    }
    validate_autonomy_schema_objects(transaction)?;
    Ok(AutonomyAuthoritySchemaUpgrade::Applied)
}

pub(super) fn validate_autonomy_schema(connection: &Connection) -> Result<(), StorageError> {
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < AUTONOMY_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_autonomy_schema_objects(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(connection, schema_version)
}

fn validate_autonomy_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    autonomy::validate_schema_objects(connection)
}

/// Schema 24 adds only the explicit, user-controlled consent authority for
/// the future privacy-minimized foreground-focus context.  It creates no
/// observation rows and no default policy rows.  All objects are installed in
/// the caller-owned IMMEDIATE transaction.
pub(super) fn apply_perception_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<PerceptionAuthoritySchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != AUTONOMY_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }

    for table_sql in perception::MIGRATION_024_TABLE_SQLS {
        transaction
            .execute_batch(table_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    #[cfg(test)]
    if should_fail_migration_024_at_for_test(Migration024Failpoint::AfterTable) {
        return Err(StorageError::migration_transaction_failed());
    }

    for trigger_sql in perception::MIGRATION_024_TRIGGER_SQLS {
        transaction
            .execute_batch(trigger_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    #[cfg(test)]
    if should_fail_migration_024_at_for_test(Migration024Failpoint::AfterSemanticGuards) {
        return Err(StorageError::migration_transaction_failed());
    }

    writer_fence_manifest::install_perception_writer_fence_manifest_in_transaction(transaction)?;
    #[cfg(test)]
    if should_fail_migration_024_at_for_test(Migration024Failpoint::AfterWriterFences) {
        return Err(StorageError::migration_transaction_failed());
    }

    validate_perception_schema_objects(transaction)?;
    #[cfg(test)]
    if should_fail_migration_024_at_for_test(Migration024Failpoint::BeforeSchemaVersion) {
        return Err(StorageError::migration_transaction_failed());
    }

    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                PERCEPTION_AUTHORITY_SCHEMA_VERSION,
                PERCEPTION_AUTHORITY_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_024_at_for_test(Migration024Failpoint::PreCommit) {
        return Err(StorageError::migration_transaction_failed());
    }
    validate_perception_schema_objects(transaction)?;
    Ok(PerceptionAuthoritySchemaUpgrade::Applied)
}

pub(super) fn validate_perception_schema(connection: &Connection) -> Result<(), StorageError> {
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < PERCEPTION_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_perception_schema_objects(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(connection, schema_version)
}

fn validate_perception_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    perception::validate_schema_objects(connection)
}

/// Schema 25 adds the SQLite-authoritative managed Live2D package registry.
/// Package bytes remain outside SQLite, but no managed asset is trusted unless
/// its package and manifest rows are registered atomically here.
pub(super) fn apply_body_package_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<BodyPackageAuthoritySchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != PERCEPTION_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }

    for table_sql in body_package::MIGRATION_025_TABLE_SQLS {
        transaction
            .execute_batch(table_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    for trigger_sql in body_package::MIGRATION_025_TRIGGER_SQLS {
        transaction
            .execute_batch(trigger_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    writer_fence_manifest::install_body_package_writer_fence_manifest_in_transaction(transaction)?;

    validate_body_package_schema_objects(transaction)?;
    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                BODY_PACKAGE_AUTHORITY_SCHEMA_VERSION,
                BODY_PACKAGE_AUTHORITY_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    validate_body_package_schema_objects(transaction)?;
    Ok(BodyPackageAuthoritySchemaUpgrade::Applied)
}

pub(super) fn validate_body_package_schema(connection: &Connection) -> Result<(), StorageError> {
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < BODY_PACKAGE_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_body_package_schema_objects(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(connection, schema_version)
}

fn validate_body_package_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    body_package::validate_schema_objects(connection)
}

/// Schema 26 adds the SQLite-authoritative managed Cubism Core component
/// authority.  Core bytes remain outside SQLite, but no managed Core file is
/// trusted unless its component row is registered here and the registered
/// SHA-256 stays present in the production allowlist.
pub(super) fn apply_live2d_core_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<Live2DCoreAuthoritySchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != BODY_PACKAGE_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }

    for table_sql in live2d_core::MIGRATION_026_TABLE_SQLS {
        transaction
            .execute_batch(table_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    for trigger_sql in live2d_core::MIGRATION_026_TRIGGER_SQLS {
        transaction
            .execute_batch(trigger_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    writer_fence_manifest::install_live2d_core_writer_fence_manifest_in_transaction(transaction)?;

    validate_live2d_core_schema_objects(transaction)?;
    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION,
                LIVE2D_CORE_AUTHORITY_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    validate_live2d_core_schema_objects(transaction)?;
    Ok(Live2DCoreAuthoritySchemaUpgrade::Applied)
}

pub(super) fn validate_live2d_core_schema(connection: &Connection) -> Result<(), StorageError> {
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_live2d_core_schema_objects(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(connection, schema_version)
}

fn validate_live2d_core_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    live2d_core::validate_schema_objects(connection)
}

/// Schema 27 adds the independent D23-B1 screen-perception consent authority.
/// It creates no observation rows, no capture-target rows, and no default
/// policy rows.  All objects are installed in the caller-owned IMMEDIATE
/// transaction.
pub(super) fn apply_screen_perception_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<ScreenPerceptionAuthoritySchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }

    for table_sql in screen_perception::MIGRATION_027_TABLE_SQLS {
        transaction
            .execute_batch(table_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    #[cfg(test)]
    if should_fail_migration_027_at_for_test(Migration027Failpoint::AfterTable) {
        return Err(StorageError::migration_transaction_failed());
    }

    for trigger_sql in screen_perception::MIGRATION_027_TRIGGER_SQLS {
        transaction
            .execute_batch(trigger_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    #[cfg(test)]
    if should_fail_migration_027_at_for_test(Migration027Failpoint::AfterSemanticGuards) {
        return Err(StorageError::migration_transaction_failed());
    }

    writer_fence_manifest::install_screen_perception_writer_fence_manifest_in_transaction(
        transaction,
    )?;
    #[cfg(test)]
    if should_fail_migration_027_at_for_test(Migration027Failpoint::AfterWriterFences) {
        return Err(StorageError::migration_transaction_failed());
    }

    validate_screen_perception_schema_objects(transaction)?;
    #[cfg(test)]
    if should_fail_migration_027_at_for_test(Migration027Failpoint::BeforeSchemaVersion) {
        return Err(StorageError::migration_transaction_failed());
    }

    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION,
                SCREEN_PERCEPTION_AUTHORITY_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    #[cfg(test)]
    if should_fail_migration_027_at_for_test(Migration027Failpoint::PreCommit) {
        return Err(StorageError::migration_transaction_failed());
    }
    validate_screen_perception_schema_objects(transaction)?;
    Ok(ScreenPerceptionAuthoritySchemaUpgrade::Applied)
}

pub(super) fn validate_screen_perception_schema(
    connection: &Connection,
) -> Result<(), StorageError> {
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_screen_perception_schema_objects(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(connection, schema_version)
}

fn validate_screen_perception_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    screen_perception::validate_schema_objects(connection)
}

/// Schema 28 adds only the independent D25-A Life-scoped outbound policy and
/// its immutable explicit-user event evidence. It performs no backfill and
/// does not inspect any D23 consent, session, target, candidate, grant, or
/// attachment state.
pub(super) fn apply_screen_vision_outbound_policy_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<ScreenVisionOutboundPolicyAuthoritySchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }

    for table_sql in screen_vision_outbound_policy::MIGRATION_028_TABLE_SQLS {
        transaction
            .execute_batch(table_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    for trigger_sql in screen_vision_outbound_policy::MIGRATION_028_TRIGGER_SQLS {
        transaction
            .execute_batch(trigger_sql)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    writer_fence_manifest::install_screen_vision_outbound_policy_writer_fence_manifest_in_transaction(
        transaction,
    )?;

    validate_screen_vision_outbound_policy_schema_objects(transaction)?;
    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_SCHEMA_VERSION,
                SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    validate_screen_vision_outbound_policy_schema_objects(transaction)?;
    Ok(ScreenVisionOutboundPolicyAuthoritySchemaUpgrade::Applied)
}

pub(super) fn validate_screen_vision_outbound_policy_schema(
    connection: &Connection,
) -> Result<(), StorageError> {
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_screen_vision_outbound_policy_schema_objects(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(connection, schema_version)
}

fn validate_screen_vision_outbound_policy_schema_objects(
    connection: &Connection,
) -> Result<(), StorageError> {
    screen_vision_outbound_policy::validate_schema_objects(connection)
}

/// Schema 29 expands only the existing model-profile purpose vocabulary with
/// the independent Vision purpose. The table rebuild preserves rowids, profile
/// data, active mappings, timestamps, indexes, and foreign-key semantics; it
/// creates no Vision rows or active mapping.
pub(super) fn apply_vision_model_profile_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<VisionModelProfileSchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)?
        != SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_SCHEMA_VERSION
    {
        return Err(StorageError::migration_version_invariant_failed());
    }

    transaction
        .execute_batch(VISION_MODEL_PROFILE_MIGRATION_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    model_profile::validate_schema_029(transaction)?;

    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO schema_migration (version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                VISION_MODEL_PROFILE_SCHEMA_VERSION,
                VISION_MODEL_PROFILE_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    model_profile::validate_schema_029(transaction)?;
    Ok(VisionModelProfileSchemaUpgrade::Applied)
}

pub(super) fn validate_model_profile_schema(connection: &Connection) -> Result<(), StorageError> {
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < VISION_MODEL_PROFILE_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    model_profile::validate_schema_029(connection)
}

/// Schema 30 adds only the durable, Life-scoped user authorization root and
/// its immutable transition evidence. It performs no backfill and creates no
/// authorization rows; missing rows therefore remain denied.
pub(super) fn apply_capability_authorization_schema_upgrade(
    transaction: &Transaction<'_>,
) -> Result<CapabilityAuthorizationSchemaUpgrade, StorageError> {
    if connection::read_schema_version(transaction)? != VISION_MODEL_PROFILE_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }

    transaction
        .execute_batch(capability_authorization::MIGRATION_030_SQL)
        .map_err(|_| StorageError::migration_transaction_failed())?;
    writer_fence_manifest::install_capability_authorization_writer_fence_manifest_in_transaction(
        transaction,
    )?;

    capability_authorization::validate_schema_objects(transaction)?;
    let migration_now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| StorageError::migration_transaction_failed())?;
    transaction
        .execute(
            "INSERT INTO schema_migration(version,name,applied_at) VALUES (?1,?2,?3)",
            params![
                CAPABILITY_AUTHORIZATION_SCHEMA_VERSION,
                CAPABILITY_AUTHORIZATION_MIGRATION_NAME,
                migration_now
            ],
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    capability_authorization::validate_schema_objects(transaction)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(
        transaction,
        CAPABILITY_AUTHORIZATION_SCHEMA_VERSION,
    )?;
    Ok(CapabilityAuthorizationSchemaUpgrade::Applied)
}

pub(super) fn validate_capability_authorization_schema(
    connection: &Connection,
) -> Result<(), StorageError> {
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < CAPABILITY_AUTHORIZATION_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    capability_authorization::validate_schema_objects(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(connection, schema_version)
}

pub(super) fn validate_experience_episode_schema(
    connection: &Connection,
) -> Result<(), StorageError> {
    let schema_version = connection::read_schema_version(connection)?;
    if schema_version < EXPERIENCE_EPISODE_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_experience_episode_schema_objects(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(connection, schema_version)
}

fn validate_experience_episode_schema_objects(connection: &Connection) -> Result<(), StorageError> {
    experience_episode::validate_schema_objects(connection)
}

pub(super) fn validate_generation_catchup_attempt_schema(
    connection: &Connection,
) -> Result<(), StorageError> {
    if connection::read_schema_version(connection)? != GENERATION_CATCHUP_ATTEMPT_SCHEMA_VERSION {
        return Err(StorageError::migration_version_invariant_failed());
    }
    validate_generation_catchup_attempt_schema_objects(connection)
}

/// Validates the complete Schema-18 object set, including its own writer-fence
/// manifest selection. Only valid when the database has no later fence
/// triggers (that is, at schema 18).
fn validate_generation_catchup_attempt_schema_objects(
    connection: &Connection,
) -> Result<(), StorageError> {
    validate_generation_catchup_attempt_schema_objects_inner(connection)?;
    writer_fence_manifest::validate_writer_fence_manifest_for_schema(
        connection,
        GENERATION_CATCHUP_ATTEMPT_SCHEMA_VERSION,
    )
}

/// Validates the Schema-18 catch-up objects (table DDL, columns, FK, semantic
/// triggers) WITHOUT the writer-fence manifest check, so later schemas can
/// keep validating these objects while selecting the manifest for their own
/// version.
fn validate_generation_catchup_attempt_schema_objects_inner(
    connection: &Connection,
) -> Result<(), StorageError> {
    // The frozen domains and cross-field semantics are proven from SQLite's own
    // persisted DDL.  A normalized full-statement comparison is used instead of
    // `PRAGMA table_info`, which does not represent CHECK expressions, table
    // constraints (PRIMARY KEY / UNIQUE / FOREIGN KEY), or trigger bodies.
    let table_sql: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_rebuild_catchup_item'",
        [], |row| row.get(0),
    ).map_err(|_| StorageError::migration_transaction_failed())?;
    if normalize_schema_fragment(&table_sql)
        != normalize_schema_fragment(CREATE_REBUILD_CATCHUP_ATTEMPT_TABLE_SQL)
    {
        return Err(StorageError::migration_transaction_failed());
    }
    // Independent table-info checks for the NOT NULL / type / default shape of
    // the identity and attempt columns (the CHECK expressions themselves are
    // already proven by the full normalized statement comparison above).
    for (column, declared_type, not_null, default_value) in [
        ("job_id", "TEXT", 1, None),
        ("source_outbox_id", "INTEGER", 1, None),
        ("life_id", "TEXT", 1, None),
        ("memory_id", "TEXT", 1, None),
        ("mutation_sequence", "INTEGER", 1, None),
        ("desired_action", "TEXT", 1, None),
        ("state", "TEXT", 1, None),
        ("io_phase", "TEXT", 1, None),
        ("attempt_count", "INTEGER", 1, Some("0")),
        ("attempt_fence", "INTEGER", 1, Some("0")),
    ] {
        let found: Option<(String, i64, Option<String>)> = connection
            .query_row(
                "SELECT type, \"notnull\", dflt_value FROM pragma_table_info('memory_vector_generation_rebuild_catchup_item') WHERE name=?1",
                [column],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| StorageError::migration_transaction_failed())?;
        if !matches!(found.as_ref(), Some((ty, nn, default)) if ty == declared_type && *nn == not_null && default.as_deref() == default_value)
        {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    let foreign_key: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('memory_vector_generation_rebuild_catchup_item')
             WHERE \"table\"='memory_vector_generation_rebuild_job' AND \"from\"='job_id' AND \"to\"='job_id'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StorageError::migration_transaction_failed())?;
    if foreign_key != 1 {
        return Err(StorageError::migration_transaction_failed());
    }
    // The semantic trigger bodies are authority-bearing: only existence is not
    // enough.  Each frozen trigger SQL must match exactly, so a correct name
    // with a weakened or empty body is rejected without any repair.
    for (name, expected_sql) in [
        (
            "memory_vector_generation_rebuild_catchup_identity_immutable",
            CREATE_REBUILD_CATCHUP_ATTEMPT_IDENTITY_TRIGGER_SQL,
        ),
        (
            "memory_vector_generation_rebuild_catchup_supersede_guard",
            CREATE_REBUILD_CATCHUP_ATTEMPT_SUPERSEDE_TRIGGER_SQL,
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StorageError::migration_transaction_failed())?;
        let Some(actual) = actual else {
            return Err(StorageError::migration_transaction_failed());
        };
        if normalize_schema_fragment(&actual) != normalize_schema_fragment(expected_sql) {
            return Err(StorageError::migration_transaction_failed());
        }
    }
    Ok(())
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
    // `table_info` deliberately does not expose CHECK expressions. Reuse the
    // existing SQLite-schema normalization path to prove that Schema 16 still
    // carries the two frozen authority-epoch domains in its actual table DDL.
    for (table, expected_definition) in [
        (
            "memory_vector_late_delete_resolution",
            NORMALIZED_CAPTURED_GENERATION_AUTHORITY_EPOCH_COLUMN_DDL,
        ),
        (
            "memory_vector_generation",
            NORMALIZED_GENERATION_AUTHORITY_EPOCH_COLUMN_DDL,
        ),
    ] {
        let table_sql: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StorageError::migration_transaction_failed())?;
        let definitions = table_sql
            .as_deref()
            .and_then(normalized_top_level_column_definitions)
            .ok_or_else(StorageError::migration_transaction_failed)?;
        if definitions
            .iter()
            .filter(|definition| definition.as_str() == expected_definition)
            .count()
            != 1
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

/// SQLite stores object SQL without the terminating semicolon; frozen
/// migration files may include one followed by a newline. Strip surrounding
/// whitespace and any trailing semicolons from both sides before the exact
/// normalized comparison.
fn normalized_frozen_object_sql(value: &str) -> String {
    normalize_schema_fragment(value.trim().trim_end_matches(';'))
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
    if expected_schema_version == GENERATION_LIFECYCLE_SCHEMA_VERSION {
        validate_generation_lifecycle_schema(connection)?;
    }
    if expected_schema_version == GENERATION_CATCHUP_ATTEMPT_SCHEMA_VERSION {
        validate_generation_catchup_attempt_schema(connection)?;
    }
    if expected_schema_version == EMOTION_AUTHORITY_SCHEMA_VERSION {
        validate_emotion_authority_schema(connection)?;
    }
    if expected_schema_version == RELATIONSHIP_AUTHORITY_SCHEMA_VERSION {
        validate_relationship_authority_schema(connection)?;
    }
    if expected_schema_version == EXPERIENCE_EPISODE_SCHEMA_VERSION {
        validate_experience_episode_schema(connection)?;
    }
    if expected_schema_version == LIFE_INTENT_AUTHORITY_SCHEMA_VERSION {
        validate_life_intent_schema(connection)?;
    }
    if expected_schema_version == AUTONOMY_AUTHORITY_SCHEMA_VERSION {
        validate_autonomy_schema(connection)?;
    }
    if expected_schema_version >= PERCEPTION_AUTHORITY_SCHEMA_VERSION {
        validate_perception_schema(connection)?;
    }
    if expected_schema_version >= BODY_PACKAGE_AUTHORITY_SCHEMA_VERSION {
        validate_body_package_schema(connection)?;
    }
    if expected_schema_version >= LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION {
        validate_live2d_core_schema(connection)?;
    }
    if expected_schema_version >= SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION {
        validate_screen_perception_schema(connection)?;
    }
    if expected_schema_version >= SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_SCHEMA_VERSION {
        validate_screen_vision_outbound_policy_schema(connection)?;
    }
    if expected_schema_version >= VISION_MODEL_PROFILE_SCHEMA_VERSION {
        validate_model_profile_schema(connection)?;
    }
    if expected_schema_version >= CAPABILITY_AUTHORIZATION_SCHEMA_VERSION {
        validate_capability_authorization_schema(connection)?;
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

/// Test-only failure points for the single Schema-17 migration transaction.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration017Failpoint {
    BeforeAuthorityTable,
    AfterAuthorityObjects,
    AfterOutboxTransformation,
    AfterIndexesAndGuards,
    BeforeFinalization,
    PreCommit,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_017_FAILPOINT: std::cell::Cell<Option<Migration017Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_017_at_for_test(failpoint: Migration017Failpoint) {
    MIGRATION_017_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_017_at_for_test(failpoint: Migration017Failpoint) -> bool {
    MIGRATION_017_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

/// Test-only failure points for the single Schema-18 migration transaction.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration018Failpoint {
    AfterTable,
    AfterSemanticGuards,
    AfterWriterFences,
    BeforeSchemaVersion,
    PreCommit,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_018_FAILPOINT: std::cell::Cell<Option<Migration018Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_018_at_for_test(failpoint: Migration018Failpoint) {
    MIGRATION_018_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_018_at_for_test(failpoint: Migration018Failpoint) -> bool {
    MIGRATION_018_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

/// Test-only failure points for the single Schema-19 emotion-authority
/// transaction. Each variant fires after its own durable boundary has been
/// reached inside the caller-owned transaction, so the whole upgrade (tables,
/// backfill, initializer trigger, writer fences, validators, version row)
/// rolls back as one atomic unit.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration019Failpoint {
    AfterStateTable,
    AfterEventTable,
    AfterBackfill,
    AfterInitializerTrigger,
    AfterWriterFences,
    BeforeSchemaVersion,
    PreCommit,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_019_FAILPOINT: std::cell::Cell<Option<Migration019Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_019_at_for_test(failpoint: Migration019Failpoint) {
    MIGRATION_019_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_019_at_for_test(failpoint: Migration019Failpoint) -> bool {
    MIGRATION_019_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

/// Test-only failpoints for Migration020
/// (`apply_relationship_authority_schema_upgrade`). Each variant corresponds to
/// a phase of the single-transaction upgrade. The failpoint returns
/// `MIGRATION_TRANSACTION_FAILED` from inside the transaction, so the whole
/// upgrade (tables, backfill, initializer trigger, writer fences, validators,
/// version row) rolls back as one atomic unit.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration020Failpoint {
    AfterStateTable,
    AfterEventTable,
    AfterBackfill,
    AfterInitializerTrigger,
    AfterWriterFences,
    BeforeSchemaVersion,
    PreCommit,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_020_FAILPOINT: std::cell::Cell<Option<Migration020Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_020_at_for_test(failpoint: Migration020Failpoint) {
    MIGRATION_020_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_020_at_for_test(failpoint: Migration020Failpoint) -> bool {
    MIGRATION_020_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

/// Test-only failpoints for Migration021. Every point is inside the single
/// caller-owned transaction, so a failure proves the Episode table, semantic
/// guards, writer fences, and version row do not escape as a partial upgrade.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration021Failpoint {
    AfterTable,
    AfterSemanticGuards,
    AfterWriterFences,
    BeforeSchemaVersion,
    PreCommit,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_021_FAILPOINT: std::cell::Cell<Option<Migration021Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_021_at_for_test(failpoint: Migration021Failpoint) {
    MIGRATION_021_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_021_at_for_test(failpoint: Migration021Failpoint) -> bool {
    MIGRATION_021_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

/// Test-only failpoints for Migration022. Every point is inside the single
/// caller-owned transaction, so a failure proves the five D14 tables, the
/// semantic immutability guards, the writer fences, and the version row do not
/// escape as a partial upgrade.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration022Failpoint {
    AfterTable,
    AfterSemanticGuards,
    AfterWriterFences,
    BeforeSchemaVersion,
    PreCommit,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_022_FAILPOINT: std::cell::Cell<Option<Migration022Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_022_at_for_test(failpoint: Migration022Failpoint) {
    MIGRATION_022_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_022_at_for_test(failpoint: Migration022Failpoint) -> bool {
    MIGRATION_022_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

/// Test-only failpoints for Migration023. Every point is inside the single
/// caller-owned transaction, so a failure proves the four D15 tables, the
/// selective/fixed semantic guards, the writer fences, and the version row do
/// not escape as a partial upgrade.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration023Failpoint {
    AfterTable,
    AfterSemanticGuards,
    AfterWriterFences,
    BeforeSchemaVersion,
    PreCommit,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_023_FAILPOINT: std::cell::Cell<Option<Migration023Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_023_at_for_test(failpoint: Migration023Failpoint) {
    MIGRATION_023_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_023_at_for_test(failpoint: Migration023Failpoint) -> bool {
    MIGRATION_023_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

/// Test-only failpoints for Migration024.  Each point fires inside the single
/// caller-owned 23-to-24 transaction, proving the consent tables, semantic
/// guards, writer fences, and version row roll back together.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration024Failpoint {
    AfterTable,
    AfterSemanticGuards,
    AfterWriterFences,
    BeforeSchemaVersion,
    PreCommit,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_024_FAILPOINT: std::cell::Cell<Option<Migration024Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_024_at_for_test(failpoint: Migration024Failpoint) {
    MIGRATION_024_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_024_at_for_test(failpoint: Migration024Failpoint) -> bool {
    MIGRATION_024_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

/// Test-only failpoints for Migration027.  Each point fires inside the single
/// caller-owned 26-to-27 transaction, proving the consent tables, semantic
/// guards, writer fences, and version row roll back together.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration027Failpoint {
    AfterTable,
    AfterSemanticGuards,
    AfterWriterFences,
    BeforeSchemaVersion,
    PreCommit,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_027_FAILPOINT: std::cell::Cell<Option<Migration027Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_027_at_for_test(failpoint: Migration027Failpoint) {
    MIGRATION_027_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_027_at_for_test(failpoint: Migration027Failpoint) -> bool {
    MIGRATION_027_FAILPOINT.with(|next| {
        if next.get() == Some(failpoint) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

/// Test-only failpoints for Migration016 (`apply_late_delete_generation_authority_schema_upgrade`).
/// Each variant corresponds to a phase of the single-transaction upgrade. The
/// failpoint returns `MIGRATION_TRANSACTION_FAILED` from inside the transaction,
/// so the whole upgrade (DDL, backfills, triggers, validators, version row)
/// rolls back as one atomic unit. `PreCommit` is consumed just before the
/// version row insert, proving that validator success is not commit success.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Migration016Failpoint {
    /// After `memory_vector_sync_outbox.delete_witness_at` has been added and
    /// before any further ALTER (Failure Point A).
    AfterOutboxSchema,
    /// After the Resolution schema columns
    /// (`witness_age_anchor_at`, `captured_generation_authority_epoch`) have
    /// been added (Failure Point B).
    AfterResolutionSchema,
    /// After `memory_vector_generation.authority_epoch` has been added
    /// (Failure Point C).
    AfterGenerationSchema,
    /// After the historical nonterminal Resolution convergence UPDATE has run
    /// (Failure Point D).
    AfterResolutionConvergence,
    /// After the historical canonical Unknown Resolution backfill INSERT and
    /// before the coverage postcondition check (Failure Point E).
    AfterHistoricalCoverageBackfill,
    /// After the first/second Generation semantic trigger has been installed
    /// and before the third (Failure Point F).
    AfterFirstSemanticTrigger,
    /// After every migration step and validator, immediately before the
    /// schema_migration version row insert (Failure Point G).
    PreCommit,
}

#[cfg(test)]
thread_local! {
    static MIGRATION_016_FAILPOINT: std::cell::Cell<Option<Migration016Failpoint>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_next_migration_016_at_for_test(failpoint: Migration016Failpoint) {
    MIGRATION_016_FAILPOINT.with(|next| next.set(Some(failpoint)));
}

#[cfg(test)]
fn should_fail_migration_016_at_for_test(failpoint: Migration016Failpoint) -> bool {
    MIGRATION_016_FAILPOINT.with(|next| {
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
    if expected_schema_version >= EXPERIENCE_EPISODE_SCHEMA_VERSION {
        validate_experience_episode_schema(connection)?;
    }
    if expected_schema_version >= LIFE_INTENT_AUTHORITY_SCHEMA_VERSION {
        validate_life_intent_schema(connection)?;
    }
    if expected_schema_version >= AUTONOMY_AUTHORITY_SCHEMA_VERSION {
        validate_autonomy_schema(connection)?;
    }
    if expected_schema_version >= PERCEPTION_AUTHORITY_SCHEMA_VERSION {
        validate_perception_schema(connection)?;
    }
    if expected_schema_version >= BODY_PACKAGE_AUTHORITY_SCHEMA_VERSION {
        validate_body_package_schema(connection)?;
    }
    if expected_schema_version >= LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION {
        validate_live2d_core_schema(connection)?;
    }
    if expected_schema_version >= SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION {
        validate_screen_perception_schema(connection)?;
    }
    if expected_schema_version >= SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_SCHEMA_VERSION {
        validate_screen_vision_outbound_policy_schema(connection)?;
    }
    if expected_schema_version >= VISION_MODEL_PROFILE_SCHEMA_VERSION {
        validate_model_profile_schema(connection)?;
    }
    if expected_schema_version >= CAPABILITY_AUTHORIZATION_SCHEMA_VERSION {
        validate_capability_authorization_schema(connection)?;
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

    fn schema_sixteen_connection() -> Connection {
        let mut connection = version_fourteen_connection();
        apply_late_delete_resolution_upgrade(&mut connection);
        apply_late_delete_generation_authority_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION
        );
        connection
    }

    fn apply_generation_lifecycle_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_generation_lifecycle_schema_upgrade(&transaction).unwrap(),
            GenerationLifecycleSchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn schema_seventeen_connection() -> Connection {
        let mut connection = schema_sixteen_connection();
        apply_generation_lifecycle_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            GENERATION_LIFECYCLE_SCHEMA_VERSION
        );
        connection
    }

    fn apply_generation_catchup_attempt_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_generation_catchup_attempt_schema_upgrade(&transaction).unwrap(),
            GenerationCatchupAttemptSchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn schema_eighteen_connection() -> Connection {
        let mut connection = schema_seventeen_connection();
        apply_generation_catchup_attempt_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            GENERATION_CATCHUP_ATTEMPT_SCHEMA_VERSION
        );
        connection
    }

    fn apply_emotion_authority_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_emotion_authority_schema_upgrade(&transaction).unwrap(),
            EmotionAuthoritySchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn apply_relationship_authority_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_relationship_authority_schema_upgrade(&transaction).unwrap(),
            RelationshipAuthoritySchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn apply_experience_episode_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_experience_episode_schema_upgrade(&transaction).unwrap(),
            ExperienceEpisodeSchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn apply_life_intent_authority_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_life_intent_schema_upgrade(&transaction).unwrap(),
            LifeIntentAuthoritySchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn apply_autonomy_authority_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_autonomy_schema_upgrade(&transaction).unwrap(),
            AutonomyAuthoritySchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn apply_perception_authority_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_perception_schema_upgrade(&transaction).unwrap(),
            PerceptionAuthoritySchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn apply_body_package_authority_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_body_package_schema_upgrade(&transaction).unwrap(),
            BodyPackageAuthoritySchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn schema_twenty_one_connection() -> Connection {
        let mut connection = schema_twenty_connection();
        apply_experience_episode_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            EXPERIENCE_EPISODE_SCHEMA_VERSION
        );
        connection
    }

    fn schema_twenty_two_connection() -> Connection {
        let mut connection = schema_twenty_one_connection();
        apply_life_intent_authority_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            LIFE_INTENT_AUTHORITY_SCHEMA_VERSION
        );
        connection
    }

    fn schema_twenty_three_connection() -> Connection {
        let mut connection = schema_twenty_two_connection();
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
        apply_autonomy_authority_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            AUTONOMY_AUTHORITY_SCHEMA_VERSION
        );
        connection
    }

    const VERIFICATION_LIFE_ID: &str = "migration-024-verification-life";

    fn seed_verification_life(connection: &Connection) {
        connection
            .execute(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES ('migration-024-verification-persona', 'Persona', 1, '{}')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO life_identity
                 (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES (?1, 'Verification Life', '2026-08-27T00:00:00.000Z', 1,
                         'migration-024-verification-body',
                         'migration-024-verification-persona', 1)",
                [VERIFICATION_LIFE_ID],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO app_state (singleton, current_life_id) VALUES (1, ?1)",
                [VERIFICATION_LIFE_ID],
            )
            .unwrap();
    }

    fn schema_twenty_four_connection_with_current_life() -> (Connection, &'static str) {
        let mut connection = schema_twenty_three_connection();
        apply_perception_authority_upgrade(&mut connection);
        seed_verification_life(&connection);
        (connection, VERIFICATION_LIFE_ID)
    }

    fn schema_twenty_five_connection_with_current_life() -> (Connection, &'static str) {
        let (mut connection, life_id) = schema_twenty_four_connection_with_current_life();
        apply_body_package_authority_upgrade(&mut connection);
        (connection, life_id)
    }

    fn apply_live2d_core_authority_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_live2d_core_schema_upgrade(&transaction).unwrap(),
            Live2DCoreAuthoritySchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn schema_twenty_six_connection_with_current_life() -> (Connection, &'static str) {
        let (mut connection, life_id) = schema_twenty_five_connection_with_current_life();
        apply_live2d_core_authority_upgrade(&mut connection);
        (connection, life_id)
    }

    fn weaken_perception_policy_guard(connection: &Connection) {
        connection
            .execute_batch(
                "DROP TRIGGER life_perception_policy_immutable_guard;
                 CREATE TRIGGER life_perception_policy_immutable_guard
                 BEFORE UPDATE ON life_perception_policy
                 WHEN digital_life_writer_epoch() IS 1
                  AND NEW.life_id IS NOT OLD.life_id
                 BEGIN
                     SELECT RAISE(ROLLBACK, 'LIFE_PERCEPTION_POLICY_IMMUTABLE');
                 END;",
            )
            .unwrap();
    }

    fn schema_nineteen_connection() -> Connection {
        let mut connection = schema_eighteen_connection();
        apply_emotion_authority_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            EMOTION_AUTHORITY_SCHEMA_VERSION
        );
        connection
    }

    fn schema_twenty_connection() -> Connection {
        let mut connection = schema_nineteen_connection();
        apply_relationship_authority_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            RELATIONSHIP_AUTHORITY_SCHEMA_VERSION
        );
        connection
    }

    fn seed_lives_at_schema_eighteen(connection: &Connection) -> i64 {
        // Lives are inserted before Schema 19 exists, so no initializer
        // trigger or emotion writer fence is involved yet.
        connection
            .execute(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES ('persona-a', 'Persona', 1, '{}')",
                [],
            )
            .unwrap();
        for (id, name) in [
            ("life-a", "Life A"),
            ("life-b", "Life B"),
            ("life-c", "Life C"),
        ] {
            connection
                .execute(
                    "INSERT INTO life_identity
                 (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES
                 (?1, ?2, '2026-08-23T00:00:00.000Z', 1, ?3, 'persona-a', 1)",
                    rusqlite::params![id, name, format!("body-{id}")],
                )
                .unwrap();
        }
        3
    }

    #[test]
    fn migration_018_schema_seventeen_to_eighteen_is_atomic_and_preserves_c_snapshot_schema() {
        let mut connection = schema_seventeen_connection();
        let c_snapshot_sql: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_rebuild_item'",
            [], |row| row.get(0),
        ).unwrap();
        apply_generation_catchup_attempt_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            GENERATION_CATCHUP_ATTEMPT_SCHEMA_VERSION
        );
        validate_generation_catchup_attempt_schema(&connection).unwrap();
        let table_exists: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_rebuild_catchup_item'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(table_exists, 1);
        let c_snapshot_after: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_rebuild_item'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(c_snapshot_after, c_snapshot_sql);
        assert_eq!(
            writer_fence_manifest::generation_catchup_writer_fence_trigger_specs().len(),
            3
        );
        writer_fence_manifest::validate_writer_fence_manifest_for_schema(
            &connection,
            GENERATION_CATCHUP_ATTEMPT_SCHEMA_VERSION,
        )
        .unwrap();
        let writer_fence_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='trigger' AND name GLOB 'digital_life_writer_epoch_*'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(writer_fence_count, 45);
    }

    #[test]
    fn migration_019_schema_eighteen_to_nineteen_is_atomic_and_preserves_schema_eighteen() {
        let mut connection = schema_eighteen_connection();
        let catchup_table_sql: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_rebuild_catchup_item'",
            [], |row| row.get(0),
        ).unwrap();
        apply_emotion_authority_upgrade(&mut connection);

        assert_eq!(
            schema_version(&connection),
            EMOTION_AUTHORITY_SCHEMA_VERSION
        );
        validate_emotion_authority_schema(&connection).unwrap();
        for table in ["emotion_state", "emotion_event"] {
            let exists: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1);
        }
        let version_name: String = connection
            .query_row(
                "SELECT name FROM schema_migration WHERE version=?1",
                [EMOTION_AUTHORITY_SCHEMA_VERSION],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version_name, EMOTION_AUTHORITY_MIGRATION_NAME);
        // The Schema 18 catch-up table DDL is byte-for-byte unchanged.
        let catchup_after: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_rebuild_catchup_item'",
                [], |row| row.get(0),
            )
            .unwrap();
        assert_eq!(catchup_after, catchup_table_sql);
        assert_eq!(
            writer_fence_manifest::emotion_writer_fence_trigger_specs().len(),
            6
        );
        // Exactly 18 + 6 + 18 + 3 + 6 = 51 writer fences.
        let writer_fence_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='trigger' AND name GLOB 'digital_life_writer_epoch_*'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(writer_fence_count, 51);
    }

    #[test]
    fn migration_019_backfills_neutral_state_for_every_existing_life() {
        let mut connection = schema_eighteen_connection();
        let life_count = seed_lives_at_schema_eighteen(&connection);
        assert_eq!(life_count, 3);
        assert_eq!(
            schema_version(&connection),
            GENERATION_CATCHUP_ATTEMPT_SCHEMA_VERSION
        );

        apply_emotion_authority_upgrade(&mut connection);

        let state_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM emotion_state", [], |row| row.get(0))
            .unwrap();
        assert_eq!(state_count, life_count);
        let neutral_invariants: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM emotion_state
                 WHERE valence <> 0 OR activation <> 0 OR revision <> 0
                    OR policy_version <> 1 OR last_applied_at = '' OR updated_at = ''",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(neutral_invariants, 0);
        let life_mapping: Vec<(String, String)> = connection
            .prepare("SELECT l.id, s.life_id FROM life_identity l LEFT JOIN emotion_state s ON s.life_id=l.id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(life_mapping.len(), 3);
        for (life_id, state_life_id) in life_mapping {
            assert_eq!(life_id, state_life_id);
        }
    }

    #[test]
    fn migration_019_initializer_creates_exactly_one_neutral_row_per_new_life() {
        let mut connection = schema_eighteen_connection();
        apply_emotion_authority_upgrade(&mut connection);
        connection
            .execute(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES ('persona-a', 'Persona', 1, '{}')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO life_identity
                 (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES ('life-new', 'Life New', '2026-08-23T00:00:00.000Z', 1,
                         'body', 'persona-a', 1)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO life_identity
                 (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES ('life-newer', 'Life Newer', '2026-08-23T00:00:00.000Z', 1,
                         'body', 'persona-a', 1)",
                [],
            )
            .unwrap();

        let state_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM emotion_state", [], |row| row.get(0))
            .unwrap();
        assert_eq!(state_count, 2);
        for life_id in ["life-new", "life-newer"] {
            let (valence, activation, revision, policy_version): (i64, i64, i64, i64) = connection
                .query_row(
                    "SELECT valence, activation, revision, policy_version
                     FROM emotion_state WHERE life_id=?1",
                    [life_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            assert_eq!(
                (valence, activation, revision, policy_version),
                (0, 0, 0, 1)
            );
        }
        // An UPSERT that only updates an existing life must not create a
        // second state row (AFTER INSERT triggers fire only on the insert arm).
        connection
            .execute(
                "INSERT INTO life_identity
                 (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES ('life-new', 'Life New renamed', '2026-08-23T00:00:00.000Z', 2,
                         'body', 'persona-a', 1)
                 ON CONFLICT(id) DO UPDATE SET version = excluded.version",
                [],
            )
            .unwrap();
        let state_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM emotion_state", [], |row| row.get(0))
            .unwrap();
        assert_eq!(state_count, 2);
    }

    #[test]
    fn migration_019_missing_initializer_trigger_fails_validation_without_repair() {
        let mut connection = schema_eighteen_connection();
        apply_emotion_authority_upgrade(&mut connection);
        connection
            .execute_batch("DROP TRIGGER emotion_state_life_insert_initializer")
            .unwrap();

        let error = validate_emotion_authority_schema(&connection).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        let remaining: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='trigger' AND name='emotion_state_life_insert_initializer'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn migration_019_failpoints_roll_back_to_exact_schema_eighteen_preimage() {
        for point in [
            Migration019Failpoint::AfterStateTable,
            Migration019Failpoint::AfterEventTable,
            Migration019Failpoint::AfterBackfill,
            Migration019Failpoint::AfterInitializerTrigger,
            Migration019Failpoint::AfterWriterFences,
            Migration019Failpoint::BeforeSchemaVersion,
            Migration019Failpoint::PreCommit,
        ] {
            let mut connection = schema_eighteen_connection();
            fail_next_migration_019_at_for_test(point);
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_emotion_authority_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");

            // Each failpoint fires after its own durable boundary has been
            // reached inside the caller-owned transaction.
            let state_exists: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='emotion_state'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let event_exists: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='emotion_event'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let emotion_fence_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND name LIKE 'digital_life_writer_epoch_emotion_%'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            match point {
                Migration019Failpoint::AfterStateTable => {
                    assert_eq!(state_exists, 1);
                    assert_eq!(event_exists, 0);
                    assert_eq!(emotion_fence_count, 0);
                }
                Migration019Failpoint::AfterEventTable => {
                    assert_eq!(state_exists, 1);
                    assert_eq!(event_exists, 1);
                    assert_eq!(emotion_fence_count, 0);
                }
                Migration019Failpoint::AfterBackfill
                | Migration019Failpoint::AfterInitializerTrigger => {
                    assert_eq!(emotion_fence_count, 0);
                }
                Migration019Failpoint::AfterWriterFences => {
                    assert_eq!(emotion_fence_count, 6);
                }
                Migration019Failpoint::BeforeSchemaVersion | Migration019Failpoint::PreCommit => {
                    assert_eq!(emotion_fence_count, 6);
                }
            }
            drop(transaction);

            // The committed preimage is exactly Schema 18 again.
            assert_eq!(
                schema_version(&connection),
                GENERATION_CATCHUP_ATTEMPT_SCHEMA_VERSION
            );
            validate_generation_catchup_attempt_schema(&connection).unwrap();
            let emotion_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name IN ('emotion_state', 'emotion_event')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(emotion_count, 0);
            let writer_fence_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='trigger' AND name GLOB 'digital_life_writer_epoch_*'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(writer_fence_count, 45);
        }
    }

    #[test]
    fn migration_019_backfill_rolls_back_with_lives_when_validation_fails() {
        let mut connection = schema_eighteen_connection();
        seed_lives_at_schema_eighteen(&connection);
        let preimage = schema_version(&connection);

        // AfterBackfill fails only after the backfill rows exist inside the
        // transaction; the rollback must remove them with the whole upgrade.
        fail_next_migration_019_at_for_test(Migration019Failpoint::AfterBackfill);
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_emotion_authority_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        drop(transaction);

        assert_eq!(schema_version(&connection), preimage);
        let missing: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('emotion_state','emotion_event')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(missing, 0);
        // The seeded lives themselves are untouched by the failed upgrade.
        let life_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM life_identity", [], |row| row.get(0))
            .unwrap();
        assert_eq!(life_count, 3);
    }

    #[test]
    fn migration_020_schema_nineteen_to_twenty_is_atomic_and_preserves_schema_nineteen() {
        let mut connection = schema_nineteen_connection();
        let emotion_state_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='emotion_state'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let emotion_event_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='emotion_event'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        apply_relationship_authority_upgrade(&mut connection);

        assert_eq!(
            schema_version(&connection),
            RELATIONSHIP_AUTHORITY_SCHEMA_VERSION
        );
        validate_relationship_authority_schema(&connection).unwrap();
        for table in ["relationship_state", "relationship_event"] {
            let exists: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1);
        }
        let version_name: String = connection
            .query_row(
                "SELECT name FROM schema_migration WHERE version=?1",
                [RELATIONSHIP_AUTHORITY_SCHEMA_VERSION],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version_name, RELATIONSHIP_AUTHORITY_MIGRATION_NAME);
        // The Schema 19 emotion authority DDL is byte-for-byte unchanged.
        let emotion_state_after: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='emotion_state'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(emotion_state_after, emotion_state_sql);
        let emotion_event_after: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='emotion_event'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(emotion_event_after, emotion_event_sql);
        assert_eq!(
            writer_fence_manifest::relationship_writer_fence_trigger_specs().len(),
            6
        );
        // Exactly 18 + 6 + 18 + 3 + 6 + 6 = 57 writer fences.
        let writer_fence_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='trigger' AND name GLOB 'digital_life_writer_epoch_*'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(writer_fence_count, 57);
    }

    #[test]
    fn migration_020_backfills_neutral_primary_user_state_for_every_existing_life() {
        let mut connection = schema_nineteen_connection();
        seed_lives_at_schema_eighteen(&connection);
        assert_eq!(
            schema_version(&connection),
            EMOTION_AUTHORITY_SCHEMA_VERSION
        );

        apply_relationship_authority_upgrade(&mut connection);

        let state_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM relationship_state", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(state_count, 3);
        let neutral_invariants: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM relationship_state
                 WHERE subject_id <> 'primary_user'
                    OR familiarity <> 0 OR trust <> 0 OR emotional_closeness <> 0
                    OR collaboration <> 0 OR safety <> 0 OR dependency_tendency <> 0
                    OR boundary_comfort <> 0 OR tension <> 0
                    OR revision <> 0 OR policy_version <> 1
                    OR last_applied_at = '' OR updated_at = ''",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(neutral_invariants, 0);
        let life_mapping: Vec<(String, String)> = connection
            .prepare(
                "SELECT l.id, s.life_id FROM life_identity l
                  LEFT JOIN relationship_state s
                    ON s.life_id=l.id AND s.subject_id='primary_user'",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(life_mapping.len(), 3);
        for (life_id, state_life_id) in life_mapping {
            assert_eq!(life_id, state_life_id);
        }
    }

    #[test]
    fn migration_020_initializer_creates_exactly_one_neutral_primary_user_row_per_new_life() {
        let mut connection = schema_nineteen_connection();
        apply_relationship_authority_upgrade(&mut connection);
        connection
            .execute(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES ('persona-a', 'Persona', 1, '{}')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO life_identity
                 (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES ('life-new', 'Life New', '2026-08-25T00:00:00.000Z', 1,
                         'body', 'persona-a', 1)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO life_identity
                 (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES ('life-newer', 'Life Newer', '2026-08-25T00:00:00.000Z', 1,
                         'body', 'persona-a', 1)",
                [],
            )
            .unwrap();

        let state_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM relationship_state", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(state_count, 2);
        for life_id in ["life-new", "life-newer"] {
            let (subject_id, revision, policy_version): (String, i64, i64) = connection
                .query_row(
                    "SELECT subject_id, revision, policy_version
                     FROM relationship_state WHERE life_id=?1",
                    [life_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(subject_id, "primary_user");
            assert_eq!((revision, policy_version), (0, 1));
        }
        // An UPSERT that only updates an existing life must not create a
        // second state row (AFTER INSERT triggers fire only on the insert arm).
        connection
            .execute(
                "INSERT INTO life_identity
                 (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES ('life-new', 'Life New renamed', '2026-08-25T00:00:00.000Z', 2,
                         'body', 'persona-a', 1)
                 ON CONFLICT(id) DO UPDATE SET version = excluded.version",
                [],
            )
            .unwrap();
        let state_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM relationship_state", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(state_count, 2);
    }

    #[test]
    fn migration_020_missing_initializer_trigger_fails_validation_without_repair() {
        let mut connection = schema_nineteen_connection();
        apply_relationship_authority_upgrade(&mut connection);
        connection
            .execute_batch("DROP TRIGGER relationship_state_life_insert_initializer")
            .unwrap();

        let error = validate_relationship_authority_schema(&connection).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        let remaining: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='trigger' AND name='relationship_state_life_insert_initializer'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn migration_020_tables_enforce_frozen_domains_keys_and_uniqueness() {
        let mut connection = schema_nineteen_connection();
        apply_relationship_authority_upgrade(&mut connection);
        connection
            .execute(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES ('persona-a', 'Persona', 1, '{}')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO life_identity
                 (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES ('probe-life', 'Probe', '2026-08-25T00:00:00.000Z', 1,
                         'body', 'persona-a', 1)",
                [],
            )
            .unwrap();

        let base_state_insert = |familiarity: i32| {
            connection.execute(
                "INSERT INTO relationship_state
                 (life_id, subject_id, familiarity, trust, emotional_closeness,
                  collaboration, safety, dependency_tendency, boundary_comfort, tension,
                  revision, policy_version, last_applied_at, updated_at)
                 VALUES ('probe-life', 'second-subject', ?1, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                         '2026-08-25T11:00:00.000Z', '2026-08-25T11:00:00.000Z')",
                [familiarity],
            )
        };
        for out_of_range in [-1_i32, 1001] {
            assert!(
                base_state_insert(out_of_range).is_err(),
                "state familiarity {out_of_range} must violate its CHECK"
            );
        }
        // Composite primary key rejects a duplicate (life_id, subject_id).
        assert!(connection
            .execute(
                "INSERT INTO relationship_state
                     (life_id, subject_id, familiarity, trust, emotional_closeness,
                      collaboration, safety, dependency_tendency, boundary_comfort, tension,
                      revision, policy_version, last_applied_at, updated_at)
                     VALUES ('probe-life', 'primary_user', 5, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                             '2026-08-25T11:00:00.000Z', '2026-08-25T11:00:00.000Z')",
                [],
            )
            .is_err());
        assert!(base_state_insert(0).is_ok());

        // Events cannot attach to a non-existent relationship_state pair.
        let orphan_event = connection.execute(
            "INSERT INTO relationship_event
             (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
              familiarity_delta, trust_delta, emotional_closeness_delta,
              collaboration_delta, safety_delta, dependency_tendency_delta,
              boundary_comfort_delta, tension_delta,
              result_familiarity, result_trust, result_emotional_closeness,
              result_collaboration, result_safety, result_dependency_tendency,
              result_boundary_comfort, result_tension,
              applied_revision, event_time, policy_version, created_at)
             VALUES ('orphan', 'ghost-life', 'primary_user', 'k', 'r', 'policy_reason',
                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                     1, 't', 1, 'c')",
            [],
        );
        assert!(orphan_event.is_err());

        // Both frozen UNIQUE constraints hold.
        let first = connection.execute(
            "INSERT INTO relationship_event
             (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
              familiarity_delta, trust_delta, emotional_closeness_delta,
              collaboration_delta, safety_delta, dependency_tendency_delta,
              boundary_comfort_delta, tension_delta,
              result_familiarity, result_trust, result_emotional_closeness,
              result_collaboration, result_safety, result_dependency_tendency,
              result_boundary_comfort, result_tension,
              applied_revision, event_time, policy_version, created_at)
             VALUES ('ev-1', 'probe-life', 'primary_user', 'kind', 'ref', 'policy_reason',
                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                     1, '2026-08-25T11:00:00.000Z', 1, '2026-08-25T11:00:00.000Z')",
            [],
        );
        assert_eq!(first.unwrap(), 1);
        let same_source = connection.execute(
            "INSERT INTO relationship_event
             (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
              familiarity_delta, trust_delta, emotional_closeness_delta,
              collaboration_delta, safety_delta, dependency_tendency_delta,
              boundary_comfort_delta, tension_delta,
              result_familiarity, result_trust, result_emotional_closeness,
              result_collaboration, result_safety, result_dependency_tendency,
              result_boundary_comfort, result_tension,
              applied_revision, event_time, policy_version, created_at)
             VALUES ('ev-2', 'probe-life', 'primary_user', 'kind', 'ref', 'policy_reason',
                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                     2, '2026-08-25T11:00:00.000Z', 1, '2026-08-25T11:00:00.000Z')",
            [],
        );
        assert!(same_source.is_err(), "duplicate source identity must fail");
        let same_revision = connection.execute(
            "INSERT INTO relationship_event
             (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
              familiarity_delta, trust_delta, emotional_closeness_delta,
              collaboration_delta, safety_delta, dependency_tendency_delta,
              boundary_comfort_delta, tension_delta,
              result_familiarity, result_trust, result_emotional_closeness,
              result_collaboration, result_safety, result_dependency_tendency,
              result_boundary_comfort, result_tension,
              applied_revision, event_time, policy_version, created_at)
             VALUES ('ev-3', 'probe-life', 'primary_user', 'other-kind', 'other-ref',
                     'policy_reason',
                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                     1, '2026-08-25T11:00:00.000Z', 1, '2026-08-25T11:00:00.000Z')",
            [],
        );
        assert!(
            same_revision.is_err(),
            "duplicate applied_revision must fail"
        );

        // The event CHECK constraints reject out-of-domain results and deltas.
        for (column, bad_value) in [
            ("result_trust", 1001),
            ("result_trust", -1001),
            ("trust_delta", -1001),
            ("result_familiarity", -1),
            ("tension_delta", 1001),
        ] {
            let sql = format!(
                "INSERT INTO relationship_event
                 (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
                  familiarity_delta, trust_delta, emotional_closeness_delta,
                  collaboration_delta, safety_delta, dependency_tendency_delta,
                  boundary_comfort_delta, tension_delta,
                  result_familiarity, result_trust, result_emotional_closeness,
                  result_collaboration, result_safety, result_dependency_tendency,
                  result_boundary_comfort, result_tension,
                  applied_revision, event_time, policy_version, created_at)
                 SELECT 'bad-{column}-{bad_value}', 'probe-life', 'primary_user',
                        'kind', 'ref-bad', 'policy_reason',
                        0, 0, 0, 0, 0, 0, 0, 0,
                        CASE WHEN '{column}'='result_familiarity' THEN {bad_value} ELSE 0 END,
                        CASE WHEN '{column}'='result_trust' THEN {bad_value} ELSE 0 END,
                        0, 0, 0, 0, 0, 0,
                        CASE WHEN '{column}'='trust_delta' THEN {bad_value}
                             WHEN '{column}'='tension_delta' THEN 0 ELSE 1 END,
                        '2026-08-25T11:00:00.000Z', 1, '2026-08-25T11:00:00.000Z'"
            );
            // Deltas are inserted positionally above; fix tension_delta too.
            let sql = sql.replace(
                &format!("CASE WHEN '{column}'='tension_delta' THEN 0 ELSE 1 END"),
                &format!(
                    "CASE WHEN '{column}'='tension_delta' THEN {bad_value}
                          WHEN '{column}'='trust_delta' THEN 0 ELSE 1 END"
                ),
            );
            assert!(
                connection.execute(&sql, []).is_err(),
                "{column}={bad_value} must violate its CHECK"
            );
        }
    }

    #[test]
    fn migration_030_is_present_thirty_is_current_and_thirty_one_is_absent() {
        assert_eq!(
            super::super::connection::MAX_SUPPORTED_SCHEMA_VERSION,
            CAPABILITY_AUTHORIZATION_SCHEMA_VERSION
        );
        let migrations_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/storage/migrations");
        let entries = std::fs::read_dir(&migrations_dir).unwrap();
        let mut highest = 0;
        for entry in entries {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            let digits: String = name
                .chars()
                .take_while(|character| character.is_ascii_digit())
                .collect();
            if let Ok(version) = digits.parse::<i64>() {
                highest = highest.max(version);
            }
        }
        assert_eq!(highest, 30, "Migration 030 must be the current migration");
        let names = std::fs::read_dir(&migrations_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for version in [
            "022", "023", "024", "025", "026", "027", "028", "029", "030",
        ] {
            assert!(
                names.iter().any(|name| name.starts_with(version)),
                "Migration {version} must exist"
            );
        }
        assert!(
            !names.iter().any(|name| name.starts_with("031")),
            "Migration 031 must not exist"
        );
    }

    #[test]
    fn migration_021_fresh_database_reaches_schema_twenty_one_without_backfill() {
        let mut connection = schema_twenty_connection();
        apply_experience_episode_upgrade(&mut connection);

        assert_eq!(
            schema_version(&connection),
            EXPERIENCE_EPISODE_SCHEMA_VERSION
        );
        validate_experience_episode_schema(&connection).unwrap();
        let episode_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM experience_episode", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(episode_count, 0);
        assert_eq!(writer_fence_count(&connection), 60);
        let migration_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migration WHERE version = ?1",
                [EXPERIENCE_EPISODE_SCHEMA_VERSION],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migration_count, 1);

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_experience_episode_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        drop(transaction);
        assert_eq!(
            schema_version(&connection),
            EXPERIENCE_EPISODE_SCHEMA_VERSION
        );
    }

    #[test]
    fn migration_021_schema_twenty_upgrade_preserves_populated_conversation_without_episodes() {
        let mut connection = schema_twenty_connection();
        seed_lives_at_schema_eighteen(&connection);
        connection
            .execute_batch(
                "INSERT INTO conversation
                     (id, life_id, title, revision, created_at, updated_at, last_message_at)
                 VALUES ('migration-conversation', 'life-a', 'Migration Conversation', 1,
                         '2026-08-26T00:00:00.000Z', '2026-08-26T00:00:00.002Z',
                         '2026-08-26T00:00:00.002Z');
                 INSERT INTO conversation_message
                     (id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at)
                 VALUES
                     ('migration-user-message', 'migration-conversation', 'life-a',
                      'migration-turn', 'user', 'historical user content', 1,
                      '2026-08-26T00:00:00.001Z'),
                     ('migration-assistant-message', 'migration-conversation', 'life-a',
                      'migration-turn', 'assistant', 'historical assistant content', 2,
                      '2026-08-26T00:00:00.002Z');",
            )
            .unwrap();

        apply_experience_episode_upgrade(&mut connection);

        assert_eq!(
            schema_version(&connection),
            EXPERIENCE_EPISODE_SCHEMA_VERSION
        );
        let episode_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM experience_episode", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(episode_count, 0);
        let message_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM conversation_message WHERE conversation_id = 'migration-conversation'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(message_count, 2);
        validate_experience_episode_schema(&connection).unwrap();
    }

    #[test]
    fn migration_021_failure_points_roll_back_to_exact_schema_twenty_preimage() {
        for point in [
            Migration021Failpoint::AfterTable,
            Migration021Failpoint::AfterSemanticGuards,
            Migration021Failpoint::AfterWriterFences,
            Migration021Failpoint::BeforeSchemaVersion,
            Migration021Failpoint::PreCommit,
        ] {
            let mut connection = schema_twenty_connection();
            fail_next_migration_021_at_for_test(point);
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_experience_episode_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");

            let table_exists: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'table' AND name = 'experience_episode'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let semantic_guard_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'trigger'
                       AND name IN ('experience_episode_source_binding_guard',
                                    'experience_episode_immutable_guard')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let episode_fence_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'trigger'
                       AND name GLOB 'digital_life_writer_epoch_experience_episode_*'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            match point {
                Migration021Failpoint::AfterTable => {
                    assert_eq!(table_exists, 1);
                    assert_eq!(semantic_guard_count, 0);
                    assert_eq!(episode_fence_count, 0);
                }
                Migration021Failpoint::AfterSemanticGuards => {
                    assert_eq!(table_exists, 1);
                    assert_eq!(semantic_guard_count, 2);
                    assert_eq!(episode_fence_count, 0);
                }
                Migration021Failpoint::AfterWriterFences
                | Migration021Failpoint::BeforeSchemaVersion
                | Migration021Failpoint::PreCommit => {
                    assert_eq!(table_exists, 1);
                    assert_eq!(semantic_guard_count, 2);
                    assert_eq!(episode_fence_count, 3);
                }
            }
            drop(transaction);

            assert_eq!(
                schema_version(&connection),
                RELATIONSHIP_AUTHORITY_SCHEMA_VERSION
            );
            validate_relationship_authority_schema(&connection).unwrap();
            assert_eq!(writer_fence_count(&connection), 57);
            let remaining_episode_objects: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'experience_episode%'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(remaining_episode_objects, 0);
            let migration_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version = ?1",
                    [EXPERIENCE_EPISODE_SCHEMA_VERSION],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(migration_count, 0);
        }
    }

    #[test]
    fn schema_twenty_and_schema_twenty_one_writer_fences_both_reopen_exactly() {
        let schema_twenty = schema_twenty_connection();
        writer_fence_manifest::validate_writer_fence_manifest_for_schema(
            &schema_twenty,
            RELATIONSHIP_AUTHORITY_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&schema_twenty), 57);

        let mut schema_twenty_one = schema_twenty_connection();
        apply_experience_episode_upgrade(&mut schema_twenty_one);
        writer_fence_manifest::validate_writer_fence_manifest_for_schema(
            &schema_twenty_one,
            EXPERIENCE_EPISODE_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&schema_twenty_one), 60);
        validate_emotion_authority_schema(&schema_twenty_one).unwrap();
        validate_relationship_authority_schema(&schema_twenty_one).unwrap();
    }

    #[test]
    fn migration_020_failpoints_roll_back_to_exact_schema_nineteen_preimage() {
        for point in [
            Migration020Failpoint::AfterStateTable,
            Migration020Failpoint::AfterEventTable,
            Migration020Failpoint::AfterBackfill,
            Migration020Failpoint::AfterInitializerTrigger,
            Migration020Failpoint::AfterWriterFences,
            Migration020Failpoint::BeforeSchemaVersion,
            Migration020Failpoint::PreCommit,
        ] {
            let mut connection = schema_nineteen_connection();
            fail_next_migration_020_at_for_test(point);
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_relationship_authority_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");

            // Each failpoint fires after its own durable boundary has been
            // reached inside the caller-owned transaction.
            let state_exists: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='table' AND name='relationship_state'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let event_exists: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='table' AND name='relationship_event'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let initializer_exists: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='trigger'
                       AND name='relationship_state_life_insert_initializer'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let relationship_fence_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='trigger'
                       AND name LIKE 'digital_life_writer_epoch_relationship_%'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            match point {
                Migration020Failpoint::AfterStateTable => {
                    assert_eq!(state_exists, 1);
                    assert_eq!(event_exists, 0);
                    assert_eq!(initializer_exists, 0);
                    assert_eq!(relationship_fence_count, 0);
                }
                Migration020Failpoint::AfterEventTable => {
                    assert_eq!(state_exists, 1);
                    assert_eq!(event_exists, 1);
                    assert_eq!(initializer_exists, 0);
                    assert_eq!(relationship_fence_count, 0);
                }
                Migration020Failpoint::AfterBackfill => {
                    assert_eq!(initializer_exists, 0);
                    assert_eq!(relationship_fence_count, 0);
                }
                Migration020Failpoint::AfterInitializerTrigger => {
                    assert_eq!(initializer_exists, 1);
                    assert_eq!(relationship_fence_count, 0);
                }
                Migration020Failpoint::AfterWriterFences => {
                    assert_eq!(initializer_exists, 1);
                    assert_eq!(relationship_fence_count, 6);
                }
                Migration020Failpoint::BeforeSchemaVersion | Migration020Failpoint::PreCommit => {
                    assert_eq!(initializer_exists, 1);
                    assert_eq!(relationship_fence_count, 6);
                }
            }
            drop(transaction);

            // The committed preimage is exactly Schema 19 again.
            assert_eq!(
                schema_version(&connection),
                EMOTION_AUTHORITY_SCHEMA_VERSION
            );
            validate_emotion_authority_schema(&connection).unwrap();
            let relationship_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name LIKE 'relationship_%'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(relationship_count, 0);
            let writer_fence_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='trigger' AND name GLOB 'digital_life_writer_epoch_*'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(writer_fence_count, 51);
        }
    }

    #[test]
    fn migration_022_schema_twenty_one_to_twenty_two_with_zero_historical_backfill() {
        let mut connection = schema_twenty_one_connection();
        seed_lives_at_schema_eighteen(&connection);
        connection
            .execute_batch(
                "INSERT INTO conversation
                     (id, life_id, title, revision, created_at, updated_at, last_message_at)
                 VALUES ('migration-022-conversation', 'life-a', 'D14 Conversation', 1,
                         '2026-08-27T00:00:00.000Z', '2026-08-27T00:00:00.002Z',
                         '2026-08-27T00:00:00.002Z');
                 INSERT INTO conversation_message
                     (id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at)
                 VALUES
                     ('migration-022-user-message', 'migration-022-conversation', 'life-a',
                      'migration-022-turn', 'user', 'historical user content', 1,
                      '2026-08-27T00:00:00.001Z'),
                     ('migration-022-assistant-message', 'migration-022-conversation', 'life-a',
                      'migration-022-turn', 'assistant', 'historical assistant content', 2,
                      '2026-08-27T00:00:00.002Z');",
            )
            .unwrap();

        apply_life_intent_authority_upgrade(&mut connection);

        assert_eq!(
            schema_version(&connection),
            LIFE_INTENT_AUTHORITY_SCHEMA_VERSION
        );
        validate_life_intent_schema(&connection).unwrap();
        validate_experience_episode_schema(&connection).unwrap();
        for table in [
            "life_goal",
            "life_plan",
            "life_plan_step",
            "life_action_intent",
            "life_intent_event",
        ] {
            let row_count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(row_count, 0, "Migration022 must synthesize no {table} rows");
        }
        let life_rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM life_identity", [], |row| row.get(0))
            .unwrap();
        assert_eq!(life_rows, 3, "existing lives remain unchanged");
        let message_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM conversation_message WHERE conversation_id = 'migration-022-conversation'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            message_count, 2,
            "existing conversation rows remain unchanged"
        );
        assert_eq!(writer_fence_count(&connection), 75);
        let migration_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migration WHERE version = ?1",
                [LIFE_INTENT_AUTHORITY_SCHEMA_VERSION],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migration_count, 1);

        // Migration022 can never apply twice.
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_life_intent_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        drop(transaction);
        assert_eq!(
            schema_version(&connection),
            LIFE_INTENT_AUTHORITY_SCHEMA_VERSION
        );
    }

    #[test]
    fn migration_022_failure_points_roll_back_to_exact_schema_twenty_one_preimage() {
        for point in [
            Migration022Failpoint::AfterTable,
            Migration022Failpoint::AfterSemanticGuards,
            Migration022Failpoint::AfterWriterFences,
            Migration022Failpoint::BeforeSchemaVersion,
            Migration022Failpoint::PreCommit,
        ] {
            let mut connection = schema_twenty_one_connection();
            fail_next_migration_022_at_for_test(point);
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_life_intent_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");

            let table_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'table'
                       AND name IN ('life_goal','life_plan','life_plan_step',
                                    'life_action_intent','life_intent_event')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let guard_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'trigger'
                       AND name IN ('life_goal_immutable_guard','life_plan_immutable_guard',
                                    'life_plan_step_immutable_guard',
                                    'life_action_intent_immutable_guard',
                                    'life_intent_event_immutable_guard')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let life_intent_fence_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'trigger'
                       AND name GLOB 'digital_life_writer_epoch_life_*'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            match point {
                Migration022Failpoint::AfterTable => {
                    assert_eq!(table_count, 5);
                    assert_eq!(guard_count, 0);
                    assert_eq!(life_intent_fence_count, 0);
                }
                Migration022Failpoint::AfterSemanticGuards => {
                    assert_eq!(table_count, 5);
                    assert_eq!(guard_count, 5);
                    assert_eq!(life_intent_fence_count, 0);
                }
                Migration022Failpoint::AfterWriterFences
                | Migration022Failpoint::BeforeSchemaVersion
                | Migration022Failpoint::PreCommit => {
                    assert_eq!(table_count, 5);
                    assert_eq!(guard_count, 5);
                    assert_eq!(life_intent_fence_count, 15);
                }
            }
            drop(transaction);

            // The committed preimage is exactly Schema 21 again.
            assert_eq!(
                schema_version(&connection),
                EXPERIENCE_EPISODE_SCHEMA_VERSION
            );
            validate_experience_episode_schema(&connection).unwrap();
            assert_eq!(writer_fence_count(&connection), 60);
            let remaining_objects: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE name LIKE 'life_goal%'
                        OR name LIKE 'life_plan%'
                        OR name LIKE 'life_action_intent%'
                        OR name LIKE 'life_intent_event%'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(remaining_objects, 0);
            let migration_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version = ?1",
                    [LIFE_INTENT_AUTHORITY_SCHEMA_VERSION],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(migration_count, 0);
        }
    }

    #[test]
    fn migration_023_creates_four_tables_once_without_historical_backfill() {
        let mut connection = schema_twenty_two_connection();
        connection
            .execute_batch(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES ('migration-023-persona', 'Persona', 1, '{}');
                 INSERT INTO life_identity
                     (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES ('migration-023-life', 'Life', '2026-08-27T00:00:00.000Z', 1,
                         'migration-023-body', 'migration-023-persona', 1);
                 INSERT INTO life_goal
                     (goal_id, life_id, title, objective, status, revision,
                      created_by_kind, created_at, updated_at, closed_at, goal_version)
                 VALUES ('migration-023-goal', 'migration-023-life', 'Goal', 'Objective',
                         'active', 1, 'user_explicit', '2026-08-27T00:00:00.000Z',
                         '2026-08-27T00:00:00.000Z', NULL, 1);",
            )
            .unwrap();

        apply_autonomy_authority_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            AUTONOMY_AUTHORITY_SCHEMA_VERSION
        );
        validate_autonomy_schema(&connection).unwrap();
        assert_eq!(writer_fence_count(&connection), 87);
        for table in [
            "life_autonomy_policy",
            "life_autonomy_policy_event",
            "life_proactive_intent",
            "life_proactive_intent_event",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "Migration023 must synthesize no {table} rows");
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM life_identity WHERE id='migration-023-life'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM life_goal WHERE goal_id='migration-023-goal'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version=?1",
                    [AUTONOMY_AUTHORITY_SCHEMA_VERSION],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version=24",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_autonomy_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        drop(transaction);
        assert_eq!(writer_fence_count(&connection), 87);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version=?1",
                    [AUTONOMY_AUTHORITY_SCHEMA_VERSION],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn migration_023_failure_points_roll_back_to_exact_schema_twenty_two_preimage() {
        let d15_trigger_names = [
            "digital_life_writer_epoch_life_autonomy_policy_insert",
            "digital_life_writer_epoch_life_autonomy_policy_update",
            "digital_life_writer_epoch_life_autonomy_policy_delete",
            "digital_life_writer_epoch_life_autonomy_policy_event_insert",
            "digital_life_writer_epoch_life_autonomy_policy_event_update",
            "digital_life_writer_epoch_life_autonomy_policy_event_delete",
            "digital_life_writer_epoch_life_proactive_intent_insert",
            "digital_life_writer_epoch_life_proactive_intent_update",
            "digital_life_writer_epoch_life_proactive_intent_delete",
            "digital_life_writer_epoch_life_proactive_intent_event_insert",
            "digital_life_writer_epoch_life_proactive_intent_event_update",
            "digital_life_writer_epoch_life_proactive_intent_event_delete",
        ];
        for point in [
            Migration023Failpoint::AfterTable,
            Migration023Failpoint::AfterSemanticGuards,
            Migration023Failpoint::AfterWriterFences,
            Migration023Failpoint::BeforeSchemaVersion,
            Migration023Failpoint::PreCommit,
        ] {
            let mut connection = schema_twenty_two_connection();
            fail_next_migration_023_at_for_test(point);
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_autonomy_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");

            let table_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='table' AND name IN
                       ('life_autonomy_policy','life_autonomy_policy_event',
                        'life_proactive_intent','life_proactive_intent_event')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let guard_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='trigger' AND name IN
                       ('life_autonomy_policy_immutable_guard',
                        'life_autonomy_policy_event_immutable_guard',
                        'life_proactive_intent_immutable_guard',
                        'life_proactive_intent_event_immutable_guard')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let fence_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='trigger' AND name IN
                       ('digital_life_writer_epoch_life_autonomy_policy_insert',
                        'digital_life_writer_epoch_life_autonomy_policy_update',
                        'digital_life_writer_epoch_life_autonomy_policy_delete',
                        'digital_life_writer_epoch_life_autonomy_policy_event_insert',
                        'digital_life_writer_epoch_life_autonomy_policy_event_update',
                        'digital_life_writer_epoch_life_autonomy_policy_event_delete',
                        'digital_life_writer_epoch_life_proactive_intent_insert',
                        'digital_life_writer_epoch_life_proactive_intent_update',
                        'digital_life_writer_epoch_life_proactive_intent_delete',
                        'digital_life_writer_epoch_life_proactive_intent_event_insert',
                        'digital_life_writer_epoch_life_proactive_intent_event_update',
                        'digital_life_writer_epoch_life_proactive_intent_event_delete')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            match point {
                Migration023Failpoint::AfterTable => {
                    assert_eq!(table_count, 4);
                    assert_eq!(guard_count, 0);
                    assert_eq!(fence_count, 0);
                }
                Migration023Failpoint::AfterSemanticGuards => {
                    assert_eq!(table_count, 4);
                    assert_eq!(guard_count, 4);
                    assert_eq!(fence_count, 0);
                }
                Migration023Failpoint::AfterWriterFences
                | Migration023Failpoint::BeforeSchemaVersion
                | Migration023Failpoint::PreCommit => {
                    assert_eq!(table_count, 4);
                    assert_eq!(guard_count, 4);
                    assert_eq!(fence_count, 12);
                }
            }
            drop(transaction);

            assert_eq!(
                schema_version(&connection),
                LIFE_INTENT_AUTHORITY_SCHEMA_VERSION
            );
            validate_life_intent_schema(&connection).unwrap();
            writer_fence_manifest::validate_writer_fence_manifest_for_schema(
                &connection,
                LIFE_INTENT_AUTHORITY_SCHEMA_VERSION,
            )
            .unwrap();
            assert_eq!(writer_fence_count(&connection), 75);
            for name in d15_trigger_names.iter() {
                let count: i64 = connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema WHERE name=?1",
                        [name],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap();
                assert_eq!(count, 0, "failed Migration023 must remove {name}");
            }
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM schema_migration WHERE version=?1",
                        [AUTONOMY_AUTHORITY_SCHEMA_VERSION],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn migration_024_creates_two_consent_tables_once_without_backfill() {
        let mut connection = schema_twenty_three_connection();
        connection
            .execute_batch(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES ('migration-024-persona', 'Persona', 1, '{}');
                 INSERT INTO life_identity
                     (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES ('migration-024-life', 'Life', '2026-08-27T00:00:00.000Z', 1,
                         'migration-024-body', 'migration-024-persona', 1);",
            )
            .unwrap();

        apply_perception_authority_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            PERCEPTION_AUTHORITY_SCHEMA_VERSION
        );
        validate_perception_schema(&connection).unwrap();
        assert_eq!(writer_fence_count(&connection), 93);
        for table in ["life_perception_policy", "life_perception_policy_event"] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "Migration024 must synthesize no {table} rows");
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM life_identity WHERE id='migration-024-life'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version=?1",
                    [PERCEPTION_AUTHORITY_SCHEMA_VERSION],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version=25",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_perception_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        drop(transaction);
        assert_eq!(writer_fence_count(&connection), 93);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version=?1",
                    [PERCEPTION_AUTHORITY_SCHEMA_VERSION],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn migration_024_failure_points_roll_back_to_exact_schema_twenty_three_preimage() {
        let new_fence_names = [
            "digital_life_writer_epoch_life_perception_policy_insert",
            "digital_life_writer_epoch_life_perception_policy_update",
            "digital_life_writer_epoch_life_perception_policy_delete",
            "digital_life_writer_epoch_life_perception_policy_event_insert",
            "digital_life_writer_epoch_life_perception_policy_event_update",
            "digital_life_writer_epoch_life_perception_policy_event_delete",
        ];
        for point in [
            Migration024Failpoint::AfterTable,
            Migration024Failpoint::AfterSemanticGuards,
            Migration024Failpoint::AfterWriterFences,
            Migration024Failpoint::BeforeSchemaVersion,
            Migration024Failpoint::PreCommit,
        ] {
            let mut connection = schema_twenty_three_connection();
            fail_next_migration_024_at_for_test(point);
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_perception_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");

            let table_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='table' AND name IN
                       ('life_perception_policy','life_perception_policy_event')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let guard_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='trigger' AND name IN
                       ('life_perception_policy_immutable_guard',
                        'life_perception_policy_event_immutable_guard')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let fence_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='trigger' AND name IN
                       ('digital_life_writer_epoch_life_perception_policy_insert',
                        'digital_life_writer_epoch_life_perception_policy_update',
                        'digital_life_writer_epoch_life_perception_policy_delete',
                        'digital_life_writer_epoch_life_perception_policy_event_insert',
                        'digital_life_writer_epoch_life_perception_policy_event_update',
                        'digital_life_writer_epoch_life_perception_policy_event_delete')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            match point {
                Migration024Failpoint::AfterTable => {
                    assert_eq!(table_count, 2);
                    assert_eq!(guard_count, 0);
                    assert_eq!(fence_count, 0);
                }
                Migration024Failpoint::AfterSemanticGuards => {
                    assert_eq!(table_count, 2);
                    assert_eq!(guard_count, 2);
                    assert_eq!(fence_count, 0);
                }
                Migration024Failpoint::AfterWriterFences
                | Migration024Failpoint::BeforeSchemaVersion
                | Migration024Failpoint::PreCommit => {
                    assert_eq!(table_count, 2);
                    assert_eq!(guard_count, 2);
                    assert_eq!(fence_count, 6);
                }
            }
            drop(transaction);

            assert_eq!(
                schema_version(&connection),
                AUTONOMY_AUTHORITY_SCHEMA_VERSION
            );
            validate_autonomy_schema(&connection).unwrap();
            writer_fence_manifest::validate_writer_fence_manifest_for_schema(
                &connection,
                AUTONOMY_AUTHORITY_SCHEMA_VERSION,
            )
            .unwrap();
            assert_eq!(writer_fence_count(&connection), 87);
            for name in new_fence_names {
                let count: i64 = connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema WHERE name=?1",
                        [name],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap();
                assert_eq!(count, 0, "failed Migration024 must remove {name}");
            }
            for name in [
                "life_perception_policy",
                "life_perception_policy_event",
                "life_perception_policy_immutable_guard",
                "life_perception_policy_event_immutable_guard",
            ] {
                let count: i64 = connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema WHERE name=?1",
                        [name],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap();
                assert_eq!(count, 0, "failed Migration024 must remove {name}");
            }
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM schema_migration WHERE version=?1",
                        [PERCEPTION_AUTHORITY_SCHEMA_VERSION],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn schema_twenty_three_and_schema_twenty_four_reopen_against_their_own_manifests() {
        let schema_twenty_three = schema_twenty_three_connection();
        validate_autonomy_schema(&schema_twenty_three).unwrap();
        writer_fence_manifest::validate_writer_fence_manifest_for_schema(
            &schema_twenty_three,
            AUTONOMY_AUTHORITY_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&schema_twenty_three), 87);
        assert!(validate_perception_schema(&schema_twenty_three).is_err());

        let mut schema_twenty_four = schema_twenty_three_connection();
        apply_perception_authority_upgrade(&mut schema_twenty_four);
        validate_perception_schema(&schema_twenty_four).unwrap();
        writer_fence_manifest::validate_writer_fence_manifest_for_schema(
            &schema_twenty_four,
            PERCEPTION_AUTHORITY_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&schema_twenty_four), 93);
        validate_autonomy_schema(&schema_twenty_four).unwrap();
    }

    #[test]
    fn migration_024_generic_schema_verifiers_reject_a_weakened_perception_guard() {
        let (connection, life_id) = schema_twenty_four_connection_with_current_life();
        weaken_perception_policy_guard(&connection);
        assert_eq!(writer_fence_count(&connection), 93);

        let error = verify_schema_after_upgrade(&connection, PERCEPTION_AUTHORITY_SCHEMA_VERSION)
            .unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        assert_eq!(writer_fence_count(&connection), 93);

        let error =
            verify_database(&connection, PERCEPTION_AUTHORITY_SCHEMA_VERSION, life_id).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        assert_eq!(writer_fence_count(&connection), 93);
    }

    #[test]
    fn migration_024_generic_schema_verifiers_accept_valid_schema_twenty_four() {
        let (connection, life_id) = schema_twenty_four_connection_with_current_life();

        verify_schema_after_upgrade(&connection, PERCEPTION_AUTHORITY_SCHEMA_VERSION).unwrap();
        verify_database(&connection, PERCEPTION_AUTHORITY_SCHEMA_VERSION, life_id).unwrap();
        assert_eq!(writer_fence_count(&connection), 93);
    }

    #[test]
    fn migration_024_generic_schema_verifiers_keep_schema_twenty_three_compatible() {
        let connection = schema_twenty_three_connection();
        seed_verification_life(&connection);

        let perception_object_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE name IN
                   ('life_perception_policy', 'life_perception_policy_event',
                    'life_perception_policy_immutable_guard',
                    'life_perception_policy_event_immutable_guard')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(perception_object_count, 0);
        assert_eq!(writer_fence_count(&connection), 87);

        verify_schema_after_upgrade(&connection, AUTONOMY_AUTHORITY_SCHEMA_VERSION).unwrap();
        verify_database(
            &connection,
            AUTONOMY_AUTHORITY_SCHEMA_VERSION,
            VERIFICATION_LIFE_ID,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&connection), 87);
    }

    #[test]
    fn migration_025_upgrades_schema_twenty_four_without_backfill_and_installs_full_manifest() {
        let (mut connection, life_id) = schema_twenty_four_connection_with_current_life();
        apply_body_package_authority_upgrade(&mut connection);

        assert_eq!(
            schema_version(&connection),
            BODY_PACKAGE_AUTHORITY_SCHEMA_VERSION
        );
        validate_body_package_schema(&connection).unwrap();
        assert_eq!(writer_fence_count(&connection), 99);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM body_package", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM body_package_asset", [], |row| row
                    .get::<_, i64>(0),)
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM life_identity WHERE id=?1",
                    [life_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_foreign_key_list('body_package')
                     WHERE \"table\"='life_identity'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "body_package must not become a Life foreign-key child"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_foreign_key_list('body_package_asset')
                     WHERE \"table\"='body_package' AND \"from\"='body_id'
                       AND \"to\"='body_id' AND on_delete='CASCADE'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn migration_025_constraints_and_immutability_guards_are_authoritative() {
        let (mut connection, _) = schema_twenty_four_connection_with_current_life();
        apply_body_package_authority_upgrade(&mut connection);

        assert!(connection
            .execute(
                "INSERT INTO body_package
                 (body_id, display_name, presentation_kind, model_entry_path,
                  package_content_hash, package_version, installed_at)
                 VALUES ('live2d-not-hex', 'Invalid', 'live2d', 'avatar.model3.json',
                         'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         1, '2026-08-29T00:00:00.000Z')",
                [],
            )
            .is_err());
        connection
            .execute(
                "INSERT INTO body_package
                 (body_id, display_name, presentation_kind, model_entry_path,
                  package_content_hash, package_version, installed_at)
                 VALUES ('live2d-abc', 'Test Body', 'live2d', 'avatar.model3.json',
                         'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         1, '2026-08-29T00:00:00.000Z')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO body_package_asset
                 (body_id, relative_path, asset_kind, content_hash, size_bytes)
                 VALUES ('live2d-abc', 'avatar.model3.json', 'model3',
                         'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 2)",
                [],
            )
            .unwrap();
        assert!(connection
            .execute(
                "UPDATE body_package SET display_name='Changed' WHERE body_id='live2d-abc'",
                [],
            )
            .unwrap_err()
            .to_string()
            .contains("BODY_PACKAGE_IMMUTABLE"));
        assert!(connection
            .execute(
                "UPDATE body_package_asset SET size_bytes=3
                 WHERE body_id='live2d-abc' AND relative_path='avatar.model3.json'",
                [],
            )
            .unwrap_err()
            .to_string()
            .contains("BODY_PACKAGE_ASSET_IMMUTABLE"));

        connection
            .execute("DELETE FROM body_package WHERE body_id='live2d-abc'", [])
            .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM body_package_asset WHERE body_id='live2d-abc'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "asset rows must cascade only with their package"
        );
    }

    #[test]
    fn migration_025_generic_schema_verifiers_accept_valid_schema_twenty_five() {
        let (connection, life_id) = schema_twenty_five_connection_with_current_life();
        verify_schema_after_upgrade(&connection, BODY_PACKAGE_AUTHORITY_SCHEMA_VERSION).unwrap();
        verify_database(&connection, BODY_PACKAGE_AUTHORITY_SCHEMA_VERSION, life_id).unwrap();
        assert_eq!(writer_fence_count(&connection), 99);
    }

    #[test]
    fn migration_026_upgrades_schema_twenty_five_without_backfill_and_installs_full_manifest() {
        let (mut connection, life_id) = schema_twenty_five_connection_with_current_life();
        apply_live2d_core_authority_upgrade(&mut connection);

        assert_eq!(
            schema_version(&connection),
            LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION
        );
        validate_live2d_core_schema(&connection).unwrap();
        assert_eq!(writer_fence_count(&connection), 102);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM live2d_core_component", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            0,
            "Migration026 must synthesize no component rows"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM life_identity WHERE id=?1",
                    [life_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "existing lives remain unchanged"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version=?1",
                    [LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_live2d_core_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        drop(transaction);
        assert_eq!(
            schema_version(&connection),
            LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION
        );
    }

    #[test]
    fn migration_026_constraints_and_immutability_guard_are_authoritative() {
        let (connection, _life_id) = schema_twenty_six_connection_with_current_life();

        // slot, runtime_family, managed_relative_path, and sha256 form must
        // be exact; the table carries no user path / URL / source text.
        for (sql, label) in [
            (
                "INSERT INTO live2d_core_component
                 (slot, runtime_family, version_label, sha256, managed_relative_path, installed_at)
                 VALUES ('other', 'cubism4', 'v1', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'live2dcubismcore.min.js', '2026-08-29T00:00:00.000Z')",
                "slot must be 'active'",
            ),
            (
                "INSERT INTO live2d_core_component
                 (slot, runtime_family, version_label, sha256, managed_relative_path, installed_at)
                 VALUES ('active', 'cubism5', 'v1', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'live2dcubismcore.min.js', '2026-08-29T00:00:00.000Z')",
                "runtime_family must be cubism4",
            ),
            (
                "INSERT INTO live2d_core_component
                 (slot, runtime_family, version_label, sha256, managed_relative_path, installed_at)
                 VALUES ('active', 'cubism4', 'v1', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'live2dcubismcore.min.js', '2026-08-29T00:00:00.000Z')",
                "sha256 must be lowercase",
            ),
            (
                "INSERT INTO live2d_core_component
                 (slot, runtime_family, version_label, sha256, managed_relative_path, installed_at)
                 VALUES ('active', 'cubism4', 'v1', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'other.js', '2026-08-29T00:00:00.000Z')",
                "managed_relative_path must be the fixed resource",
            ),
            (
                "INSERT INTO live2d_core_component
                 (slot, runtime_family, version_label, sha256, managed_relative_path, installed_at)
                 VALUES ('active', 'cubism4', 'v1', 'short', 'live2dcubismcore.min.js', '2026-08-29T00:00:00.000Z')",
                "sha256 length must be 64",
            ),
            (
                "INSERT INTO live2d_core_component
                 (slot, runtime_family, version_label, sha256, managed_relative_path, installed_at)
                 VALUES ('active', 'cubism4', 'v1', 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', 'live2dcubismcore.min.js', '2026-08-29T00:00:00.000Z')",
                "sha256 must be exactly 64 lowercase hex characters (z rejected)",
            ),
            (
                "INSERT INTO live2d_core_component
                 (slot, runtime_family, version_label, sha256, managed_relative_path, installed_at)
                 VALUES ('active', 'cubism4', 'v1', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag', 'live2dcubismcore.min.js', '2026-08-29T00:00:00.000Z')",
                "sha256 must be exactly 64 lowercase hex characters (g rejected)",
            ),
            (
                "INSERT INTO live2d_core_component
                 (slot, runtime_family, version_label, sha256, managed_relative_path, installed_at)
                 VALUES ('active', 'cubism4', 'v1', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'live2dcubismcore.min.js', '2026-08-29T00:00:00.000Z')",
                "sha256 length must be 64 (65 hex chars rejected)",
            ),
            (
                "INSERT INTO live2d_core_component
                 (slot, runtime_family, version_label, sha256, managed_relative_path, installed_at)
                 VALUES ('active', 'cubism4', 'v1', 'aaaa-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'live2dcubismcore.min.js', '2026-08-29T00:00:00.000Z')",
                "sha256 must be exactly 64 lowercase hex characters (punctuation rejected)",
            ),
        ] {
            assert!(
                connection.execute(sql, []).is_err(),
                "{label} must be rejected by the schema"
            );
        }

        // A valid 64-char lowercase hex value is accepted.
        connection
            .execute(
                "INSERT INTO live2d_core_component
                 (slot, runtime_family, version_label, sha256, managed_relative_path, installed_at)
                 VALUES ('active', 'cubism4', 'v1', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'live2dcubismcore.min.js', '2026-08-29T00:00:00.000Z')",
                [],
            )
            .unwrap();
        assert!(connection
            .execute(
                "UPDATE live2d_core_component SET version_label='changed' WHERE slot='active'",
                [],
            )
            .unwrap_err()
            .to_string()
            .contains("LIVE2D_CORE_COMPONENT_IMMUTABLE"));

        let forbidden_columns: Vec<String> = connection
            .prepare("SELECT name FROM pragma_table_info('live2d_core_component')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        for column in &forbidden_columns {
            assert!(
                !["source_path", "url", "script_url", "source_text", "payload"]
                    .contains(&column.as_str()),
                "live2d_core_component must not carry {column}"
            );
        }
    }

    #[test]
    fn migration_026_generic_schema_verifiers_accept_valid_schema_twenty_six() {
        let (connection, life_id) = schema_twenty_six_connection_with_current_life();
        verify_schema_after_upgrade(&connection, LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION).unwrap();
        verify_database(&connection, LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION, life_id).unwrap();
        assert_eq!(writer_fence_count(&connection), 102);
    }

    fn apply_screen_perception_authority_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_screen_perception_schema_upgrade(&transaction).unwrap(),
            ScreenPerceptionAuthoritySchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn schema_twenty_seven_connection_with_current_life() -> (Connection, &'static str) {
        let (mut connection, life_id) = schema_twenty_six_connection_with_current_life();
        apply_screen_perception_authority_upgrade(&mut connection);
        (connection, life_id)
    }

    fn apply_screen_vision_outbound_policy_authority_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_screen_vision_outbound_policy_schema_upgrade(&transaction).unwrap(),
            ScreenVisionOutboundPolicyAuthoritySchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn schema_twenty_eight_connection_with_current_life() -> (Connection, &'static str) {
        let (mut connection, life_id) = schema_twenty_seven_connection_with_current_life();
        apply_screen_vision_outbound_policy_authority_upgrade(&mut connection);
        (connection, life_id)
    }

    fn apply_vision_model_profile_authority_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_vision_model_profile_schema_upgrade(&transaction).unwrap(),
            VisionModelProfileSchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn apply_capability_authorization_authority_upgrade(connection: &mut Connection) {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            apply_capability_authorization_schema_upgrade(&transaction).unwrap(),
            CapabilityAuthorizationSchemaUpgrade::Applied
        );
        transaction.commit().unwrap();
    }

    fn model_profile_identity_rows(connection: &Connection) -> Vec<(i64, String)> {
        let mut statement = connection
            .prepare("SELECT rowid, id FROM model_profile ORDER BY rowid")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    type ModelProfileRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        Option<f64>,
        Option<i64>,
        Option<i64>,
        String,
        String,
    );

    fn model_profile_rows(connection: &Connection) -> Vec<ModelProfileRow> {
        let mut statement = connection
            .prepare(
                "SELECT id, purpose, provider_kind, display_name, base_url, model_name,
                        temperature, max_tokens, embedding_dimension, created_at, updated_at
                 FROM model_profile ORDER BY id",
            )
            .unwrap();
        statement
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
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn active_model_profile_identity_rows(connection: &Connection) -> Vec<(i64, String, String)> {
        let mut statement = connection
            .prepare("SELECT rowid, purpose, profile_id FROM active_model_profile ORDER BY rowid")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn migration_029_preserves_existing_profiles_and_active_mappings_without_vision_backfill() {
        let (mut connection, life_id) = schema_twenty_eight_connection_with_current_life();
        connection
            .execute_batch(
                "INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES
                    ('d26-chat', 'chat', 'openai_compatible', 'D26 Chat',
                     'https://chat.example.invalid/v1', 'chat-model', 0.7, 4096, NULL,
                     '2026-08-31T00:00:00.001Z', '2026-08-31T00:00:00.002Z'),
                    ('d26-embedding', 'embedding', 'openai_compatible', 'D26 Embedding',
                     'https://embedding.example.invalid/v1', 'embedding-model', NULL, NULL, 1536,
                     '2026-08-31T00:00:00.003Z', '2026-08-31T00:00:00.004Z'),
                    ('d26-candidate', 'candidate_extraction', 'openai_compatible', 'D26 Candidate',
                     'https://candidate.example.invalid/v1', 'candidate-model', 0.0, 4096, NULL,
                     '2026-08-31T00:00:00.005Z', '2026-08-31T00:00:00.006Z');
                 INSERT INTO active_model_profile (purpose, profile_id) VALUES
                    ('chat', 'd26-chat'),
                    ('embedding', 'd26-embedding'),
                    ('candidate_extraction', 'd26-candidate');",
            )
            .unwrap();
        let profiles_before = model_profile_identity_rows(&connection);
        let active_before = active_model_profile_identity_rows(&connection);
        let profile_data_before = model_profile_rows(&connection);

        apply_vision_model_profile_authority_upgrade(&mut connection);

        assert_eq!(
            schema_version(&connection),
            VISION_MODEL_PROFILE_SCHEMA_VERSION
        );
        validate_model_profile_schema(&connection).unwrap();
        validate_screen_vision_outbound_policy_schema(&connection).unwrap();
        verify_schema_after_upgrade(&connection, VISION_MODEL_PROFILE_SCHEMA_VERSION).unwrap();
        verify_database(&connection, VISION_MODEL_PROFILE_SCHEMA_VERSION, life_id).unwrap();
        assert_eq!(model_profile_identity_rows(&connection), profiles_before);
        assert_eq!(
            active_model_profile_identity_rows(&connection),
            active_before
        );
        assert_eq!(model_profile_rows(&connection), profile_data_before);
        assert_eq!(writer_fence_count(&connection), 114);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM model_profile WHERE purpose='vision'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM active_model_profile WHERE purpose='vision'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration
                     WHERE version=?1 AND name='029_vision_model_profiles'",
                    [VISION_MODEL_PROFILE_SCHEMA_VERSION],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        let foreign_key_violations: i64 = connection
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(foreign_key_violations, 0);
    }

    #[test]
    fn migration_029_rejects_reapply_and_malformed_reconstructed_schema() {
        let (mut connection, _life_id) = schema_twenty_eight_connection_with_current_life();
        apply_vision_model_profile_authority_upgrade(&mut connection);

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_vision_model_profile_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        drop(transaction);

        let original_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='model_profile'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let weakened_sql = original_sql.replacen("max_tokens <= 4096", "max_tokens <= 4095", 1);
        assert_ne!(weakened_sql, original_sql);
        let schema_cookie: i64 = connection
            .query_row("PRAGMA schema_version", [], |row| row.get(0))
            .unwrap();
        connection
            .pragma_update(None, "writable_schema", "ON")
            .unwrap();
        connection
            .execute(
                "UPDATE sqlite_schema SET sql=?1 WHERE type='table' AND name='model_profile'",
                [&weakened_sql],
            )
            .unwrap();
        connection
            .pragma_update(None, "schema_version", schema_cookie + 1)
            .unwrap();
        connection
            .pragma_update(None, "writable_schema", "OFF")
            .unwrap();

        assert!(validate_model_profile_schema(&connection).is_err());
    }

    #[test]
    fn migration_030_preserves_schema_29_adds_empty_default_deny_root_and_rejects_malformed_schema()
    {
        let (mut connection, life_id) = schema_twenty_eight_connection_with_current_life();
        apply_vision_model_profile_authority_upgrade(&mut connection);
        connection
            .execute(
                "INSERT INTO model_profile (
                    id, purpose, provider_kind, display_name, base_url, model_name,
                    temperature, max_tokens, embedding_dimension, created_at, updated_at
                 ) VALUES ('d28-preserved', 'vision', 'openai_compatible', 'D28 Preserved',
                    'https://vision.example.invalid/v1', 'vision-model', 0.0, 1024, NULL,
                    '2026-09-01T00:00:00.001Z', '2026-09-01T00:00:00.002Z')",
                [],
            )
            .unwrap();

        apply_capability_authorization_authority_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            CAPABILITY_AUTHORIZATION_SCHEMA_VERSION
        );
        validate_capability_authorization_schema(&connection).unwrap();
        verify_schema_after_upgrade(&connection, CAPABILITY_AUTHORIZATION_SCHEMA_VERSION).unwrap();
        verify_database(
            &connection,
            CAPABILITY_AUTHORIZATION_SCHEMA_VERSION,
            life_id,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&connection), 120);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM life_capability_authorization",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM life_capability_authorization_event",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM model_profile WHERE id='d28-preserved'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration
                     WHERE version=?1 AND name='030_capability_authorization_root'",
                    [CAPABILITY_AUTHORIZATION_SCHEMA_VERSION],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_capability_authorization_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        drop(transaction);

        let original_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type='table' AND name='life_capability_authorization'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let weakened_sql = original_sql.replacen("revision >= 1", "revision >= 0", 1);
        assert_ne!(weakened_sql, original_sql);
        let schema_cookie: i64 = connection
            .query_row("PRAGMA schema_version", [], |row| row.get(0))
            .unwrap();
        connection
            .pragma_update(None, "writable_schema", "ON")
            .unwrap();
        connection
            .execute(
                "UPDATE sqlite_schema SET sql=?1
                 WHERE type='table' AND name='life_capability_authorization'",
                [&weakened_sql],
            )
            .unwrap();
        connection
            .pragma_update(None, "schema_version", schema_cookie + 1)
            .unwrap();
        connection
            .pragma_update(None, "writable_schema", "OFF")
            .unwrap();
        assert!(validate_capability_authorization_schema(&connection).is_err());
    }

    #[test]
    fn migration_027_creates_two_consent_tables_once_without_backfill() {
        let mut connection = schema_twenty_six_connection_with_current_life().0;
        connection
            .execute_batch(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES ('migration-027-persona', 'Persona', 1, '{}');
                 INSERT INTO life_identity
                     (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES ('migration-027-life', 'Life', '2026-08-27T00:00:00.000Z', 1,
                         'migration-027-body', 'migration-027-persona', 1);",
            )
            .unwrap();

        apply_screen_perception_authority_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION
        );
        validate_screen_perception_schema(&connection).unwrap();
        assert_eq!(writer_fence_count(&connection), 108);
        for table in [
            "life_screen_perception_policy",
            "life_screen_perception_policy_event",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "Migration027 must synthesize no {table} rows");
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM life_identity WHERE id='migration-027-life'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version=?1",
                    [SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_screen_perception_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        drop(transaction);
        assert_eq!(writer_fence_count(&connection), 108);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version=?1",
                    [SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn migration_027_failure_points_roll_back_to_exact_schema_twenty_six_preimage() {
        let new_fence_names = [
            "digital_life_writer_epoch_life_screen_perception_policy_insert",
            "digital_life_writer_epoch_life_screen_perception_policy_update",
            "digital_life_writer_epoch_life_screen_perception_policy_delete",
            "digital_life_writer_epoch_life_screen_perception_policy_event_insert",
            "digital_life_writer_epoch_life_screen_perception_policy_event_update",
            "digital_life_writer_epoch_life_screen_perception_policy_event_delete",
        ];
        for point in [
            Migration027Failpoint::AfterTable,
            Migration027Failpoint::AfterSemanticGuards,
            Migration027Failpoint::AfterWriterFences,
            Migration027Failpoint::BeforeSchemaVersion,
            Migration027Failpoint::PreCommit,
        ] {
            let mut connection = schema_twenty_six_connection_with_current_life().0;
            fail_next_migration_027_at_for_test(point);
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_screen_perception_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");

            let table_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='table' AND name IN
                       ('life_screen_perception_policy','life_screen_perception_policy_event')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let guard_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='trigger' AND name IN
                       ('life_screen_perception_policy_immutable_guard',
                        'life_screen_perception_policy_event_immutable_guard')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let fence_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type='trigger' AND name IN
                       ('digital_life_writer_epoch_life_screen_perception_policy_insert',
                        'digital_life_writer_epoch_life_screen_perception_policy_update',
                        'digital_life_writer_epoch_life_screen_perception_policy_delete',
                        'digital_life_writer_epoch_life_screen_perception_policy_event_insert',
                        'digital_life_writer_epoch_life_screen_perception_policy_event_update',
                        'digital_life_writer_epoch_life_screen_perception_policy_event_delete')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            match point {
                Migration027Failpoint::AfterTable => {
                    assert_eq!(table_count, 2);
                    assert_eq!(guard_count, 0);
                    assert_eq!(fence_count, 0);
                }
                Migration027Failpoint::AfterSemanticGuards => {
                    assert_eq!(table_count, 2);
                    assert_eq!(guard_count, 2);
                    assert_eq!(fence_count, 0);
                }
                Migration027Failpoint::AfterWriterFences
                | Migration027Failpoint::BeforeSchemaVersion
                | Migration027Failpoint::PreCommit => {
                    assert_eq!(table_count, 2);
                    assert_eq!(guard_count, 2);
                    assert_eq!(fence_count, 6);
                }
            }
            drop(transaction);

            assert_eq!(
                schema_version(&connection),
                LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION
            );
            validate_live2d_core_schema(&connection).unwrap();
            writer_fence_manifest::validate_writer_fence_manifest_for_schema(
                &connection,
                LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION,
            )
            .unwrap();
            assert_eq!(writer_fence_count(&connection), 102);
            for name in new_fence_names {
                let count: i64 = connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema WHERE name=?1",
                        [name],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap();
                assert_eq!(count, 0, "failed Migration027 must remove {name}");
            }
            for name in [
                "life_screen_perception_policy",
                "life_screen_perception_policy_event",
                "life_screen_perception_policy_immutable_guard",
                "life_screen_perception_policy_event_immutable_guard",
            ] {
                let count: i64 = connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema WHERE name=?1",
                        [name],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap();
                assert_eq!(count, 0, "failed Migration027 must remove {name}");
            }
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM schema_migration WHERE version=?1",
                        [SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn migration_027_constraints_and_immutability_guards_are_authoritative() {
        let (connection, _life_id) = schema_twenty_seven_connection_with_current_life();

        for (sql, label) in [
            (
                "INSERT INTO life_screen_perception_policy
                 (life_id, screen_perception_enabled, revision, created_at, updated_at, policy_version)
                 VALUES ('missing-life', 1, 1, '2026-08-29T00:00:00.000Z', '2026-08-29T00:00:00.000Z', 1)",
                "missing life must be rejected by the FK",
            ),
            (
                "INSERT INTO life_screen_perception_policy
                 (life_id, screen_perception_enabled, revision, created_at, updated_at, policy_version)
                 VALUES ('  ', 1, 1, '2026-08-29T00:00:00.000Z', '2026-08-29T00:00:00.000Z', 1)",
                "blank life_id must be rejected",
            ),
            (
                "INSERT INTO life_screen_perception_policy
                 (life_id, screen_perception_enabled, revision, created_at, updated_at, policy_version)
                 VALUES ('migration-027-life', 2, 1, '2026-08-29T00:00:00.000Z', '2026-08-29T00:00:00.000Z', 1)",
                "screen_perception_enabled must be 0 or 1",
            ),
            (
                "INSERT INTO life_screen_perception_policy
                 (life_id, screen_perception_enabled, revision, created_at, updated_at, policy_version)
                 VALUES ('migration-027-life', 1, 0, '2026-08-29T00:00:00.000Z', '2026-08-29T00:00:00.000Z', 1)",
                "revision must be >= 1",
            ),
            (
                "INSERT INTO life_screen_perception_policy
                 (life_id, screen_perception_enabled, revision, created_at, updated_at, policy_version)
                 VALUES ('migration-027-life', 1, 1, '2026-08-29T00:00:00.000Z', '2026-08-29T00:00:00.000Z', 2)",
                "policy_version must be 1",
            ),
        ] {
            assert!(connection.execute(sql, []).is_err(), "{label}");
        }

        // The verification life exists; a valid row is accepted.
        connection
            .execute(
                "INSERT INTO life_screen_perception_policy
                 (life_id, screen_perception_enabled, revision, created_at, updated_at, policy_version)
                 VALUES (?1, 1, 1, '2026-08-29T00:00:00.000Z', '2026-08-29T00:00:00.000Z', 1)",
                [VERIFICATION_LIFE_ID],
            )
            .unwrap();
        assert!(connection
            .execute(
                "UPDATE life_screen_perception_policy
                 SET life_id='other-life' WHERE life_id=?1",
                [VERIFICATION_LIFE_ID],
            )
            .unwrap_err()
            .to_string()
            .contains("LIFE_SCREEN_PERCEPTION_POLICY_IMMUTABLE"));
        assert!(connection
            .execute(
                "UPDATE life_screen_perception_policy
                 SET created_at='changed' WHERE life_id=?1",
                [VERIFICATION_LIFE_ID],
            )
            .unwrap_err()
            .to_string()
            .contains("LIFE_SCREEN_PERCEPTION_POLICY_IMMUTABLE"));

        connection
            .execute(
                "INSERT INTO life_screen_perception_policy_event
                 (event_id, life_id, old_screen_perception_enabled, new_screen_perception_enabled,
                  expected_revision, applied_revision, actor_kind, occurred_at, event_version)
                 VALUES ('evt-1', ?1, 0, 1, 1, 2, 'user_explicit',
                         '2026-08-29T00:00:00.000Z', 1)",
                [VERIFICATION_LIFE_ID],
            )
            .unwrap();
        assert!(connection
            .execute(
                "UPDATE life_screen_perception_policy_event
                 SET new_screen_perception_enabled=0 WHERE event_id='evt-1'",
                [],
            )
            .unwrap_err()
            .to_string()
            .contains("LIFE_SCREEN_PERCEPTION_POLICY_EVENT_IMMUTABLE"));

        let forbidden_columns: Vec<String> = connection
            .prepare("SELECT name FROM pragma_table_info('life_screen_perception_policy')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        for column in &forbidden_columns {
            assert!(
                ![
                    "screenshot",
                    "pixel",
                    "ocr",
                    "window_title",
                    "process_path",
                    "pid",
                    "hwnd",
                    "monitor",
                    "capture_target",
                    "capture_token",
                ]
                .contains(&column.as_str()),
                "life_screen_perception_policy must not carry {column}"
            );
        }
    }

    #[test]
    fn migration_027_generic_schema_verifiers_accept_valid_schema_twenty_seven() {
        let (connection, life_id) = schema_twenty_seven_connection_with_current_life();
        verify_schema_after_upgrade(&connection, SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION)
            .unwrap();
        verify_database(
            &connection,
            SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION,
            life_id,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&connection), 108);
    }

    #[test]
    fn migration_028_upgrades_schema_twenty_seven_without_backfill_and_rejects_reapply() {
        let (mut connection, life_id) = schema_twenty_seven_connection_with_current_life();
        assert!(validate_screen_vision_outbound_policy_schema(&connection).is_err());
        apply_screen_vision_outbound_policy_authority_upgrade(&mut connection);

        assert_eq!(
            schema_version(&connection),
            SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_SCHEMA_VERSION
        );
        validate_screen_perception_schema(&connection).unwrap();
        validate_screen_vision_outbound_policy_schema(&connection).unwrap();
        verify_schema_after_upgrade(
            &connection,
            SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_SCHEMA_VERSION,
        )
        .unwrap();
        verify_database(
            &connection,
            SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_SCHEMA_VERSION,
            life_id,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&connection), 114);

        for table in [
            "life_screen_vision_outbound_policy",
            "life_screen_vision_outbound_policy_event",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "Migration028 must synthesize no {table} rows");
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM life_screen_perception_policy",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "D23 local consent must not be converted into D25-A rows"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version=?1",
                    [SCREEN_VISION_OUTBOUND_POLICY_AUTHORITY_SCHEMA_VERSION],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_screen_vision_outbound_policy_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_VERSION_INVARIANT_FAILED");
        drop(transaction);
        assert_eq!(writer_fence_count(&connection), 114);
    }

    #[test]
    fn migration_028_schema_has_only_durable_policy_columns_and_exact_foreign_keys() {
        let (connection, _life_id) = schema_twenty_eight_connection_with_current_life();
        let expected_columns = [
            (
                "life_screen_vision_outbound_policy",
                vec![
                    "life_id",
                    "screen_vision_outbound_enabled",
                    "revision",
                    "created_at",
                    "updated_at",
                    "policy_version",
                ],
            ),
            (
                "life_screen_vision_outbound_policy_event",
                vec![
                    "event_id",
                    "life_id",
                    "old_screen_vision_outbound_enabled",
                    "new_screen_vision_outbound_enabled",
                    "expected_revision",
                    "applied_revision",
                    "actor_kind",
                    "occurred_at",
                    "event_version",
                ],
            ),
        ];
        for (table, expected) in expected_columns {
            let mut statement = connection
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap();
            let columns: Vec<String> = statement
                .query_map([], |row| row.get(1))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(columns, expected);
        }
        for (child, parent, from, to) in [
            (
                "life_screen_vision_outbound_policy",
                "life_identity",
                "life_id",
                "id",
            ),
            (
                "life_screen_vision_outbound_policy_event",
                "life_screen_vision_outbound_policy",
                "life_id",
                "life_id",
            ),
        ] {
            let count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)
                     WHERE \"table\"=?2 AND \"from\"=?3 AND \"to\"=?4
                       AND on_delete='CASCADE'",
                    params![child, parent, from, to],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "{child} must cascade from {parent}");
        }
        let forbidden = [
            "image",
            "pixel",
            "screenshot",
            "ocr",
            "capture",
            "window",
            "process",
            "pid",
            "hwnd",
            "provider",
            "url",
            "base64",
            "multipart",
        ];
        for table in [
            "life_screen_vision_outbound_policy",
            "life_screen_vision_outbound_policy_event",
        ] {
            let mut statement = connection
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap();
            let columns: Vec<String> = statement
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            for column in columns {
                assert!(
                    !forbidden
                        .iter()
                        .any(|word| column.to_ascii_lowercase().contains(word)),
                    "D25-A table must not carry {column}"
                );
            }
        }
    }

    #[test]
    fn schema_twenty_six_and_schema_twenty_seven_reopen_against_their_own_manifests() {
        let schema_twenty_six = schema_twenty_six_connection_with_current_life().0;
        validate_live2d_core_schema(&schema_twenty_six).unwrap();
        writer_fence_manifest::validate_writer_fence_manifest_for_schema(
            &schema_twenty_six,
            LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&schema_twenty_six), 102);
        assert!(validate_screen_perception_schema(&schema_twenty_six).is_err());

        let mut schema_twenty_seven = schema_twenty_six_connection_with_current_life().0;
        apply_screen_perception_authority_upgrade(&mut schema_twenty_seven);
        validate_screen_perception_schema(&schema_twenty_seven).unwrap();
        writer_fence_manifest::validate_writer_fence_manifest_for_schema(
            &schema_twenty_seven,
            SCREEN_PERCEPTION_AUTHORITY_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&schema_twenty_seven), 108);
        validate_live2d_core_schema(&schema_twenty_seven).unwrap();
    }

    #[test]
    fn migration_027_generic_schema_verifiers_keep_schema_twenty_six_compatible() {
        let connection = schema_twenty_six_connection_with_current_life().0;
        let screen_object_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE name IN
                   ('life_screen_perception_policy', 'life_screen_perception_policy_event',
                    'life_screen_perception_policy_immutable_guard',
                    'life_screen_perception_policy_event_immutable_guard')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(screen_object_count, 0);
        assert_eq!(writer_fence_count(&connection), 102);

        verify_schema_after_upgrade(&connection, LIVE2D_CORE_AUTHORITY_SCHEMA_VERSION).unwrap();
        assert_eq!(writer_fence_count(&connection), 102);
    }

    #[test]
    fn schema_twenty_two_and_schema_twenty_three_reopen_against_their_own_manifests() {
        let mut connection = schema_twenty_two_connection();
        writer_fence_manifest::validate_writer_fence_manifest_for_schema(
            &connection,
            LIFE_INTENT_AUTHORITY_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&connection), 75);
        assert!(validate_autonomy_schema(&connection).is_err());

        apply_autonomy_authority_upgrade(&mut connection);
        validate_autonomy_schema(&connection).unwrap();
        writer_fence_manifest::validate_writer_fence_manifest_for_schema(
            &connection,
            AUTONOMY_AUTHORITY_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&connection), 87);
    }

    #[test]
    fn schema_twenty_one_reopen_stays_at_sixty_and_schema_twenty_two_reopens_at_seventy_five() {
        // Schema 21 is validated exactly at its own 60-trigger manifest.
        let mut schema_twenty_one = schema_twenty_connection();
        apply_experience_episode_upgrade(&mut schema_twenty_one);
        writer_fence_manifest::validate_writer_fence_manifest_for_schema(
            &schema_twenty_one,
            EXPERIENCE_EPISODE_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&schema_twenty_one), 60);
        let downgrade_probe = validate_life_intent_schema(&schema_twenty_one).unwrap_err();
        assert_eq!(downgrade_probe.code, "MIGRATION_VERSION_INVARIANT_FAILED");

        // Schema 22 reopens and validates at exactly 75 triggers.
        apply_life_intent_authority_upgrade(&mut schema_twenty_one);
        validate_life_intent_schema(&schema_twenty_one).unwrap();
        writer_fence_manifest::validate_writer_fence_manifest_for_schema(
            &schema_twenty_one,
            LIFE_INTENT_AUTHORITY_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(writer_fence_count(&schema_twenty_one), 75);
        validate_emotion_authority_schema(&schema_twenty_one).unwrap();
        validate_relationship_authority_schema(&schema_twenty_one).unwrap();
        validate_experience_episode_schema(&schema_twenty_one).unwrap();
    }

    #[test]
    fn migration_022_wrong_epoch_semantic_guard_fails_closed_without_repair() {
        // Both a semantically weakened body and the pre-F1 whole-table epoch
        // body fail exact Schema22 validation: a correct trigger name with any
        // body that is not the frozen selective-guard body is a wrong-epoch
        // object and is never repaired during reopen.
        for (wrong_body, wrong_epoch_marker) in [
            // Whole-table epoch: rejects every UPDATE, forbidding B2 lifecycle.
            (
                "CREATE TRIGGER life_goal_immutable_guard
                 BEFORE UPDATE ON life_goal
                 WHEN digital_life_writer_epoch() IS 1
                 BEGIN
                     SELECT RAISE(ROLLBACK, 'LIFE_GOAL_IMMUTABLE');
                 END;",
                "no selective column comparison may exist",
            ),
            // Weakened category: same name, different fixed code.
            (
                "CREATE TRIGGER life_goal_immutable_guard
                 BEFORE UPDATE ON life_goal
                 WHEN digital_life_writer_epoch() IS 1
                 BEGIN
                     SELECT RAISE(ROLLBACK, 'LIFE_GOAL_NOT_IMMUTABLE');
                 END;",
                "LIFE_GOAL_NOT_IMMUTABLE",
            ),
            // Weakened epoch: drops the authorized-writer condition.
            (
                "CREATE TRIGGER life_goal_immutable_guard
                 BEFORE UPDATE ON life_goal
                 WHEN (
                     NEW.goal_id IS NOT OLD.goal_id
                     OR NEW.life_id IS NOT OLD.life_id
                     OR NEW.title IS NOT OLD.title
                     OR NEW.objective IS NOT OLD.objective
                     OR NEW.created_by_kind IS NOT OLD.created_by_kind
                     OR NEW.created_at IS NOT OLD.created_at
                     OR NEW.goal_version IS NOT OLD.goal_version
                 )
                 BEGIN
                     SELECT RAISE(ROLLBACK, 'LIFE_GOAL_IMMUTABLE');
                 END;",
                "writer epoch condition dropped",
            ),
        ] {
            let mut connection = schema_twenty_one_connection();
            apply_life_intent_authority_upgrade(&mut connection);
            connection
                .execute_batch(&format!(
                    "DROP TRIGGER life_goal_immutable_guard;\n{wrong_body}"
                ))
                .unwrap();
            let error = validate_life_intent_schema(&connection).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
            // The wrong-epoch trigger is never repaired by validation, and its
            // stored body is exactly the wrong shape that was installed.
            let sql: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='life_goal_immutable_guard'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            match wrong_epoch_marker {
                "no selective column comparison may exist" => {
                    assert!(
                        !sql.contains("NEW."),
                        "the whole-table epoch body must remain stored"
                    )
                }
                "LIFE_GOAL_NOT_IMMUTABLE" => assert!(sql.contains("LIFE_GOAL_NOT_IMMUTABLE")),
                "writer epoch condition dropped" => {
                    assert!(
                        !sql.contains("digital_life_writer_epoch()"),
                        "the weakened WHEN must remain stored"
                    )
                }
                other => unreachable!("unexpected marker {other}"),
            }
        }
    }

    #[test]
    fn migration_018_schema18_missing_catchup_trigger_fails_validation_without_repair() {
        let mut connection = schema_seventeen_connection();
        apply_generation_catchup_attempt_upgrade(&mut connection);
        let missing = writer_fence_manifest::generation_catchup_writer_fence_trigger_specs()[0];
        connection
            .execute_batch(&format!("DROP TRIGGER {}", missing.name))
            .unwrap();

        let error = validate_generation_catchup_attempt_schema(&connection).unwrap_err();
        assert_eq!(error.code, "WRITER_FENCE_MANIFEST_MISSING");
        let remaining: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND name=?1",
                [missing.name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn migration_018_failpoints_roll_back_to_exact_schema_seventeen_preimage() {
        for point in [
            Migration018Failpoint::AfterTable,
            Migration018Failpoint::AfterSemanticGuards,
            Migration018Failpoint::AfterWriterFences,
            Migration018Failpoint::BeforeSchemaVersion,
            Migration018Failpoint::PreCommit,
        ] {
            let mut connection = schema_seventeen_connection();
            fail_next_migration_018_at_for_test(point);
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_generation_catchup_attempt_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");

            // Demonstrate the phases are genuinely distinct: each failpoint
            // fires after its own durable boundary has been reached inside the
            // caller-owned transaction (the rollback happens only on drop).
            let table_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_rebuild_catchup_item'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let guard_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND name IN ('memory_vector_generation_rebuild_catchup_identity_immutable','memory_vector_generation_rebuild_catchup_supersede_guard')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let fence_count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND name LIKE 'digital_life_writer_epoch_memory_vector_generation_rebuild_catchup_item_%'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let version_eighteen_rows: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM schema_migration WHERE version=18",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let (expected_table, expected_guards, expected_fences, expected_version) = match point {
                // Phase A boundary: table exists, no semantic guards, no fences.
                Migration018Failpoint::AfterTable => (1, 0, 0, 0),
                // Phase B boundary: table + both semantic guards, no fences.
                Migration018Failpoint::AfterSemanticGuards => (1, 2, 0, 0),
                // Phase C boundary: table + guards + all three Schema18 fences,
                // but the version boundary is not yet written.
                Migration018Failpoint::AfterWriterFences => (1, 2, 3, 0),
                // Phase D boundary: validated objects, version row not yet written.
                Migration018Failpoint::BeforeSchemaVersion => (1, 2, 3, 0),
                // Phase E boundary: the version-18 row exists inside the
                // transaction but is rolled back with it.
                Migration018Failpoint::PreCommit => (1, 2, 3, 1),
            };
            assert_eq!(table_count, expected_table, "{point:?} table phase");
            assert_eq!(guard_count, expected_guards, "{point:?} guard phase");
            assert_eq!(fence_count, expected_fences, "{point:?} fence phase");
            assert_eq!(
                version_eighteen_rows, expected_version,
                "{point:?} version phase"
            );

            drop(transaction);
            assert_eq!(
                schema_version(&connection),
                GENERATION_LIFECYCLE_SCHEMA_VERSION
            );
            let objects: i64 = connection.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'memory_vector_generation_rebuild_catchup%' OR name LIKE 'digital_life_writer_epoch_memory_vector_generation_rebuild_catchup%'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(
                objects, 0,
                "{point:?} must roll back to the exact Schema17 preimage"
            );
            validate_generation_lifecycle_schema(&connection).unwrap();
        }
    }

    #[test]
    fn migration_018_catchup_table_enforces_action_attempt_and_immutable_identity() {
        let mut connection = schema_seventeen_connection();
        apply_generation_catchup_attempt_upgrade(&mut connection);
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        let valid = "INSERT INTO memory_vector_generation_rebuild_catchup_item
            (job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash,canonical_document,state,io_phase,updated_at)
            VALUES ('job',42,'life','memory',100,'upsert',1,'hash','payload','pending','not_started','now')";
        connection.execute_batch(valid).unwrap();
        for invalid in [
            "INSERT INTO memory_vector_generation_rebuild_catchup_item (job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash,canonical_document,state,io_phase,updated_at) VALUES ('a',1,'l','m',0,'upsert',1,'h','p','pending','not_started','now')",
            "INSERT INTO memory_vector_generation_rebuild_catchup_item (job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash,canonical_document,state,io_phase,updated_at) VALUES ('a',2,'l','n',1,'upsert',NULL,'h','p','pending','not_started','now')",
            "INSERT INTO memory_vector_generation_rebuild_catchup_item (job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash,canonical_document,state,io_phase,updated_at) VALUES ('a',3,'l','o',1,'delete',1,NULL,NULL,'pending','not_started','now')",
            "INSERT INTO memory_vector_generation_rebuild_catchup_item (job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash,canonical_document,state,io_phase,attempt_count,updated_at) VALUES ('a',31,'l','o-hash',1,'delete',NULL,'hash',NULL,'pending','not_started',0,'now')",
            "INSERT INTO memory_vector_generation_rebuild_catchup_item (job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash,canonical_document,state,io_phase,attempt_count,updated_at) VALUES ('a',4,'l','p',1,'delete',NULL,NULL,'payload','pending','not_started',0,'now')",
            "INSERT INTO memory_vector_generation_rebuild_catchup_item (job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash,canonical_document,state,io_phase,attempt_count,updated_at) VALUES ('a',5,'l','q',1,'delete',NULL,NULL,NULL,'pending','not_started',6,'now')",
            "INSERT INTO memory_vector_generation_rebuild_catchup_item (job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash,canonical_document,state,io_phase,attempt_count,updated_at) VALUES ('a',6,'l','r',1,'merge',1,'hash','payload','pending','not_started',0,'now')",
        ] { assert!(connection.execute_batch(invalid).is_err()); }
        assert!(connection.execute_batch(valid).is_err());
        connection.execute_batch("INSERT INTO memory_vector_generation_rebuild_catchup_item
            (job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash,canonical_document,state,io_phase,updated_at)
            VALUES ('job',42,'life','memory',103,'upsert',2,'hash-103','payload-103','pending','not_started','now')").unwrap();
        assert!(connection.execute_batch("INSERT INTO memory_vector_generation_rebuild_catchup_item
            (job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash,canonical_document,state,io_phase,updated_at)
            VALUES ('job',43,'life','memory',103,'upsert',2,'hash-103','payload-103','pending','not_started','now')").is_err());
        assert!(connection.execute_batch("UPDATE memory_vector_generation_rebuild_catchup_item SET mutation_sequence=103 WHERE job_id='job' AND source_outbox_id=42 AND mutation_sequence=100").is_err());
        assert!(connection.execute_batch("UPDATE memory_vector_generation_rebuild_catchup_item SET desired_action='delete' WHERE job_id='job' AND source_outbox_id=42 AND mutation_sequence=100").is_err());
        connection.execute_batch("UPDATE memory_vector_generation_rebuild_catchup_item SET state='uncertain',io_phase='embedding_started',last_send_disposition='possibly_sent' WHERE job_id='job' AND source_outbox_id=42 AND mutation_sequence=100").unwrap();
        assert!(connection.execute_batch("UPDATE memory_vector_generation_rebuild_catchup_item SET state='superseded' WHERE job_id='job' AND source_outbox_id=42 AND mutation_sequence=100").is_err());
    }

    #[test]
    fn d9d3_d_f1_schema18_weakened_identity_trigger_body_fails_closed_without_repair() {
        let mut connection = schema_seventeen_connection();
        apply_generation_catchup_attempt_upgrade(&mut connection);
        connection
            .execute_batch(
                "DROP TRIGGER memory_vector_generation_rebuild_catchup_identity_immutable;
                 CREATE TRIGGER memory_vector_generation_rebuild_catchup_identity_immutable
                 BEFORE UPDATE OF job_id, source_outbox_id, life_id, memory_id, mutation_sequence,
                                  desired_action, target_revision, target_content_hash
                 ON memory_vector_generation_rebuild_catchup_item
                 BEGIN
                     SELECT 1;
                 END;",
            )
            .unwrap();

        let error = validate_generation_catchup_attempt_schema(&connection).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        // Fails closed without repair: the weakened trigger is still there.
        let weakened: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='memory_vector_generation_rebuild_catchup_identity_immutable'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(weakened.contains("SELECT 1;"));
    }

    #[test]
    fn d9d3_d_f1_schema18_weakened_supersede_guard_body_fails_closed_without_repair() {
        let mut connection = schema_seventeen_connection();
        apply_generation_catchup_attempt_upgrade(&mut connection);
        connection
            .execute_batch(
                "DROP TRIGGER memory_vector_generation_rebuild_catchup_supersede_guard;
                 CREATE TRIGGER memory_vector_generation_rebuild_catchup_supersede_guard
                 BEFORE UPDATE OF state ON memory_vector_generation_rebuild_catchup_item
                 WHEN NEW.state='superseded'
                 BEGIN
                     SELECT 1;
                 END;",
            )
            .unwrap();

        let error = validate_generation_catchup_attempt_schema(&connection).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        let weakened: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='memory_vector_generation_rebuild_catchup_supersede_guard'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(weakened.contains("SELECT 1;"));
    }

    #[test]
    fn d9d3_d_f1_schema18_weakened_delete_cross_field_check_fails_closed() {
        let mut connection = schema_seventeen_connection();
        apply_generation_catchup_attempt_upgrade(&mut connection);
        // The persisted SQL file is normalized before string surgery so the
        // weakening is robust to the working-tree line ending (CRLF checkout).
        let normalized_ddl = CREATE_REBUILD_CATCHUP_ATTEMPT_TABLE_SQL.replace("\r\n", "\n");
        let weakened = normalized_ddl.replace(
            "CHECK ((desired_action='upsert' AND target_revision IS NOT NULL AND target_revision>0 AND target_content_hash IS NOT NULL AND target_content_hash<>'')\n        OR (desired_action='delete' AND target_revision IS NULL AND target_content_hash IS NULL AND canonical_document IS NULL))",
            "CHECK (desired_action IN ('upsert','delete'))",
        );
        assert_ne!(weakened, normalized_ddl);
        let schema_cookie: i64 = connection
            .query_row("PRAGMA schema_version", [], |r| r.get(0))
            .unwrap();
        connection
            .execute_batch("PRAGMA writable_schema=ON")
            .unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE sqlite_schema SET sql=?1 WHERE type='table' AND name='memory_vector_generation_rebuild_catchup_item'",
                    [&weakened],
                )
                .unwrap(),
            1
        );
        connection
            .pragma_update(None, "schema_version", schema_cookie + 1)
            .unwrap();
        connection
            .execute_batch("PRAGMA writable_schema=OFF")
            .unwrap();

        let error = validate_generation_catchup_attempt_schema(&connection).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        // No repair: the weakened DDL is still present in the database.
        let remaining: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_rebuild_catchup_item'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(remaining.contains("CHECK (desired_action IN ('upsert','delete'))"));
    }

    #[test]
    fn d9d3_d_f1_schema18_weakened_attempt_count_domain_fails_closed() {
        let mut connection = schema_seventeen_connection();
        apply_generation_catchup_attempt_upgrade(&mut connection);
        let weakened = CREATE_REBUILD_CATCHUP_ATTEMPT_TABLE_SQL.replace(
            "attempt_count BETWEEN 0 AND 5",
            "attempt_count BETWEEN 0 AND 9",
        );
        assert_ne!(weakened, CREATE_REBUILD_CATCHUP_ATTEMPT_TABLE_SQL);
        let schema_cookie: i64 = connection
            .query_row("PRAGMA schema_version", [], |r| r.get(0))
            .unwrap();
        connection
            .execute_batch("PRAGMA writable_schema=ON")
            .unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE sqlite_schema SET sql=?1 WHERE type='table' AND name='memory_vector_generation_rebuild_catchup_item'",
                    [&weakened],
                )
                .unwrap(),
            1
        );
        connection
            .pragma_update(None, "schema_version", schema_cookie + 1)
            .unwrap();
        connection
            .execute_batch("PRAGMA writable_schema=OFF")
            .unwrap();

        let error = validate_generation_catchup_attempt_schema(&connection).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        let remaining: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_rebuild_catchup_item'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(remaining.contains("attempt_count BETWEEN 0 AND 9"));
    }

    #[test]
    fn migration_017_upgrades_schema_sixteen_with_zero_active_pointer_and_unverified_witness() {
        let mut connection = schema_sixteen_connection();
        insert_historical_row(
            &connection,
            HistoricalRowFixture {
                life_id: "migration-017-life",
                memory_id: "migration-017-historical-row",
                desired_action: "upsert",
                state: "pending",
                migration_disposition: None,
                attempt_count: 0,
                mutation_sequence: 1,
                target_revision: Some(1),
                target_content_hash: Some("migration-017-content"),
                claimed_generation_id: None,
                last_error_code: None,
                last_send_disposition: None,
                next_attempt_at: None,
                lease_owner: None,
                lease_fence_epoch: None,
                lease_expires_at: None,
            },
        );
        connection
            .execute(
                "INSERT INTO memory_vector_generation
                 (generation_id,descriptor_hash,dimension,state,authority_epoch)
                 VALUES ('generation-building','descriptor-building',8,'building',1)",
                [],
            )
            .unwrap();
        apply_generation_lifecycle_upgrade(&mut connection);
        assert_eq!(
            schema_version(&connection),
            GENERATION_LIFECYCLE_SCHEMA_VERSION
        );
        validate_generation_lifecycle_schema(&connection).unwrap();
        let pointer: Option<String> = connection
            .query_row(
                "SELECT active_generation_id FROM memory_vector_generation_authority WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pointer, None);
        let witness: (Option<String>, String) = connection
            .query_row(
                "SELECT create_operation_id,state FROM memory_vector_generation_store_witness
                 WHERE generation_id='generation-building'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(witness, (None, "unverified".to_string()));
        let epoch: Option<i64> = connection
            .query_row(
                "SELECT claimed_generation_authority_epoch FROM memory_vector_sync_outbox
                 WHERE life_id='migration-017-life' AND memory_id='migration-017-historical-row'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
            .flatten();
        assert_eq!(epoch, None);
    }

    #[test]
    fn migration_017_single_active_initializes_pointer() {
        let mut connection = schema_sixteen_connection();
        connection
            .execute(
                "INSERT INTO memory_vector_generation
                 (generation_id,descriptor_hash,dimension,state,authority_epoch)
                 VALUES ('generation-active','descriptor-active',8,'active',1)",
                [],
            )
            .unwrap();
        apply_generation_lifecycle_upgrade(&mut connection);
        let pointer: Option<String> = connection
            .query_row(
                "SELECT active_generation_id FROM memory_vector_generation_authority WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pointer.as_deref(), Some("generation-active"));
    }

    #[test]
    fn migration_017_duplicate_building_fails_closed_without_schema_seventeen_objects() {
        let mut connection = schema_sixteen_connection();
        connection
            .execute_batch(
                "INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch)
                 VALUES ('generation-a','descriptor-a',8,'building',1);
                 INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch)
                 VALUES ('generation-b','descriptor-b',8,'building',1)",
            )
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_generation_lifecycle_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        drop(transaction);
        assert_eq!(
            schema_version(&connection),
            LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION
        );
        let table: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_authority'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(table, None);
    }

    #[test]
    fn migration_017_duplicate_active_fails_closed_without_schema_seventeen_objects() {
        let mut connection = schema_sixteen_connection();
        connection
            .execute_batch(
                "INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch)
                 VALUES ('generation-a','descriptor-a',8,'active',1);
                 INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch)
                 VALUES ('generation-b','descriptor-b',8,'active',1)",
            )
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_generation_lifecycle_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        drop(transaction);
        assert_eq!(
            schema_version(&connection),
            LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION
        );
        let table: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_authority'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(table, None);
    }

    #[test]
    fn migration_017_invalid_legacy_lifecycle_fails_closed_without_schema_seventeen_objects() {
        let mut connection = schema_sixteen_connection();
        // This corruption seam is test-only: Schema 16 normally rejects the
        // value, while the migration must still fail closed if a damaged file
        // reaches the upgrade boundary.
        connection
            .execute_batch(
                "PRAGMA ignore_check_constraints=ON;
                 INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch)
                 VALUES ('generation-corrupt','descriptor-corrupt',8,'corrupt',1);
                 PRAGMA ignore_check_constraints=OFF;",
            )
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = apply_generation_lifecycle_schema_upgrade(&transaction).unwrap_err();
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        drop(transaction);
        assert_eq!(
            schema_version(&connection),
            LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION
        );
        let table: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name='memory_vector_generation_authority'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(table, None);
    }

    #[test]
    fn migration_017_failpoints_roll_back_to_schema_sixteen() {
        for failpoint in [
            Migration017Failpoint::BeforeAuthorityTable,
            Migration017Failpoint::AfterAuthorityObjects,
            Migration017Failpoint::AfterOutboxTransformation,
            Migration017Failpoint::AfterIndexesAndGuards,
            Migration017Failpoint::BeforeFinalization,
            Migration017Failpoint::PreCommit,
        ] {
            let mut connection = schema_sixteen_connection();
            fail_next_migration_017_at_for_test(failpoint);
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let error = apply_generation_lifecycle_schema_upgrade(&transaction).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
            drop(transaction);
            assert_eq!(
                schema_version(&connection),
                LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION
            );
            let schema_seventeen_table_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='table'
                     AND name IN ('memory_vector_generation_authority','memory_vector_generation_binding',
                                  'memory_vector_generation_store_witness','memory_vector_generation_rebuild_job',
                                  'memory_vector_generation_rebuild_item','memory_vector_generation_rebuild_resolution')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(schema_seventeen_table_count, 0, "{failpoint:?}");
        }
    }

    /// Rewrites SQLite's persisted DDL only in this test fixture, then bumps
    /// SQLite's schema cookie so later PRAGMAs and validator reads observe a
    /// real weakened Schema-16 definition rather than a helper string.
    fn weaken_schema_sixteen_table_definition(
        connection: &Connection,
        table: &str,
        expected_fragment: &str,
        replacement: &str,
    ) {
        let original: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(original.contains(expected_fragment));
        let weakened = original.replacen(expected_fragment, replacement, 1);
        assert_ne!(weakened, original);
        let sqlite_schema_version: i64 = connection
            .query_row("PRAGMA schema_version", [], |row| row.get(0))
            .unwrap();
        connection
            .execute_batch("PRAGMA writable_schema=ON")
            .unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE sqlite_schema SET sql=?1 WHERE type='table' AND name=?2",
                    params![weakened, table],
                )
                .unwrap(),
            1
        );
        connection
            .pragma_update(None, "schema_version", sqlite_schema_version + 1)
            .unwrap();
        connection
            .execute_batch("PRAGMA writable_schema=OFF")
            .unwrap();
        assert_eq!(
            schema_version(connection),
            LATE_DELETE_GENERATION_AUTHORITY_SCHEMA_VERSION,
            "a weakened database can still claim Schema 16"
        );
    }

    #[test]
    fn schema_16_authority_epoch_domains_accept_frozen_ddl() {
        let connection = schema_sixteen_connection();
        validate_late_delete_generation_authority_schema(&connection).unwrap();
    }

    #[test]
    fn schema_16_authority_epoch_domain_rejects_removed_and_weakened_check() {
        for replacement in ["", "CHECK (authority_epoch >= 0)"] {
            let connection = schema_sixteen_connection();
            weaken_schema_sixteen_table_definition(
                &connection,
                "memory_vector_generation",
                "CHECK (authority_epoch >= 1)",
                replacement,
            );
            let error = validate_late_delete_generation_authority_schema(&connection).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        }
    }

    #[test]
    fn schema_16_captured_generation_authority_epoch_domain_rejects_removed_and_weakened_check() {
        for replacement in ["", "CHECK (captured_generation_authority_epoch >= -1)"] {
            let connection = schema_sixteen_connection();
            weaken_schema_sixteen_table_definition(
                &connection,
                "memory_vector_late_delete_resolution",
                "CHECK (captured_generation_authority_epoch >= 0)",
                replacement,
            );
            let error = validate_late_delete_generation_authority_schema(&connection).unwrap_err();
            assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        }
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

    fn assert_migration_016_rolled_back_to_schema_15(connection: &Connection) {
        assert_eq!(
            schema_version(connection),
            LATE_DELETE_RESOLUTION_SCHEMA_VERSION
        );
        let schema_16_columns: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('memory_vector_sync_outbox')
                 WHERE name='delete_witness_at'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(schema_16_columns, 0);
        assert_eq!(writer_fence_count(connection), 24);
    }

    #[test]
    fn migration_016_historical_canonical_unknown_missing_resolution() {
        let mut connection = version_fourteen_connection();
        apply_late_delete_resolution_upgrade(&mut connection);
        connection
            .execute_batch(
                "INSERT INTO memory_vector_generation
                   (generation_id,descriptor_hash,dimension,state)
                 VALUES ('historical-generation','descriptor-historical',768,'retired');
                 INSERT INTO memory_vector_sync_outbox
                   (life_id,memory_id,desired_action,state,attempt_count,mutation_sequence,
                    target_revision,target_content_hash,claimed_generation_id,
                    fenced_claim_epoch,last_marked_claim_epoch,last_send_disposition,
                    last_error_code,migration_disposition)
                 VALUES ('historical-life','missing-resolution','delete','blocked',2,71,
                         9,'legacy-target','historical-generation',7,6,'possibly_sent',
                         'TEMPORARY_FAILURE','legacy_upsert_rebuild_required');",
            )
            .unwrap();

        apply_late_delete_generation_authority_upgrade(&mut connection);
        let row: (String, i64, String, String, String, Option<String>) = connection
            .query_row(
                "SELECT r.state,r.captured_generation_authority_epoch,
                        r.witness_age_anchor_at,o.delete_witness_at,
                        r.embedding_descriptor_id,r.witness_error_code
                   FROM memory_vector_late_delete_resolution AS r
                   JOIN memory_vector_sync_outbox AS o ON o.id=r.outbox_id
                  WHERE r.life_id='historical-life' AND r.memory_id='missing-resolution'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row.0, "waiting_rebuild");
        assert_eq!(row.1, 0);
        assert_eq!(row.2, row.3);
        assert_eq!(row.4, "descriptor-historical");
        assert_eq!(
            row.5, None,
            "non-canonical error detail is not copied into the witness"
        );
    }

    #[test]
    fn migration_016_historical_canonical_unknown_missing_generation() {
        let mut connection = version_fourteen_connection();
        connection
            .execute_batch(
                "INSERT INTO memory_vector_generation
                   (generation_id,descriptor_hash,dimension,state)
                 VALUES ('existing-generation','descriptor-existing',32,'active');
                 INSERT INTO memory_vector_sync_outbox
                   (life_id,memory_id,desired_action,state,attempt_count,mutation_sequence,
                    claimed_generation_id,fenced_claim_epoch,last_marked_claim_epoch,
                    last_send_disposition)
                 VALUES ('coverage-life','existing-resolution','delete','blocked',1,81,
                         'existing-generation',1,1,'possibly_sent');",
            )
            .unwrap();
        apply_late_delete_resolution_upgrade(&mut connection);
        connection
            .execute_batch(
                "INSERT INTO memory_vector_sync_outbox
                   (life_id,memory_id,desired_action,state,attempt_count,mutation_sequence,
                    claimed_generation_id,fenced_claim_epoch,last_marked_claim_epoch,
                    last_send_disposition)
                 VALUES
                   ('coverage-life','valid-missing-resolution','delete','blocked',2,82,
                    'existing-generation',2,2,'possibly_sent'),
                   ('coverage-life','missing-generation','delete','blocked',2,83,
                    'gone-generation',3,3,'possibly_sent'),
                   ('coverage-life','ordinary-delete','delete','blocked',2,84,
                    'existing-generation',4,4,NULL),
                   ('coverage-life','unknown-upsert','upsert','blocked',2,85,
                    'existing-generation',5,5,'possibly_sent');",
            )
            .unwrap();

        let error = {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            apply_late_delete_generation_authority_schema_upgrade(&transaction).unwrap_err()
        };
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        assert_migration_016_rolled_back_to_schema_15(&connection);
        let resolution_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_late_delete_resolution
                 WHERE life_id='coverage-life'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            resolution_count, 1,
            "the valid missing row must not be partially backfilled"
        );
    }

    #[test]
    fn migration_016_historical_canonical_unknown_generation_identity_mismatch_stays_waiting_rebuild(
    ) {
        let mut connection = version_fourteen_connection();
        apply_late_delete_resolution_upgrade(&mut connection);
        // Schema 15 has no descriptor/dimension/state snapshot on the outbox.
        // A Generation whose present contract differs from the historical
        // caller expectation can therefore only supply the required SQL shape;
        // it must never turn this historical witness back into authority.
        connection
            .execute_batch(
                "INSERT INTO memory_vector_generation
                   (generation_id,descriptor_hash,dimension,state)
                 VALUES ('mismatch-generation','current-descriptor',1536,'failed');
                 INSERT INTO memory_vector_sync_outbox
                   (life_id,memory_id,desired_action,state,attempt_count,mutation_sequence,
                    claimed_generation_id,fenced_claim_epoch,last_marked_claim_epoch,
                    last_error_code)
                 VALUES ('mismatch-life','mismatch-row','delete','blocked',3,86,
                         'mismatch-generation',8,7,'PROVIDER_RESULT_UNKNOWN');",
            )
            .unwrap();

        apply_late_delete_generation_authority_upgrade(&mut connection);
        let row: (String, i64, String, i64, String) = connection
            .query_row(
                "SELECT state,captured_generation_authority_epoch,
                        embedding_descriptor_id,embedding_dimension,captured_generation_state
                   FROM memory_vector_late_delete_resolution
                  WHERE life_id='mismatch-life' AND memory_id='mismatch-row'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row.0, "waiting_rebuild");
        assert_eq!(row.1, 0);
        assert_eq!(
            (row.2, row.3, row.4),
            ("current-descriptor".into(), 1536, "failed".into())
        );
    }

    #[test]
    fn migration_016_historical_canonical_unknown_incomplete_attempt_witness_rolls_back() {
        let mut connection = version_fourteen_connection();
        apply_late_delete_resolution_upgrade(&mut connection);
        connection
            .execute_batch(
                "INSERT INTO memory_vector_generation
                   (generation_id,descriptor_hash,dimension,state)
                 VALUES ('incomplete-generation','descriptor-incomplete',64,'active');
                 INSERT INTO memory_vector_sync_outbox
                   (life_id,memory_id,desired_action,state,attempt_count,mutation_sequence,
                    claimed_generation_id,fenced_claim_epoch,last_marked_claim_epoch,
                    last_send_disposition)
                 VALUES ('incomplete-life','too-many-attempts','delete','blocked',6,87,
                         'incomplete-generation',9,9,'possibly_sent');",
            )
            .unwrap();

        let error = {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            apply_late_delete_generation_authority_schema_upgrade(&transaction).unwrap_err()
        };
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        assert_migration_016_rolled_back_to_schema_15(&connection);
    }

    #[test]
    fn migration_016_historical_canonical_unknown_postcondition() {
        let mut connection = version_fourteen_connection();
        connection
            .execute_batch(
                "INSERT INTO memory_vector_generation
                   (generation_id,descriptor_hash,dimension,state)
                 VALUES ('postcondition-generation','descriptor-postcondition',16,'building');
                 INSERT INTO memory_vector_sync_outbox
                   (life_id,memory_id,desired_action,state,attempt_count,mutation_sequence,
                    claimed_generation_id,fenced_claim_epoch,last_marked_claim_epoch,
                    last_send_disposition)
                 VALUES ('postcondition-life','wrong-outbox','delete','blocked',1,91,
                         'postcondition-generation',1,1,'possibly_sent');",
            )
            .unwrap();
        apply_late_delete_resolution_upgrade(&mut connection);
        connection
            .execute(
                "UPDATE memory_vector_late_delete_resolution SET outbox_id=999999
                 WHERE life_id='postcondition-life' AND memory_id='wrong-outbox'",
                [],
            )
            .unwrap();

        let error = {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            apply_late_delete_generation_authority_schema_upgrade(&transaction).unwrap_err()
        };
        assert_eq!(error.code, "MIGRATION_TRANSACTION_FAILED");
        assert_migration_016_rolled_back_to_schema_15(&connection);
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
