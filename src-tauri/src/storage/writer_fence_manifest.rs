//! Static writer-fence Trigger manifest.
//!
//! H1-A3 defined and validated this manifest. H1-B installs its exact static
//! contents during the fixed schema-13 transaction.

use rusqlite::{Connection, Transaction};

use super::StorageError;

pub(super) const WRITER_FENCE_SCHEMA_VERSION: i64 = 13;
pub(super) const LATE_DELETE_WRITER_FENCE_SCHEMA_VERSION: i64 = 15;
pub(super) const GENERATION_LIFECYCLE_WRITER_FENCE_SCHEMA_VERSION: i64 = 17;
pub(super) const GENERATION_CATCHUP_WRITER_FENCE_SCHEMA_VERSION: i64 = 18;
pub(super) const EMOTION_WRITER_FENCE_SCHEMA_VERSION: i64 = 19;
pub(super) const RELATIONSHIP_WRITER_FENCE_SCHEMA_VERSION: i64 = 20;
pub(super) const EXPERIENCE_EPISODE_WRITER_FENCE_SCHEMA_VERSION: i64 = 21;
pub(super) const LIFE_INTENT_WRITER_FENCE_SCHEMA_VERSION: i64 = 22;
pub(super) const AUTONOMY_WRITER_FENCE_SCHEMA_VERSION: i64 = 23;
pub(super) const PERCEPTION_WRITER_FENCE_SCHEMA_VERSION: i64 = 24;
pub(super) const BODY_PACKAGE_WRITER_FENCE_SCHEMA_VERSION: i64 = 25;
const WRITER_FENCE_TRIGGER_PREFIX: &str = "digital_life_writer_epoch_";
const HISTORICAL_WRITER_FENCE_TRIGGER_COUNT: usize = 18;
const LATE_DELETE_WRITER_FENCE_TRIGGER_COUNT: usize = 24;
const GENERATION_LIFECYCLE_WRITER_FENCE_TRIGGER_COUNT: usize = 42;
const GENERATION_CATCHUP_WRITER_FENCE_TRIGGER_COUNT: usize = 45;
const EMOTION_WRITER_FENCE_TRIGGER_COUNT: usize = 51;
const RELATIONSHIP_WRITER_FENCE_TRIGGER_COUNT: usize = 57;
const EXPERIENCE_EPISODE_WRITER_FENCE_TRIGGER_COUNT: usize = 60;
const LIFE_INTENT_WRITER_FENCE_TRIGGER_COUNT: usize = 75;
const AUTONOMY_WRITER_FENCE_TRIGGER_COUNT: usize = 87;
const PERCEPTION_WRITER_FENCE_TRIGGER_COUNT: usize = 93;
const BODY_PACKAGE_WRITER_FENCE_TRIGGER_COUNT: usize = 99;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum WriterFenceOperation {
    Insert,
    Update,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WriterFenceTriggerSpec {
    pub(super) name: &'static str,
    pub(super) table: &'static str,
    pub(super) operation: WriterFenceOperation,
    pub(super) ddl: &'static str,
}

macro_rules! writer_fence_trigger_spec {
    ($name:literal, $table:literal, $operation:ident, $operation_sql:literal) => {
        WriterFenceTriggerSpec {
            name: $name,
            table: $table,
            operation: WriterFenceOperation::$operation,
            ddl: concat!(
                "CREATE TRIGGER ",
                $name,
                "\nBEFORE ",
                $operation_sql,
                " ON ",
                $table,
                "\nWHEN digital_life_writer_epoch() IS NOT 1\nBEGIN\n    SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');\nEND"
            ),
        }
    };
}

const WRITER_FENCE_TRIGGER_SPECS: &[WriterFenceTriggerSpec] = &[
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_outbox_insert",
        "memory_vector_sync_outbox",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_outbox_update",
        "memory_vector_sync_outbox",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_outbox_delete",
        "memory_vector_sync_outbox",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_mutation_clock_insert",
        "memory_vector_sync_mutation_clock",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_mutation_clock_update",
        "memory_vector_sync_mutation_clock",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_mutation_clock_delete",
        "memory_vector_sync_mutation_clock",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_runtime_lease_insert",
        "memory_vector_sync_runtime_lease",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_runtime_lease_update",
        "memory_vector_sync_runtime_lease",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_runtime_lease_delete",
        "memory_vector_sync_runtime_lease",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_insert",
        "memory_vector_generation",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_update",
        "memory_vector_generation",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_delete",
        "memory_vector_generation",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_item_insert",
        "memory_vector_generation_item",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_item_update",
        "memory_vector_generation_item",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_item_delete",
        "memory_vector_generation_item",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_settings_insert",
        "memory_vector_sync_settings",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_settings_update",
        "memory_vector_sync_settings",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_sync_settings_delete",
        "memory_vector_sync_settings",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_late_delete_resolution_insert",
        "memory_vector_late_delete_resolution",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_late_delete_resolution_update",
        "memory_vector_late_delete_resolution",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_late_delete_resolution_delete",
        "memory_vector_late_delete_resolution",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_late_delete_runtime_lease_insert",
        "memory_vector_late_delete_runtime_lease",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_late_delete_runtime_lease_update",
        "memory_vector_late_delete_runtime_lease",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_late_delete_runtime_lease_delete",
        "memory_vector_late_delete_runtime_lease",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_authority_insert",
        "memory_vector_generation_authority",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_authority_update",
        "memory_vector_generation_authority",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_authority_delete",
        "memory_vector_generation_authority",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_binding_insert",
        "memory_vector_generation_binding",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_binding_update",
        "memory_vector_generation_binding",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_binding_delete",
        "memory_vector_generation_binding",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_store_witness_insert",
        "memory_vector_generation_store_witness",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_store_witness_update",
        "memory_vector_generation_store_witness",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_store_witness_delete",
        "memory_vector_generation_store_witness",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_job_insert",
        "memory_vector_generation_rebuild_job",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_job_update",
        "memory_vector_generation_rebuild_job",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_job_delete",
        "memory_vector_generation_rebuild_job",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_item_insert",
        "memory_vector_generation_rebuild_item",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_item_update",
        "memory_vector_generation_rebuild_item",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_item_delete",
        "memory_vector_generation_rebuild_item",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_resolution_insert",
        "memory_vector_generation_rebuild_resolution",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_resolution_update",
        "memory_vector_generation_rebuild_resolution",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_resolution_delete",
        "memory_vector_generation_rebuild_resolution",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_catchup_item_insert",
        "memory_vector_generation_rebuild_catchup_item",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_catchup_item_update",
        "memory_vector_generation_rebuild_catchup_item",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_memory_vector_generation_rebuild_catchup_item_delete",
        "memory_vector_generation_rebuild_catchup_item",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_emotion_state_insert",
        "emotion_state",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_emotion_state_update",
        "emotion_state",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_emotion_state_delete",
        "emotion_state",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_emotion_event_insert",
        "emotion_event",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_emotion_event_update",
        "emotion_event",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_emotion_event_delete",
        "emotion_event",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_relationship_state_insert",
        "relationship_state",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_relationship_state_update",
        "relationship_state",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_relationship_state_delete",
        "relationship_state",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_relationship_event_insert",
        "relationship_event",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_relationship_event_update",
        "relationship_event",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_relationship_event_delete",
        "relationship_event",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_experience_episode_insert",
        "experience_episode",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_experience_episode_update",
        "experience_episode",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_experience_episode_delete",
        "experience_episode",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_goal_insert",
        "life_goal",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_goal_update",
        "life_goal",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_goal_delete",
        "life_goal",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_plan_insert",
        "life_plan",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_plan_update",
        "life_plan",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_plan_delete",
        "life_plan",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_plan_step_insert",
        "life_plan_step",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_plan_step_update",
        "life_plan_step",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_plan_step_delete",
        "life_plan_step",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_action_intent_insert",
        "life_action_intent",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_action_intent_update",
        "life_action_intent",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_action_intent_delete",
        "life_action_intent",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_intent_event_insert",
        "life_intent_event",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_intent_event_update",
        "life_intent_event",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_intent_event_delete",
        "life_intent_event",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_autonomy_policy_insert",
        "life_autonomy_policy",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_autonomy_policy_update",
        "life_autonomy_policy",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_autonomy_policy_delete",
        "life_autonomy_policy",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_autonomy_policy_event_insert",
        "life_autonomy_policy_event",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_autonomy_policy_event_update",
        "life_autonomy_policy_event",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_autonomy_policy_event_delete",
        "life_autonomy_policy_event",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_proactive_intent_insert",
        "life_proactive_intent",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_proactive_intent_update",
        "life_proactive_intent",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_proactive_intent_delete",
        "life_proactive_intent",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_proactive_intent_event_insert",
        "life_proactive_intent_event",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_proactive_intent_event_update",
        "life_proactive_intent_event",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_proactive_intent_event_delete",
        "life_proactive_intent_event",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_perception_policy_insert",
        "life_perception_policy",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_perception_policy_update",
        "life_perception_policy",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_perception_policy_delete",
        "life_perception_policy",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_perception_policy_event_insert",
        "life_perception_policy_event",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_perception_policy_event_update",
        "life_perception_policy_event",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_life_perception_policy_event_delete",
        "life_perception_policy_event",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_body_package_insert",
        "body_package",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_body_package_update",
        "body_package",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_body_package_delete",
        "body_package",
        Delete,
        "DELETE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_body_package_asset_insert",
        "body_package_asset",
        Insert,
        "INSERT"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_body_package_asset_update",
        "body_package_asset",
        Update,
        "UPDATE"
    ),
    writer_fence_trigger_spec!(
        "digital_life_writer_epoch_body_package_asset_delete",
        "body_package_asset",
        Delete,
        "DELETE"
    ),
];

pub(super) fn writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec] {
    &WRITER_FENCE_TRIGGER_SPECS[..HISTORICAL_WRITER_FENCE_TRIGGER_COUNT]
}

pub(super) fn late_delete_writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec] {
    &WRITER_FENCE_TRIGGER_SPECS
        [HISTORICAL_WRITER_FENCE_TRIGGER_COUNT..LATE_DELETE_WRITER_FENCE_TRIGGER_COUNT]
}

pub(super) fn generation_lifecycle_writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec]
{
    &WRITER_FENCE_TRIGGER_SPECS
        [LATE_DELETE_WRITER_FENCE_TRIGGER_COUNT..GENERATION_LIFECYCLE_WRITER_FENCE_TRIGGER_COUNT]
}

pub(super) fn generation_catchup_writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec] {
    &WRITER_FENCE_TRIGGER_SPECS[GENERATION_LIFECYCLE_WRITER_FENCE_TRIGGER_COUNT
        ..GENERATION_CATCHUP_WRITER_FENCE_TRIGGER_COUNT]
}

pub(super) fn emotion_writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec] {
    &WRITER_FENCE_TRIGGER_SPECS
        [GENERATION_CATCHUP_WRITER_FENCE_TRIGGER_COUNT..EMOTION_WRITER_FENCE_TRIGGER_COUNT]
}

pub(super) fn relationship_writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec] {
    &WRITER_FENCE_TRIGGER_SPECS
        [EMOTION_WRITER_FENCE_TRIGGER_COUNT..RELATIONSHIP_WRITER_FENCE_TRIGGER_COUNT]
}

pub(super) fn experience_episode_writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec] {
    &WRITER_FENCE_TRIGGER_SPECS
        [RELATIONSHIP_WRITER_FENCE_TRIGGER_COUNT..EXPERIENCE_EPISODE_WRITER_FENCE_TRIGGER_COUNT]
}

pub(super) fn life_intent_writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec] {
    &WRITER_FENCE_TRIGGER_SPECS
        [EXPERIENCE_EPISODE_WRITER_FENCE_TRIGGER_COUNT..LIFE_INTENT_WRITER_FENCE_TRIGGER_COUNT]
}

pub(super) fn autonomy_writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec] {
    &WRITER_FENCE_TRIGGER_SPECS
        [LIFE_INTENT_WRITER_FENCE_TRIGGER_COUNT..AUTONOMY_WRITER_FENCE_TRIGGER_COUNT]
}

pub(super) fn perception_writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec] {
    &WRITER_FENCE_TRIGGER_SPECS
        [AUTONOMY_WRITER_FENCE_TRIGGER_COUNT..PERCEPTION_WRITER_FENCE_TRIGGER_COUNT]
}

pub(super) fn body_package_writer_fence_trigger_specs() -> &'static [WriterFenceTriggerSpec] {
    &WRITER_FENCE_TRIGGER_SPECS
        [PERCEPTION_WRITER_FENCE_TRIGGER_COUNT..BODY_PACKAGE_WRITER_FENCE_TRIGGER_COUNT]
}

pub(super) fn install_life_intent_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in life_intent_writer_fence_trigger_specs().iter().enumerate() {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(
            EXPERIENCE_EPISODE_WRITER_FENCE_TRIGGER_COUNT + index + 1,
        ) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

pub(super) fn install_autonomy_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in autonomy_writer_fence_trigger_specs().iter().enumerate() {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(
            LIFE_INTENT_WRITER_FENCE_TRIGGER_COUNT + index + 1,
        ) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

pub(super) fn install_perception_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in perception_writer_fence_trigger_specs().iter().enumerate() {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(AUTONOMY_WRITER_FENCE_TRIGGER_COUNT + index + 1)
        {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

pub(super) fn install_body_package_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in body_package_writer_fence_trigger_specs().iter().enumerate() {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(
            PERCEPTION_WRITER_FENCE_TRIGGER_COUNT + index + 1,
        ) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

pub(super) fn install_experience_episode_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in experience_episode_writer_fence_trigger_specs()
        .iter()
        .enumerate()
    {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(
            RELATIONSHIP_WRITER_FENCE_TRIGGER_COUNT + index + 1,
        ) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

pub(super) fn install_relationship_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in relationship_writer_fence_trigger_specs().iter().enumerate() {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(EMOTION_WRITER_FENCE_TRIGGER_COUNT + index + 1) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

pub(super) fn install_emotion_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in emotion_writer_fence_trigger_specs().iter().enumerate() {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(
            GENERATION_CATCHUP_WRITER_FENCE_TRIGGER_COUNT + index + 1,
        ) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

pub(super) fn install_generation_catchup_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in generation_catchup_writer_fence_trigger_specs()
        .iter()
        .enumerate()
    {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(
            GENERATION_LIFECYCLE_WRITER_FENCE_TRIGGER_COUNT + index + 1,
        ) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

/// Installs the fixed manifest into the caller-owned schema transaction. The
/// manifest remains the sole authority for names, tables, operations, and DDL.
pub(super) fn install_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in writer_fence_trigger_specs().iter().enumerate() {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(index + 1) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

pub(super) fn install_late_delete_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in late_delete_writer_fence_trigger_specs().iter().enumerate() {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(
            HISTORICAL_WRITER_FENCE_TRIGGER_COUNT + index + 1,
        ) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

pub(super) fn install_generation_lifecycle_writer_fence_manifest_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<(), StorageError> {
    for (index, spec) in generation_lifecycle_writer_fence_trigger_specs()
        .iter()
        .enumerate()
    {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if should_fail_trigger_install_at_for_test(
            LATE_DELETE_WRITER_FENCE_TRIGGER_COUNT + index + 1,
        ) {
            return Err(StorageError::migration_transaction_failed());
        }
        transaction
            .execute_batch(spec.ddl)
            .map_err(|_| StorageError::migration_transaction_failed())?;
    }
    Ok(())
}

/// Confirms that the reserved writer-fence Trigger namespace exactly matches
/// the static manifest. This never repairs or installs schema objects.
pub(super) fn validate_writer_fence_manifest(connection: &Connection) -> Result<(), StorageError> {
    validate_writer_fence_manifest_for_schema(
        connection,
        super::connection::read_schema_version(connection)?,
    )
}

/// Validates against an explicitly supplied schema version.  Migration 015
/// uses this before recording version 15, so a version row can never be the
/// thing that makes an incomplete six-trigger extension appear valid.
pub(super) fn validate_writer_fence_manifest_for_schema(
    connection: &Connection,
    schema_version: i64,
) -> Result<(), StorageError> {
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema")
        .map_err(|_| StorageError::writer_fence_manifest_mismatch())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|_| StorageError::writer_fence_manifest_mismatch())?;

    let expected = if schema_version >= BODY_PACKAGE_WRITER_FENCE_SCHEMA_VERSION {
        WRITER_FENCE_TRIGGER_SPECS
    } else if schema_version >= PERCEPTION_WRITER_FENCE_SCHEMA_VERSION {
        &WRITER_FENCE_TRIGGER_SPECS[..PERCEPTION_WRITER_FENCE_TRIGGER_COUNT]
    } else if schema_version >= AUTONOMY_WRITER_FENCE_SCHEMA_VERSION {
        &WRITER_FENCE_TRIGGER_SPECS[..AUTONOMY_WRITER_FENCE_TRIGGER_COUNT]
    } else if schema_version >= LIFE_INTENT_WRITER_FENCE_SCHEMA_VERSION {
        &WRITER_FENCE_TRIGGER_SPECS[..LIFE_INTENT_WRITER_FENCE_TRIGGER_COUNT]
    } else if schema_version >= EXPERIENCE_EPISODE_WRITER_FENCE_SCHEMA_VERSION {
        &WRITER_FENCE_TRIGGER_SPECS[..EXPERIENCE_EPISODE_WRITER_FENCE_TRIGGER_COUNT]
    } else if schema_version >= RELATIONSHIP_WRITER_FENCE_SCHEMA_VERSION {
        &WRITER_FENCE_TRIGGER_SPECS[..RELATIONSHIP_WRITER_FENCE_TRIGGER_COUNT]
    } else if schema_version >= EMOTION_WRITER_FENCE_SCHEMA_VERSION {
        &WRITER_FENCE_TRIGGER_SPECS[..EMOTION_WRITER_FENCE_TRIGGER_COUNT]
    } else if schema_version >= GENERATION_CATCHUP_WRITER_FENCE_SCHEMA_VERSION {
        &WRITER_FENCE_TRIGGER_SPECS[..GENERATION_CATCHUP_WRITER_FENCE_TRIGGER_COUNT]
    } else if schema_version >= GENERATION_LIFECYCLE_WRITER_FENCE_SCHEMA_VERSION {
        &WRITER_FENCE_TRIGGER_SPECS[..GENERATION_LIFECYCLE_WRITER_FENCE_TRIGGER_COUNT]
    } else if schema_version >= LATE_DELETE_WRITER_FENCE_SCHEMA_VERSION {
        &WRITER_FENCE_TRIGGER_SPECS[..LATE_DELETE_WRITER_FENCE_TRIGGER_COUNT]
    } else {
        writer_fence_trigger_specs()
    };
    let mut found = vec![false; expected.len()];
    for row in rows {
        let (object_type, name, table, sql) =
            row.map_err(|_| StorageError::writer_fence_manifest_mismatch())?;
        if !name
            .to_ascii_lowercase()
            .starts_with(WRITER_FENCE_TRIGGER_PREFIX)
        {
            continue;
        }

        let Some((index, expected_spec)) = expected
            .iter()
            .enumerate()
            .find(|(_, expected_spec)| expected_spec.name == name)
        else {
            return Err(StorageError::writer_fence_manifest_mismatch());
        };

        if object_type != "trigger"
            || table.as_deref() != Some(expected_spec.table)
            || sql.as_deref() != Some(expected_spec.ddl)
        {
            return Err(StorageError::writer_fence_manifest_mismatch());
        }
        found[index] = true;
    }

    if found.iter().any(|present| !present) {
        return Err(StorageError::writer_fence_manifest_missing());
    }
    Ok(())
}

// Compile-time contracts retain the future validator and runtime classification
// without allowing H1-A3's production initialization to invoke either one.
const _: fn(&Connection) -> Result<(), StorageError> = validate_writer_fence_manifest;
const _: fn() -> StorageError = StorageError::incompatible_database_writer;

#[cfg(test)]
thread_local! {
    static FAIL_TRIGGER_INSTALL_AT: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(super) fn fail_trigger_install_at_for_test(index: usize) {
    FAIL_TRIGGER_INSTALL_AT.with(|fail_at| fail_at.set(Some(index)));
}

#[cfg(test)]
fn should_fail_trigger_install_at_for_test(index: usize) -> bool {
    FAIL_TRIGGER_INSTALL_AT.with(|fail_at| {
        if fail_at.get() == Some(index) {
            fail_at.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        path::{Path, PathBuf},
    };

    use rusqlite::{functions::FunctionFlags, params, Connection, Error};

    use super::*;

    const PROTECTED_TABLES: [&str; 6] = [
        "memory_vector_sync_outbox",
        "memory_vector_sync_mutation_clock",
        "memory_vector_sync_runtime_lease",
        "memory_vector_generation",
        "memory_vector_generation_item",
        "memory_vector_sync_settings",
    ];

    fn manifest_connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        for table in PROTECTED_TABLES {
            connection
                .execute_batch(&format!("CREATE TABLE {table} (id INTEGER PRIMARY KEY)"))
                .unwrap();
        }
        connection
    }

    fn install_manifest(connection: &Connection) {
        for spec in writer_fence_trigger_specs() {
            connection.execute_batch(spec.ddl).unwrap();
        }
    }

    fn expect_error(result: Result<(), StorageError>, code: &str) {
        let error = result.expect_err("the static writer-fence manifest must reject the schema");
        assert_eq!(error.code, code);
    }

    fn replace_trigger(connection: &Connection, spec: WriterFenceTriggerSpec, ddl: &str) {
        connection
            .execute_batch(&format!("DROP TRIGGER {}", spec.name))
            .unwrap();
        connection.execute_batch(ddl).unwrap();
    }

    fn initialized_fenced_database() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let storage =
            super::super::StorageService::initialize_with_roots(root.path().to_path_buf(), None)
                .unwrap();
        let path = storage.test_database_main_path().unwrap();
        drop(storage);
        (root, path)
    }

    fn initialized_schema_twenty_two_database() -> (tempfile::TempDir, PathBuf) {
        let (root, path) = initialized_fenced_database();
        let connection = authorized_connection(&path);
        connection
            .execute_batch(
                "DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_asset_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_asset_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_asset_delete;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_delete;
                 DROP TRIGGER IF EXISTS body_package_asset_immutable_guard;
                 DROP TRIGGER IF EXISTS body_package_immutable_guard;
                 DROP TABLE IF EXISTS body_package_asset;
                 DROP TABLE IF EXISTS body_package;
                 DELETE FROM schema_migration WHERE version = 25;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_event_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_event_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_event_delete;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_delete;
                 DROP TRIGGER IF EXISTS life_perception_policy_immutable_guard;
                 DROP TRIGGER IF EXISTS life_perception_policy_event_immutable_guard;
                 DROP TABLE IF EXISTS life_perception_policy_event;
                 DROP TABLE IF EXISTS life_perception_policy;
                 DELETE FROM schema_migration WHERE version = 24;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_autonomy_policy_event_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_autonomy_policy_event_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_autonomy_policy_event_delete;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_autonomy_policy_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_autonomy_policy_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_autonomy_policy_delete;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_proactive_intent_event_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_proactive_intent_event_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_proactive_intent_event_delete;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_proactive_intent_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_proactive_intent_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_proactive_intent_delete;
                 DROP TRIGGER IF EXISTS life_autonomy_policy_immutable_guard;
                 DROP TRIGGER IF EXISTS life_autonomy_policy_event_immutable_guard;
                 DROP TRIGGER IF EXISTS life_proactive_intent_immutable_guard;
                 DROP TRIGGER IF EXISTS life_proactive_intent_event_immutable_guard;
                 DROP TABLE IF EXISTS life_proactive_intent_event;
                 DROP TABLE IF EXISTS life_proactive_intent;
                 DROP TABLE IF EXISTS life_autonomy_policy_event;
                 DROP TABLE IF EXISTS life_autonomy_policy;
                 DELETE FROM schema_migration WHERE version = 23;",
            )
            .unwrap();
        drop(connection);
        (root, path)
    }

    fn initialized_schema_twenty_three_database() -> (tempfile::TempDir, PathBuf) {
        let (root, path) = initialized_fenced_database();
        let connection = authorized_connection(&path);
        connection
            .execute_batch(
                "DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_asset_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_asset_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_asset_delete;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_body_package_delete;
                 DROP TRIGGER IF EXISTS body_package_asset_immutable_guard;
                 DROP TRIGGER IF EXISTS body_package_immutable_guard;
                 DROP TABLE IF EXISTS body_package_asset;
                 DROP TABLE IF EXISTS body_package;
                 DELETE FROM schema_migration WHERE version = 25;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_event_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_event_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_event_delete;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_insert;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_update;
                 DROP TRIGGER IF EXISTS digital_life_writer_epoch_life_perception_policy_delete;
                 DROP TRIGGER IF EXISTS life_perception_policy_immutable_guard;
                 DROP TRIGGER IF EXISTS life_perception_policy_event_immutable_guard;
                 DROP TABLE IF EXISTS life_perception_policy_event;
                 DROP TABLE IF EXISTS life_perception_policy;
                 DELETE FROM schema_migration WHERE version = 24;",
            )
            .unwrap();
        drop(connection);
        (root, path)
    }

    fn seed_protected_rows(connection: &Connection) {
        connection
            .execute_batch(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES ('writer-fence-persona', 'Writer Fence', 1, '{}');
                 INSERT INTO life_identity
                     (id, name, created_at, version, body_id, persona_id, persona_version)
                 VALUES
                     ('writer-fence-life', 'Writer Fence', '2026-01-01T00:00:00.000Z', 1,
                      'writer-fence-body', 'writer-fence-persona', 1),
                     ('writer-fence-life-alt', 'Writer Fence Alt', '2026-01-01T00:00:00.000Z', 1,
                      'writer-fence-body-alt', 'writer-fence-persona', 1);
                 INSERT INTO memory_vector_sync_outbox
                     (life_id, memory_id, desired_action, state, attempt_count, mutation_sequence)
                 VALUES ('writer-fence-life', 'outbox-seed', 'delete', 'pending', 2, 4);
                 UPDATE memory_vector_sync_mutation_clock
                 SET last_sequence=4 WHERE singleton=1;
                 INSERT INTO memory_vector_sync_runtime_lease
                     (lease_name, owner_id, fence_epoch, expires_at)
                 VALUES ('memory-vector-single-event-consumer', 'seed-owner', 4,
                         '2026-02-01T00:00:00.000Z');
                 INSERT INTO memory_vector_generation
                     (generation_id, descriptor_hash, dimension, state, authority_epoch)
                 VALUES ('generation-seed', 'seed-descriptor', 3, 'building', 1);
                 INSERT INTO memory_vector_generation_item
                     (generation_id, life_id, memory_id, memory_revision, content_hash)
                 VALUES ('generation-seed', 'writer-fence-life', 'item-seed', 1, 'seed-hash');
                 INSERT INTO memory_vector_sync_settings (life_id, enabled)
                 VALUES ('writer-fence-life', 1);",
            )
            .unwrap();
    }

    fn authorized_connection(path: &Path) -> Connection {
        super::super::connection::open_authorized_test_connection(path).unwrap()
    }

    fn protected_insert(connection: &Connection, table: &str) -> rusqlite::Result<usize> {
        match table {
            "memory_vector_sync_outbox" => connection.execute(
                "INSERT INTO memory_vector_sync_outbox
                 (life_id, memory_id, desired_action, state, attempt_count, mutation_sequence)
                 VALUES ('writer-fence-life', 'outbox-insert', 'delete', 'pending', 0, 5)",
                [],
            ),
            "memory_vector_sync_mutation_clock" => connection.execute(
                "INSERT OR REPLACE INTO memory_vector_sync_mutation_clock (singleton, last_sequence)
                 VALUES (1, 5)",
                [],
            ),
            "memory_vector_sync_runtime_lease" => connection.execute(
                "INSERT OR REPLACE INTO memory_vector_sync_runtime_lease
                 (lease_name, owner_id, fence_epoch, expires_at)
                 VALUES ('memory-vector-single-event-consumer', 'insert-owner', 5,
                         '2026-03-01T00:00:00.000Z')",
                [],
            ),
            "memory_vector_generation" => connection.execute(
                "INSERT INTO memory_vector_generation
                 (generation_id, descriptor_hash, dimension, state)
                 VALUES ('generation-insert', 'insert-descriptor', 3, 'failed')",
                [],
            ),
            "memory_vector_generation_item" => connection.execute(
                "INSERT INTO memory_vector_generation_item
                 (generation_id, life_id, memory_id, memory_revision, content_hash)
                 VALUES ('generation-seed', 'writer-fence-life', 'item-insert', 1, 'insert-hash')",
                [],
            ),
            "memory_vector_sync_settings" => connection.execute(
                "INSERT INTO memory_vector_sync_settings (life_id, enabled)
                 VALUES ('writer-fence-life-alt', 1)",
                [],
            ),
            _ => unreachable!("the protected table list is static"),
        }
    }

    fn protected_update(connection: &Connection, table: &str) -> rusqlite::Result<usize> {
        match table {
            "memory_vector_sync_outbox" => connection.execute(
                "UPDATE memory_vector_sync_outbox
                 SET updated_at='2026-04-01T00:00:00.000Z'
                 WHERE life_id='writer-fence-life' AND memory_id='outbox-seed'",
                [],
            ),
            "memory_vector_sync_mutation_clock" => connection.execute(
                "UPDATE memory_vector_sync_mutation_clock
                 SET last_sequence=last_sequence+1 WHERE singleton=1",
                [],
            ),
            "memory_vector_sync_runtime_lease" => connection.execute(
                "UPDATE memory_vector_sync_runtime_lease SET owner_id='updated-owner'
                 WHERE lease_name='memory-vector-single-event-consumer'",
                [],
            ),
            "memory_vector_generation" => connection.execute(
                "UPDATE memory_vector_generation SET state='active', authority_epoch=authority_epoch+1
                 WHERE generation_id='generation-seed'",
                [],
            ),
            "memory_vector_generation_item" => connection.execute(
                "UPDATE memory_vector_generation_item SET content_hash='updated-hash'
                 WHERE generation_id='generation-seed' AND life_id='writer-fence-life'
                   AND memory_id='item-seed'",
                [],
            ),
            "memory_vector_sync_settings" => connection.execute(
                "UPDATE memory_vector_sync_settings SET enabled=0 WHERE life_id='writer-fence-life'",
                [],
            ),
            _ => unreachable!("the protected table list is static"),
        }
    }

    fn protected_delete(connection: &Connection, table: &str) -> rusqlite::Result<usize> {
        match table {
            "memory_vector_sync_outbox" => connection.execute(
                "DELETE FROM memory_vector_sync_outbox
                 WHERE life_id='writer-fence-life' AND memory_id='outbox-seed'",
                [],
            ),
            "memory_vector_sync_mutation_clock" => connection.execute(
                "DELETE FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                [],
            ),
            "memory_vector_sync_runtime_lease" => connection.execute(
                "DELETE FROM memory_vector_sync_runtime_lease
                 WHERE lease_name='memory-vector-single-event-consumer'",
                [],
            ),
            "memory_vector_generation" => connection.execute(
                "DELETE FROM memory_vector_generation WHERE generation_id='generation-seed'",
                [],
            ),
            "memory_vector_generation_item" => connection.execute(
                "DELETE FROM memory_vector_generation_item
                 WHERE generation_id='generation-seed' AND life_id='writer-fence-life'
                   AND memory_id='item-seed'",
                [],
            ),
            "memory_vector_sync_settings" => connection.execute(
                "DELETE FROM memory_vector_sync_settings WHERE life_id='writer-fence-life'",
                [],
            ),
            _ => unreachable!("the protected table list is static"),
        }
    }

    fn update_attempt_count(connection: &Connection) -> rusqlite::Result<usize> {
        connection.execute(
            "UPDATE memory_vector_sync_outbox
             SET attempt_count=3
             WHERE life_id='writer-fence-life' AND memory_id='outbox-seed'",
            [],
        )
    }

    fn update_fenced_claim_epoch(connection: &Connection) -> rusqlite::Result<usize> {
        connection.execute(
            "UPDATE memory_vector_sync_outbox
             SET fenced_claim_epoch=1
             WHERE life_id='writer-fence-life' AND memory_id='outbox-seed'",
            [],
        )
    }

    fn update_last_marked_claim_epoch(connection: &Connection) -> rusqlite::Result<usize> {
        connection.execute(
            "UPDATE memory_vector_sync_outbox
             SET last_marked_claim_epoch=0
             WHERE life_id='writer-fence-life' AND memory_id='outbox-seed'",
            [],
        )
    }

    fn late_delete_resolution_insert(connection: &Connection) -> rusqlite::Result<usize> {
        connection.execute(
            "INSERT INTO memory_vector_late_delete_resolution
             (outbox_id, life_id, memory_id, mutation_sequence, claimed_generation_id,
              embedding_descriptor_id, embedding_dimension, captured_generation_state,
              witness_attempt_ordinal, witness_claim_epoch, witness_marked_claim_epoch,
              witness_send_disposition, witness_age_anchor_at, captured_generation_authority_epoch,
              state, created_at, updated_at)
             VALUES (991, 'writer-fence-life', 'late-resolution', 991, 'generation-seed',
                     'seed-descriptor', 3, 'building', 1, 1, 1, 'possibly_sent',
                     '2026-01-01T00:00:00.000Z', 1, 'pending',
                     '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')",
            [],
        )
    }

    fn late_delete_runtime_lease_insert(connection: &Connection) -> rusqlite::Result<usize> {
        connection.execute(
            "INSERT INTO memory_vector_late_delete_runtime_lease
             (lease_name, lease_owner, lease_fence_epoch, lease_expires_at, created_at, updated_at)
             VALUES ('memory-vector-late-delete-resolver', NULL, 0, NULL,
                     '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')",
            [],
        )
    }

    fn expect_static_incompatible_writer(result: rusqlite::Result<usize>) {
        match result.unwrap_err() {
            Error::SqliteFailure(_, Some(message)) => {
                assert_eq!(message, "INCOMPATIBLE_DATABASE_WRITER");
            }
            other => panic!("epoch-zero writer must receive the static trigger error: {other}"),
        }
    }

    #[test]
    fn writer_fence_manifest_has_exactly_eighteen_static_specs() {
        assert_eq!(WRITER_FENCE_SCHEMA_VERSION, 13);
        assert_eq!(writer_fence_trigger_specs().len(), 18);
    }

    #[test]
    fn writer_fence_manifest_covers_every_protected_table_and_operation() {
        for table in PROTECTED_TABLES {
            let operations = writer_fence_trigger_specs()
                .iter()
                .filter(|spec| spec.table == table)
                .map(|spec| spec.operation)
                .collect::<BTreeSet<_>>();
            assert_eq!(
                operations,
                BTreeSet::from([
                    WriterFenceOperation::Insert,
                    WriterFenceOperation::Update,
                    WriterFenceOperation::Delete,
                ])
            );
        }
    }

    #[test]
    fn writer_fence_manifest_names_and_exact_ddls_are_unique() {
        let names = writer_fence_trigger_specs()
            .iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), 18);
        for spec in writer_fence_trigger_specs() {
            assert!(spec.name.starts_with(WRITER_FENCE_TRIGGER_PREFIX));
            assert!(spec
                .ddl
                .starts_with(&format!("CREATE TRIGGER {}\nBEFORE ", spec.name)));
            assert!(spec.ddl.contains(&format!(" ON {}\n", spec.table)));
            assert!(spec.ddl.contains("digital_life_writer_epoch() IS NOT 1"));
            assert!(spec
                .ddl
                .contains("RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER')"));
            assert!(!spec.ddl.contains("IF NOT EXISTS"));
        }
    }

    #[test]
    fn writer_fence_manifest_validator_accepts_an_exact_manifest() {
        let connection = manifest_connection();
        install_manifest(&connection);
        validate_writer_fence_manifest(&connection).unwrap();
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_missing_trigger_without_repairing_it() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let missing = writer_fence_trigger_specs()[0];
        connection
            .execute_batch(&format!("DROP TRIGGER {}", missing.name))
            .unwrap();

        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISSING",
        );
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = ?1",
                [missing.name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_renamed_reserved_trigger() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        connection
            .execute_batch(&format!("DROP TRIGGER {}", spec.name))
            .unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER digital_life_writer_epoch_renamed_insert
                 BEFORE INSERT ON memory_vector_sync_outbox
                 WHEN digital_life_writer_epoch() IS NOT 1
                 BEGIN
                     SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
                 END",
            )
            .unwrap();

        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_wrong_table() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        replace_trigger(
            &connection,
            spec,
            "CREATE TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert
             BEFORE INSERT ON memory_vector_generation
             WHEN digital_life_writer_epoch() IS NOT 1
             BEGIN
                 SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
             END",
        );
        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_changed_operation() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        replace_trigger(
            &connection,
            spec,
            "CREATE TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert
             BEFORE UPDATE ON memory_vector_sync_outbox
             WHEN digital_life_writer_epoch() IS NOT 1
             BEGIN
                 SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
             END",
        );
        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_changed_capability_function() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        replace_trigger(
            &connection,
            spec,
            "CREATE TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert
             BEFORE INSERT ON memory_vector_sync_outbox
             WHEN another_writer_epoch() IS NOT 1
             BEGIN
                 SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
             END",
        );
        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_a_changed_epoch_value() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        replace_trigger(
            &connection,
            spec,
            "CREATE TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert
             BEFORE INSERT ON memory_vector_sync_outbox
             WHEN digital_life_writer_epoch() IS NOT 2
             BEGIN
                 SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
             END",
        );
        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_abort_instead_of_rollback() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        replace_trigger(
            &connection,
            spec,
            "CREATE TRIGGER digital_life_writer_epoch_memory_vector_sync_outbox_insert
             BEFORE INSERT ON memory_vector_sync_outbox
             WHEN digital_life_writer_epoch() IS NOT 1
             BEGIN
                 SELECT RAISE(ABORT, 'INCOMPATIBLE_DATABASE_WRITER');
             END",
        );
        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_null_sql() {
        let connection = manifest_connection();
        install_manifest(&connection);
        let spec = writer_fence_trigger_specs()[0];
        connection
            .pragma_update(None, "writable_schema", "ON")
            .unwrap();
        connection
            .execute(
                "UPDATE sqlite_schema SET sql = NULL WHERE name = ?1",
                [spec.name],
            )
            .unwrap();
        connection
            .pragma_update(None, "writable_schema", "OFF")
            .unwrap();

        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_rejects_an_unregistered_reserved_trigger() {
        let connection = manifest_connection();
        install_manifest(&connection);
        connection
            .execute_batch(
                "CREATE TRIGGER digital_life_writer_epoch_unregistered_insert
                 BEFORE INSERT ON memory_vector_sync_outbox
                 WHEN digital_life_writer_epoch() IS NOT 1
                 BEGIN
                     SELECT RAISE(ROLLBACK, 'INCOMPATIBLE_DATABASE_WRITER');
                 END",
            )
            .unwrap();

        expect_error(
            validate_writer_fence_manifest(&connection),
            "WRITER_FENCE_MANIFEST_MISMATCH",
        );
    }

    #[test]
    fn writer_fence_manifest_validator_allows_an_unrelated_business_trigger() {
        let connection = manifest_connection();
        install_manifest(&connection);
        connection
            .execute_batch(
                "CREATE TRIGGER unrelated_business_trigger
                 BEFORE INSERT ON memory_vector_sync_outbox
                 BEGIN
                     SELECT 1;
                 END",
            )
            .unwrap();

        validate_writer_fence_manifest(&connection).unwrap();
    }

    #[test]
    fn incompatible_database_writer_error_is_static_and_deidentified() {
        let error = StorageError::incompatible_database_writer();
        assert_eq!(error.code, "INCOMPATIBLE_DATABASE_WRITER");
        assert!(!error.message.contains("CREATE TRIGGER"));
        assert!(!error.message.contains("\\\\"));
    }

    #[test]
    fn generation_semantic_errors_are_static_and_deidentified() {
        for error in [
            StorageError::generation_authority_delete_forbidden(),
            StorageError::generation_identity_immutable(),
        ] {
            assert!(!error.recoverable);
            assert!(!error.message.contains("CREATE TRIGGER"));
            assert!(!error.message.contains("\\\\"));
        }
    }

    #[test]
    fn writer_fence_authorized_fixture_permits_all_eighteen_operations() {
        let (_root, path) = initialized_fenced_database();
        let connection = authorized_connection(&path);
        seed_protected_rows(&connection);

        for table in PROTECTED_TABLES {
            assert_eq!(
                protected_insert(&connection, table).unwrap(),
                1,
                "{table} insert"
            );
            assert_eq!(
                protected_update(&connection, table).unwrap(),
                1,
                "{table} update"
            );
        }
        for table in [
            "memory_vector_sync_outbox",
            "memory_vector_sync_mutation_clock",
            "memory_vector_sync_runtime_lease",
            "memory_vector_generation_item",
            "memory_vector_sync_settings",
        ] {
            assert_eq!(
                protected_delete(&connection, table).unwrap(),
                1,
                "{table} delete"
            );
        }
        let delete_error = protected_delete(&connection, "memory_vector_generation").unwrap_err();
        assert!(delete_error
            .to_string()
            .contains("GENERATION_AUTHORITY_DELETE_FORBIDDEN"));
    }

    #[test]
    fn writer_fence_raw_legacy_connection_rejects_all_eighteen_operations() {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        seed_protected_rows(&authorized);
        drop(authorized);
        let raw = Connection::open(&path).unwrap();

        for table in PROTECTED_TABLES {
            assert!(
                protected_insert(&raw, table).is_err(),
                "{table} insert must fail"
            );
            assert!(
                protected_update(&raw, table).is_err(),
                "{table} update must fail"
            );
            assert!(
                protected_delete(&raw, table).is_err(),
                "{table} delete must fail"
            );
        }
    }

    #[test]
    fn schema_15_writer_fence_has_exactly_twenty_four_specs_and_protects_late_delete_tables() {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        validate_writer_fence_manifest(&authorized).unwrap();
        assert_eq!(writer_fence_trigger_specs().len(), 18);
        assert_eq!(late_delete_writer_fence_trigger_specs().len(), 6);
        assert_eq!(generation_lifecycle_writer_fence_trigger_specs().len(), 18);
        assert_eq!(generation_catchup_writer_fence_trigger_specs().len(), 3);
        assert_eq!(emotion_writer_fence_trigger_specs().len(), 6);
        assert_eq!(relationship_writer_fence_trigger_specs().len(), 6);
        assert_eq!(experience_episode_writer_fence_trigger_specs().len(), 3);
        assert_eq!(life_intent_writer_fence_trigger_specs().len(), 15);
        assert_eq!(autonomy_writer_fence_trigger_specs().len(), 12);
        assert_eq!(WRITER_FENCE_TRIGGER_SPECS.len(), 99);
        let resolution_id = late_delete_resolution_insert(&authorized).unwrap();
        assert_eq!(resolution_id, 1);
        assert_eq!(authorized.execute("UPDATE memory_vector_late_delete_resolution SET updated_at='2026-01-02T00:00:00.000Z' WHERE memory_id='late-resolution'", []).unwrap(), 1);
        assert_eq!(authorized.execute("DELETE FROM memory_vector_late_delete_resolution WHERE memory_id='late-resolution'", []).unwrap(), 1);
        assert_eq!(authorized.execute("UPDATE memory_vector_late_delete_runtime_lease SET updated_at='2026-01-02T00:00:00.000Z' WHERE lease_name='memory-vector-late-delete-resolver'", []).unwrap(), 1);
        assert_eq!(authorized.execute("DELETE FROM memory_vector_late_delete_runtime_lease WHERE lease_name='memory-vector-late-delete-resolver'", []).unwrap(), 1);
        assert_eq!(late_delete_runtime_lease_insert(&authorized).unwrap(), 1);
        assert_eq!(late_delete_resolution_insert(&authorized).unwrap(), 1);
        drop(authorized);

        let raw = Connection::open(&path).unwrap();
        raw.create_scalar_function(
            "digital_life_writer_epoch",
            0,
            FunctionFlags::SQLITE_UTF8
                | FunctionFlags::SQLITE_DETERMINISTIC
                | FunctionFlags::SQLITE_INNOCUOUS,
            |_| Ok(0_i64),
        )
        .unwrap();
        for (operation, result) in [
            ("resolution insert", late_delete_resolution_insert(&raw)),
            ("resolution update", raw.execute("UPDATE memory_vector_late_delete_resolution SET updated_at='2026-01-03T00:00:00.000Z'", [])),
            ("resolution delete", raw.execute("DELETE FROM memory_vector_late_delete_resolution", [])),
            ("runtime lease insert", late_delete_runtime_lease_insert(&raw)),
            ("runtime lease update", raw.execute("UPDATE memory_vector_late_delete_runtime_lease SET updated_at='2026-01-03T00:00:00.000Z'", [])),
            ("runtime lease delete", raw.execute("DELETE FROM memory_vector_late_delete_runtime_lease", [])),
        ] {
            let error = result.expect_err("raw Schema-15 DML must be stopped by its writer-fence trigger");
            assert!(error.to_string().contains("INCOMPATIBLE_DATABASE_WRITER"), "{operation}: {error}");
        }
    }

    #[test]
    fn writer_fence_epoch_zero_connection_is_rejected_with_the_static_code() {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        seed_protected_rows(&authorized);
        drop(authorized);
        let epoch_zero = Connection::open(&path).unwrap();
        epoch_zero
            .create_scalar_function(
                "digital_life_writer_epoch",
                0,
                FunctionFlags::SQLITE_UTF8
                    | FunctionFlags::SQLITE_DETERMINISTIC
                    | FunctionFlags::SQLITE_INNOCUOUS,
                |_| Ok(0_i64),
            )
            .unwrap();

        expect_static_incompatible_writer(protected_update(
            &epoch_zero,
            "memory_vector_sync_outbox",
        ));
    }

    #[test]
    fn schema_19_emotion_tables_are_authorized_writer_only() {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        seed_protected_rows(&authorized);
        // The initializer trigger must not interfere with seeded lives: the
        // neutral emotion_state row is created for every existing life.
        assert_eq!(
            authorized
                .query_row(
                    "SELECT COUNT(*) FROM emotion_state WHERE life_id='writer-fence-life'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        // Authorized writer can write both emotion tables.
        assert_eq!(
            authorized
                .execute(
                    "UPDATE emotion_state SET updated_at='2026-08-23T00:00:00.000Z'
                     WHERE life_id='writer-fence-life'",
                    [],
                )
                .unwrap(),
            1
        );
        assert_eq!(
            authorized
                .execute(
                    "INSERT INTO emotion_event
                     (event_id, life_id, source_kind, source_ref, valence_delta,
                      activation_delta, result_valence, result_activation,
                      applied_revision, event_time, policy_version, created_at)
                     VALUES ('fence-event-1', 'writer-fence-life', 'fence', 'seed',
                             1, 1, 1, 1, 1, '2026-08-23T00:00:00.000Z', 1,
                             '2026-08-23T00:00:00.000Z')",
                    [],
                )
                .unwrap(),
            1
        );
        drop(authorized);

        let raw = Connection::open(&path).unwrap();
        for (operation, result) in [
            (
                "state insert",
                raw.execute(
                    "INSERT INTO emotion_state
                     (life_id, valence, activation, revision, policy_version,
                      last_applied_at, updated_at)
                     VALUES ('raw-life', 0, 0, 0, 1, '2026-01-01T00:00:00.000Z',
                             '2026-01-01T00:00:00.000Z')",
                    [],
                ),
            ),
            (
                "state update",
                raw.execute("UPDATE emotion_state SET revision=1", []),
            ),
            (
                "state delete",
                raw.execute(
                    "DELETE FROM emotion_state WHERE life_id='writer-fence-life'",
                    [],
                ),
            ),
            (
                "event insert",
                raw.execute(
                    "INSERT INTO emotion_event
                     (event_id, life_id, source_kind, source_ref, valence_delta,
                      activation_delta, result_valence, result_activation,
                      applied_revision, event_time, policy_version, created_at)
                     VALUES ('raw-event', 'writer-fence-life', 'fence', 'raw',
                             1, 1, 1, 1, 1, '2026-08-23T00:00:00.000Z', 1,
                             '2026-08-23T00:00:00.000Z')",
                    [],
                ),
            ),
            (
                "event update",
                raw.execute("UPDATE emotion_event SET policy_version=2", []),
            ),
            (
                "event delete",
                raw.execute(
                    "DELETE FROM emotion_event WHERE event_id='fence-event-1'",
                    [],
                ),
            ),
        ] {
            assert!(
                result.is_err(),
                "raw emotion {operation} must be stopped by its writer-fence trigger"
            );
        }
        // Nothing was changed by the rejected raw writes.
        let row_count: (i64, i64) = raw
            .query_row(
                "SELECT (SELECT COUNT(*) FROM emotion_state),
                        (SELECT COUNT(*) FROM emotion_event)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(row_count, (2, 1));
    }

    #[test]
    fn schema_20_relationship_tables_are_authorized_writer_only() {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        seed_protected_rows(&authorized);
        // The initializer trigger must not interfere with seeded lives: the
        // neutral primary_user relationship_state row is created for every
        // existing life.
        assert_eq!(
            authorized
                .query_row(
                    "SELECT COUNT(*) FROM relationship_state
                     WHERE life_id='writer-fence-life' AND subject_id='primary_user'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        // Authorized writer can write both relationship tables.
        assert_eq!(
            authorized
                .execute(
                    "UPDATE relationship_state SET updated_at='2026-08-25T00:00:00.000Z'
                     WHERE life_id='writer-fence-life' AND subject_id='primary_user'",
                    [],
                )
                .unwrap(),
            1
        );
        assert_eq!(
            authorized
                .execute(
                    "INSERT INTO relationship_event
                     (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
                      familiarity_delta, trust_delta, emotional_closeness_delta,
                      collaboration_delta, safety_delta, dependency_tendency_delta,
                      boundary_comfort_delta, tension_delta,
                      result_familiarity, result_trust, result_emotional_closeness,
                      result_collaboration, result_safety, result_dependency_tendency,
                      result_boundary_comfort, result_tension,
                      applied_revision, event_time, policy_version, created_at)
                     VALUES ('fence-rel-event-1', 'writer-fence-life', 'primary_user',
                             'fence', 'seed', 'policy_fence_seed',
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                             1, '2026-08-25T00:00:00.000Z', 1,
                             '2026-08-25T00:00:00.000Z')",
                    [],
                )
                .unwrap(),
            1
        );
        drop(authorized);

        let raw = Connection::open(&path).unwrap();
        for (operation, result) in [
            (
                "state insert",
                raw.execute(
                    "INSERT INTO relationship_state
                     (life_id, subject_id, familiarity, trust, emotional_closeness,
                      collaboration, safety, dependency_tendency, boundary_comfort, tension,
                      revision, policy_version, last_applied_at, updated_at)
                     VALUES ('raw-life', 'primary_user', 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                             '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')",
                    [],
                ),
            ),
            (
                "state update",
                raw.execute("UPDATE relationship_state SET revision=1", []),
            ),
            (
                "state delete",
                raw.execute(
                    "DELETE FROM relationship_state
                     WHERE life_id='writer-fence-life' AND subject_id='primary_user'",
                    [],
                ),
            ),
            (
                "event insert",
                raw.execute(
                    "INSERT INTO relationship_event
                     (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
                      familiarity_delta, trust_delta, emotional_closeness_delta,
                      collaboration_delta, safety_delta, dependency_tendency_delta,
                      boundary_comfort_delta, tension_delta,
                      result_familiarity, result_trust, result_emotional_closeness,
                      result_collaboration, result_safety, result_dependency_tendency,
                      result_boundary_comfort, result_tension,
                      applied_revision, event_time, policy_version, created_at)
                     VALUES ('raw-rel-event', 'writer-fence-life', 'primary_user',
                             'fence', 'raw', 'policy_fence_raw',
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                             2, '2026-08-25T00:00:00.000Z', 1,
                             '2026-08-25T00:00:00.000Z')",
                    [],
                ),
            ),
            (
                "event update",
                raw.execute("UPDATE relationship_event SET policy_version=2", []),
            ),
            (
                "event delete",
                raw.execute(
                    "DELETE FROM relationship_event WHERE event_id='fence-rel-event-1'",
                    [],
                ),
            ),
        ] {
            assert!(
                result.is_err(),
                "raw relationship {operation} must be stopped by its writer-fence trigger"
            );
        }
        // Nothing was changed by the rejected raw writes.
        let row_count: (i64, i64) = raw
            .query_row(
                "SELECT (SELECT COUNT(*) FROM relationship_state),
                        (SELECT COUNT(*) FROM relationship_event)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(row_count, (2, 1));
    }

    #[test]
    fn schema_18_generation_identity_immutable_generation_delete_denied_late_delete_resolution_runtime_create_captured_generation_authority_late_delete_24h_semantic_guards_are_orthogonal_to_the_schema19_writer_fence_triggers(
    ) {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        seed_protected_rows(&authorized);
        assert_eq!(WRITER_FENCE_TRIGGER_SPECS.len(), 99);
        let reserved: i64 = authorized.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND name LIKE 'digital_life_writer_epoch_%'", [], |r| r.get(0)).unwrap();
        assert_eq!(reserved, 99);
        for name in [
            "memory_vector_generation_semantic_delete_guard",
            "memory_vector_generation_semantic_identity_guard",
            "memory_vector_generation_semantic_epoch_guard",
        ] {
            assert!(!name.starts_with(WRITER_FENCE_TRIGGER_PREFIX));
            assert_eq!(
                authorized
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND name=?1",
                        [name],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                1
            );
        }
        assert!(authorized.execute("UPDATE memory_vector_generation SET generation_id='other' WHERE generation_id='generation-seed'", []).unwrap_err().to_string().contains("GENERATION_IDENTITY_IMMUTABLE"));
        assert!(authorized.execute("UPDATE memory_vector_generation SET descriptor_hash='other' WHERE generation_id='generation-seed'", []).unwrap_err().to_string().contains("GENERATION_IDENTITY_IMMUTABLE"));
        assert!(authorized.execute("UPDATE memory_vector_generation SET dimension=4 WHERE generation_id='generation-seed'", []).unwrap_err().to_string().contains("GENERATION_IDENTITY_IMMUTABLE"));
        assert!(authorized.execute("UPDATE memory_vector_generation SET state='active' WHERE generation_id='generation-seed'", []).unwrap_err().to_string().contains("GENERATION_AUTHORITY_EPOCH_INVALID"));
        assert_eq!(authorized.execute("UPDATE memory_vector_generation SET state='active', authority_epoch=2 WHERE generation_id='generation-seed' AND authority_epoch=1", []).unwrap(), 1);
        drop(authorized);
        let stale = Connection::open(&path).unwrap();
        stale
            .create_scalar_function(
                "digital_life_writer_epoch",
                0,
                FunctionFlags::SQLITE_UTF8
                    | FunctionFlags::SQLITE_DETERMINISTIC
                    | FunctionFlags::SQLITE_INNOCUOUS,
                |_| Ok(0_i64),
            )
            .unwrap();
        expect_static_incompatible_writer(stale.execute("UPDATE memory_vector_generation SET state='retired', authority_epoch=3 WHERE generation_id='generation-seed'", []));
        expect_static_incompatible_writer(protected_delete(&stale, "memory_vector_generation"));
        drop(stale);
        let raw = Connection::open(&path).unwrap();
        assert!(protected_delete(&raw, "memory_vector_generation").is_err());
        assert_eq!(raw.query_row("SELECT COUNT(*) FROM memory_vector_generation WHERE generation_id='generation-seed'", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
    }

    #[test]
    fn attempt_claim_identity_authorized_writer_can_update_both_epoch_columns() {
        let (_root, path) = initialized_fenced_database();
        let connection = authorized_connection(&path);
        seed_protected_rows(&connection);

        assert_eq!(
            connection
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET fenced_claim_epoch=1, last_marked_claim_epoch=1
                     WHERE life_id='writer-fence-life' AND memory_id='outbox-seed'",
                    [],
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT fenced_claim_epoch, last_marked_claim_epoch
                     FROM memory_vector_sync_outbox
                     WHERE life_id='writer-fence-life' AND memory_id='outbox-seed'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap(),
            (1, 1)
        );
        assert_eq!(writer_fence_trigger_specs().len(), 18);
    }

    #[test]
    fn attempt_claim_identity_raw_legacy_writer_cannot_modify_attempt_or_epoch_columns() {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        seed_protected_rows(&authorized);
        drop(authorized);
        let raw = Connection::open(&path).unwrap();

        assert!(update_attempt_count(&raw).is_err());
        assert!(update_fenced_claim_epoch(&raw).is_err());
        assert!(update_last_marked_claim_epoch(&raw).is_err());
    }

    #[test]
    fn attempt_claim_identity_epoch_zero_writer_is_rejected_with_static_code_for_all_updates() {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        seed_protected_rows(&authorized);
        drop(authorized);
        let epoch_zero = Connection::open(&path).unwrap();
        epoch_zero
            .create_scalar_function(
                "digital_life_writer_epoch",
                0,
                FunctionFlags::SQLITE_UTF8
                    | FunctionFlags::SQLITE_DETERMINISTIC
                    | FunctionFlags::SQLITE_INNOCUOUS,
                |_| Ok(0_i64),
            )
            .unwrap();

        expect_static_incompatible_writer(update_attempt_count(&epoch_zero));
        expect_static_incompatible_writer(update_fenced_claim_epoch(&epoch_zero));
        expect_static_incompatible_writer(update_last_marked_claim_epoch(&epoch_zero));
    }

    const D14_FENCED_TABLES: [&str; 5] = [
        "life_goal",
        "life_plan",
        "life_plan_step",
        "life_action_intent",
        "life_intent_event",
    ];

    fn seed_d14_authority_rows(connection: &Connection) {
        connection
            .execute_batch(
                "INSERT INTO life_goal
                     (goal_id, life_id, title, objective, status, revision, created_by_kind,
                      created_at, updated_at, closed_at, goal_version)
                 VALUES ('wf-goal', 'writer-fence-life', 'Fence Goal', 'Fence objective',
                         'active', 1, 'user_explicit', '2026-08-27T00:00:00.000Z',
                         '2026-08-27T00:00:00.000Z', NULL, 1);
                 INSERT INTO life_plan
                     (plan_id, life_id, goal_id, title, status, revision,
                      created_at, updated_at, closed_at, plan_version)
                 VALUES ('wf-plan', 'writer-fence-life', 'wf-goal', 'Fence Plan',
                         'draft', 1, '2026-08-27T00:00:00.000Z',
                         '2026-08-27T00:00:00.000Z', NULL, 1);
                 INSERT INTO life_plan_step
                     (step_id, life_id, plan_id, ordinal, summary, status, revision,
                      created_at, updated_at, closed_at, step_version)
                 VALUES ('wf-step', 'writer-fence-life', 'wf-plan', 1, 'Fence step summary',
                         'pending', 1, '2026-08-27T00:00:00.000Z',
                         '2026-08-27T00:00:00.000Z', NULL, 1);
                 INSERT INTO life_action_intent
                     (action_id, life_id, step_id, execution_class, summary, status, revision,
                      created_at, updated_at, closed_at, action_version)
                 VALUES ('wf-action', 'writer-fence-life', 'wf-step', 'internal_intent',
                         'Fence action summary', 'proposed', 1, '2026-08-27T00:00:00.000Z',
                         '2026-08-27T00:00:00.000Z', NULL, 1);
                 INSERT INTO life_intent_event
                     (event_id, life_id, entity_kind, goal_id, plan_id, step_id, action_id,
                      from_status, to_status, expected_revision, applied_revision,
                      actor_kind, occurred_at, event_version)
                 VALUES ('wf-event', 'writer-fence-life', 'action', NULL, NULL, NULL, 'wf-action',
                         'proposed', 'dismissed', 1, 2, 'user_explicit',
                         '2026-08-27T00:00:00.000Z', 1);",
            )
            .unwrap();
    }

    #[test]
    fn schema_22_writer_fence_manifest_is_seventy_five_and_covers_every_d14_table() {
        let (_root, path) = initialized_schema_twenty_two_database();
        let authorized = authorized_connection(&path);
        validate_writer_fence_manifest(&authorized).unwrap();
        let reserved: i64 = authorized
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='trigger' AND name LIKE 'digital_life_writer_epoch_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reserved, 75);
        assert_eq!(life_intent_writer_fence_trigger_specs().len(), 15);
        for table in D14_FENCED_TABLES {
            for operation in ["insert", "update", "delete"] {
                let count: i64 = authorized
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema
                         WHERE type='trigger'
                           AND name = ?1
                           AND sql LIKE ?2",
                        params![
                            format!("digital_life_writer_epoch_{table}_{operation}"),
                            format!("%ON {table}%")
                        ],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 1, "{table} {operation} fence must exist");
            }
        }
    }

    #[test]
    fn schema_23_writer_fence_manifest_adds_exactly_twelve_autonomy_operations() {
        let (_root, path) = initialized_schema_twenty_three_database();
        let authorized = authorized_connection(&path);
        validate_writer_fence_manifest(&authorized).unwrap();
        assert_eq!(life_intent_writer_fence_trigger_specs().len(), 15);
        assert_eq!(autonomy_writer_fence_trigger_specs().len(), 12);
        assert_eq!(AUTONOMY_WRITER_FENCE_TRIGGER_COUNT, 87);
        for table in [
            "life_autonomy_policy",
            "life_autonomy_policy_event",
            "life_proactive_intent",
            "life_proactive_intent_event",
        ] {
            for operation in ["insert", "update", "delete"] {
                let count: i64 = authorized
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema
                         WHERE type='trigger'
                           AND name = ?1
                           AND tbl_name = ?2
                           AND sql LIKE ?3",
                        params![
                            format!("digital_life_writer_epoch_{table}_{operation}"),
                            table,
                            format!("%BEFORE {} ON {table}%", operation.to_ascii_uppercase())
                        ],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 1, "{table} {operation} fence must exist");
            }
        }
    }

    #[test]
    fn schema_25_writer_fence_manifest_adds_exactly_six_body_package_operations_after_perception() {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        validate_writer_fence_manifest(&authorized).unwrap();
        assert_eq!(autonomy_writer_fence_trigger_specs().len(), 12);
        assert_eq!(perception_writer_fence_trigger_specs().len(), 6);
        assert_eq!(WRITER_FENCE_TRIGGER_SPECS.len(), 99);
        for table in ["life_perception_policy", "life_perception_policy_event"] {
            for operation in ["insert", "update", "delete"] {
                let count: i64 = authorized
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema
                         WHERE type='trigger'
                           AND name = ?1
                           AND tbl_name = ?2
                           AND sql LIKE ?3",
                        params![
                            format!("digital_life_writer_epoch_{table}_{operation}"),
                            table,
                            format!("%BEFORE {} ON {table}%", operation.to_ascii_uppercase())
                        ],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 1, "{table} {operation} fence must exist");
            }
        }
        for table in ["body_package", "body_package_asset"] {
            for operation in ["insert", "update", "delete"] {
                let count: i64 = authorized
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema
                         WHERE type='trigger'
                           AND name = ?1
                           AND tbl_name = ?2
                           AND sql LIKE ?3",
                        params![
                            format!("digital_life_writer_epoch_{table}_{operation}"),
                            table,
                            format!("%BEFORE {} ON {table}%", operation.to_ascii_uppercase())
                        ],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 1, "{table} {operation} fence must exist");
            }
        }
    }

    #[test]
    fn d14_tables_allow_authorized_writers_and_stop_every_other_writer() {
        let (_root, path) = initialized_fenced_database();
        let authorized = authorized_connection(&path);
        seed_protected_rows(&authorized);
        seed_d14_authority_rows(&authorized);
        drop(authorized);

        let epoch_zero = Connection::open(&path).unwrap();
        epoch_zero
            .create_scalar_function(
                "digital_life_writer_epoch",
                0,
                FunctionFlags::SQLITE_UTF8
                    | FunctionFlags::SQLITE_DETERMINISTIC
                    | FunctionFlags::SQLITE_INNOCUOUS,
                |_| Ok(0_i64),
            )
            .unwrap();
        for sql in [
            "UPDATE life_goal SET title='raw' WHERE goal_id='wf-goal'",
            "DELETE FROM life_goal WHERE goal_id='wf-goal'",
            "UPDATE life_plan SET title='raw' WHERE plan_id='wf-plan'",
            "DELETE FROM life_plan WHERE plan_id='wf-plan'",
            "UPDATE life_plan_step SET summary='raw' WHERE step_id='wf-step'",
            "DELETE FROM life_plan_step WHERE step_id='wf-step'",
            "UPDATE life_action_intent SET summary='raw' WHERE action_id='wf-action'",
            "DELETE FROM life_action_intent WHERE action_id='wf-action'",
            "UPDATE life_intent_event SET to_status='cancelled' WHERE event_id='wf-event'",
            "DELETE FROM life_intent_event WHERE event_id='wf-event'",
        ] {
            expect_static_incompatible_writer(epoch_zero.execute(sql, []));
        }
        let raw = Connection::open(&path).unwrap();
        for sql in [
            "INSERT INTO life_goal
                 (goal_id, life_id, title, objective, status, revision, created_by_kind,
                  created_at, updated_at, closed_at, goal_version)
             VALUES ('raw-goal', 'writer-fence-life', 'Raw', 'Raw objective', 'active', 1,
                     'user_explicit', '2026-08-27T00:00:00.000Z',
                     '2026-08-27T00:00:00.000Z', NULL, 1)",
            "INSERT INTO life_plan
                 (plan_id, life_id, goal_id, title, status, revision,
                  created_at, updated_at, closed_at, plan_version)
             VALUES ('raw-plan', 'writer-fence-life', 'wf-goal', 'Raw', 'draft', 1,
                     '2026-08-27T00:00:00.000Z', '2026-08-27T00:00:00.000Z', NULL, 1)",
            "INSERT INTO life_plan_step
                 (step_id, life_id, plan_id, ordinal, summary, status, revision,
                  created_at, updated_at, closed_at, step_version)
             VALUES ('raw-step', 'writer-fence-life', 'wf-plan', 5, 'Raw step', 'pending', 1,
                     '2026-08-27T00:00:00.000Z', '2026-08-27T00:00:00.000Z', NULL, 1)",
            "INSERT INTO life_action_intent
                 (action_id, life_id, step_id, execution_class, summary, status, revision,
                  created_at, updated_at, closed_at, action_version)
             VALUES ('raw-action', 'writer-fence-life', 'wf-step', 'internal_intent',
                     'Raw action', 'proposed', 1, '2026-08-27T00:00:00.000Z',
                     '2026-08-27T00:00:00.000Z', NULL, 1)",
            "INSERT INTO life_intent_event
                 (event_id, life_id, entity_kind, goal_id, plan_id, step_id, action_id,
                  from_status, to_status, expected_revision, applied_revision,
                  actor_kind, occurred_at, event_version)
             VALUES ('raw-event', 'writer-fence-life', 'goal', 'wf-goal', NULL, NULL, NULL,
                     'active', 'completed', 1, 2, 'user_explicit',
                     '2026-08-27T00:00:00.000Z', 1)",
        ] {
            assert!(
                raw.execute(sql, []).is_err(),
                "raw {sql} must be stopped by its D14 writer-fence trigger"
            );
        }

        // Authorized epoch-1 writers continue to work on every D14 table.
        let authorized = authorized_connection(&path);
        authorized
            .execute_batch(
                "INSERT INTO life_action_intent
                     (action_id, life_id, step_id, execution_class, summary, status, revision,
                      created_at, updated_at, closed_at, action_version)
                 VALUES ('wf-action-2', 'writer-fence-life', 'wf-step', 'agent_task_proposal',
                         'Second authorized action', 'proposed', 1,
                         '2026-08-27T00:00:00.000Z', '2026-08-27T00:00:00.000Z', NULL, 1);",
            )
            .unwrap();
        let action_count: i64 = authorized
            .query_row(
                "SELECT COUNT(*) FROM life_action_intent WHERE action_id = 'wf-action-2'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(action_count, 1);
    }
}
